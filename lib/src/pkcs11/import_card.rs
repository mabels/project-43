use anyhow::{Context, Result};
use openpgp::cert::prelude::*;
use openpgp::crypto::mpi;
use openpgp::packet::{
    key::{Key4, PrimaryRole, PublicParts, SubordinateRole},
    signature::SignatureBuilder,
    UserID,
};
use openpgp::types::{Curve, HashAlgorithm, KeyFlags, SignatureType};
use openpgp::Packet;
use openpgp_card_sequoia::types::KeyType;
use sequoia_openpgp as openpgp;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::key_store::store::KeyStore;
use crate::pkcs11::card::open_card;

/// Read all three slot public keys off a connected OpenPGP card, synthesise a
/// self-signed OpenPGP cert using the card itself to create the UID binding
/// signature, then import the cert into `ks` and write a
/// `<fingerprint>.card.json` recording the card's AID.
///
/// The resulting cert has:
/// - Primary key (SIG slot)  → CERTIFY + SIGN
/// - Subkey    (AUTH slot)   → AUTHENTICATE  (if slot is populated)
/// - Subkey    (DEC slot)    → ENCRYPT_COMMUNICATIONS + ENCRYPT_STORAGE (if slot is populated)
///
/// `card_ident`: if `Some`, selects the card by AID ident string; if `None`,
/// uses the first connected card.  Run `p43 key list-cards` to find idents.
///
/// `uid_override`: if `Some`, used as the cert's UID.  Falls back to the
/// cardholder name stored on the card.  Returns an error if neither is set.
///
/// `pin`: the card's User Signing PIN (the one that unlocks the SIG slot;
/// typically the regular "User PIN" on YubiKeys, not the Admin PIN).
pub fn import_card_cert(
    ks: &KeyStore,
    card_ident: Option<&str>,
    uid_override: Option<&str>,
    pin: &str,
) -> Result<()> {
    let mut card = open_card(card_ident)?;
    let mut tx = card
        .transaction()
        .context("Failed to open card transaction")?;

    // ── 1. Read all metadata before consuming tx with to_signing_card ────────

    let ident = tx
        .application_identifier()
        .context("Failed to read card AID")?
        .ident();

    let cardholder_name = tx.cardholder_name().unwrap_or_default();

    // Read all three key-generation timestamps in one shot.
    let gen_times = tx.key_generation_times().ok();

    let sig_creation_time = gen_times
        .as_ref()
        .and_then(|t| t.signature())
        .map(|ts| UNIX_EPOCH + Duration::from_secs(ts.get() as u64))
        .unwrap_or_else(SystemTime::now);

    let auth_creation_time_opt: Option<SystemTime> = gen_times
        .as_ref()
        .and_then(|t| t.authentication())
        .map(|ts| UNIX_EPOCH + Duration::from_secs(ts.get() as u64));

    let dec_creation_time_opt: Option<SystemTime> = gen_times
        .as_ref()
        .and_then(|t| t.decryption())
        .map(|ts| UNIX_EPOCH + Duration::from_secs(ts.get() as u64));

    // Signing slot — required.
    let sig_mpis = tx
        .public_key(KeyType::Signing)
        .context("Failed to read signing-slot public key")?
        .context("No signing key on card")?
        .mpis()
        .clone();

    // Auth slot — optional.
    let auth_mpis_opt: Option<mpi::PublicKey> = tx
        .public_key(KeyType::Authentication)
        .ok()
        .flatten()
        .map(|pm| pm.mpis().clone());

    // Decryption slot — optional.
    let dec_mpis_opt: Option<mpi::PublicKey> = tx
        .public_key(KeyType::Decryption)
        .ok()
        .flatten()
        .map(|pm| pm.mpis().clone());

    // ── 2. Resolve UID ────────────────────────────────────────────────────────

    let uid_str: String = match uid_override {
        Some(s) => s.to_owned(),
        None => {
            anyhow::ensure!(
                !cardholder_name.is_empty(),
                "No UID available: set a cardholder name on the card or pass --uid"
            );
            cardholder_name
        }
    };

    // ── 3. Build primary key from signing-slot MPIs ──────────────────────────

    let primary: openpgp::packet::Key<PublicParts, PrimaryRole> =
        build_primary_key(&sig_mpis, sig_creation_time)?;

    // Bare cert (primary only) — needed so uid.bind() / sign_subkey_binding()
    // can reference the primary fingerprint.
    let bare = Cert::from_packets(std::iter::once(Packet::from(primary.clone())))
        .context("Failed to create bare cert from primary key")?;

    let uid = UserID::from(uid_str.as_bytes());

    // ── 4. Build optional subkeys from auth / decryption slot MPIs ───────────

    let auth_subkey_opt: Option<openpgp::packet::Key<PublicParts, SubordinateRole>> = auth_mpis_opt
        .as_ref()
        .map(|m| build_auth_subkey(m, auth_creation_time_opt.unwrap_or_else(SystemTime::now)))
        .transpose()?;

    let dec_subkey_opt: Option<openpgp::packet::Key<PublicParts, SubordinateRole>> = dec_mpis_opt
        .as_ref()
        .map(|m| build_enc_subkey(m, dec_creation_time_opt.unwrap_or_else(SystemTime::now)))
        .transpose()?;

    // ── 5. Self-certify using the card's signing slot ─────────────────────────

    tx.verify_user_signing_pin(pin)
        .context("PIN verification failed")?;

    let mut sign_card = tx
        .to_signing_card(None)
        .context("Failed to open signing card mode")?;

    let (uid_sig, auth_sig_opt, enc_sig_opt) = {
        let mut signer = sign_card
            .signer(&|| eprintln!("Touch YubiKey now…"))
            .context("Failed to get signer from card")?;

        // UID binding — primary key gets CERTIFY + SIGN.
        let uid_sig = uid
            .bind(
                &mut signer,
                &bare,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_key_flags(KeyFlags::empty().set_certification().set_signing())
                    .context("set_key_flags (primary) failed")?
                    .set_preferred_hash_algorithms(vec![
                        HashAlgorithm::SHA512,
                        HashAlgorithm::SHA256,
                    ])
                    .context("set_preferred_hash_algorithms failed")?,
            )
            .context("Failed to create UID binding signature")?;

        // Auth subkey binding.
        let auth_sig_opt = auth_subkey_opt
            .as_ref()
            .map(|sk| {
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_key_flags(KeyFlags::empty().set_authentication())
                    .context("set_key_flags (auth subkey) failed")?
                    .sign_subkey_binding(&mut signer, bare.primary_key().key(), sk)
                    .context("Failed to create auth SubkeyBinding signature")
            })
            .transpose()?;

        // Encrypt subkey binding.
        let enc_sig_opt = dec_subkey_opt
            .as_ref()
            .map(|sk| {
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_key_flags(
                        KeyFlags::empty()
                            .set_transport_encryption()
                            .set_storage_encryption(),
                    )
                    .context("set_key_flags (enc subkey) failed")?
                    .sign_subkey_binding(&mut signer, bare.primary_key().key(), sk)
                    .context("Failed to create encrypt SubkeyBinding signature")
            })
            .transpose()?;

        (uid_sig, auth_sig_opt, enc_sig_opt)
    };
    let _ = sign_card; // explicitly end the card borrow before assembling the cert

    // ── 6. Assemble and save ──────────────────────────────────────────────────

    let has_auth = auth_subkey_opt.is_some();
    let has_enc = dec_subkey_opt.is_some();

    let mut extra: Vec<Packet> = vec![Packet::from(uid), Packet::from(uid_sig)];

    if let (Some(sk), Some(sig)) = (auth_subkey_opt, auth_sig_opt) {
        extra.push(Packet::from(sk));
        extra.push(Packet::from(sig));
    }
    if let (Some(sk), Some(sig)) = (dec_subkey_opt, enc_sig_opt) {
        extra.push(Packet::from(sk));
        extra.push(Packet::from(sig));
    }

    let cert = bare
        .insert_packets(extra)
        .context("Failed to insert UID/subkeys into cert")?;

    let fp = cert.fingerprint().to_hex();
    ks.save(&cert, None)
        .context("Failed to save cert to key store")?;
    ks.register_card(&fp, &ident)
        .context("Failed to register card AID")?;

    println!("Imported key {}", fp);
    println!("  UID:   {}", uid_str);
    println!("  Card:  {}", ident);
    println!(
        "  Slots: SIG{}{}",
        if has_auth { " + AUTH" } else { "" },
        if has_enc { " + ENC" } else { "" },
    );

    Ok(())
}

// ── Key-building helpers ───────────────────────────────────────────────────────

fn build_primary_key(
    mpis: &mpi::PublicKey,
    ct: SystemTime,
) -> Result<openpgp::packet::Key<PublicParts, PrimaryRole>> {
    match mpis {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => {
            let raw = q.value();
            anyhow::ensure!(
                raw.len() >= 33 && raw[0] == 0x40,
                "Unexpected Ed25519 q encoding on SIG slot (len={}, prefix={:#x})",
                raw.len(),
                raw.first().copied().unwrap_or(0)
            );
            Ok(Key4::import_public_ed25519(&raw[1..], Some(ct))
                .context("Failed to construct Ed25519 primary key")?
                .into())
        }
        mpi::PublicKey::RSA { e, n } => Ok(Key4::import_public_rsa(e.value(), n.value(), Some(ct))
            .context("Failed to construct RSA primary key")?
            .into()),
        other => anyhow::bail!("Unsupported algorithm on SIG slot: {:?}", other),
    }
}

fn build_auth_subkey(
    mpis: &mpi::PublicKey,
    ct: SystemTime,
) -> Result<openpgp::packet::Key<PublicParts, SubordinateRole>> {
    match mpis {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => {
            let raw = q.value();
            anyhow::ensure!(
                raw.len() >= 33 && raw[0] == 0x40,
                "Unexpected Ed25519 q encoding on AUTH slot"
            );
            Ok(Key4::import_public_ed25519(&raw[1..], Some(ct))
                .context("Failed to construct Ed25519 auth subkey")?
                .into())
        }
        mpi::PublicKey::RSA { e, n } => Ok(Key4::import_public_rsa(e.value(), n.value(), Some(ct))
            .context("Failed to construct RSA auth subkey")?
            .into()),
        other => anyhow::bail!("Unsupported algorithm on AUTH slot: {:?}", other),
    }
}

fn build_enc_subkey(
    mpis: &mpi::PublicKey,
    ct: SystemTime,
) -> Result<openpgp::packet::Key<PublicParts, SubordinateRole>> {
    match mpis {
        mpi::PublicKey::ECDH {
            curve: Curve::Cv25519,
            q,
            hash,
            sym,
        } => {
            let raw = q.value();
            anyhow::ensure!(
                raw.len() >= 33 && raw[0] == 0x40,
                "Unexpected Cv25519 q encoding on DEC slot (len={}, prefix={:#x})",
                raw.len(),
                raw.first().copied().unwrap_or(0)
            );
            Ok(
                Key4::import_public_cv25519(&raw[1..], *hash, *sym, Some(ct))
                    .context("Failed to construct Cv25519 encrypt subkey")?
                    .into(),
            )
        }
        mpi::PublicKey::RSA { e, n } => Ok(Key4::import_public_rsa(e.value(), n.value(), Some(ct))
            .context("Failed to construct RSA encrypt subkey")?
            .into()),
        other => anyhow::bail!("Unsupported algorithm on DEC slot: {:?}", other),
    }
}
