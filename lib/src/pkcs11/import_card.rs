use anyhow::{Context, Result};
use openpgp::cert::prelude::*;
use openpgp::crypto::mpi;
use openpgp::packet::{
    key::{Key4, PrimaryRole, PublicParts},
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

/// Read the signing-slot public key off a connected OpenPGP card, synthesise
/// a self-signed OpenPGP cert using the card itself to create the UID binding
/// signature, then import the cert into `ks` and write a
/// `<fingerprint>.card.json` recording the card's AID.
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

    let creation_time = tx
        .key_generation_times()
        .ok()
        .and_then(|t| {
            t.signature()
                .map(|ts| UNIX_EPOCH + Duration::from_secs(ts.get() as u64))
        })
        .unwrap_or_else(SystemTime::now);

    let pub_material = tx
        .public_key(KeyType::Signing)
        .context("Failed to read signing-slot public key")?
        .context("No signing key on card")?;
    let mpis = pub_material.mpis().clone();

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

    // ── 3. Build primary key from card's signing-slot MPIs ───────────────────

    let primary: openpgp::packet::Key<PublicParts, PrimaryRole> = match &mpis {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => {
            let raw = q.value();
            anyhow::ensure!(
                raw.len() >= 33 && raw[0] == 0x40,
                "Unexpected Ed25519 q encoding from card (len={}, prefix={:#x})",
                raw.len(),
                raw.first().copied().unwrap_or(0)
            );
            Key4::import_public_ed25519(&raw[1..], Some(creation_time))
                .context("Failed to construct Ed25519 primary key")?
                .into()
        }
        mpi::PublicKey::RSA { e, n } => {
            Key4::import_public_rsa(e.value(), n.value(), Some(creation_time))
                .context("Failed to construct RSA primary key")?
                .into()
        }
        other => anyhow::bail!("Unsupported algorithm on signing slot: {:?}", other),
    };

    // Create a bare cert (primary key only) so that uid.bind() can reference it.
    let bare = Cert::from_packets(std::iter::once(Packet::from(primary.clone())))
        .context("Failed to create bare cert from primary key")?;

    let uid = UserID::from(uid_str.as_bytes());

    // ── 4. Self-certify the UID using the card's signing slot ─────────────────

    tx.verify_user_signing_pin(pin)
        .context("PIN verification failed")?;

    let mut sign_card = tx
        .to_signing_card(None)
        .context("Failed to open signing card mode")?;

    let binding_sig = {
        let mut signer = sign_card
            .signer(&|| eprintln!("Touch YubiKey now…"))
            .context("Failed to get signer from card")?;

        let sig_builder = SignatureBuilder::new(SignatureType::PositiveCertification)
            // Primary key carries CERTIFY + SIGN: the card's signing slot IS
            // the signing key, and OpenPGP allows the primary key to sign.
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())
            .context("set_key_flags failed")?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])
            .context("set_preferred_hash_algorithms failed")?;

        uid.bind(&mut signer, &bare, sig_builder)
            .context("Failed to create UID binding signature")?
    };
    drop(sign_card);

    // ── 5. Assemble and save ──────────────────────────────────────────────────

    let cert = bare
        .insert_packets([Packet::from(uid), Packet::from(binding_sig)])
        .context("Failed to insert UID into cert")?;

    let fp = cert.fingerprint().to_hex();
    ks.save(&cert, None)
        .context("Failed to save cert to key store")?;
    ks.register_card(&fp, &ident)
        .context("Failed to register card AID")?;

    println!("Imported key {}", fp);
    println!("  UID:   {}", uid_str);
    println!("  Card:  {}", ident);

    Ok(())
}
