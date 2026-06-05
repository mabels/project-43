//! Card-backed PGP operations (sign, verify, encrypt, decrypt, sign+encrypt,
//! decrypt+verify).
//!
//! Signing and decryption are performed on the YubiKey / OpenPGP card via
//! [`openpgp_card_rpgp::CardSlot`].  Encryption and signature verification
//! are pure-software rPGP operations (they only need the recipient's / signer's
//! public key, so no card involvement).

use anyhow::{Context, Result};
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, Esk, Message, MessageBuilder, SignedPublicKey,
    VerificationResult,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{DecryptionKey, EskType, Password, SigningKey, VerifyingKey};
use rand::thread_rng;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;

use crate::pkcs11::card::{open_card, open_first_card, pin_to_secret};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Load a public cert from a file (armored PGP public key block).
pub(crate) fn load_cert(path: &Path) -> Result<SignedPublicKey> {
    let f = std::fs::File::open(path)
        .with_context(|| format!("Failed to open public key file {:?}", path))?;
    let (key, _) = SignedPublicKey::from_armor_single(io::BufReader::new(f))
        .with_context(|| format!("Failed to parse public key from {:?}", path))?;
    Ok(key)
}

/// Verify embedded signatures in a (already-read-to-end) Message against a
/// signer cert (primary key + all subkeys are tried).
fn verify_signed_message(msg: &Message<'_>, signer: &SignedPublicKey) -> Result<()> {
    // Not a Signed message → nothing to verify.
    if matches!(msg, Message::Literal { .. }) {
        return Ok(());
    }
    let primary: &dyn VerifyingKey = &signer.primary_key;
    let subkeys: Vec<&dyn VerifyingKey> = signer
        .public_subkeys
        .iter()
        .map(|sk| sk as &dyn VerifyingKey)
        .collect();
    let mut all_keys: Vec<&dyn VerifyingKey> = vec![primary];
    all_keys.extend(subkeys);
    let results = msg.verify_nested(&all_keys)?;
    if results
        .iter()
        .any(|r| matches!(r, VerificationResult::Valid(_)))
    {
        Ok(())
    } else {
        anyhow::bail!("No valid signature found in message")
    }
}

// ── card sign ─────────────────────────────────────────────────────────────────

/// Sign `data` using the card's signing slot; returns an armored detached
/// signature.
pub fn sign(data: &[u8], pin: &str) -> Result<String> {
    sign_with_ident(data, pin, None)
}

/// Like [`sign`] but selects a card by AID ident string.
pub fn sign_with_ident(data: &[u8], pin: &str, ident: Option<&str>) -> Result<String> {
    let mut card = open_card(ident)?;
    let mut tx = card.transaction().context("Failed to open transaction")?;
    tx.verify_user_signing_pin(pin_to_secret(pin))
        .context("PIN verification failed")?;
    let touch = || eprintln!("Touch YubiKey now...");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Signing, &touch)
        .context("Failed to init signing slot")?;
    let raw_sig = slot
        .sign_data(data, false, &Password::empty(), HashAlgorithm::Sha256)
        .map_err(|e| anyhow::anyhow!("Card sign failed: {e}"))?;
    DetachedSignature::new(raw_sig)
        .to_armored_string(ArmorOptions::default())
        .context("Failed to armor signature")
}

// ── software verify ───────────────────────────────────────────────────────────

/// Verify a detached signature (armored) against `data` using the signer's
/// public key file.
pub fn verify(data: &[u8], sig_armor: &[u8], signer_path: &Path) -> Result<()> {
    let cert = load_cert(signer_path)?;
    let (det_sig, _) = DetachedSignature::from_armor_single(Cursor::new(sig_armor))
        .context("Failed to parse detached signature")?;

    // Try primary key first, then each subkey.
    if det_sig.verify(&cert.primary_key, data).is_ok() {
        return Ok(());
    }
    for sk in &cert.public_subkeys {
        if det_sig.verify(sk, data).is_ok() {
            return Ok(());
        }
    }
    anyhow::bail!("Signature verification failed")
}

// ── software encrypt ──────────────────────────────────────────────────────────

/// Encrypt `data` for `recipient_path` (public key file); returns an armored
/// PGP message.
pub fn encrypt(data: &[u8], recipient_path: &Path) -> Result<String> {
    let recipient = load_cert(recipient_path)?;

    let enc_subkey = recipient
        .public_subkeys
        .iter()
        .find(|sk| {
            sk.signatures
                .iter()
                .any(|sig| sig.key_flags().encrypt_comms())
        })
        .context("No encryption subkey found in recipient cert")?;

    let mut builder = MessageBuilder::from_bytes("", data.to_vec())
        .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(thread_rng(), enc_subkey)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
    builder
        .to_armored_string(thread_rng(), ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Failed to build encrypted message: {e}"))
}

// ── card decrypt ──────────────────────────────────────────────────────────────

/// Decrypt an armored OpenPGP message using the card's decryption slot.
pub fn decrypt(data: &[u8], pin: &str) -> Result<Vec<u8>> {
    decrypt_with_card(data, pin, None)
}

/// Like [`decrypt`] but selects a card by AID ident string.
pub fn decrypt_with_card(data: &[u8], pin: &str, ident: Option<&str>) -> Result<Vec<u8>> {
    // Accept both ASCII-armored (new format) and raw binary PGP (old format).
    let msg = if let Ok((msg, _)) = Message::from_armor(BufReader::new(Cursor::new(data))) {
        msg
    } else {
        Message::from_bytes(data).context("Failed to parse PGP message (tried armor and binary)")?
    };

    let mut card = open_card(ident)?;
    let mut tx = card.transaction().context("Failed to open transaction")?;
    tx.verify_user_pin(pin_to_secret(pin))
        .context("PIN verification failed")?;
    let touch = || eprintln!("Touch YubiKey now...");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Decryption, &touch)
        .context("Failed to init decryption slot")?;

    // `CardSlot::decrypt_message` has a known bug (comment: "FIXME: match id?"):
    // it propagates an error on the first PKESK that doesn't match the card's key
    // type, rather than skipping it and trying the next one.  When a message is
    // sealed to multiple recipients (e.g. RSA card + Curve25519 soft key), the
    // first mismatched PKESK causes an "Unsupported key type" error even though
    // the correct PKESK comes later.
    //
    // Work-around: find the PKESK that matches this card slot by key ID /
    // fingerprint, decrypt just the session key directly, then finish with
    // `decrypt_with_session_key` which is not affected by the bug.
    let session_key = match &msg {
        Message::Encrypted { esk, .. } => {
            let mut found = None;
            for e in esk {
                if let Esk::PublicKeyEncryptedSessionKey(pkesk) = e {
                    if !pkesk.match_identity(&slot) {
                        continue;
                    }
                    let values = match pkesk.values() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    match slot.decrypt(&Password::empty(), values, EskType::V3_4) {
                        Ok(Ok(sk)) => {
                            found = Some(sk);
                            break;
                        }
                        // Inner Err means "not our PKESK", outer Err is a hard
                        // failure — skip in both cases and try the next packet.
                        _ => continue,
                    }
                }
            }
            found.context("No PKESK in this message matched the card's decryption key")?
        }
        _ => anyhow::bail!("Message is not an encrypted message"),
    };

    let mut decrypted = msg
        .decrypt_with_session_key(session_key)
        .map_err(|e| anyhow::anyhow!("Card decrypt failed: {e}"))?;
    let mut out = Vec::new();
    decrypted.read_to_end(&mut out)?;
    Ok(out)
}

// ── card sign + software encrypt ──────────────────────────────────────────────

/// Sign `data` with the card signing slot, then encrypt to `recipient_path`.
/// The card slot implements [`SigningKey`], so signing happens inside the
/// message builder at serialisation time (one card touch total).
pub fn sign_encrypt(data: &[u8], recipient_path: &Path, pin: &str) -> Result<String> {
    let recipient = load_cert(recipient_path)?;
    let enc_subkey = recipient
        .public_subkeys
        .iter()
        .find(|sk| {
            sk.signatures
                .iter()
                .any(|sig| sig.key_flags().encrypt_comms())
        })
        .context("No encryption subkey found in recipient cert")?;

    let mut card = open_first_card()?;
    let mut tx = card.transaction().context("Failed to open transaction")?;
    tx.verify_user_signing_pin(pin_to_secret(pin))
        .context("PIN verification failed")?;
    let touch = || eprintln!("Touch YubiKey now...");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Signing, &touch)
        .context("Failed to init signing slot")?;

    let mut builder = MessageBuilder::from_bytes("", data.to_vec())
        .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(thread_rng(), enc_subkey)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
    builder.sign(
        &slot as &dyn SigningKey,
        Password::empty(),
        HashAlgorithm::Sha256,
    );
    // Card touch happens during to_armored_string when the builder signs.
    builder
        .to_armored_string(thread_rng(), ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Failed to build message: {e}"))
}

// ── card decrypt + software verify ───────────────────────────────────────────

/// Decrypt a signed+encrypted message using the card, then verify the
/// embedded signature against `signer_path`.
pub fn decrypt_verify(data: &[u8], signer_path: &Path, pin: &str) -> Result<Vec<u8>> {
    let cert = load_cert(signer_path)?;
    let (msg, _) = Message::from_armor(BufReader::new(Cursor::new(data)))
        .context("Failed to parse armored message")?;

    let mut card = open_first_card()?;
    let mut tx = card.transaction().context("Failed to open transaction")?;
    tx.verify_user_pin(pin_to_secret(pin))
        .context("PIN verification failed")?;
    let touch = || eprintln!("Touch YubiKey now...");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Decryption, &touch)
        .context("Failed to init decryption slot")?;
    let mut decrypted = slot
        .decrypt_message(msg)
        .map_err(|e| anyhow::anyhow!("Card decrypt failed: {e}"))?;

    // Read the plaintext; this also finalises signature packet state.
    let mut out = Vec::new();
    decrypted.read_to_end(&mut out)?;
    verify_signed_message(&decrypted, &cert)?;
    Ok(out)
}

// ── YubiKey slot info ─────────────────────────────────────────────────────────

/// One slot's public-key metadata — algo string + OpenSSH key + optional PGP armor.
pub struct CardSlotInfo {
    pub role: String,
    pub algo: String,
    pub openssh_key: Option<String>,
    /// Armored OpenPGP public key packet for this slot (single raw packet, no cert).
    pub pgp_armored: Option<String>,
}

/// Read all three OpenPGP slots from the card identified by `ident` and
/// return their public-key metadata.  Slots with no key loaded are skipped.
pub fn read_card_slot_info(ident: &str, label: &str) -> anyhow::Result<Vec<CardSlotInfo>> {
    let mut card = open_card(Some(ident))
        .with_context(|| format!("Cannot open card {ident} — is the YubiKey connected?"))?;
    let mut tx = card.transaction().context("card transaction")?;
    let no_touch: &(dyn Fn() + Send + Sync) = &|| {};

    let mut slots = Vec::new();
    for (key_type, role) in &[
        (KeyType::Authentication, "auth"),
        (KeyType::Signing, "sign"),
        (KeyType::Decryption, "encrypt"),
    ] {
        let slot = match CardSlot::init_from_card(&mut tx, *key_type, no_touch) {
            Ok(s) => s,
            Err(_) => continue,
        };
        use pgp::types::KeyDetails as _;
        let params = slot.public_key().public_params();
        let algo = crate::ssh_agent::pub_params_algo_string(params);
        let openssh_key = if *role != "encrypt" {
            crate::ssh_agent::pub_params_to_openssh_string(params, label)
        } else {
            None
        };
        // Armor the raw OpenPGP public key packet as "PUBLIC KEY BLOCK".
        let pgp_armored = {
            use pgp::armor::{self, BlockType};
            let mut armored = Vec::new();
            let ok = armor::write(
                slot.public_key(),
                BlockType::PublicKey,
                &mut armored,
                None,
                false,
            )
            .is_ok();
            if ok {
                String::from_utf8(armored).ok()
            } else {
                None
            }
        };
        slots.push(CardSlotInfo {
            role: role.to_string(),
            algo,
            openssh_key,
            pgp_armored,
        });
    }
    Ok(slots)
}

// ── bytes-based variants (no filesystem paths) ────────────────────────────────

/// Sign-then-encrypt using a card identified by `ident`, with the recipient's
/// armored public key given as raw bytes (no file path needed).
pub fn sign_encrypt_with_recipient_bytes(
    data: &[u8],
    recipient_armored: &[u8],
    pin: &str,
    ident: Option<&str>,
) -> Result<String> {
    let recipient = load_pubkey_from_bytes(recipient_armored)?;
    let enc_subkey = recipient
        .public_subkeys
        .iter()
        .find(|sk| {
            sk.signatures
                .iter()
                .any(|sig| sig.key_flags().encrypt_comms())
        })
        .context("No encryption subkey in recipient cert")?;

    let mut card = open_card(ident)?;
    let mut tx = card.transaction().context("Failed to open transaction")?;
    tx.verify_user_signing_pin(pin_to_secret(pin))
        .context("PIN verification failed")?;
    let touch = || eprintln!("Touch YubiKey now...");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Signing, &touch)
        .context("Failed to init signing slot")?;

    let mut builder = MessageBuilder::from_bytes("", data.to_vec())
        .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(thread_rng(), enc_subkey)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
    builder.sign(
        &slot as &dyn SigningKey,
        Password::empty(),
        HashAlgorithm::Sha256,
    );
    builder
        .to_armored_string(thread_rng(), ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Failed to build message: {e}"))
}

/// Decrypt-then-verify using a card, with the signer's armored public key
/// given as raw bytes.
pub fn decrypt_verify_with_signer_bytes(
    data: &[u8],
    signer_armored: &[u8],
    pin: &str,
    ident: Option<&str>,
) -> Result<Vec<u8>> {
    let cert = load_pubkey_from_bytes(signer_armored)?;
    let (msg, _) = Message::from_armor(BufReader::new(Cursor::new(data)))
        .context("Failed to parse armored message")?;

    let mut card = open_card(ident)?;
    let mut tx = card.transaction().context("Failed to open transaction")?;
    tx.verify_user_pin(pin_to_secret(pin))
        .context("PIN verification failed")?;
    let touch = || eprintln!("Touch YubiKey now...");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Decryption, &touch)
        .context("Failed to init decryption slot")?;
    let mut decrypted = slot
        .decrypt_message(msg)
        .map_err(|e| anyhow::anyhow!("Card decrypt failed: {e}"))?;

    let mut out = Vec::new();
    decrypted.read_to_end(&mut out)?;
    verify_signed_message(&decrypted, &cert)?;
    Ok(out)
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn load_pubkey_from_bytes(bytes: &[u8]) -> Result<SignedPublicKey> {
    crate::pgp_ops::load_pubkey_from_bytes(bytes)
}
