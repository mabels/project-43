//! Software-key PGP operations using rPGP.
//!
//! These back [`VirtualCard`] in tests and are the non-card path for sign /
//! encrypt / decrypt when hardware is absent.

use anyhow::{Context, Result};
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, Message, MessageBuilder, SignedPublicKey,
    SignedSecretKey, VerificationResult,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{Password, VerifyingKey};
use rand::thread_rng;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;

use crate::pkcs11::ops::load_cert;

// ── key loading ───────────────────────────────────────────────────────────────

/// Load an armored secret key from disk.
pub fn load_secret_cert(key_file: &Path, _passphrase: &str) -> Result<SignedSecretKey> {
    let f = std::fs::File::open(key_file)
        .with_context(|| format!("Failed to open secret key file {:?}", key_file))?;
    let (key, _) = SignedSecretKey::from_armor_single(io::BufReader::new(f))
        .with_context(|| format!("Failed to parse secret key from {:?}", key_file))?;
    Ok(key)
}

/// Build a [`Password`] from a passphrase string.
fn make_password(passphrase: &str) -> Password {
    if passphrase.is_empty() {
        Password::empty()
    } else {
        Password::from(passphrase)
    }
}

/// Sign `data` with the best available key from `key`: first signing-capable
/// subkey, falling back to the primary.  Uses concrete types so the
/// monomorphised `sign_binary_data` bound (`Sized`) is satisfied.
fn detach_sign(
    key: &SignedSecretKey,
    pw: &Password,
    data: &[u8],
) -> pgp::errors::Result<DetachedSignature> {
    if let Some(sk) = key
        .secret_subkeys
        .iter()
        .find(|sk| sk.signatures.iter().any(|sig| sig.key_flags().sign()))
    {
        // SignedSecretSubKey derefs to SecretSubkey which impl SigningKey.
        let sk_ref: &pgp::packet::SecretSubkey = sk;
        DetachedSignature::sign_binary_data(
            thread_rng(),
            sk_ref,
            pw,
            pgp::crypto::hash::HashAlgorithm::Sha256,
            data,
        )
    } else {
        DetachedSignature::sign_binary_data(
            thread_rng(),
            &key.primary_key,
            pw,
            pgp::crypto::hash::HashAlgorithm::Sha256,
            data,
        )
    }
}

/// Verify embedded signatures in a (read-to-end) Message against a signer cert.
fn verify_signed_message(msg: &Message<'_>, signer: &SignedPublicKey) -> Result<()> {
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

// ── public API ────────────────────────────────────────────────────────────────

/// Create an armored detached signature over `data` using a software key.
pub fn sign(data: &[u8], key_file: &Path, passphrase: &str) -> Result<String> {
    let key = load_secret_cert(key_file, passphrase)?;
    let pw = make_password(passphrase);
    detach_sign(&key, &pw, data)
        .map_err(|e| anyhow::anyhow!("Sign failed: {e}"))?
        .to_armored_string(ArmorOptions::default())
        .context("Failed to armor signature")
}

/// Decrypt an armored OpenPGP message using a software key.
pub fn decrypt(data: &[u8], key_file: &Path, passphrase: &str) -> Result<Vec<u8>> {
    let key = load_secret_cert(key_file, passphrase)?;
    let pw = make_password(passphrase);
    let (msg, _) = Message::from_armor(BufReader::new(Cursor::new(data)))
        .context("Failed to parse armored message")?;
    let mut decrypted = msg
        .decrypt(&pw, &key)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;
    let mut out = Vec::new();
    decrypted.read_to_end(&mut out)?;
    Ok(out)
}

/// Sign then encrypt `data` to `recipient_path` using a software key.
/// Signing key is embedded in the MessageBuilder so one pass produces both.
pub fn sign_encrypt(
    data: &[u8],
    key_file: &Path,
    recipient_path: &Path,
    passphrase: &str,
) -> Result<String> {
    let key = load_secret_cert(key_file, passphrase)?;
    let pw = make_password(passphrase);
    let recipient: SignedPublicKey = load_cert(recipient_path)?;

    let enc_subkey = recipient
        .public_subkeys
        .iter()
        .find(|sk| {
            sk.signatures
                .iter()
                .any(|sig| sig.key_flags().encrypt_comms())
        })
        .context("No encryption subkey found in recipient cert")?;

    // Find best signing key (subkey preferred, primary fallback) and build
    // the sign+encrypt message in one builder pass.
    let mut builder = MessageBuilder::from_bytes("", data.to_vec())
        .seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(thread_rng(), enc_subkey)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
    if let Some(sk) = key
        .secret_subkeys
        .iter()
        .find(|sk| sk.signatures.iter().any(|sig| sig.key_flags().sign()))
    {
        let sk_ref: &pgp::packet::SecretSubkey = sk;
        builder.sign(sk_ref, pw, HashAlgorithm::Sha256);
    } else {
        builder.sign(&key.primary_key, pw, HashAlgorithm::Sha256);
    }
    builder
        .to_armored_string(thread_rng(), ArmorOptions::default())
        .map_err(|e| anyhow::anyhow!("Failed to build message: {e}"))
}

/// Decrypt a signed+encrypted message and verify the embedded signature.
pub fn decrypt_verify(
    data: &[u8],
    key_file: &Path,
    signer_path: &Path,
    passphrase: &str,
) -> Result<Vec<u8>> {
    let key = load_secret_cert(key_file, passphrase)?;
    let pw = make_password(passphrase);
    let signer_cert: SignedPublicKey = load_cert(signer_path)?;

    let (msg, _) = Message::from_armor(BufReader::new(Cursor::new(data)))
        .context("Failed to parse armored message")?;
    let mut decrypted = msg
        .decrypt(&pw, &key)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    let mut out = Vec::new();
    decrypted.read_to_end(&mut out)?;
    verify_signed_message(&decrypted, &signer_cert)?;
    Ok(out)
}
