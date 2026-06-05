//! Pure-Rust rPGP operations for soft (file-backed) keys.
//!
//! This module is **always compiled** — it has no PC/SC or hardware dependency.
//! It backs [`crate::bus::authority`] and [`crate::ssh_agent`] on all targets
//! (including Android and iOS where the `pcsc` feature is disabled).
//!
//! The `pcsc`-gated `pkcs11::soft_ops` module re-exports everything here so
//! existing call sites inside the `pcsc` feature boundary keep working unchanged.

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

// ── key loading ───────────────────────────────────────────────────────────────

/// Load an armored public key from a file.
pub fn load_cert(path: &Path) -> Result<SignedPublicKey> {
    let f = std::fs::File::open(path)
        .with_context(|| format!("Failed to open public key file {:?}", path))?;
    let (key, _) = SignedPublicKey::from_armor_single(io::BufReader::new(f))
        .with_context(|| format!("Failed to parse public key from {:?}", path))?;
    Ok(key)
}

/// Load an armored secret key from disk.
pub fn load_secret_cert(key_file: &Path, _passphrase: &str) -> Result<SignedSecretKey> {
    let f = std::fs::File::open(key_file)
        .with_context(|| format!("Failed to open secret key file {:?}", key_file))?;
    let (key, _) = SignedSecretKey::from_armor_single(io::BufReader::new(f))
        .with_context(|| format!("Failed to parse secret key from {:?}", key_file))?;
    Ok(key)
}

/// Verify that `passphrase` can unlock the signing key in `key`.
///
/// Tries to sign a small test blob — an incorrect passphrase will fail the
/// AES-GCM decryption inside the sign operation.  Returns `Ok(())` on
/// success, an error with a human-readable message on failure.
pub fn verify_passphrase(key: &SignedSecretKey, passphrase: &str) -> Result<()> {
    let pw = make_password(passphrase);
    detach_sign(key, &pw, b"p43-passphrase-check")
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Wrong passphrase: {e}"))
}

/// Load an armored secret key from raw bytes.
///
/// GPG export files often concatenate the private and public key blocks in
/// a single `.asc` file.  `from_armor_single` fails on those because it
/// reads across block boundaries.  This function extracts just the
/// `-----BEGIN PGP PRIVATE KEY BLOCK-----` … `-----END PGP PRIVATE KEY BLOCK-----`
/// section first, then parses it in isolation.
pub fn load_secret_cert_from_bytes(bytes: &[u8]) -> Result<SignedSecretKey> {
    let text = std::str::from_utf8(bytes).context("OpenPGP key file is not valid UTF-8")?;

    // Extract the private-key armor block (first occurrence).
    let block = extract_armor_block(text, "PGP PRIVATE KEY BLOCK").unwrap_or(text); // fall back to the whole buffer if no markers found

    let (key, _) =
        SignedSecretKey::from_armor_single(io::BufReader::new(Cursor::new(block.as_bytes())))
            .context("Failed to parse OpenPGP secret key from bytes")?;
    Ok(key)
}

/// Extract a single armor block delimited by `-----BEGIN <tag>-----` /
/// `-----END <tag>-----` from `text`.  Returns `None` if the markers are absent.
fn extract_armor_block<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let begin = format!("-----BEGIN {}-----", tag);
    let end = format!("-----END {}-----", tag);
    let start = text.find(begin.as_str())?;
    let finish = text[start..].find(end.as_str())? + start + end.len();
    Some(&text[start..finish])
}

/// Return the armored public key corresponding to `key`.
pub fn pubkey_armored(key: &SignedSecretKey) -> Result<String> {
    key.to_public_key()
        .to_armored_string(ArmorOptions::default())
        .context("Failed to armor public key")
}

/// Load a public key from armored bytes (for recipients / verifiers).
pub fn load_pubkey_from_bytes(bytes: &[u8]) -> Result<SignedPublicKey> {
    let (key, _) = SignedPublicKey::from_armor_single(io::BufReader::new(Cursor::new(bytes)))
        .context("Failed to parse OpenPGP public key from bytes")?;
    Ok(key)
}

/// Sign using an already-loaded key.
pub fn sign_with_key(key: &SignedSecretKey, passphrase: &str, data: &[u8]) -> Result<String> {
    let pw = make_password(passphrase);
    detach_sign(key, &pw, data)
        .map_err(|e| anyhow::anyhow!("Sign failed: {e}"))?
        .to_armored_string(ArmorOptions::default())
        .context("Failed to armor signature")
}

/// Decrypt using an already-loaded key.
pub fn decrypt_with_key(key: &SignedSecretKey, passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
    let pw = make_password(passphrase);
    let (msg, _) = Message::from_armor(BufReader::new(Cursor::new(data)))
        .context("Failed to parse armored message")?;
    let mut decrypted = msg
        .decrypt(&pw, key)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;
    let mut out = Vec::new();
    decrypted.read_to_end(&mut out)?;
    Ok(out)
}

/// Sign-then-encrypt using an already-loaded key and a recipient's armored public key bytes.
pub fn sign_encrypt_with_key(
    key: &SignedSecretKey,
    passphrase: &str,
    data: &[u8],
    recipient_armored: &[u8],
) -> Result<String> {
    let pw = make_password(passphrase);
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

/// Decrypt-then-verify using a loaded key and a signer's armored public key bytes.
pub fn decrypt_verify_with_key(
    key: &SignedSecretKey,
    passphrase: &str,
    data: &[u8],
    signer_armored: &[u8],
) -> Result<Vec<u8>> {
    let pw = make_password(passphrase);
    let signer = load_pubkey_from_bytes(signer_armored)?;
    let (msg, _) = Message::from_armor(BufReader::new(Cursor::new(data)))
        .context("Failed to parse armored message")?;
    let mut decrypted = msg
        .decrypt(&pw, key)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;
    let mut out = Vec::new();
    decrypted.read_to_end(&mut out)?;
    verify_signed_message(&decrypted, &signer)?;
    Ok(out)
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
/// subkey, falling back to the primary.
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
        let sk_ref: &pgp::packet::SecretSubkey = sk;
        DetachedSignature::sign_binary_data(thread_rng(), sk_ref, pw, HashAlgorithm::Sha256, data)
    } else {
        DetachedSignature::sign_binary_data(
            thread_rng(),
            &key.primary_key,
            pw,
            HashAlgorithm::Sha256,
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

// ── Key metadata helpers ──────────────────────────────────────────────────────

/// Minimal per-subkey metadata extracted without a `pgp` crate dep on the caller.
pub struct SubkeyMeta {
    pub role: String,
    pub algo: String,
    pub openssh_key: Option<String>,
}

/// Extract subkey metadata from a `SignedSecretKey`.
///
/// Returns one entry per key packet: primary first, then each secret subkey.
/// The `uid` string is used as the OpenSSH comment.
pub fn extract_subkey_meta(tsk: &SignedSecretKey, uid: &str) -> Vec<SubkeyMeta> {
    use pgp::types::KeyDetails as _;

    let mut out = Vec::new();

    // Primary key — flags live on the first user-id binding signature.
    {
        let kf = tsk
            .details
            .users
            .first()
            .and_then(|u| u.signatures.first())
            .map(|sig| sig.key_flags())
            .unwrap_or_default();
        let mut roles = Vec::new();
        if kf.certify() {
            roles.push("certify");
        }
        if kf.sign() {
            roles.push("sign");
        }
        let role = if roles.is_empty() {
            "certify+sign".to_owned()
        } else {
            roles.join("+")
        };
        out.push(SubkeyMeta {
            role,
            algo: crate::ssh_agent::pub_params_algo_string(tsk.primary_key.public_params()),
            openssh_key: crate::ssh_agent::pub_params_to_openssh_string(
                tsk.primary_key.public_params(),
                uid,
            ),
        });
    }

    // Secret subkeys — flags live on the subkey binding signature.
    for sk in &tsk.secret_subkeys {
        let kf = sk
            .signatures
            .first()
            .map(|sig| sig.key_flags())
            .unwrap_or_default();
        let mut roles = Vec::new();
        if kf.sign() {
            roles.push("sign");
        }
        if kf.authentication() {
            roles.push("auth");
        }
        if kf.encrypt_comms() || kf.encrypt_storage() {
            roles.push("encrypt");
        }
        let role = if roles.is_empty() {
            "unknown".to_owned()
        } else {
            roles.join("+")
        };
        out.push(SubkeyMeta {
            role,
            algo: crate::ssh_agent::pub_params_algo_string(sk.public_params()),
            openssh_key: crate::ssh_agent::pub_params_to_openssh_string(sk.public_params(), uid),
        });
    }
    out
}

/// Hex-encoded fingerprint of the primary key.
pub fn key_fingerprint_hex(tsk: &SignedSecretKey) -> String {
    use pgp::types::KeyDetails as _;
    hex::encode(tsk.to_public_key().fingerprint().as_bytes())
}

/// Clean display algorithm string for the primary key.
pub fn key_algo_string(tsk: &SignedSecretKey) -> String {
    use pgp::types::KeyDetails as _;
    let params = tsk.primary_key.public_params();
    crate::ssh_agent::pub_params_algo_string(params)
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
