//! Bus authority key: generate, wrap, and unwrap.
//!
//! The bus authority is always a fresh Ed25519 keypair.  The 32-byte private
//! scalar is stored **OpenPGP-encrypted** to the user's main key — which can
//! be any format (RSA, ECDSA, Ed25519, …) because OpenPGP handles the
//! asymmetric wrapping.  Only the holder of the main key (soft file or card)
//! can issue new device certs.
//!
//! ## Files on disk
//!
//! | File                    | Content                              |
//! |-------------------------|--------------------------------------|
//! | `authority.pub.bin`     | 32 raw bytes — Ed25519 public key    |
//! | `authority.key.enc`     | OpenPGP-encrypted 32-byte scalar     |
//!
//! ## Typical flow
//!
//! ```text
//! # Authority side (once)
//! bus init --recipient main-key.pub.asc
//!   → authority.pub.bin  (distribute to devices)
//!   → authority.key.enc  (keep alongside main key)
//!
//! # Issue a cert (authority side, per device)
//! bus issue-cert device.csr.cbor --key-file main-key.sec.asc
//!   → unlocks authority.key.enc → signs cert → writes peers/<id>.cert.cbor
//! ```

use anyhow::{Context, Result};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message};
use sequoia_openpgp as openpgp;
use std::io::Write as _;
use std::path::Path;

// ── Generate ──────────────────────────────────────────────────────────────────

/// Generate a fresh Ed25519 authority keypair and encrypt the private scalar
/// to the OpenPGP cert at `recipient_path`.
///
/// This is a **public-key operation** — no passphrase or PIN required.
/// The recipient cert only needs to contain an encryption-capable subkey.
///
/// Returns `(pubkey_raw_32_bytes, encrypted_scalar_openpgp_bytes)`.
pub fn generate_and_encrypt(recipient_path: &Path) -> Result<([u8; 32], Vec<u8>)> {
    use rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pubkey = signing_key.verifying_key().to_bytes();
    let scalar = signing_key.to_bytes();
    let encrypted = encrypt_scalar_to_cert(&scalar, recipient_path)?;
    Ok((pubkey, encrypted))
}

// ── Unlock ────────────────────────────────────────────────────────────────────

/// Decrypt an authority key blob using a **soft** OpenPGP key.
pub fn unlock_soft(
    encrypted: &[u8],
    key_file: &Path,
    passphrase: &str,
) -> Result<ed25519_dalek::SigningKey> {
    let scalar_bytes = crate::pkcs11::soft_ops::decrypt(encrypted, key_file, passphrase)
        .context("decrypt authority key blob with soft key")?;
    scalar_to_signing_key(scalar_bytes)
}

/// Decrypt an authority key blob using a connected **OpenPGP card**.
#[cfg(feature = "pcsc")]
pub fn unlock_card(
    encrypted: &[u8],
    pin: &str,
    ident: Option<&str>,
) -> Result<ed25519_dalek::SigningKey> {
    let scalar_bytes = crate::pkcs11::ops::decrypt_with_card(encrypted, pin, ident)
        .context("decrypt authority key blob with card")?;
    scalar_to_signing_key(scalar_bytes)
}

// ── Internals ─────────────────────────────────────────────────────────────────

fn scalar_to_signing_key(scalar_bytes: Vec<u8>) -> Result<ed25519_dalek::SigningKey> {
    anyhow::ensure!(
        scalar_bytes.len() == 32,
        "authority key blob has wrong length: expected 32 bytes, got {}",
        scalar_bytes.len()
    );
    let arr: [u8; 32] = scalar_bytes.try_into().unwrap();
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}

/// OpenPGP-encrypt `plaintext` to the encryption subkey of the cert at
/// `cert_path`.  Output is binary (no ASCII armor).
fn encrypt_scalar_to_cert(plaintext: &[u8], cert_path: &Path) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_file(cert_path)
        .with_context(|| format!("load recipient cert from {}", cert_path.display()))?;

    let recipients: Vec<_> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();
    anyhow::ensure!(
        !recipients.is_empty(),
        "no encryption subkey found in cert at {}",
        cert_path.display()
    );

    let mut output = Vec::new();
    let message = Message::new(&mut output);
    let message = Encryptor2::for_recipients(message, recipients)
        .build()
        .context("build OpenPGP encryptor")?;
    let mut literal = LiteralWriter::new(message).build()?;
    literal.write_all(plaintext)?;
    literal.finalize()?;
    Ok(output)
}
