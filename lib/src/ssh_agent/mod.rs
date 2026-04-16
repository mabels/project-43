use anyhow::{bail, Context, Result};
use openpgp::crypto::mpi;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::policy::StandardPolicy;
use openpgp::types::Curve;
use sequoia_openpgp as openpgp;
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use ssh_key::public::Ed25519PublicKey;
use ssh_key::PrivateKey;
use std::path::Path;

use crate::pkcs11::soft_ops::load_secret_cert;

// ── Key slot selection ────────────────────────────────────────────────────────

/// Which OpenPGP subkey to expose as the SSH identity.
#[derive(Clone, Copy, Debug, Default)]
pub enum SshKeySlot {
    /// Authentication subkey (`KeyFlags::AUTHENTICATE`) — default.
    ///
    /// If no authentication subkey is present, falls back to the signing
    /// subkey automatically.
    #[default]
    Auth,

    /// Signing subkey (`KeyFlags::SIGN`) — explicit choice.
    Sign,
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Load an SSH [`PrivateKey`] from an OpenPGP `.sec.asc` file.
///
/// Decrypts the cert using `passphrase`, then extracts the subkey matching
/// `slot`.  When `slot` is [`SshKeySlot::Auth`] and no authentication subkey
/// exists, the signing subkey is used as a fallback.
///
/// Only Ed25519 keys are currently supported.
pub fn load_ssh_key(key_file: &Path, passphrase: &str, slot: SshKeySlot) -> Result<PrivateKey> {
    let cert = load_secret_cert(key_file, passphrase)?;
    cert_to_ssh_key(&cert, slot)
}

// ── Internal conversion ───────────────────────────────────────────────────────

fn cert_to_ssh_key(cert: &openpgp::Cert, slot: SshKeySlot) -> Result<PrivateKey> {
    let policy = StandardPolicy::new();

    // Locate the requested subkey; Auth slot falls back to Sign.
    let ka = match slot {
        SshKeySlot::Auth => cert
            .keys()
            .with_policy(&policy, None)
            .for_authentication()
            .secret()
            .next()
            .or_else(|| {
                cert.keys()
                    .with_policy(&policy, None)
                    .for_signing()
                    .secret()
                    .next()
            }),
        SshKeySlot::Sign => cert
            .keys()
            .with_policy(&policy, None)
            .for_signing()
            .secret()
            .next(),
    }
    .context(
        "No suitable subkey found in cert \
         (need an authentication or signing subkey with secret material)",
    )?;

    let key = ka.key();

    match key.mpis() {
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q,
        } => {
            let q_bytes = q.value();
            anyhow::ensure!(
                q_bytes.len() == 33 && q_bytes[0] == 0x40,
                "Unexpected EdDSA public key encoding (expected 0x40 prefix)"
            );
            let pub_bytes: [u8; 32] = q_bytes[1..33]
                .try_into()
                .context("EdDSA public key point is not 32 bytes")?;

            let priv_bytes: [u8; 32] =
                match key.optional_secret().context("No secret material in key")? {
                    SecretKeyMaterial::Unencrypted(u) => u.map(|mpi_secret| match mpi_secret {
                        mpi::SecretKeyMaterial::EdDSA { scalar } => {
                            let raw = scalar.value_padded(32);
                            raw.as_ref()
                                .try_into()
                                .context("EdDSA scalar is not 32 bytes")
                        }
                        _ => bail!("Expected EdDSA secret key material, got a different type"),
                    }),
                    SecretKeyMaterial::Encrypted(_) => {
                        bail!("Key is still encrypted — wrong passphrase?")
                    }
                }?;

            let keypair = Ed25519Keypair {
                public: Ed25519PublicKey(pub_bytes),
                private: Ed25519PrivateKey::from_bytes(&priv_bytes),
            };

            PrivateKey::new(KeypairData::Ed25519(keypair), "p43")
                .map_err(|e| anyhow::anyhow!("Failed to build SSH PrivateKey: {e}"))
        }
        _ => bail!(
            "Unsupported key algorithm for SSH agent \
             (only Ed25519 is currently supported; RSA support is planned)"
        ),
    }
}
