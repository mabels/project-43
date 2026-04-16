use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::pkcs11::soft_ops;

/// Trait that abstracts the private-key operations of an OpenPGP card.
///
/// Both the real [`PcscCard`] (wrapping `openpgp-card-sequoia`) and the
/// in-process [`VirtualCard`] implement this, so tests can exercise the full
/// operations pipeline without physical hardware.
pub trait CardOps {
    /// Sign `data` and return an armored detached signature.
    fn card_sign(&self, data: &[u8]) -> Result<String>;

    /// Decrypt an armored OpenPGP message and return the plaintext.
    fn card_decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Sign then encrypt `data` to `recipient_path` (public key file).
    fn card_sign_encrypt(&self, data: &[u8], recipient_path: &Path) -> Result<String>;

    /// Decrypt and verify a signed+encrypted message; `signer_path` is the
    /// signer's public key file.
    fn card_decrypt_verify(&self, data: &[u8], signer_path: &Path) -> Result<Vec<u8>>;
}

// ── VirtualCard ───────────────────────────────────────────────────────────────

/// A software-backed stand-in for a physical OpenPGP card.
///
/// Stores a path to a secret-key file (`.sec.asc`) and the passphrase that
/// protects it.  All [`CardOps`] methods are routed through [`soft_ops`], so
/// this can be used in tests without any PC/SC infrastructure.
pub struct VirtualCard {
    key_file: PathBuf,
    passphrase: String,
}

impl VirtualCard {
    pub fn new(key_file: impl Into<PathBuf>, passphrase: impl Into<String>) -> Self {
        Self {
            key_file: key_file.into(),
            passphrase: passphrase.into(),
        }
    }
}

impl CardOps for VirtualCard {
    fn card_sign(&self, data: &[u8]) -> Result<String> {
        soft_ops::sign(data, &self.key_file, &self.passphrase)
    }

    fn card_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        soft_ops::decrypt(data, &self.key_file, &self.passphrase)
    }

    fn card_sign_encrypt(&self, data: &[u8], recipient_path: &Path) -> Result<String> {
        soft_ops::sign_encrypt(data, &self.key_file, recipient_path, &self.passphrase)
    }

    fn card_decrypt_verify(&self, data: &[u8], signer_path: &Path) -> Result<Vec<u8>> {
        soft_ops::decrypt_verify(data, &self.key_file, signer_path, &self.passphrase)
    }
}
