//! Key-type-independent signing for bus cert issuance.
//!
//! The bus authority is always a fresh Ed25519 keypair whose private scalar
//! is stored encrypted (see [`super::authority`]).  Once unlocked, the scalar
//! becomes an `ed25519_dalek::SigningKey` that implements [`BusSigner`].
//!
//! [`super::device_key::DeviceKey`] also implements [`BusSigner`] so that
//! devices can self-sign CSRs with the same trait.

use anyhow::Result;
use ed25519_dalek::Signer as _;

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Anything that can act as a bus certificate authority:
/// produce raw Ed25519 signatures and expose a 32-byte public key.
pub trait BusSigner {
    fn sign_pubkey(&self) -> [u8; 32];
    fn fingerprint(&self) -> [u8; 8] {
        let pk = self.sign_pubkey();
        pk[..8].try_into().unwrap()
    }
    /// Sign `data` and return the raw 64-byte Ed25519 signature.
    fn sign_bytes(&self, data: &[u8]) -> Result<[u8; 64]>;
}

// ── AuthorityKey ──────────────────────────────────────────────────────────────

impl BusSigner for super::authority::AuthorityKey {
    fn sign_pubkey(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    fn sign_bytes(&self, data: &[u8]) -> Result<[u8; 64]> {
        Ok(self.signing.sign(data).to_bytes())
    }
}

// ── ed25519_dalek::SigningKey ──────────────────────────────────────────────────

/// The unlocked authority key (decrypted from `authority.key.enc`) satisfies
/// [`BusSigner`] directly.
impl BusSigner for ed25519_dalek::SigningKey {
    fn sign_pubkey(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
    fn sign_bytes(&self, data: &[u8]) -> Result<[u8; 64]> {
        Ok(self.sign(data).to_bytes())
    }
}

// ── DeviceKey also satisfies BusSigner ───────────────────────────────────────

impl BusSigner for super::device_key::DeviceKey {
    fn sign_pubkey(&self) -> [u8; 32] {
        self.sign_pubkey()
    }
    fn sign_bytes(&self, data: &[u8]) -> Result<[u8; 64]> {
        Ok(self.sign_bytes(data))
    }
}
