//! A bus identity: Ed25519 signing key + X25519 ECDH key.
//!
//! Persisted as CBOR at e.g. `<bus_dir>/device.key.cbor` or
//! `<bus_dir>/authority.key.cbor`.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

// ── Wire format ───────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct DeviceKeyBytes {
    version: u8,
    label: String,
    sign_secret: [u8; 32],
    ecdh_secret: [u8; 32],
}

// ── DeviceKey ─────────────────────────────────────────────────────────────────

/// A bus identity: Ed25519 signing key (for COSE_Sign1) + X25519 key (for ECDH).
pub struct DeviceKey {
    pub label: String,
    sign: SigningKey,
    ecdh: StaticSecret,
}

impl DeviceKey {
    /// Generate a fresh identity.
    pub fn generate(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            sign: SigningKey::generate(&mut OsRng),
            ecdh: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Raw 32-byte Ed25519 public key.
    pub fn sign_pubkey(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    /// Raw 32-byte X25519 public key.
    pub fn ecdh_pubkey(&self) -> [u8; 32] {
        X25519Public::from(&self.ecdh).to_bytes()
    }

    /// Raw 32-byte X25519 private key — used as the WireGuard private key.
    pub fn ecdh_secret(&self) -> [u8; 32] {
        self.ecdh.to_bytes()
    }

    /// First 8 bytes of the signing public key — used as COSE `kid`.
    pub fn fingerprint(&self) -> [u8; 8] {
        let pk = self.sign_pubkey();
        pk[..8].try_into().unwrap()
    }

    /// Hex-encoded first 8 bytes of signing public key — stable device id.
    pub fn device_id(&self) -> String {
        hex::encode(self.fingerprint())
    }

    /// Sign `data` with the Ed25519 signing key, returning 64 raw bytes.
    pub fn sign_bytes(&self, data: &[u8]) -> [u8; 64] {
        self.sign.sign(data).to_bytes()
    }

    /// X25519 Diffie-Hellman with a peer's public key bytes.
    pub fn ecdh_exchange(&self, peer_pub: &[u8; 32]) -> [u8; 32] {
        let peer = X25519Public::from(*peer_pub);
        self.ecdh.diffie_hellman(&peer).to_bytes()
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = DeviceKeyBytes {
            version: 1,
            label: self.label.clone(),
            sign_secret: self.sign.to_bytes(),
            ecdh_secret: self.ecdh.to_bytes(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&data, &mut buf).context("CBOR encode device key")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &buf)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let buf =
            std::fs::read(path).with_context(|| format!("read key file {}", path.display()))?;
        let data: DeviceKeyBytes =
            ciborium::from_reader(buf.as_slice()).context("CBOR decode device key")?;
        if data.version != 1 {
            bail!("unsupported device key version {}", data.version);
        }
        Ok(Self {
            label: data.label,
            sign: SigningKey::from_bytes(&data.sign_secret),
            ecdh: StaticSecret::from(data.ecdh_secret),
        })
    }
}
