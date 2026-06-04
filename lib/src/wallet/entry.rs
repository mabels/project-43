//! Wallet payload types — the typed contents stored inside sync-store items.
//!
//! Every payload is CBOR-encoded as `{ "kind": "<tag>", "payload": { … } }`
//! using serde's adjacently-tagged enum representation.  This makes each
//! item self-describing: a reader knows the payload type without consulting
//! the chain name.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ── Typed payload envelope ────────────────────────────────────────────────────

/// All wallet payload kinds.
///
/// Serialises as `{ "kind": "...", "payload": { … } }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload")]
pub enum WalletPayload {
    /// Public identity and PIN of a YubiKey card.
    #[serde(rename = "yubikey-ref")]
    YubikeyRef(YubikeyRef),

    /// Software SSH key pair.
    #[serde(rename = "ssh-key")]
    SshKey(SshKey),
}

impl WalletPayload {
    /// The `kind` string as it appears on disk.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::YubikeyRef(_) => "yubikey-ref",
            Self::SshKey(_) => "ssh-key",
        }
    }

    /// Serialise to CBOR bytes (for passing to the sync store).
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).context("wallet payload CBOR serialise")?;
        Ok(buf)
    }

    /// Deserialise from CBOR bytes (as returned by the sync store).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).context("wallet payload CBOR deserialise")
    }
}

// ── KeySlot ───────────────────────────────────────────────────────────────────

/// Which key slot to address on a card, or which role for a soft key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// SSH authentication / OpenPGP auth slot.
    Auth,
    /// OpenPGP signing slot.
    Sign,
    /// OpenPGP encryption/decryption slot.
    Enc,
}

// ── Payload structs ───────────────────────────────────────────────────────────

/// Credential for a YubiKey OpenPGP card.
///
/// Stores only what cannot be derived from the card itself — the PIN.
/// Public keys are always fetched live from the card via [`KeyCredential::pubkey_bytes`]
/// so they never go stale if the card is re-keyed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubikeyRef {
    pub version: u8,
    /// Card AID e.g. `"0006:17684870"`.
    pub card_fingerprint: String,
    /// Human-readable label e.g. `"work yubikey"`.
    pub label: String,
    /// Card User PIN.
    pub pin: String,
}

/// A software SSH private key.
///
/// The public key is derived on demand via [`KeyCredential::pubkey_bytes`] —
/// no need to store it separately since OpenSSH private key format always
/// includes the public key material internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub version: u8,
    /// OpenSSH private key bytes (the full `-----BEGIN OPENSSH PRIVATE KEY-----`
    /// blob).  The wallet's AES-GCM layer is the outer encryption.
    pub private_key: serde_bytes::ByteBuf,
    /// Comment shown in `ssh-add -l` listings.
    pub comment: String,
}
