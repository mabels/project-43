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

    /// Software OpenPGP key (file-based TSK, unencrypted — gate-key seals it).
    #[serde(rename = "pgp-key")]
    PgpKey(FilePgpKey),

    /// Bus authority keypair (Ed25519 + X25519 private scalars).
    ///
    /// Stored in the wallet so the gate-key seals it — no separate OpenPGP
    /// encryption or key-store recipients needed.  There is exactly one
    /// authority entry per wallet.
    #[serde(rename = "authority-key")]
    AuthorityKey(AuthorityKeyPayload),

    /// Uncertified device identity (keypair only, no authority signature yet).
    ///
    /// The device generates this locally, derives a CSR from it, and sends
    /// the CSR to the authority.  On approval the entry is upgraded to
    /// [`CertifiedDeviceId`].
    #[serde(rename = "device-id")]
    DeviceId(DeviceIdPayload),

    /// Certified device identity — keypair + authority-signed certificate.
    ///
    /// Created by tombstoning the corresponding [`DeviceId`] chain and
    /// replacing it with this entry once the authority returns the cert.
    #[serde(rename = "certified-device-id")]
    CertifiedDeviceId(CertifiedDeviceIdPayload),
}

impl WalletPayload {
    /// The `kind` string as it appears on disk.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::YubikeyRef(_) => "yubikey-ref",
            Self::SshKey(_) => "ssh-key",
            Self::PgpKey(_) => "pgp-key",
            Self::AuthorityKey(_) => "authority-key",
            Self::DeviceId(_) => "device-id",
            Self::CertifiedDeviceId(_) => "certified-device-id",
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

/// A software OpenPGP key stored in the wallet.
///
/// The TSK is stored as-is (passphrase encryption intact).  The passphrase is
/// stored alongside it — both are protected by the gate-key AES-GCM envelope.
/// No passphrase prompt is needed at use time; the wallet unlock is sufficient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePgpKey {
    pub version: u8,
    /// Armored OpenPGP Transferable Secret Key.
    pub key_bytes: serde_bytes::ByteBuf,
    /// Passphrase for `key_bytes` (empty string = unencrypted key).
    pub passphrase: String,
    /// Human-readable label, typically the primary UID string.
    pub label: String,
}

/// Bus authority keypair stored in the wallet.
///
/// Replacing the old `authority.key.enc` (OpenPGP-encrypted) scheme.  The
/// gate-key AES-GCM is now the only encryption layer — no key-store recipients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityKeyPayload {
    pub version: u8,
    /// 32-byte Ed25519 private scalar.
    pub ed25519_scalar: serde_bytes::ByteBuf,
    /// 32-byte X25519 private scalar.
    pub x25519_scalar: serde_bytes::ByteBuf,
    /// CBOR-encoded self-issued [`DeviceCert`] bytes.
    pub cert_bytes: serde_bytes::ByteBuf,
}

/// Uncertified device identity stored in the wallet.
///
/// Holds the Ed25519 + X25519 keypair plus the locally-derived `device_id`.
/// Use [`crate::bus::DeviceCsr`] to produce a CSR from this, send it to
/// the authority, and upgrade to [`CertifiedDeviceIdPayload`] on approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdPayload {
    pub version: u8,
    /// Human-readable device name.
    pub label: String,
    /// 32-byte Ed25519 private scalar.
    pub ed25519_scalar: serde_bytes::ByteBuf,
    /// 32-byte X25519 private scalar.
    pub x25519_scalar: serde_bytes::ByteBuf,
    /// Hex of the first 8 bytes of the Ed25519 public key — stable device ID.
    pub device_id: String,
}

/// Certified device identity: same keypair as [`DeviceIdPayload`] plus the
/// authority-signed COSE_Sign1 certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertifiedDeviceIdPayload {
    pub version: u8,
    pub label: String,
    pub ed25519_scalar: serde_bytes::ByteBuf,
    pub x25519_scalar: serde_bytes::ByteBuf,
    pub device_id: String,
    /// Raw COSE_Sign1 certificate bytes (from [`crate::bus::DeviceCert`]).
    pub cert_bytes: serde_bytes::ByteBuf,
}
