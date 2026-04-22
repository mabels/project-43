//! p43 device bus — registration, key exchange, and encrypted messaging.
//!
//! ## Flow
//!
//! ```text
//! Device                              Authority (any main key: RSA, ECDSA, …)
//! ──────                              ─────────────────────────────────────────
//! gen_key(label)                      init(--recipient pubkey.asc)
//!   → device.key.cbor                  → authority.pub.bin  (distribute)
//!                                       → authority.key.enc  (keep)
//!
//! gen_csr(device_key)                 issue_cert(csr, unlock authority.key.enc)
//!   → device.csr.cbor         ──→        → peers/<id>.cert.cbor
//!                              ←──   cert bytes
//!
//! encrypt(device_key, device_cert,    decrypt(device_key, envelope,
//!         recipient_cert, payload)            authority_pubkey)
//!   → envelope.cbor           ──→        → (payload, sender_cert)
//! ```
//!
//! The authority is always a fresh Ed25519 keypair.  Its private scalar is
//! OpenPGP-encrypted to the user's main key (any format).  See [`authority`].

pub mod authority;
pub mod cert;
pub mod csr;
pub mod device_key;
pub mod message;
pub mod signer;

// ── Convenience re-exports ────────────────────────────────────────────────────

pub use authority::{AuthorityKey, AuthorityPub};
pub use cert::{CertPayload, DeviceCert};
pub use csr::{unix_now, CsrPayload, DeviceCsr};
pub use device_key::DeviceKey;
pub use message::{decrypt, encrypt, BusDecryptor, BusEnvelope, BusRecipient, MsgPayload};
pub use signer::BusSigner;

// ── Directory helpers ─────────────────────────────────────────────────────────

use std::path::{Path, PathBuf};

/// Given the key-store root (e.g. `~/.config/project-43/keys`),
/// return the bus directory (`~/.config/project-43/bus`).
pub fn bus_dir(store_root: &Path) -> PathBuf {
    store_root.parent().unwrap_or(store_root).join("bus")
}

/// Directory where per-device key, CSR and cert files are stored.
pub fn devices_dir(bus_dir: &Path) -> PathBuf {
    bus_dir.join("devices")
}

/// Sanitise a label (or fingerprint) for use as a filesystem component.
/// Keeps alphanumerics, `-` and `_`; replaces everything else with `_`.
pub fn label_filename(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Path to the device's own key file inside `devices/`.
/// Pass `label` (from `gen-key --label`) or the device-id fingerprint when no
/// label was given.
pub fn device_key_path(bus_dir: &Path, label: &str) -> PathBuf {
    devices_dir(bus_dir).join(format!("{}.key.cbor", label_filename(label)))
}

/// Path to the device's CSR file inside `devices/`.
pub fn device_csr_path(bus_dir: &Path, label: &str) -> PathBuf {
    devices_dir(bus_dir).join(format!("{}.csr.cbor", label_filename(label)))
}

/// Path to the device's own cert file inside `devices/`.
pub fn device_cert_path(bus_dir: &Path, label: &str) -> PathBuf {
    devices_dir(bus_dir).join(format!("{}.cert.cbor", label_filename(label)))
}

/// Path to the authority's CBOR public key bundle (`AuthorityPub`).
/// Distribute to devices so they can verify certs and encrypt to the phone.
pub fn authority_pub_path(bus_dir: &Path) -> PathBuf {
    bus_dir.join("authority.pub.cbor")
}

/// Path to the authority's self-issued device cert.
/// Used when the authority is a message sender (authority → device).
pub fn authority_cert_path(bus_dir: &Path) -> PathBuf {
    bus_dir.join("authority.cert.cbor")
}

/// Path to the OpenPGP-encrypted authority private scalar.
/// Keep alongside the main key; used by `issue-cert` to unlock signing.
pub fn authority_enc_path(bus_dir: &Path) -> PathBuf {
    bus_dir.join("authority.key.enc")
}

/// Path for a device cert stored in the authority's peer registry.
pub fn peer_cert_path(bus_dir: &Path, device_id: &str) -> PathBuf {
    bus_dir.join("peers").join(format!("{device_id}.cert.cbor"))
}
