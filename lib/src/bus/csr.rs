//! Device Certificate Signing Request.
//!
//! A CSR is a `COSE_Sign1` structure:
//!   - payload  : CBOR-encoded [`CsrPayload`]
//!   - algorithm: EdDSA (-8)
//!   - signed by: the device's own Ed25519 key (self-attestation / proof of possession)
//!
//! The verifier checks the self-signature before issuing a [`DeviceCert`].

use anyhow::{bail, Context, Result};
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::device_key::DeviceKey;

// ── Payload ───────────────────────────────────────────────────────────────────

/// CBOR payload embedded inside the CSR's COSE_Sign1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrPayload {
    pub version: u8,
    /// Human-readable device label, e.g. `"my-laptop-ssh-agent"`.
    pub label: String,
    /// Raw 32-byte Ed25519 public key.
    #[serde(with = "serde_bytes")]
    pub sign_pubkey: Vec<u8>,
    /// Raw 32-byte X25519 public key.
    #[serde(with = "serde_bytes")]
    pub ecdh_pubkey: Vec<u8>,
    /// 16 random bytes — prevents replay / bind to a point in time.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
}

// ── DeviceCsr ─────────────────────────────────────────────────────────────────

pub struct DeviceCsr {
    pub payload: CsrPayload,
    /// Serialised COSE_Sign1 bytes (tagged).
    pub cose_bytes: Vec<u8>,
}

impl DeviceCsr {
    /// Create and self-sign a CSR for `key`, using the key's own label.
    pub fn generate(key: &DeviceKey) -> Result<Self> {
        Self::generate_with_label(key, None)
    }

    /// Create and self-sign a CSR for `key`.
    ///
    /// `label_override` replaces the device key's label in the CSR payload.
    /// Use this when the same key should appear under a different name to the
    /// authority (e.g. `"laptop-ssh-agent"` vs `"laptop-ui"`).
    pub fn generate_with_label(key: &DeviceKey, label_override: Option<&str>) -> Result<Self> {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let payload = CsrPayload {
            version: 1,
            label: label_override.unwrap_or(&key.label).to_string(),
            sign_pubkey: key.sign_pubkey().to_vec(),
            ecdh_pubkey: key.ecdh_pubkey().to_vec(),
            nonce: nonce.to_vec(),
            timestamp: unix_now()?,
        };

        let payload_cbor = cbor_encode(&payload)?;

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let unprotected = HeaderBuilder::new()
            .key_id(key.fingerprint().to_vec())
            .build();

        let cose = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload_cbor)
            .create_signature(b"", |sig_input| key.sign_bytes(sig_input).to_vec())
            .build();

        let cose_bytes = cose
            .to_tagged_vec()
            .map_err(|e| anyhow::anyhow!("encode CSR to CBOR: {:?}", e))?;
        Ok(Self {
            payload,
            cose_bytes,
        })
    }

    /// Parse a CSR from raw COSE bytes and verify the self-signature.
    /// Returns the validated payload.
    pub fn verify(cose_bytes: &[u8]) -> Result<CsrPayload> {
        let cose = coset::CoseSign1::from_tagged_slice(cose_bytes)
            .map_err(|e| anyhow::anyhow!("parse CSR COSE_Sign1: {:?}", e))?;

        let payload_bytes = cose
            .payload
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("CSR has no payload"))?;

        let payload: CsrPayload = cbor_decode(payload_bytes)?;

        if payload.version != 1 {
            bail!("unsupported CSR version {}", payload.version);
        }
        if payload.sign_pubkey.len() != 32 {
            bail!("invalid CSR sign key length");
        }
        if payload.ecdh_pubkey.len() != 32 {
            bail!("invalid CSR ECDH key length");
        }

        let vk = VerifyingKey::from_bytes(payload.sign_pubkey[..].try_into()?)
            .context("parse CSR verifying key")?;

        cose.verify_signature(b"", |sig, data| {
            let sig_arr: [u8; 64] = sig.try_into().map_err(|_| "bad sig length".to_string())?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
            vk.verify(data, &sig).map_err(|e| e.to_string())
        })
        .map_err(|e| anyhow::anyhow!("CSR self-signature invalid: {}", e))?;

        Ok(payload)
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &self.cose_bytes)?;
        Ok(())
    }

    pub fn load_bytes(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).with_context(|| format!("read CSR {}", path.display()))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn cbor_encode<T: serde::Serialize>(val: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).context("CBOR encode")?;
    Ok(buf)
}

pub fn cbor_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).context("CBOR decode")
}

/// Decode raw CBOR bytes and pretty-print them as JSON.
///
/// Every CBOR byte-string field (`Vec<u8>`) is rendered as a base64 string
/// so the output is human-readable.  All other CBOR types map to their natural
/// JSON equivalents (integer → number, text → string, map → object, …).
///
/// Returns an error if the bytes are not valid CBOR.
pub fn cbor_to_json_pretty(bytes: &[u8]) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let value: ciborium::Value =
        ciborium::from_reader(bytes).context("CBOR decode for display")?;

    fn convert(v: ciborium::Value) -> serde_json::Value {
        match v {
            ciborium::Value::Bytes(b) => {
                serde_json::Value::String(B64.encode(&b))
            }
            ciborium::Value::Text(s) => serde_json::Value::String(s),
            ciborium::Value::Bool(b) => serde_json::Value::Bool(b),
            ciborium::Value::Null => serde_json::Value::Null,
            ciborium::Value::Integer(i) => {
                let n: i128 = i.into();
                serde_json::Value::Number(
                    serde_json::Number::from(n as i64),
                )
            }
            ciborium::Value::Float(f) => serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            ciborium::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(convert).collect())
            }
            ciborium::Value::Map(pairs) => {
                let mut obj = serde_json::Map::new();
                for (k, v) in pairs {
                    let key = match k {
                        ciborium::Value::Text(s) => s,
                        ciborium::Value::Integer(i) => {
                            let n: i128 = i.into();
                            n.to_string()
                        }
                        other => format!("{:?}", other),
                    };
                    obj.insert(key, convert(v));
                }
                serde_json::Value::Object(obj)
            }
            // CBOR tags wrap a value — unwrap and recurse.
            ciborium::Value::Tag(_, inner) => convert(*inner),
            _ => serde_json::Value::Null,
        }
    }

    Ok(serde_json::to_string_pretty(&convert(value))?)
}

pub fn unix_now() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64)
}
