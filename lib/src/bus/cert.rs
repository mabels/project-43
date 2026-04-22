//! Device certificate issuance and verification.
//!
//! A [`DeviceCert`] is a `COSE_Sign1` binding a device's public keys to a label,
//! signed by any [`BusSigner`] (soft key on disk or OpenPGP card).
//!
//! Issued certs live at `<bus_dir>/peers/<device_id>.cert.cbor`.

use anyhow::{bail, Context, Result};
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::{
    csr::{cbor_decode, cbor_encode, unix_now, CsrPayload},
    signer::BusSigner,
};

// ── Payload ───────────────────────────────────────────────────────────────────

/// CBOR payload inside the cert's COSE_Sign1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertPayload {
    pub version: u8,
    /// Stable hex identifier derived from the device's signing public key.
    pub device_id: String,
    pub label: String,
    /// Raw 32-byte Ed25519 public key (for COSE_Sign1 verification).
    #[serde(with = "serde_bytes")]
    pub sign_pubkey: Vec<u8>,
    /// Raw 32-byte X25519 public key (for ECDH key agreement).
    #[serde(with = "serde_bytes")]
    pub ecdh_pubkey: Vec<u8>,
    /// First 8 bytes of authority signing key — identifies the issuer.
    #[serde(with = "serde_bytes")]
    pub issuer_fp: Vec<u8>,
    /// Issued-at unix timestamp.
    pub iat: i64,
    /// Expiry unix timestamp; `None` = never expires.
    pub exp: Option<i64>,
}

// ── DeviceCert ────────────────────────────────────────────────────────────────

pub struct DeviceCert {
    pub payload: CertPayload,
    /// Serialised COSE_Sign1 bytes (tagged).
    pub cose_bytes: Vec<u8>,
}

impl DeviceCert {
    // ── Issuance ──────────────────────────────────────────────────────────────

    /// Issue a cert for a verified CSR payload, signed by `authority`.
    ///
    /// `authority` can be any [`BusSigner`]: a soft key on disk or an OpenPGP card.
    pub fn issue(
        csr: &CsrPayload,
        authority: &dyn BusSigner,
        ttl_secs: Option<i64>,
    ) -> Result<Self> {
        let iat = unix_now()?;
        let exp = ttl_secs.map(|t| iat + t);
        let device_id = hex::encode(&csr.sign_pubkey[..8]);

        let payload = CertPayload {
            version: 1,
            device_id,
            label: csr.label.clone(),
            sign_pubkey: csr.sign_pubkey.clone(),
            ecdh_pubkey: csr.ecdh_pubkey.clone(),
            issuer_fp: authority.fingerprint().to_vec(),
            iat,
            exp,
        };

        let payload_cbor = cbor_encode(&payload)?;

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let unprotected = HeaderBuilder::new()
            .key_id(authority.fingerprint().to_vec())
            .build();

        // Pre-sign so the closure can be infallible (coset requires `Vec<u8>`).
        // Any signing error becomes a hard failure before COSE encoding.
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload_cbor)
            .create_signature(b"", |sig_input| {
                authority
                    .sign_bytes(sig_input)
                    .expect("authority signing failed")
                    .to_vec()
            })
            .build();

        let cose_bytes = cose
            .to_tagged_vec()
            .map_err(|e| anyhow::anyhow!("encode cert to CBOR: {:?}", e))?;
        Ok(Self {
            payload,
            cose_bytes,
        })
    }

    // ── Verification ──────────────────────────────────────────────────────────

    /// Parse and verify a cert against a known authority public key.
    pub fn verify(cose_bytes: &[u8], authority_sign_pubkey: &[u8; 32]) -> Result<CertPayload> {
        let cose = coset::CoseSign1::from_tagged_slice(cose_bytes)
            .map_err(|e| anyhow::anyhow!("parse cert COSE_Sign1: {:?}", e))?;

        let payload_bytes = cose
            .payload
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("cert has no payload"))?;

        let payload: CertPayload = cbor_decode(payload_bytes)?;

        if payload.version != 1 {
            bail!("unsupported cert version {}", payload.version);
        }

        let vk = VerifyingKey::from_bytes(authority_sign_pubkey)
            .context("parse authority verifying key")?;

        cose.verify_signature(b"", |sig, data| {
            let sig_arr: [u8; 64] = sig.try_into().map_err(|_| "bad sig length".to_string())?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
            vk.verify(data, &sig).map_err(|e| e.to_string())
        })
        .map_err(|e| anyhow::anyhow!("cert signature invalid: {}", e))?;

        // Check expiry.
        if let Some(exp) = payload.exp {
            let now = unix_now()?;
            if now > exp {
                bail!("cert expired at {}", exp);
            }
        }

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

    pub fn load(path: &Path) -> Result<Self> {
        let cose_bytes =
            std::fs::read(path).with_context(|| format!("read cert {}", path.display()))?;

        // Decode payload without verifying (caller does full verify separately).
        let cose = coset::CoseSign1::from_tagged_slice(&cose_bytes)
            .map_err(|e| anyhow::anyhow!("parse cert COSE_Sign1: {:?}", e))?;
        let payload_bytes = cose
            .payload
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("cert has no payload"))?;
        let payload: CertPayload = cbor_decode(payload_bytes)?;

        Ok(Self {
            payload,
            cose_bytes,
        })
    }
}
