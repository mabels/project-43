//! Encrypted + authenticated bus messages.
//!
//! ## Encrypt
//! 1. Inner content signed as `COSE_Sign1` with sender's Ed25519 key.
//! 2. Outer envelope: ECDH-ES (ephemeral X25519) → HKDF-SHA256 → AES-256-GCM.
//! 3. Everything serialised as a CBOR [`BusEnvelope`].
//!
//! ## Decrypt
//! 1. Parse [`BusEnvelope`].
//! 2. ECDH(recipient_ecdh_key, eph_pub) → HKDF → AES key.
//! 3. AES-256-GCM decrypt → COSE_Sign1 bytes.
//! 4. Verify inner signature against sender cert's `sign_pubkey`.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use super::{
    authority::{AuthorityKey, AuthorityPub},
    cert::CertPayload,
    csr::{cbor_decode, cbor_encode},
    device_key::DeviceKey,
    signer::BusSigner,
};

// ── Traits ────────────────────────────────────────────────────────────────────

/// Anything that can be an ECDH *recipient* in a [`BusEnvelope`].
pub trait BusRecipient {
    fn recipient_ecdh_pub(&self) -> [u8; 32];
}

impl BusRecipient for CertPayload {
    fn recipient_ecdh_pub(&self) -> [u8; 32] {
        self.ecdh_pubkey[..]
            .try_into()
            .expect("ecdh_pubkey must be 32 bytes")
    }
}

impl BusRecipient for AuthorityPub {
    fn recipient_ecdh_pub(&self) -> [u8; 32] {
        self.x25519_pub[..]
            .try_into()
            .expect("x25519_pub must be 32 bytes")
    }
}

/// Anything that can perform the ECDH *decryption* side of a [`BusEnvelope`].
pub trait BusDecryptor {
    fn ecdh_exchange(&self, peer_pub: &[u8; 32]) -> [u8; 32];
}

impl BusDecryptor for DeviceKey {
    fn ecdh_exchange(&self, peer_pub: &[u8; 32]) -> [u8; 32] {
        self.ecdh_exchange(peer_pub)
    }
}

impl BusDecryptor for AuthorityKey {
    fn ecdh_exchange(&self, peer_pub: &[u8; 32]) -> [u8; 32] {
        self.ecdh_exchange(peer_pub)
    }
}

// ── HKDF info string ──────────────────────────────────────────────────────────

const HKDF_INFO: &[u8] = b"p43-bus-v1";

// ── Wire envelope ─────────────────────────────────────────────────────────────

/// Outer CBOR wrapper for an encrypted bus message.
#[derive(Debug, Serialize, Deserialize)]
pub struct BusEnvelope {
    pub version: u8,
    /// Ephemeral X25519 public key (32 bytes) — used for ECDH.
    pub eph_pub: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// AES-256-GCM ciphertext (includes 16-byte GCM tag).
    pub ciphertext: Vec<u8>,
    /// Sender's raw cert bytes (COSE_Sign1) — lets recipient verify the inner sig.
    pub sender_cert: Vec<u8>,
}

// ── Inner signed payload ──────────────────────────────────────────────────────

/// Application payload carried inside the encrypted+signed envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgPayload {
    /// UUID for correlation / dedup.
    pub msg_id: String,
    /// Unix timestamp.
    pub timestamp: i64,
    /// Application-defined message type, e.g. `"ssh.sign_request"`.
    pub kind: String,
    /// Raw CBOR body (application-defined schema).
    pub body: Vec<u8>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Encrypt and sign a message for `recipient`.
///
/// - `sender_key`  : sender's bus identity (used for inner COSE_Sign1)
/// - `sender_cert` : sender's cert bytes (embedded so recipient can verify)
/// - `recipient`   : recipient's cert payload (need `ecdh_pubkey`)
/// - `payload`     : message to seal
pub fn encrypt(
    sender_key: &dyn BusSigner,
    sender_cert: &[u8],
    recipient: &dyn BusRecipient,
    payload: &MsgPayload,
) -> Result<Vec<u8>> {
    // 1. Sign the payload as COSE_Sign1.
    let inner_bytes = sign_payload(sender_key, payload)?;

    // 2. ECDH key agreement.
    let eph_priv = StaticSecret::random_from_rng(OsRng);
    let eph_pub = X25519Public::from(&eph_priv);
    let recipient_pub = recipient.recipient_ecdh_pub();
    let shared = eph_priv.diffie_hellman(&X25519Public::from(recipient_pub));
    let aes_key = derive_key(shared.as_bytes())?;

    // 3. AES-256-GCM encrypt.
    let cipher = Aes256Gcm::new(&aes_key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, inner_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {}", e))?;

    // 4. Build envelope.
    let env = BusEnvelope {
        version: 1,
        eph_pub: eph_pub.as_bytes().to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
        sender_cert: sender_cert.to_vec(),
    };
    cbor_encode(&env)
}

/// Decrypt and verify a [`BusEnvelope`].
///
/// Returns the decrypted [`MsgPayload`] and the sender's [`CertPayload`]
/// (already signature-verified against `authority_sign_pubkey`).
pub fn decrypt(
    recipient_key: &dyn BusDecryptor,
    envelope_bytes: &[u8],
    authority_sign_pubkey: &[u8; 32],
) -> Result<(MsgPayload, CertPayload)> {
    let env: BusEnvelope = cbor_decode(envelope_bytes)?;

    // 1. Verify & parse sender cert.
    let sender_cert = super::cert::DeviceCert::verify(&env.sender_cert, authority_sign_pubkey)?;

    // 2. ECDH key agreement.
    let eph_pub: [u8; 32] = env
        .eph_pub
        .as_slice()
        .try_into()
        .context("ephemeral key must be 32 bytes")?;
    let shared = recipient_key.ecdh_exchange(&eph_pub);
    let aes_key = derive_key(&shared)?;

    // 3. AES-256-GCM decrypt.
    let cipher = Aes256Gcm::new(&aes_key.into());
    let nonce_arr: [u8; 12] = env
        .nonce
        .as_slice()
        .try_into()
        .context("nonce must be 12 bytes")?;
    let nonce = Nonce::from_slice(&nonce_arr);
    let inner_bytes = cipher
        .decrypt(nonce, env.ciphertext.as_slice())
        .map_err(|e| anyhow::anyhow!("AES-GCM decrypt: {}", e))?;

    // 4. Verify inner COSE_Sign1 against sender cert's sign_pubkey.
    let payload = verify_payload(&inner_bytes, &sender_cert)?;

    Ok((payload, sender_cert))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn derive_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(key)
}

fn sign_payload(key: &dyn BusSigner, payload: &MsgPayload) -> Result<Vec<u8>> {
    let payload_cbor = cbor_encode(payload)?;
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
        .create_signature(b"", |sig_input| {
            key.sign_bytes(sig_input)
                .expect("bus message signing failed")
                .to_vec()
        })
        .build();
    cose.to_tagged_vec()
        .map_err(|e| anyhow::anyhow!("encode inner COSE_Sign1: {:?}", e))
}

fn verify_payload(cose_bytes: &[u8], sender_cert: &CertPayload) -> Result<MsgPayload> {
    let cose = coset::CoseSign1::from_tagged_slice(cose_bytes)
        .map_err(|e| anyhow::anyhow!("parse inner COSE_Sign1: {:?}", e))?;
    let payload_bytes = cose
        .payload
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("inner COSE_Sign1 has no payload"))?;
    let payload: MsgPayload = cbor_decode(payload_bytes)?;

    let vk = VerifyingKey::from_bytes(
        sender_cert.sign_pubkey[..]
            .try_into()
            .context("sender sign_pubkey length")?,
    )
    .context("parse sender verifying key")?;

    cose.verify_signature(b"", |sig, data| {
        let sig_arr: [u8; 64] = sig.try_into().map_err(|_| "bad sig length".to_string())?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(data, &sig).map_err(|e| e.to_string())
    })
    .map_err(|e| anyhow::anyhow!("inner message signature invalid: {}", e))?;

    Ok(payload)
}
