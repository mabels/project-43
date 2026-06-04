//! Item envelope — the immutable CBOR blob stored per chain node.

use super::padding::{pad, unpad};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload as AeadPayload},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

// ── Item id (SHA-1, 20 bytes) ─────────────────────────────────────────────────

/// 20-byte SHA-1 identifier for an item.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ItemId(pub ByteBuf);

impl ItemId {
    /// Derive from arbitrary bytes (e.g. ciphertext for root, or prev id).
    pub fn from_bytes(b: &[u8]) -> Self {
        let hash = Sha1::digest(b);
        Self(ByteBuf::from(hash.as_slice().to_vec()))
    }

    /// SHA-1(self) — the id the successor item will use.
    pub fn next(&self) -> Self {
        Self::from_bytes(&self.0)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(&*self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ── KeyRef ────────────────────────────────────────────────────────────────────

/// How to derive the `root_key` that feeds HKDF for this item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KeyRef {
    /// Root key = gate_key.random identified by gate_key_id.
    #[serde(rename = "direct")]
    Direct { gate_key_id: ByteBuf },

    /// Root key = plaintext bytes of another Level 2 item (key_material payload).
    #[serde(rename = "indirect_l2")]
    IndirectL2 { item_id: ByteBuf },

    /// Root key = card.decrypt(sealed blob held in another Level 2 item).
    #[serde(rename = "indirect_card")]
    IndirectCard {
        item_id: ByteBuf,
        card_fingerprint: String,
    },

    /// Root key is a pre-shared chain-scoped key (no gate-key needed).
    #[serde(rename = "chain_share")]
    ChainShare { shared_key: ByteBuf },
}

// ── Item envelope ─────────────────────────────────────────────────────────────

/// On-disk CBOR representation of a single chain node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemEnvelope {
    pub id: ItemId,
    pub version: u8,
    pub prev: Option<ItemId>,
    pub next: ItemId,
    pub deleted: bool,
    pub creator_id: String,
    /// SHA-256 of the plaintext payload — stored unencrypted so deduplication
    /// and sync tools can compare content without holding the decryption key.
    pub cid: ByteBuf,
    pub key_ref: KeyRef,
    pub nonce: ByteBuf,
    pub ciphertext: ByteBuf,
}

/// Compute a content identifier: SHA-256(prev_salt || payload).
///
/// `prev_salt` is the previous item's ID bytes (or zeros for the root).
/// This prevents rainbow-table attacks on the plaintext CID: an attacker
/// needs the specific `prev_id` to precompute hashes of known payloads
/// (e.g. all 4-6 digit PINs).  Deduplication still works because two
/// consecutive appends of the same payload share the same `prev_id`.
pub fn cid_of(prev_salt: &[u8], payload: &[u8]) -> ByteBuf {
    let mut hasher = Sha256::new();
    hasher.update(prev_salt);
    hasher.update(payload);
    ByteBuf::from(hasher.finalize().as_slice().to_vec())
}

pub const ROOT_SALT: &[u8] = &[0u8; 20]; // sentinel for root items (no prev)

impl ItemEnvelope {
    /// Encrypt `payload` bytes and produce a new root item.
    ///
    /// `chain_key = HKDF(root_key, salt=nonce)` — the nonce is generated
    /// first, breaking the circular dependency between id and key.
    /// `id = SHA-1(ciphertext)` so the id is content-addressed.
    pub fn new_root(
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
        payload: &[u8],
    ) -> Result<Self> {
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let chain_key = derive_chain_key_from_nonce(root_key, &nonce_bytes)?;
        let cipher = Aes256Gcm::new_from_slice(&chain_key).context("invalid chain key length")?;

        let padded = pad(payload);
        let ciphertext = cipher
            .encrypt(
                &nonce_bytes,
                AeadPayload {
                    msg: &padded,
                    aad: b"",
                },
            )
            .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;

        let id = ItemId::from_bytes(&ciphertext);
        let next = id.next();

        Ok(Self {
            id,
            version: 1,
            prev: None,
            next,
            deleted: false,
            creator_id: creator_id.to_owned(),
            cid: cid_of(ROOT_SALT, payload),
            key_ref,
            nonce: ByteBuf::from(nonce_bytes.to_vec()),
            ciphertext: ByteBuf::from(ciphertext),
        })
    }

    /// Encrypt `payload` bytes and produce a successor item in the chain.
    ///
    /// `id = SHA-1(prev_id)`, `chain_key = HKDF(root_key, salt=nonce)`.
    pub fn new_successor(
        prev: &ItemId,
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
        payload: &[u8],
    ) -> Result<Self> {
        let id = prev.next();
        let next = id.next();
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let chain_key = derive_chain_key_from_nonce(root_key, &nonce_bytes)?;
        let cipher = Aes256Gcm::new_from_slice(&chain_key).context("invalid chain key length")?;

        let padded = pad(payload);
        let ciphertext = cipher
            .encrypt(
                &nonce_bytes,
                AeadPayload {
                    msg: &padded,
                    aad: b"",
                },
            )
            .map_err(|e| anyhow::anyhow!("encrypt failed: {e}"))?;

        Ok(Self {
            id,
            version: 1,
            prev: Some(prev.clone()),
            next,
            deleted: false,
            creator_id: creator_id.to_owned(),
            cid: cid_of(prev.as_bytes(), payload),
            key_ref,
            nonce: ByteBuf::from(nonce_bytes.to_vec()),
            ciphertext: ByteBuf::from(ciphertext),
        })
    }

    /// Produce an authenticated tombstone successor.
    ///
    /// Encrypts an empty payload (`b""`) with the root key — zero payload length
    /// after unpadding is the delete marker.  Producing a valid ciphertext
    /// proves the caller holds the root key; a forged tombstone without the key
    /// will fail AES-GCM authentication.
    pub fn new_tombstone(
        prev: &ItemId,
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
    ) -> Result<Self> {
        // Re-use new_successor with an empty payload.  deleted=true is set below.
        let mut item = Self::new_successor(prev, root_key, key_ref, creator_id, b"")?;
        item.deleted = true;
        item.cid = ByteBuf::from(vec![]); // no user payload → no CID
        Ok(item)
    }

    /// Decrypt the payload bytes.
    ///
    /// For tombstone items (`deleted = true`) this returns an empty `Vec` —
    /// zero-length payload is the delete marker.  Callers can also use this
    /// to verify tombstone authenticity: a forged tombstone will fail AES-GCM
    /// authentication here before the empty-length check.
    pub fn decrypt(&self, root_key: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce);
        let chain_key = derive_chain_key_from_nonce(root_key, nonce)?;
        let cipher = Aes256Gcm::new_from_slice(&chain_key).context("invalid chain key length")?;
        let padded = cipher
            .decrypt(
                nonce,
                AeadPayload {
                    msg: &self.ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| anyhow::anyhow!("decryption failed — wrong key or corrupted item"))?;
        unpad(&padded).context("unpad failed")
    }

    /// Serialise to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).context("CBOR serialise failed")?;
        Ok(buf)
    }

    /// Deserialise from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        ciborium::from_reader(data).context("CBOR deserialise failed")
    }
}

// ── HKDF chain key derivation ─────────────────────────────────────────────────

/// Derive the AES-256-GCM key for one item.
///
/// Salt = the item's nonce (12 random bytes, generated before encryption).
/// This breaks the circular dependency: root item id = SHA-1(ciphertext) is
/// computed AFTER encryption, but the key must be known BEFORE encryption.
/// Using the nonce as salt keeps per-item key isolation while avoiding the cycle.
pub fn derive_chain_key_from_nonce(
    root_key: &[u8],
    nonce: &aes_gcm::Nonce<aes_gcm::aead::generic_array::typenum::U12>,
) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(Some(nonce.as_slice()), root_key);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    hk.expand(b"p43-level2-item-v1", &mut out)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(out)
}
