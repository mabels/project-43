//! Wallet — typed payload layer on top of the sync store.
//!
//! All chains in the store are content-addressed (meta filename = chain_id =
//! SHA-1 of the root item).  The wallet scans all chains, decrypts each tip,
//! and identifies wallet entries by their payload kind.  No persistent index
//! is needed — the scan is O(n) and wallets are small.

pub mod chain;
pub mod credential;
pub mod entry;
#[cfg(test)]
mod tests;

pub use chain::{ChainName, KNOWN_KINDS};
pub use credential::KeyCredential;
pub use credential::PgpCredential;
pub use entry::{
    AuthorityKeyPayload, CertifiedDeviceIdPayload, DeviceIdPayload, FilePgpKey, KeySlot, SshKey,
    WalletPayload, YubikeyRef,
};

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::sync_store::{ChainRef, ChainStore, FileObjectStore, ItemId, KeyRef};

// ── Wallet ────────────────────────────────────────────────────────────────────

/// High-level wallet: typed read/write over a sync-store directory.
///
/// All chains are named by their content-derived chain_id (SHA-1 hex).
/// The wallet finds its entries by decrypting each chain tip and checking
/// the payload kind against [`KNOWN_KINDS`].
pub struct Wallet {
    pub(crate) store: ChainStore,
}

impl Wallet {
    /// Open the wallet at `base_dir/sync-store`.
    pub fn open(base_dir: &Path) -> Result<Self> {
        let obj_store = Arc::new(
            FileObjectStore::open(base_dir.join("sync-store"))
                .context("cannot open wallet sync-store")?,
        );
        Ok(Self {
            store: ChainStore::new(obj_store),
        })
    }

    // ── Index ─────────────────────────────────────────────────────────────────

    /// Build an in-memory index: scan all chains, decrypt tips, extract names.
    ///
    /// Returns `HashMap<chain_name_string, chain_id>` for all wallet entries.
    fn build_index(&self, root_key: &[u8]) -> Result<HashMap<String, ItemId>> {
        let mut idx = HashMap::new();
        for (chain_ref, meta) in self.store.list_chains()? {
            if let Some(bytes) = self.store.read(&chain_ref, root_key)? {
                if let Ok(payload) = WalletPayload::from_cbor(&bytes) {
                    let name = chain_name_for(&payload);
                    let chain_id = ItemId(meta.chain_id.clone());
                    idx.insert(name, chain_id);
                }
            }
        }
        Ok(idx)
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Read the current value for `(fingerprint, kind)`.
    pub fn get(
        &self,
        fingerprint: &str,
        kind: &str,
        root_key: &[u8],
    ) -> Result<Option<WalletPayload>> {
        let target = ChainName::new(fingerprint, kind);
        let target_name = format!("{}-{}", target.fingerprint, target.kind);
        let idx = self.build_index(root_key)?;
        match idx.get(&target_name) {
            None => Ok(None),
            Some(chain_id) => {
                let chain = ChainRef::new(chain_id.as_hex());
                match self.store.read(&chain, root_key)? {
                    None => Ok(None),
                    Some(bytes) => Ok(Some(WalletPayload::from_cbor(&bytes)?)),
                }
            }
        }
    }

    /// List all wallet entries (fingerprint, kind) pairs.
    pub fn list(&self) -> Result<Vec<ChainName>> {
        // Without root_key we can only list known-kind meta filenames.
        // Wallet entries whose meta was written with fingerprint-kind names
        // are found this way; content-addressed entries require decryption.
        let chains = self.store.list_chains()?;
        Ok(chains
            .into_iter()
            .filter_map(|(c, _)| ChainName::from_chain_name(&c.name))
            .collect())
    }

    /// List all wallet entries with their stable chain_id (requires root_key
    /// to scan content-addressed chains).
    pub fn list_with_ids(&self, root_key: &[u8]) -> Result<Vec<(ChainName, String)>> {
        let idx = self.build_index(root_key)?;
        let mut result = Vec::new();
        for (name, chain_id) in &idx {
            if let Some(cn) = ChainName::from_chain_name(name) {
                result.push((cn, chain_id.as_hex()));
            }
        }
        result.sort_by(|a, b| a.0.fingerprint.cmp(&b.0.fingerprint));
        Ok(result)
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Write (append) a payload for `(fingerprint, kind)`.
    ///
    /// Scans the index to find an existing chain; creates one via `create()`
    /// if not found.  The chain is always named by its content-derived chain_id.
    pub fn put(
        &self,
        fingerprint: &str,
        kind: &str,
        payload: &WalletPayload,
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
    ) -> Result<()> {
        let target = ChainName::new(fingerprint, kind);
        let target_name = format!("{}-{}", target.fingerprint, target.kind);
        let bytes = payload.to_cbor()?;

        let idx = self.build_index(root_key)?;
        match idx.get(&target_name) {
            None => {
                // Create a new content-addressed chain.
                self.store.create(root_key, key_ref, creator_id, &bytes)?;
            }
            Some(chain_id) => {
                let chain = ChainRef::new(chain_id.as_hex());
                self.store
                    .append(&chain, root_key, key_ref, creator_id, &bytes)?;
            }
        }
        Ok(())
    }

    /// Delete (tombstone) the chain for `(fingerprint, kind)`.
    pub fn delete(
        &self,
        fingerprint: &str,
        kind: &str,
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
    ) -> Result<()> {
        let target = ChainName::new(fingerprint, kind);
        let target_name = format!("{}-{}", target.fingerprint, target.kind);
        let idx = self.build_index(root_key)?;
        let chain_id = idx
            .get(&target_name)
            .ok_or_else(|| anyhow::anyhow!("wallet entry {target_name} not found"))?;
        let chain = ChainRef::new(chain_id.as_hex());
        self.store.delete(&chain, root_key, key_ref, creator_id)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Derive the wallet name string (`fingerprint-kind`) from a decoded payload.
fn chain_name_for(payload: &WalletPayload) -> String {
    match payload {
        WalletPayload::YubikeyRef(r) => {
            format!("{}-yubikey-ref", r.card_fingerprint.replace(':', "_"))
        }
        WalletPayload::SshKey(k) => {
            // Re-derive the fingerprint from the private key bytes.
            if let Ok(sk) = ssh_key::PrivateKey::from_openssh(&k.private_key) {
                let fp = sk
                    .public_key()
                    .fingerprint(Default::default())
                    .to_string()
                    .replace(':', "_");
                format!("{fp}-ssh-key")
            } else if !k.comment.is_empty() {
                // Fallback: sanitise the comment (replace non-alphanumeric with _)
                let safe: String = k
                    .comment
                    .chars()
                    .map(|c| {
                        if c.is_alphanumeric() || c == '_' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                format!("{safe}-ssh-key")
            } else {
                // Last resort: SHA-256 of the private key bytes
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&*k.private_key);
                format!("{}-ssh-key", hex::encode(&hash[..10]))
            }
        }
        WalletPayload::PgpKey(k) => {
            // Use a sanitised label as the fingerprint component.
            let safe: String = k
                .label
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            format!("{safe}-pgp-key")
        }
        // Authority key: there is exactly one per wallet; use a stable name.
        WalletPayload::AuthorityKey(_) => "authority-authority-key".to_owned(),
        // Device IDs use the device_id hex as the fingerprint component.
        WalletPayload::DeviceId(d) => format!("{}-device-id", d.device_id),
        WalletPayload::CertifiedDeviceId(d) => {
            format!("{}-certified-device-id", d.device_id)
        }
    }
}
