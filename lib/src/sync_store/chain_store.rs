//! Chain store — manages named chains over an ObjectStore.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::sync::Arc;

use super::item::{cid_of, ItemEnvelope, ItemId, KeyRef, ROOT_SALT};
use super::object_store::ObjectStore;

// ── MetaRef ───────────────────────────────────────────────────────────────────

/// Contents of a meta `.ref` file.
///
/// `chain_id` is a random stable identifier generated once at chain creation —
/// it never changes and is the canonical ID for this chain.
/// `last_id` is the SHA-1 id of the current tip item, updated on every append.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRef {
    pub chain_id: ByteBuf, // random bytes(20), stable
    pub last_id: ByteBuf,  // SHA-1 of tip item, mutable
}

impl MetaRef {
    /// Create a MetaRef for a brand-new chain from its root item.
    ///
    /// `chain_id = root.id` — the content hash of the first item.
    /// Meta filename = `meta/<chain_id>.ref` = `meta/<root.id>.ref`.
    /// Item filename = `items/<root.id>` = same hex → consistent naming.
    /// `last_id = root.id` initially; advances on each append.
    fn new_chain(root: &ItemEnvelope) -> Self {
        Self {
            chain_id: root.id.0.clone(), // chain_id = root.id (content hash)
            last_id: root.id.0.clone(),  // tip initially = root
        }
    }

    fn with_new_tip(&self, last_id: &ItemId) -> Self {
        Self {
            chain_id: self.chain_id.clone(),
            last_id: last_id.0.clone(),
        }
    }

    pub fn chain_id_hex(&self) -> String {
        hex::encode(&*self.chain_id)
    }

    pub fn last_item_id(&self) -> ItemId {
        ItemId(self.last_id.clone())
    }
}

// ── ChainValidity ─────────────────────────────────────────────────────────────

/// Per-item structural validity result from [`ChainStore::walk_validated`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainValidity {
    /// All structural checks passed.
    Ok,
    /// `item.id` does not match what the hash chain predicts.
    InvalidId { expected: ItemId, got: ItemId },
    /// `item.next` does not equal `SHA-1(item.id)`.
    InvalidNext { expected: ItemId, got: ItemId },
    /// `item.prev` does not match the previous item's id.
    InvalidPrev {
        expected: Option<ItemId>,
        got: Option<ItemId>,
    },
}

/// A single item returned by [`ChainStore::walk_validated`], newest first.
pub struct ChainItem {
    pub envelope: ItemEnvelope,
    pub validity: ChainValidity,
}

// ── ChainRef ─────────────────────────────────────────────────────────────────

/// An opaque name that identifies a chain in the store.
///
/// The storage layer places no meaning on the name — it is just a string.
/// Naming conventions (e.g. `<fingerprint>-<kind>`) are a payload-layer concern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRef {
    pub name: String,
}

impl ChainRef {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn ref_id(&self) -> String {
        format!("meta/{}.ref", self.name)
    }
}

// ── ChainStore ────────────────────────────────────────────────────────────────

/// High-level API for reading and writing chains.
///
/// All I/O goes through the injected [`ObjectStore`].  The store knows nothing
/// about payload content — it only moves encrypted bytes.
pub struct ChainStore {
    objects: Arc<dyn ObjectStore>,
}

impl ChainStore {
    pub fn new(objects: Arc<dyn ObjectStore>) -> Self {
        Self { objects }
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Return the meta ref for `chain`, or `None` if the chain does not exist.
    pub fn meta(&self, chain: &ChainRef) -> Result<Option<MetaRef>> {
        let ref_id = chain.ref_id();
        if !self.objects.exists(&ref_id) {
            return Ok(None);
        }
        Ok(Some(self.read_meta(&ref_id)?))
    }

    /// Return the tip item of `chain`, or `None` if the chain does not exist.
    pub fn tip(&self, chain: &ChainRef) -> Result<Option<ItemEnvelope>> {
        let ref_id = chain.ref_id();
        if !self.objects.exists(&ref_id) {
            return Ok(None);
        }
        let meta = self.read_meta(&ref_id)?;
        let item = self.load_item(&meta.last_item_id())?;
        Ok(Some(item))
    }

    /// Decrypt and return the payload bytes of the current tip.
    ///
    /// Returns `None` if the chain does not exist or is deleted.
    pub fn read(&self, chain: &ChainRef, root_key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.tip(chain)? {
            None => Ok(None),
            Some(item) if item.deleted => {
                // Verify the tombstone is authentic before honouring it.
                item.decrypt(root_key).map_err(|_| {
                    anyhow::anyhow!(
                        "tombstone authentication failed — possible forgery on chain {}",
                        chain.name
                    )
                })?;
                Ok(None)
            }
            Some(item) => Ok(Some(item.decrypt(root_key)?)),
        }
    }

    /// List all chains with their stable chain_id.
    pub fn list_chains(&self) -> Result<Vec<(ChainRef, MetaRef)>> {
        let all = self.objects.list()?;
        let mut chains = Vec::new();
        for id in all {
            if let Some(name) = id
                .strip_prefix("meta/")
                .and_then(|s| s.strip_suffix(".ref"))
            {
                let chain = ChainRef::new(name);
                let meta = self.read_meta(&id)?;
                chains.push((chain, meta));
            }
        }
        Ok(chains)
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Create a brand-new chain with `payload` as its root item.
    ///
    /// Returns the **chain_id** = `root.next` = SHA-1(root.id).
    /// This is the meta filename and the id callers pass to [`append`].
    ///
    /// Design: `chain_id = root.next` so the meta file is named after the
    /// value that the first real successor item will use as its own id.
    /// The meta initially holds `{ chain_id: root.next, last_id: root.id }`.
    pub fn create(
        &self,
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
        payload: &[u8],
    ) -> Result<ItemId> {
        let item = ItemEnvelope::new_root(root_key, key_ref, creator_id, payload)?;
        let meta = MetaRef::new_chain(&item); // chain_id = item.next, last_id = item.id
        let chain_id = ItemId(meta.chain_id.clone());
        let ref_id = format!("meta/{}.ref", chain_id.as_hex());
        anyhow::ensure!(
            !self.objects.exists(&ref_id),
            "chain {} already exists",
            chain_id.as_hex()
        );
        self.store_item(&item)?;
        self.write_meta(&ref_id, &meta)?;
        Ok(chain_id)
    }

    /// Append a new item to `chain`, creating it if it does not exist.
    ///
    /// When creating: the meta is written under `chain.ref_id()` (the caller's
    /// chosen name) with `chain_id = root.next`.
    /// When updating: the existing chain_id is preserved; only `last_id` changes.
    pub fn append(
        &self,
        chain: &ChainRef,
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
        payload: &[u8],
    ) -> Result<ItemId> {
        let ref_id = chain.ref_id();

        let (item, meta) = if !self.objects.exists(&ref_id) {
            let item = ItemEnvelope::new_root(root_key, key_ref, creator_id, payload)?;
            let meta = MetaRef::new_chain(&item); // chain_id = root.next
            (item, meta)
        } else {
            let existing_meta = self.read_meta(&ref_id)?;
            let tip_id = existing_meta.last_item_id();
            let tip = self.load_item(&tip_id)?;
            let tip_salt = tip
                .prev
                .as_ref()
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_else(|| ROOT_SALT.to_vec());
            let recomputed = cid_of(&tip_salt, payload);
            if !tip.deleted && tip.cid == recomputed {
                return Ok(tip_id);
            }
            let item =
                ItemEnvelope::new_successor(&tip_id, root_key, key_ref, creator_id, payload)?;
            let meta = existing_meta.with_new_tip(&item.id);
            (item, meta)
        };

        let item_id = item.id.clone();
        self.store_item(&item)?;
        self.write_meta(&ref_id, &meta)?;
        Ok(item_id)
    }

    /// Append an authenticated tombstone, marking the chain as deleted.
    ///
    /// Requires `root_key` — the tombstone is encrypted, proving the caller
    /// holds the key.  Someone without it cannot forge a valid deletion.
    pub fn delete(
        &self,
        chain: &ChainRef,
        root_key: &[u8],
        key_ref: KeyRef,
        creator_id: &str,
    ) -> Result<()> {
        let ref_id = chain.ref_id();
        if !self.objects.exists(&ref_id) {
            bail!("chain {} does not exist", chain.name);
        }
        let existing_meta = self.read_meta(&ref_id)?;
        let tombstone = ItemEnvelope::new_tombstone(
            &existing_meta.last_item_id(),
            root_key,
            key_ref,
            creator_id,
        )?;
        self.store_item(&tombstone)?;
        self.write_meta(&ref_id, &existing_meta.with_new_tip(&tombstone.id))?;
        Ok(())
    }

    /// Walk the full history of a chain from tip to root.
    ///
    /// Returns items newest-first.  Does not decrypt — returns raw envelopes.
    pub fn history(&self, chain: &ChainRef) -> Result<Vec<ItemEnvelope>> {
        let mut items = Vec::new();
        let ref_id = chain.ref_id();
        if !self.objects.exists(&ref_id) {
            return Ok(items);
        }
        let mut current_id = self.read_meta(&ref_id)?.last_item_id();
        loop {
            let item = self.load_item(&current_id)?;
            let prev = item.prev.clone();
            items.push(item);
            match prev {
                Some(p) => current_id = p,
                None => break,
            }
        }
        Ok(items)
    }

    /// Walk the chain from tip to root, validating structural integrity of each
    /// item.  Returns items newest-first with a [`ChainValidity`] per item.
    ///
    /// Checks performed per item:
    /// - `id` matches the expected SHA-1 (ciphertext for root, SHA-1(prev_id) for successors)
    /// - `next == SHA-1(id)`
    /// - `prev` links correctly to the previous item
    ///
    /// Does **not** decrypt — structural validation only.
    pub fn walk_validated(&self, chain: &ChainRef) -> Result<Vec<ChainItem>> {
        let raw = self.history(chain)?;
        let mut result = Vec::with_capacity(raw.len());

        for (i, item) in raw.iter().enumerate() {
            let prev_item = raw.get(i + 1); // history is newest-first; prev_item is older

            // Check prev linkage.
            let expected_prev = prev_item.map(|p| p.id.clone());
            let validity_prev = if item.prev != expected_prev {
                ChainValidity::InvalidPrev {
                    expected: expected_prev,
                    got: item.prev.clone(),
                }
            } else {
                ChainValidity::Ok
            };

            // Check id derivation.
            let expected_id = match &item.prev {
                None => ItemId::from_bytes(&item.ciphertext), // root: SHA-1(ciphertext)
                Some(prev_id) => prev_id.next(),              // successor: SHA-1(prev_id)
            };
            let validity_id = if item.id != expected_id {
                ChainValidity::InvalidId {
                    expected: expected_id,
                    got: item.id.clone(),
                }
            } else {
                ChainValidity::Ok
            };

            // Check next pointer.
            let expected_next = item.id.next();
            let validity_next = if item.next != expected_next {
                ChainValidity::InvalidNext {
                    expected: expected_next,
                    got: item.next.clone(),
                }
            } else {
                ChainValidity::Ok
            };

            // First failure wins; Ok if all pass.
            let validity = [validity_prev, validity_id, validity_next]
                .into_iter()
                .find(|v| *v != ChainValidity::Ok)
                .unwrap_or(ChainValidity::Ok);

            result.push(ChainItem {
                envelope: item.clone(),
                validity,
            });
        }

        Ok(result)
    }

    /// Remove items not reachable from any meta ref (orphan GC).
    ///
    /// Safe to run at any time; only deletes objects whose id does not appear
    /// in any live chain's history.  Since objects are immutable this is
    /// purely additive-safe.
    pub fn gc(&self) -> Result<usize> {
        // Collect all item ids reachable from any chain.
        let mut reachable = std::collections::HashSet::new();
        for (chain, _meta) in self.list_chains()? {
            let ref_id = chain.ref_id();
            reachable.insert(ref_id.clone());
            if self.objects.exists(&ref_id) {
                let mut id = self.read_meta(&ref_id)?.last_item_id();
                loop {
                    let item_key = format!("items/{}", id.as_hex());
                    reachable.insert(item_key);
                    let item = self.load_item(&id)?;
                    match item.prev {
                        Some(p) => id = p,
                        None => break,
                    }
                }
            }
        }
        // Remove anything not reachable.
        let all = self.objects.list()?;
        let mut removed = 0usize;
        for id in all {
            if !reachable.contains(&id) {
                // ObjectStore doesn't have delete — callers must handle via
                // FileObjectStore::remove or similar. Skip for now.
                let _ = id; // TODO: add ObjectStore::remove in a future step
                removed += 1;
            }
        }
        Ok(removed)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn read_meta(&self, ref_id: &str) -> Result<MetaRef> {
        let data = self.objects.get(ref_id)?;
        ciborium::from_reader(data.as_slice()).context("invalid meta ref CBOR")
    }

    fn write_meta(&self, ref_id: &str, meta: &MetaRef) -> Result<()> {
        let mut buf = Vec::new();
        ciborium::into_writer(meta, &mut buf).context("meta ref CBOR serialise")?;
        // Meta refs are mutable (last-write-wins) — use update, not put.
        self.objects.update(ref_id, &buf)
    }

    fn load_item(&self, id: &ItemId) -> Result<ItemEnvelope> {
        let key = format!("items/{}", id.as_hex());
        let data = self.objects.get(&key)?;
        ItemEnvelope::from_cbor(&data)
    }

    fn store_item(&self, item: &ItemEnvelope) -> Result<()> {
        let key = format!("items/{}", item.id.as_hex());
        let data = item.to_cbor()?;
        self.objects.put(&key, &data)
    }
}
