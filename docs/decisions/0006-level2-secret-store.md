# ADR-0006 — Level 2 secret store

**Date:** 2026-06-04  
**Status:** Accepted

---

## Terminology

| Term | Meaning |
|---|---|
| **Chain** | A named, append-only linked list of items identified by a `(fingerprint, kind)` pair |
| **Item** | A single immutable node in a chain — one CBOR file on disk |
| **Chain key** | The per-item AES-256-GCM key, derived fresh for each item via HKDF |
| **Root key** | The key material fed into HKDF to produce the chain key; depends on `key_ref` type |
| **Object store** | Abstract backend: `list`, `put` (fail-if-exists), `get` (fail-if-missing) |

---

## Context

The gate-key (ADR-0004) provides a passphrase-sealed 32-byte random.
That key needs to protect a collection of secrets: card PINs, soft-key passphrases,
card-sealed vault keys, and eventually arbitrary secret material.

Requirements that shaped the design:

- **Syncable across devices** — no single-file database; sync must work at the
  file level without merge conflicts in the common case.
- **Immutable items** — once written, an object is never modified.
- **Per-item key isolation** — compromising one item's chain key must not
  expose other items.
- **Multiple decryption paths** — direct gate-key, indirect via another Level 2
  item, indirect via card, or shared via a chain-scoped derived key.
- **Binary on disk** — CBOR throughout; `ciborium` is already a dependency.
- **Configurable storage path** — the base directory is a constructor parameter,
  not hardcoded. Enables testing with temp dirs and future alternate backends.

---

## Decision

### Layer separation

```
lib/src/level2/
  store/    ← storage layer: object store, chain logic, key derivation
              knows nothing about payload content — operates on raw bytes only
  payload/  ← payload layer: typed secret schemas (card_pin, passphrase, …)
              sits on top of the storage layer; added in ADR-0007
```

### Abstract object store

The chain logic talks to an `ObjectStore` trait, not to the filesystem directly.
This decouples chain operations from I/O and makes the backend swappable.

```rust
trait ObjectStore {
    fn list(&self)                        -> Result<Vec<String>>;
    fn put(&self, id: &str, data: &[u8]) -> Result<()>;   // error if already exists
    fn get(&self, id: &str)              -> Result<Vec<u8>>; // error if missing
    fn exists(&self, id: &str)           -> bool;
}
```

`FileObjectStore(base_path: PathBuf)` is the default implementation.
`put` uses write-then-rename for atomicity. A second `put` with the same id fails
(immutability guarantee).

### Directory layout

```
<base>/
  meta/
    <fingerprint>-<kind>.ref     ← CBOR: bytes(20) — SHA-1 id of current tip item
  items/
    <sha1-hex>.item              ← CBOR: immutable envelope
```

`fingerprint` uses `_` instead of `:` (e.g. `0006_17684870`).
The `.ref` file contains only the SHA-1 id of the tip — no kind, no metadata.
The kind is encoded in the filename for lookup; the ref itself is opaque.

### Item addressing — deterministic SHA-1 hash chain

Item IDs are not random UUIDs. They are derived deterministically:

```
root item:       id = SHA-1(ciphertext)          ← content-addressed
root.next      = SHA-1(root.id)
item_n.id      = SHA-1(item_{n-1}.id)            ← hash chain
item_n.next    = SHA-1(item_n.id)
```

Properties:
- **Content-addressed root**: same plaintext + same key → same root id.
  Duplicate writes are detected before touching the object store.
- **Predictable chain**: given any item's id, the successor's id is
  `SHA-1(current_id)`. No coordination needed to pre-allocate the next slot.
- **Integrity**: following the hash chain verifies the sequence without decrypting.
- **Conflict detection**: two concurrent writers both produce the same next id.
  A `put` collision on the object store is the conflict signal.

### Item envelope (CBOR)

```
{
  id:          bytes(20),       // SHA-1 hash — this item's address
  version:     uint,            // always 1
  prev:        bytes(20) | nil, // nil → root of chain
  next:        bytes(20),       // SHA-1(this.id) — pre-computed successor id
  deleted:     bool,            // tombstone — no payload when true
  creator_id:  text,            // device/app id for sync attribution
  key_ref:     map,             // how to derive the chain key (see below)
  nonce:       bytes(12),       // AES-256-GCM nonce
  ciphertext:  bytes,           // AES-256-GCM(chain_key, payload_bytes)
}
```

The **chain key** is always derived, never stored:

```
chain_key = HKDF-SHA256(
  ikm  = <root_key>,           // depends on key_ref type
  salt = item.id,              // 20 bytes SHA-1 — unique per item
  info = "p43-level2-item-v1"
) → 32 bytes
```

### key_ref types

**direct** — root key is the gate-key random:
```
key_ref: { type: "direct", gate_key_id: bytes(6) }
```
`root_key = gate_key.random`

**indirect_l2** — root key is the plaintext of another Level 2 item
(must be a `key_material` payload containing 32 raw bytes):
```
key_ref: { type: "indirect_l2", item_id: bytes(20) }
```
`root_key = decrypt(referenced_item).bytes`

**indirect_card** — root key comes from the card decrypting a sealed blob
held in another Level 2 item:
```
key_ref: { type: "indirect_card", item_id: bytes(20), card_fingerprint: text }
```
`root_key = card.decrypt(decrypt(referenced_item).sealed_blob)`

**chain_share** — root key is a pre-shared chain-scoped derived key:
```
key_ref: { type: "chain_share", shared_key: bytes(32) }
```
`root_key = shared_key`

Chain-share token: `shared_key = HKDF(ikm=gate_key.random, salt=chain_root_id, info="p43-chain-share-v1")`

### Meta ref

`meta/<fingerprint>-<kind>.ref` contains one CBOR value: `bytes(20)` — the SHA-1
id of the current tip item. Written atomically (write-then-rename). No other
content; the kind and fingerprint live only in the filename.

### Chain operations

**Read:**
```
1. object_store.get("meta/<fp>-<kind>.ref")  → tip_id (bytes 20)
2. object_store.get("items/<hex(tip_id)>")   → decode CBOR → check deleted
3. derive chain_key → decrypt → return payload bytes
```

**Append (create or update):**
```
1. get meta ref                     → current_tip_id  (nil if new chain)
2. encrypt payload bytes            → ciphertext
3. new_id   = SHA-1(ciphertext)     (root) OR SHA-1(current_tip_id) (update)
4. next_id  = SHA-1(new_id)
5. object_store.put("items/<hex(new_id)>", cbor_envelope)
6. object_store.put("meta/<fp>-<kind>.ref", cbor(new_id))  ← atomic rename
```

**Delete:**
```
1. get meta ref → tip_id
2. tombstone_id = SHA-1(tip_id)
3. object_store.put("items/<hex(tombstone_id)>", cbor { deleted: true, prev: tip_id, ... })
4. object_store.put("meta/<fp>-<kind>.ref", cbor(tombstone_id))
```

**Walk history:**
```
start at tip; follow prev until prev == nil (root).
```

### Sync properties

- `items/` objects are immutable and content-addressed. Copy new items to peers.
  No merge conflicts at the item level.
- `meta/` refs are last-write-wins. Conflict = two items with the same `prev` id
  (two concurrent appends). `creator_id` attributes each side without decrypting.
- Conflict resolution is deferred.

---

## Alternatives considered

**Random UUIDs for item ids** — replaced by the SHA-1 hash chain. Deterministic
ids enable content-addressed deduplication, chain integrity verification, and
conflict detection via `put`-collision on the object store.

**Single encrypted file** — rejected: merge conflicts on concurrent writes.

**Mutable items** — rejected: breaks append-only sync.

**`modified_at` for ordering** — replaced by `prev`/`next` hash chain.

**JSON on disk** — replaced by CBOR: binary-safe, compact, consistent with `bus`.

---

## Consequences

- `lib/src/level2/store/` is the next module to build.
- CLI: `p43 chain list / show / append / delete / gc`.
- Payload layer (ADR-0007) and UI Credentials tab (ADR-0005) depend on this.
- Future Matrix sync carries `.item` CBOR blobs as event content — the hash chain
  maps cleanly onto Matrix's append-only event DAG.
