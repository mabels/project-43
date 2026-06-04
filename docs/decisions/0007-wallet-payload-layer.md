# ADR-0007 — Wallet payload layer

**Date:** 2026-06-04  
**Status:** Accepted

---

## Context

ADR-0006 defines the Level 2 storage layer: immutable CBOR items, AES-256-GCM
encryption, hash-chain IDs.  The storage layer is type-agnostic — it encrypts
and decrypts raw bytes without caring what they contain.

This ADR defines the **wallet** — the payload layer that sits on top of the
storage layer and gives meaning to those bytes.

---

## Decision

### Name

The payload layer is called the **wallet**.  It holds credentials and key
references used to operate p43 hardware and software keys.  It is distinct
from the *vault* (Level 3, future: password manager entries).

### Payload envelope

Every wallet item stored in a chain is CBOR-encoded as:

```
{
  kind:    text,   // discriminant — "yubikey-ref" | "ssh-key" | …
  payload: map,    // kind-specific fields
}
```

The `kind` + `payload` adjacently-tagged structure makes the bytes
self-describing: a reader can interpret any item without consulting the chain
name.  This also enables forward-compatibility: unknown `kind` values are
surfaced as an explicit error rather than silent misparse.

In Rust this maps to a serde adjacently-tagged enum:

```rust
#[serde(tag = "kind", content = "payload")]
pub enum WalletPayload { … }
```

### Payload kinds (v1)

**`yubikey-ref`** — public identity of a YubiKey card.  Stores the
public key material so other devices can verify signatures without the card.
The PIN is stored separately as `card-pin` (different chain, same fingerprint).

```
YubikeyRef {
  version:          u8,
  card_fingerprint: String,   // AID e.g. "0006:17684870"
  label:            String,   // human name e.g. "work yubikey"
  sign_pubkey:      bytes,    // OpenPGP signing public key
  auth_pubkey:      bytes,    // OpenPGP auth public key (SSH)
  enc_pubkey:       bytes,    // OpenPGP encryption public key
}
```

**`card-pin`** — the PIN for a specific card.  Stored in a separate chain so
it can be rotated independently of the public key reference.

```
CardPin {
  version:          u8,
  card_fingerprint: String,
  pin:              String,
}
```

**`ssh-key`** — a software SSH key pair.

```
SshKey {
  version:     u8,
  private_key: bytes,    // raw private key material (wallet encryption is the outer protection)
  public_key:  bytes,    // SSH public key bytes
  comment:     String,   // e.g. "meno@macbook"
}
```

### Deferred kinds

- `vault-item` — password manager entry (title, username, password, URL, notes, TOTP)
- `vault-attachment` — binary file attached to a vault item
- `key-material` — raw 32-byte random for indirect key references (internal use)
- `passphrase` — soft-key passphrase (follows same pattern as `card-pin`)

### Chain naming convention

The wallet layer enforces the chain name format `<fingerprint>-<kind>`:

```
0006_17684870-yubikey-ref
0006_17684870-card-pin
ABCD1234EFGH-ssh-key
```

`fingerprint` uses `_` instead of `:` to be filesystem-safe.

### Module layout

```
lib/src/level2/
  store/    ← ADR-0006 storage layer (unchanged)
  wallet/
    mod.rs   ← Wallet struct, open/read/write typed entries
    entry.rs ← WalletPayload enum + payload structs
    chain.rs ← ChainName helper (fingerprint-kind convention + validation)
```

---

## Consequences

- `lib/src/level2/wallet/` is the next module to build.
- CLI: `p43 wallet list / get / add / delete` replaces the raw `p43 chain` commands
  for end users (chain commands remain for debugging/inspection).
- Bridge: wallet functions are exposed to Flutter for the UI Keys page Credentials tab (ADR-0005).
