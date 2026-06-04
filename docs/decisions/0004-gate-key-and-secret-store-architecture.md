# ADR-0004 — Gate-key and secret store architecture

**Date:** 2026-06-04  
**Status:** Accepted

---

## Context

p43 needs a persistent secret store (PINs, passphrases, vault entries) that:

- Works safely across the CLI and a future native UI
- Treats the YubiKey as the hardware root of trust
- Supports multiple unlock credentials (passphrase, biometric)
- Is designed for future sync across multiple devices
- Does not duplicate the OS Secure Enclave resource unnecessarily

The existing `CredentialCache` is in-memory only and caches raw PINs — the
wrong level of abstraction for a persistent store.

---

## Decision

### Key hierarchy

```
Level SE  — OS Secure Enclave (hardware, UI layer only)
              Touch ID → SE releases a random key
              p43 never manages this key; the OS Keychain API handles it entirely

Level PIN — OS Keychain (disk, SE-encrypted)
              Stores card PIN and soft-key passphrases
              Unlocked by Touch ID → SE
              UI layer only; CLI does not use biometrics

Gate-key  — ~/.config/project-43/gate-keys/<key-id>.sealed
              A 32-byte random sealed with Argon2id + AES-256-GCM
              One file per unlock credential (multiple allowed)
              CLI and UI passphrase path; SE path uses Keychain directly

Level 2   — ~/.config/project-43/level2.db
              Entries individually encrypted, each tagged with the key-id
              that encrypted them (fingerprint of the gate-key random)
              Groups entries by card fingerprint (AID / hex fingerprint)
              Contains: card PINs, passphrases, vault_key_sealed

Level 3   — Vault entries
              Encrypted with vault_key (unsealed from Level 2 using the card)
              Independent protection chain — compromising the gate-key alone
              is not sufficient to read vault data
```

### Gate-key design

A gate-key file (`<key-id>.sealed`) contains:

```json
{
  "version": 1,
  "key_id":  "gate-9c12ef",
  "kdf": { "algorithm": "argon2id", "salt": "...", "m_cost": 65536, "t_cost": 3, "p_cost": 4 },
  "nonce":      "...",
  "ciphertext": "..."
}
```

- `key_id` = `"gate-" + hex(SHA-256(random)[..6])` — fingerprint of the random, never secret
- `key_id` is bound as AES-GCM AAD so the file cannot be renamed without invalidating the tag
- GCM authentication tag is the verification mechanism — wrong passphrase → auth error, not garbage; no separate HMAC needed
- Argon2id parameters are stored per-file so they can be benchmarked per-device (~1 s target)

Multiple sealed files can coexist. `GateKeyStore::try_unlock` iterates all and returns on the
first GCM auth success.

### Level 2 database structure

```
entry: { key_id: "gate-9c12ef", fingerprint: "0006:17684870", ciphertext: AES-GCM(...) }
entry: { key_id: "gate-ab3401", fingerprint: "0006:17684870", ciphertext: AES-GCM(...) }
```

- Each entry carries the `key_id` of the gate-key that encrypted it
- The same secret can be stored under multiple `key_id` values (one per unlock credential)
- Adding a new passphrase = new gate-key + duplicate relevant entries under new `key_id`
- Revoking a passphrase = delete the `.sealed` file + sweep Level 2 entries for that `key_id`

### Biometric / CLI split

| Layer | CLI | Native UI |
|-------|-----|-----------|
| Touch ID / SE | ✗ | ✓ |
| Passphrase gate-key | ✓ | ✓ |
| Level 2 store access | ✓ | ✓ |
| Vault (Level 3) access | ✓ | ✓ |

The CLI never touches biometric APIs.  The native UI lets the user choose
between the biometric path and the passphrase path at setup.  Both paths
access the same Level 2 database; the SE path stores its random in the OS
Keychain rather than a `.sealed` file.

### CredentialCache role

The existing `CredentialCache` is retained for session-scoped caching:

- Passphrase path: cache the unlocked gate-key random (TTL ~15 min idle)
- Both paths: cache `vault_key` after card decryption (TTL ~15 min idle)
- Card PIN: very short TTL, only held for the duration of the card operation

The cache no longer stores raw PINs as its primary purpose.

---

## Consequences

- The gate-key module (`lib/src/gate_key/`) is the first concrete piece of the Level 2 stack
- Level 2 database schema is the next piece to design and build
- Biometric integration is deferred to the native UI layer (Dart/Swift) — not a Rust concern
- Future multi-device sync operates at Level 2 and Level 3; the gate-key layer is local-only
- The vault_key (Level 3) is always sealed to the YubiKey enc_key — compromising a
  gate-key alone cannot expose vault data

---

## Alternatives considered

**Single master key sealed to both passphrase and SE** — rejected because it requires a
separate `unlock-biometric.sealed` file and forces the Rust layer to understand SE key
wrapping.  Cleaner to let the OS Keychain be the SE-path storage natively.

**LUKS-style key slots** — considered but the multi-file directory approach is simpler to
audit, revoke, and extend without implementing a custom binary container format.

**JWT for sealed-file verification** — rejected.  AES-GCM authentication tag is sufficient;
JWT would be redundant and add signature key management overhead.
