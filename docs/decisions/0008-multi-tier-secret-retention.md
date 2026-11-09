# ADR-0008 — Multi-tier secret retention (auth × TTL × isolation)

**Date:** 2026-10-07
**Status:** Proposed

---

## Context

p43 already decrypts and holds several kinds of secret material in memory, but
each does it ad hoc, with no shared model:

| Holder | Where | Lifecycle today |
|---|---|---|
| `CredentialCache` | `lib/src/credential_cache.rs` | plaintext `String`s, one global sliding TTL, purged by `lock_all` |
| `SIGNING_KEY_CACHE` (+ RSA cache) | `ui/rust/src/api/simple.rs:255`, `:2171` | decrypted keypairs, opt-in, cleared by `lock_all` |
| `AUTHORITY_SESSION` | `ui/rust/src/api/simple.rs:183` | unlocked authority key, cleared by `lock_all` |
| gate-key random | `lib/src/gate_key/mod.rs:40` | `Zeroizing<Vec<u8>>` while unlocked |
| `YubikeyRef.pin`, `FilePgpKey.passphrase` | `lib/src/wallet/entry.rs:109,138` | plaintext fields in decrypted payloads |
| card PIN | `lib/src/pkcs11/card.rs:228` | `SecretString`, per-call |
| at-rest material | `lib/src/sync_store/`, `gate_key/*.sealed` | ADR-0006 / ADR-0007 |

The product needs distinct retention behaviour per secret: some are public and
can be read with no gate; some may stay unlocked for a session after one
prompt; some must be wiped the moment the screen locks; some are single-use
"guard" material that unlocks other secrets or a YubiKey. Today there is no way
to express any of that — everything is implicitly "tier 1 with a global
15-minute sliding TTL". Concretely:

- The retention policy is not data; it is scattered across `set_timeout`,
  `KEY_CACHE_ENABLED`, and `lock_all`.
- Plaintext is cloned out of `CredentialCache::get` as `String` and out of the
  wallet payloads as fields; nothing zeroizes on drop and callers freely copy.
- In-use copies are ordinary heap allocations: swappable, dumpable, and
  readable by the same-user debugger.
- "Wipe on screen lock" is best-effort: `lock_all` and a Dart timer race the
  actual event, and there is no generation marker to invalidate a lease that
  was handed out just before the lock.
- CLI and UI have different capabilities (the CLI cannot prompt for biometrics)
  but that is not represented anywhere.

The four tiers described by the product are therefore not four code paths —
they are one policy record with independent axes, and the axes are the real
requirement.

There is also no way for a **user to choose the tier per secret**. A password
manager needs exactly that: the password for website A protected by tier-x, the
password for website B by tier-y, while internal secrets carry sensible defaults
(the SSH agent's own key at tier 2, the Matrix transport at tier 0). Today the
effective level is implicit in whichever cache happens to hold the value. The
assignment must be per secret, user-editable, safe by default, and impossible to
downgrade silently.

---

## Decision

### 1. A tier is a declarative policy, not an enum

Introduce a `TierPolicy` record with independent axes:

- **`auth`** — what unlocks it: `none`, `pin`, `passphrase`, `biometric`, or a
  boolean combination (`any` / `all`).
- **`retention`** — how long a decrypted copy survives: `never` (re-auth every
  use), `single_use`, `absolute(ttl)`, `sliding(ttl)`, or `until_screen_lock`,
  with an optional hard `cap`.
- **`scope`** — `request` / `screen` / `session` / `process`.
- **`isolation`** — which sealer protects the in-use copy (`soft`, `gate_key`,
  `os_keychain`, `secure_enclave`, `tpm`, `card`) plus memory hardening
  (`zeroize`, `mlock`, `no_dump`, …).
- **`surfaces`** — `cli` / `ui` / `agent` / `sync` the secret may be used from.
- **`on_lock`**, **`reuse`** (`manual` / `auto_approve` / `per_use`).
- **`delegates`** — secret-to-secrets: other secrets this one unlocks.

The well-known tiers are just names for policies (tables in
`docs/secrets-architecture.md`):

| Alias | auth | retention | scope | isolation |
|---|---|---|---|---|
| `tier0-public` | none | never | request | none |
| `tier1-session` | any(pin, passphrase, biometric) | sliding(15 m) | session | soft-hardened |
| `tier2-screen` | any(pin, passphrase, biometric) | until_screen_lock, cap absolute(5 m) | screen | soft-hardened / SE / TPM |
| `tier3-guard` | any(pin, passphrase, biometric) | single_use | request | SE / TPM / card |

"Defining a new tier" is adding a policy record to the registry; no new enum
variant, no new match arm. Unknown policies fail closed.

### 2. Unlock issues a lease, never the secret

Unlocking a secret returns a `Lease` handle (`secret`, `scope`, `epoch`,
`expires_at`, optional `uses_left`, `auth_method`). Callers ask the broker to
perform an operation *with* the lease (`with_secret(..)`); the plaintext exists
only inside the broker for the duration of that operation and is re-sealed or
wiped immediately afterwards. No API returns a copyable plaintext value.
This replaces `get(&str) -> Option<String>`.

### 3. Lock epochs make "until screen lock" race-free

A process-global monotonic `LockEpoch` is bumped on every lock event (explicit
lock button, app `paused`/`hidden` in `ui/lib/main.dart:337`, OS session lock).
Every lease records the epoch it was granted under. Any use with a stale epoch
fails; leases and their sealed blobs are dropped when the epoch advances. This
removes the timer-vs-event race in `SettingsService`/`lock_all`.

### 4. A `Sealer` trait with platform backends

One interface, several implementations selected by policy and by what the host
actually offers:

- `Soft` — in-process, zeroize + optional `mlock` / no-dump.
- `GateKey` — the existing Argon2id + AES-256-GCM `.sealed` file.
- `OsKeychain` — Apple Keychain, Android Keystore, Linux Secret Service,
  Windows DPAPI/Credential Manager.
- `SecureEnclave` — Apple SEP / Android StrongBox.
- `Tpm` — Linux/Windows TPM 2.0 (PCR-sealed); relevant for the headless
  Proxmox/SSH target where no biometric exists.
- `Card` — YubiKey-derived wrapping via the existing PC/SC stack.

Platform availability is negotiated at unlock time; the broker records which
sealer was used. In-use sealing is **device-local and never synced** — only the
at-rest material (ADR-0006 / ADR-0007) travels.

### 5. Encrypt the retained copy in RAM, not just the disk copy

The broker keeps one process-lifetime ephemeral key (`EPK`) in a locked,
no-dump page. Retained secrets are stored as AES-256-GCM ciphertext under `EPK`;
the plaintext is only materialised transiently inside `with_secret`. This
protects retained bytes against swap, core dumps, and accidental
over-read/over-copy — while being explicit that it does **not** protect
against a compromised same-privilege process (see "Honest limitations" in the
architecture doc).

### 6. Secret-to-secrets is a DAG with a most-restrictive rule

When a secret's `entry` derives from another secret, the effective policy is
the *meet* of the chain: the strictest `retention`, the union of required
`auth`, the strongest `isolation`. The chain is walked with a depth bound and a
visited set; cycles are rejected. This is the in-use analogue of the at-rest
`KeyRef` graph in `lib/src/sync_store/item.rs:48`.

### 7. Isolate the holder where the platform allows

On desktop the plaintext should live in a dedicated broker process, not the UI
process, with IPC over the existing Unix socket / bus. On mobile the OS sandbox
and TEE (Keystore/StrongBox, Secure Enclave) are the isolation boundary and a
separate process is optional. Apple/Android keychain and biometric calls stay
in the platform layer (Dart/Kotlin/Swift), consistent with ADR-0004; desktop
keychain and TPM are reached directly from Rust.

### 8. Every secret carries a user-assignable tier binding

A `TierPolicy` is a rule; a **`SecretBinding`** is which rule a given secret
uses. Every secret gets exactly one binding, and the binding is what the user
edits (website A → tier-x, website B → tier-y). Resolution is:

1. explicit per-secret assignment (user choice);
2. a default for the secret's *kind* (`vault-password`, `card-pin`,
   `ssh-agent-internal-key`, `matrix-session`, …);
3. a global fallback.

Each kind also has a **`min_tier` floor**; the effective assignment is
`max(assigned, floor)`, so a user can tighten a secret but never weaken it below
what its kind allows — a vault password cannot become `tier0-public`, a card PIN
cannot be cached at all. The binding lives inside the secret's own
**authenticated** record, with an optional cleartext hint only for prompt
selection; enforcement never trusts the hint, so metadata cannot be rewritten to
**downgrade** a secret. Changing a binding requires re-auth at the stricter of
the old and new tiers, revokes any live leases, re-seals if the sealer changed,
and writes an audit event.

Defaults for internal secrets (per the product owner): the SSH agent's internal
key is `tier2-screen`; the Matrix communication session is `tier0-public` — the
latter meaning "no user-auth gate", not "plaintext at rest", since the
orthogonal `isolation` axis still wraps it with the OS keychain.

Detailed schemas, the binding resolution, the lease protocol, platform API
matrix, module layout, migration phases and threat model live in
**`docs/secrets-architecture.md`**.

---

## Consequences

- A new `lib/src/secrets/` module (policy, binding, lease, broker, sealers)
  becomes the single place secret lifetime is decided; `CredentialCache` is
  re-expressed on top of it and later deprecated.
- Tier assignment becomes a first-class, user-editable property of every secret,
  surfaced in the UI/CLI and stored in the authenticated record. Internal
  secrets get defaults (`ssh-agent-internal-key` → `tier2-screen`,
  `matrix-session` → `tier0-public`) so the common case needs no user action.
- `lock_all` and the Dart timers shrink to "bump the epoch"; wipe semantics
  become a property of the policy, not a list of caches to clear.
- Existing wallet payloads that embed plaintext `pin` / `passphrase` fields
  keep their at-rest format, but *use* goes through tier-3 leases; a future
  payload revision can stop storing them in the clear after decryption.
- The platform matrix becomes an explicit support surface: TPM for Linux/
  Windows desktops, SEP/Keystore for Apple/Android, and no biometric path for
  the CLI (policies that require `biometric` only are simply unavailable there,
  and fall back or deny).
- Adds dependencies not currently in the tree (e.g. `libc` for memory
  hardening; `tss-esapi` or `systemd-creds` for TPM; a keychain crate). These
  are feature-gated per platform.
- More moving parts: a policy registry, epoch plumbing, and (later) an IPC
  protocol. The upside is that every future secret gets a tier by declaration
  rather than by new code.

---

## Alternatives considered

**A hardcoded `Tier0..Tier3` enum** — rejected. The tiers differ along several
independent axes (auth, TTL kind, screen-lock binding, seal strength); encoding
them as four variants forces every combination to become a code path and makes
"define a new tier" a code change. The requirement is explicitly to define new
tiers by rule.

**One global tier (or a tier per store, not per secret)** — rejected. The
requirement is explicitly per-secret: site A and site B must be able to differ.
A store-wide setting also cannot express the internal defaults (agent key at
tier 2, Matrix transport at tier 0) alongside user entries in the same store.

**Store the tier binding as unauthenticated plaintext metadata** — rejected.
It would let anyone who can write storage silently downgrade a `tier3-guard`
secret to `tier0-public` and read it without a prompt. The binding is
authenticated (inside the encrypted record) and clamped by `min_tier`.

**Keep handing out plaintext with a TTL (generalise the status quo)** —
rejected. Returning values makes revocation and epoch checks unenforceable —
once a caller holds the `String`/`Vec<u8>` it can outlive any lock. Leases plus
an operation callback are the minimum needed for "wipe on screen lock" to mean
anything.

**Put every secret in the OS keychain and be done** — rejected. The keychain
solves at-rest and some per-use auth, but not the retention/TTL/scope semantics
that define the tiers, and it is not uniformly available (headless Linux/TPM
hosts, CLI). It is one `Sealer`, not the model.

**Only encrypt at rest and rely on the OS for in-use protection** — rejected.
It leaves the in-use copy as an ordinary heap allocation; `mlock`/no-dump and
the RAM envelope are cheap and directly address swap and core-dump exposure.

**A separate secret-holding thread instead of a process** — considered. It
reduces accidental sharing but not same-process read; a process boundary is the
meaningful isolation on desktop and is deferred to phase P4 rather than baked
into the model.

**Rely on `secrecy`/`zeroize` types alone** — rejected as sufficient. They
handle drop hygiene and accidental logging, which we keep, but they do not
address swap, dumps, or lifetime policy.

---

## References

- `docs/secrets-architecture.md` — full design.
- ADR-0004 — gate-key and secret-store architecture (unlock hierarchy).
- ADR-0006 — Level 2 secret store; ADR-0007 — wallet payload layer.
- `lib/src/credential_cache.rs`, `lib/src/gate_key/mod.rs`,
  `lib/src/sync_store/item.rs`, `ui/rust/src/api/simple.rs`,
  `ui/lib/src/services/settings_service.dart`,
  `ui/lib/src/services/gate_key_service.dart`.
