# p43 — Multi-tier secret architecture

**Status:** design (companion to [ADR-0008](decisions/0008-multi-tier-secret-retention.md)).
**Scope:** how p43 decides *who may unlock* a secret, *how long* a decrypted copy
survives, *where* it is isolated, and *what it may unlock* — for every secret in
the system, on every platform.

This document is the detailed design; ADR-0008 records the decision and the
alternatives. Nothing here is implemented yet.

---

## 1. Goals and non-goals

**Goals**

- A single, data-driven model of secret lifetime: the four product tiers are
  named policies, and new tiers are new policy records.
- A minimal API that never hands out copyable plaintext: callers get *leases*
  and ask the broker to *operate* with them.
- In-use copies are encrypted in RAM, zeroized, and (where the OS permits)
  locked and excluded from dumps/fork/swap.
- Platform isolation is used where it exists: Secure Enclave / Android
  Keystore on mobile, OS keychain and TPM 2.0 on desktop.
- A secret-to-secrets relation ("this secret unlocks that one") with a
  most-restrictive rule.
- **Per-secret tier assignment**: the user picks which tier protects each
  individual secret (website A → tier-x, website B → tier-y), with safe defaults
  and a non-weakenable floor per secret kind.
- Honest, documented limits.

**Non-goals**

- Threshold / MPC / Shamir. One secret, one holder (matches `docs/vision.md`).
- Changing the at-rest format. ADR-0006/0007 stay as they are; this layer sits
  *above* decryption and is device-local.
- Protecting a secret from a malicious same-privilege process on the same
  machine by cryptography alone. See §11.
- A browser extension or autofill surface.

---

## 2. Concept model

```
SecretRef ──binding──▶ SecretBinding { tier, tighten?, assigned_by }   ← user-set, per secret
    │                          │
    │                          └──resolves──▶ TierPolicy ──selects──▶ Sealer (+ hardening)
    │
    └──entry──▶ EntryKind (inline / sync-store / gate-key / derived / card / platform)
                   │
                   └──delegates──▶ SecretRef … (DAG; effective policy = meet)

Unlock(SecretRef, auth) ─▶ Lease { scope, epoch, expires_at, uses_left, auth_method }
                                │
                    Lease ──▶ Broker.with_secret(lease, |plaintext| op)
                                │
                         LockEpoch bumped on lock ─▶ stale leases fail, blobs dropped
```

- **`SecretRef`** — a stable, non-secret identifier for a secret (e.g.
  `vault:github.com`, `wallet:0006_17684870-card-pin`, `matrix:session`).
- **`SecretBinding`** — the per-secret assignment: which tier this secret uses.
  This is the user-facing knob (see §4).
- **`TierPolicy`** — the declared rules (auth, retention, isolation, …).
- **`EntryKind`** — how the underlying secret material is obtained.
- **`Sealer`** — the platform mechanism that wraps the material.
- **`Lease`** — a time/epoch-bounded grant that permits operations.
- **`LockEpoch`** — a process-global generation counter.
- **`SecretBroker`** — the only component that ever holds plaintext.

Metadata (`SecretRef`, `SecretBinding`, `TierPolicy`, `EntryKind`) is tier 0 —
public, stored in the wallet/sync-store. The material is never in metadata.

---

## 3. Tier policy schema and per-secret bindings

```rust
// lib/src/secrets/policy.rs

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TierPolicy {
    pub name: String,
    pub auth: AuthRequirement,
    pub entry: EntryKind,
    pub retention: Retention,
    /// Hard upper bound regardless of `retention` (e.g. "screen lock OR 5 min").
    #[serde(default)]
    pub cap: Option<Duration>,
    pub isolation: Isolation,
    pub scope: Scope,
    pub surfaces: Vec<Surface>,
    #[serde(default)]
    pub on_lock: WipeAction,
    #[serde(default)]
    pub reuse: Reuse,
    /// Secret-to-secrets: other secrets this one unlocks.
    #[serde(default)]
    pub delegates: Vec<SecretRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthRequirement {
    None,
    Pin,          // card user PIN
    Passphrase,   // soft-key / wallet passphrase
    Biometric,    // Face ID / Touch ID / fingerprint
    Any(Vec<AuthRequirement>),
    All(Vec<AuthRequirement>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Retention {
    Never,                    // not cached; re-auth on every use
    SingleUse,                // valid for exactly one operation
    Absolute(Duration),       // fixed expiry from grant
    Sliding(Duration),        // expiry resets on each successful use
    UntilScreenLock,          // bounded by `cap` when present
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Scope { Request, Screen, Session, Process }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Isolation {
    pub sealer: SealerKind,
    #[serde(default)]
    pub hardening: Vec<Hardening>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum SealerKind { Soft, GateKey, OsKeychain, SecureEnclave, Tpm, Card }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Hardening { Zeroize, Mlock, NoDump, GuardPages, EphemeralEnvelope }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Surface { Cli, Ui, Agent, Sync }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Reuse { Manual, AutoApprove, PerUse }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum WipeAction { Wipe, RequireReauth, Deny }
```

### Entry kinds

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EntryKind {
    /// The secret is the payload itself (e.g. a session passphrase captured at unlock).
    Inline,
    /// Decrypt a sync-store item (ADR-0006) identified by content id.
    SyncStoreItem { cid_hex: String },
    /// Unseal a gate-key (ADR-0004) and continue with its random.
    GateKey { key_id: String },
    /// Derive from a parent secret — this is the secret-to-secrets edge.
    Derived { parent: SecretRef, info: String },
    /// Released by a card operation (PC/SC); never exported.
    Card { fingerprint: String },
    /// Held by the OS keystore under `key`.
    PlatformKeystore { key: String },
    /// TPM-sealed blob, bound to a PCR policy.
    Tpm { pcrs: Vec<u32>, blob: Vec<u8> },
}
```

### Well-known tier aliases

```rust
pub fn builtin_policies() -> Vec<TierPolicy> {
    vec![
        TierPolicy {
            name: "tier0-public".into(),
            auth: AuthRequirement::None,
            entry: EntryKind::Inline,
            retention: Retention::Never,
            cap: None,
            isolation: Isolation { sealer: SealerKind::Soft, hardening: vec![] },
            scope: Scope::Request,
            surfaces: vec![Surface::Cli, Surface::Ui, Surface::Agent, Surface::Sync],
            on_lock: WipeAction::Wipe,
            reuse: Reuse::PerUse,
            delegates: vec![],
        },
        TierPolicy {
            name: "tier1-session".into(),
            auth: AuthRequirement::Any(vec![
                AuthRequirement::Pin,
                AuthRequirement::Passphrase,
                AuthRequirement::Biometric,
            ]),
            entry: EntryKind::Inline,
            retention: Retention::Sliding(Duration::from_secs(15 * 60)),
            cap: None,
            isolation: Isolation {
                sealer: SealerKind::GateKey,
                hardening: vec![
                    Hardening::Zeroize,
                    Hardening::Mlock,
                    Hardening::NoDump,
                    Hardening::EphemeralEnvelope,
                ],
            },
            scope: Scope::Session,
            surfaces: vec![Surface::Cli, Surface::Ui, Surface::Agent],
            on_lock: WipeAction::Wipe,
            reuse: Reuse::Manual,
            delegates: vec![],
        },
        TierPolicy {
            name: "tier2-screen".into(),
            auth: AuthRequirement::Any(vec![
                AuthRequirement::Pin,
                AuthRequirement::Passphrase,
                AuthRequirement::Biometric,
            ]),
            entry: EntryKind::Inline,
            retention: Retention::UntilScreenLock,
            cap: Some(Duration::from_secs(5 * 60)),
            isolation: Isolation {
                sealer: SealerKind::Soft,
                hardening: vec![
                    Hardening::Zeroize,
                    Hardening::Mlock,
                    Hardening::NoDump,
                    Hardening::EphemeralEnvelope,
                ],
            },
            scope: Scope::Screen,
            surfaces: vec![Surface::Ui, Surface::Agent],
            on_lock: WipeAction::Wipe,
            reuse: Reuse::AutoApprove,
            delegates: vec![],
        },
        TierPolicy {
            name: "tier3-guard".into(),
            auth: AuthRequirement::Any(vec![
                AuthRequirement::Pin,
                AuthRequirement::Passphrase,
                AuthRequirement::Biometric,
            ]),
            entry: EntryKind::Inline,
            retention: Retention::SingleUse,
            cap: None,
            isolation: Isolation {
                sealer: SealerKind::Soft,
                hardening: vec![Hardening::Zeroize, Hardening::EphemeralEnvelope],
            },
            scope: Scope::Request,
            surfaces: vec![Surface::Cli, Surface::Ui, Surface::Agent],
            on_lock: WipeAction::Wipe,
            reuse: Reuse::PerUse,
            delegates: vec![],
        },
    ]
}
```

A user- or feature-defined tier is a new record with, e.g.,
`sealer: SealerKind::Tpm`, `retention: Retention::Absolute(60s)`,
`hardening: [Zeroize, EphemeralEnvelope]`. The registry is data; the broker
only ever looks policies up by name.

Example serialised policy (what an operator/config would write):

```jsonc
{
  "name": "tier2-screen",
  "auth": { "any": ["pin", "passphrase", "biometric"] },
  "entry": { "gate_key": { "key_id": "gate-9c12ef" } },
  "retention": "until_screen_lock",
  "cap_secs": 300,
  "isolation": {
    "sealer": "tpm",
    "hardening": ["zeroize", "mlock", "no_dump", "ephemeral_envelope"]
  },
  "scope": "screen",
  "surfaces": ["ui", "agent"],
  "on_lock": "wipe",
  "reuse": "auto_approve",
  "delegates": ["wallet:0006_17684870-card-pin"]
}
```

### Per-secret tier assignment (the binding)

A `TierPolicy` is a *rule*; a **binding** says which rule a given secret uses.
Every `SecretRef` has exactly one binding, and that binding is what the user
edits. This is the mechanism behind "the password for website A is protected by
tier-x and the password for website B by tier-y".

```rust
// lib/src/secrets/binding.rs

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretBinding {
    pub secret: SecretRef,
    /// The tier this secret is assigned to. This is the user-facing choice.
    pub tier: String,
    /// Optional per-secret tightening (never loosening) of the assigned tier.
    #[serde(default)]
    pub tighten: Option<PolicyOverlay>,
    /// Who set it (device id / label) and when — for audit and sync attribution.
    #[serde(default)]
    pub assigned_by: Option<String>,
    #[serde(default)]
    pub assigned_at: Option<i64>,
}
```

**Where it lives and why.** The authoritative binding is stored *inside the
secret's own authenticated record* — for a vault entry it is a field of the
encrypted item; for internal secrets it is in the wallet's authenticated item
(ADR-0006/0007). It is metadata but it must be tamper-evident: if the binding
were unauthenticated, an attacker who can write storage could silently
**downgrade** `tier3-guard` → `tier0-public` and read the secret without a
prompt. For prompt selection *before* decryption, a cleartext `tier_hint` may
be duplicated in index metadata, but enforcement never trusts it; if the hint
contradicts the authenticated binding the broker fails closed and uses the
stricter of the two.

**Resolution order** (most specific wins):

1. explicit `SecretBinding.tier` — the user's per-secret choice;
2. the secret *kind*'s default tier (see the table below);
3. the global fallback, `tier1-session`.

**Floors — clamp, never weaken.** Each secret *kind* declares a `min_tier`, and
each surface may add its own. The effective assignment is
`max(assigned, min_tier(kind), min_tier(surface))`. The user may always
*tighten* a secret but never drop it below its floor. A vault password therefore
cannot be assigned `tier0-public`, and a card PIN cannot be cached at all.

| Secret kind | Default tier | `min_tier` | Notes |
|---|---|---|---|
| `vault-password` | `tier3-guard` | `tier1-session` | per-entry, user-chosen |
| `vault-totp-seed` | `tier3-guard` | `tier1-session` | |
| `card-pin` | `tier3-guard` | `tier3-guard` | single-use, never retained |
| `soft-key-passphrase` | `tier3-guard` | `tier1-session` | |
| `ssh-agent-internal-key` | `tier2-screen` | `tier1-session` | the agent's own identity key |
| `signing-key-cache` | `tier2-screen` | `tier2-screen` | |
| `authority-session-key` | `tier2-screen` | `tier2-screen` | |
| `gate-key-random` | `tier1-session` | `tier1-session` | |
| `matrix-session` (transport) | `tier0-public` | `tier0-public` | no user gate |
| `public-key` / card AID / labels | `tier0-public` | `tier0-public` | not secret |

**Tier ≠ at-rest protection.** `tier0-public` means "no user-auth gate to
*use*", not "stored in the clear". The `isolation` axis is orthogonal: the
Matrix session can be `tier0-public` (the background listener must read it
without a prompt) while still being wrapped by the OS keychain at rest. This is
why the model keeps `auth` and `isolation` separate.

**How the user assigns it**

- **UI:** the create/edit form for any secret (a vault entry, a key, a device
  identity) shows a tier selector seeded from the kind default. It lists only
  tiers whose `auth` the current device and surface can satisfy (a desktop with
  no biometrics does not offer a `biometric`-only tier). A "default tier for new
  entries" lives in settings, with optional group/category defaults (e.g. all
  `banking` entries → `tier3-guard`).
- **CLI:** `p43 secret assign <ref> --tier tier2-screen`, and the vault commands
  gain `--tier` on create/edit.
- **Sync:** the binding travels with the encrypted record, so an assignment made
  on the phone applies on the desktop. Because it is device-portable metadata, a
  binding that names a sealer unavailable on the other device is resolved by
  capability negotiation at unlock (§4), not by rewriting the assignment.

**Reassignment semantics**

1. **Prove ownership at the stricter end.** Re-authenticate at
   `max(current_tier.auth, new_tier.auth)`, so a `tier3-guard` secret cannot be
   loosened to `tier0-public` without first proving the tier-3 credential.
2. **Revoke leases** for that secret and drop any retained blob.
3. **Re-seal if the sealer changed** (e.g. moving the at-rest wrapping key
   to/from TPM).
4. **Audit:** append an event `{ref, old_tier, new_tier, assigned_by, ts}` to the
   same append-only journal used for sign requests (see `docs/roadmap.md`);
   assignment changes are security-relevant facts.

---

## 4. Effective-policy algebra (the "rules")

A secret's declared policy is only a base. The broker computes the *effective*
policy by combining it with:

1. the secret's **binding** — which tier is assigned, and its `min_tier` floor
   (§3);
2. the secret's **delegation chain** (`entry` derived from a parent, and
   `delegates`); and
3. the **surface** and **host capability**.

**Meet (most-restrictive) rules**

- `retention`: `SingleUse` and `Never` dominate (no retention). Among caching
  policies the earliest effective expiry wins; `UntilScreenLock` is treated as
  a deadline as well as an epoch bind, so the earlier of (screen lock, cap,
  declared TTL) applies.
- `auth`: the effective requirement is the `All` of the chain — a derived
  secret requires everything its parents require, plus its own.
- `isolation`: the strongest sealer/hardening in the chain wins; if a parent
  cannot be sealed by a hardware sealer, the child cannot claim one either
  while it is retained.
- `surfaces`: intersection.
- `on_lock`: `Deny` > `RequireReauth` > `Wipe` when combining.

**Cycle handling:** walk `entry.parent` and `delegates` with a visited set and a
fixed depth bound (e.g. 16). A cycle or a depth overrun is a hard error, not a
fallback.

**Capability negotiation:** at unlock time the broker intersects the effective
`isolation.sealer` with what the host supports. A policy that demands `tpm` on
a machine with no TPM does not silently downgrade — it fails unless the policy
declares a fallback sealer list (`SealerKind` becomes an ordered preference
list in a follow-up revision). Which sealer was actually used is recorded on
the lease, because in-use sealing is device-local and not synced.

---

## 5. Lease protocol

```rust
// lib/src/secrets/lease.rs

pub struct LockEpoch(pub u64);

pub struct Lease {
    pub id: LeaseId,
    pub secret: SecretRef,
    pub scope: Scope,
    pub epoch: LockEpoch,
    pub granted_at: Instant,
    pub expires_at: Option<Instant>,
    pub uses_left: Option<u32>,
    pub auth: AuthMethod,
    pub sealer: SealerKind,
}
```

```rust
// lib/src/secrets/mod.rs
pub trait SecretBroker {
    fn policy(&self, secret: &SecretRef) -> Result<TierPolicy>;
    fn effective_policy(&self, secret: &SecretRef) -> Result<TierPolicy>;

    /// Prompt / verify per the policy, then grant a lease.
    fn unlock(&self, secret: &SecretRef, auth: AuthInput) -> Result<Lease>;

    /// Materialise inside the broker for the duration of `f`; wipe after.
    fn with_secret<R>(
        &self,
        lease: &Lease,
        f: impl FnOnce(&[u8]) -> Result<R>,
    ) -> Result<R>;

    fn renew(&self, lease: &Lease) -> Result<Lease>;   // sliding TTL
    fn revoke(&self, lease: &Lease);

    /// Bump the epoch and drop every stale sealed blob.
    fn lock(&self);
    fn epoch(&self) -> LockEpoch;
}
```

Semantics:

- `unlock` verifies `auth` against `AuthRequirement` and only then seals/wraps
  the material. The result is a `Lease`; **no method returns plaintext**.
- `with_secret` checks `epoch == current`, expiry, and `uses_left`; it decrypts
  the retained blob under the process `EPK`, invokes `f`, then wipes. For
  `SingleUse` it drops the blob unconditionally afterwards.
- `renew` is only valid for `Sliding` and when the epoch still matches.
- `lock` bumps the epoch; every lease with a lower epoch is invalid, and all
  sealed blobs are dropped. This is what `lock_all`
  (`ui/rust/src/api/simple.rs:2272`) and the Dart screen-lock handler
  (`ui/lib/main.dart:337`, `settings_service.dart:247`) become.

The epoch is the answer to the current race: a timer firing and a screen-lock
event can no longer "miss" a lease — the lease simply carries the old epoch and
fails.

---

## 6. In-RAM protection

**Retained bytes are ciphertext.** The broker creates one process-lifetime
`EPK` (32 random bytes) at startup. Every retained secret is stored as
AES-256-GCM ciphertext under a per-secret HKDF of `EPK`. Plaintext exists only
inside `with_secret` for the duration of the operation:

```
unlock → derive per-secret key from EPK → AES-GCM(secret) → kept in lease table
use    → AES-GCM⁻¹ into Zeroizing<Vec<u8>> → f(&plaintext) → zeroize
lock   → drop all ciphertext; (optionally) rotate EPK
```

**Hardening primitives** (feature-gated, best-effort, per platform):

| Primitive | What it defends | API |
|---|---|---|
| `Zeroize` on drop | accidental copies left in freed heap | `zeroize::Zeroizing`, `secrecy::SecretBox` (both already in the tree) |
| `mlock` / `VirtualLock` | swap / hibernation | `libc::mlock`, `windows::VirtualLock` |
| no-dump | core dumps | Linux `madvise(MADV_DONTDUMP)` + `prctl(PR_SET_DUMPABLE,0)`; macOS `setrlimit(RLIMIT_CORE,0)` + hardened runtime; Windows `SetErrorMode` |
| wipe-on-fork | child processes inheriting pages | Linux `madvise(MADV_WIPEONFORK)` |
| guard pages | over-read / overflow into adjacent heap | `mmap(PROT_NONE)` bracketing a dedicated region |
| no plaintext API | secrets outliving their policy through copies | leases + `with_secret` (design, not a syscall) |

`EPK` itself lives in a dedicated locked, no-dump region for the lifetime of
the broker. On mobile where `mlock` is unavailable, isolation comes from the OS
sandbox plus the keystore/TEE instead (see §8).

---

## 7. Platform sealers and auth

Each `SealerKind` maps to concrete platform facilities. `Soft` and `GateKey`
already exist in the tree; the rest are proposed and feature-gated.

| Sealer | macOS | iOS | Android | Linux | Windows |
|---|---|---|---|---|---|
| `Soft` | heap + mlock/no-dump | heap (no mlock) | heap (TEE for keys) | heap + mlock/no-dump/memfd-seal | heap + `VirtualLock`/`CryptProtectMemory` |
| `GateKey` | Argon2id + AES-GCM `.sealed` (exists) | same | same | same | same |
| `OsKeychain` | Keychain (`security-framework`) | Keychain | Keystore / EncryptedSharedPreferences | Secret Service (`libsecret`) | DPAPI / Credential Manager |
| `SecureEnclave` | SEP P-256 key (`kSecAttrTokenIDSecureEnclave`) | SEP | Keystore `setIsStrongBoxBacked` where available | — | — |
| `Tpm` | — (no TPM; SEP instead) | — | — | TPM 2.0 via `tss-esapi` / `systemd-creds` | TPM via `NCrypt` Platform Crypto Provider |
| `Card` | YubiKey PC/SC (exists) | constrained | NFC/USB-OTG (future) | PC/SC (exists) | PC/SC (exists) |

**Biometric gate.** `LocalAuthentication` (Apple), `BiometricPrompt` with a
`CryptoObject` (Android), `fprintd`/polkit (Linux, optional), Windows Hello.
On Apple and Android the keychain/keystore entry can be created with an
access-control flag so the *OS* requires a successful biometric/passcode before
releasing the key — the check is not merely a Rust-side branch.

**Where the code lives.** ADR-0004 already rules that biometric integration is
a platform (Dart/Kotlin/Swift) concern. So on Apple/Android the
`OsKeychain`/`SecureEnclave` sealers are implemented in the platform layer and
reached through the flutter_rust_bridge surface; the Rust broker talks to them
through a `PlatformSealer` callback. Desktop OS keychain (`security-framework`,
`libsecret`, `windows`) and TPM (`tss-esapi`) are reached directly from Rust.

**TPM specifics.** A TPM seals a small blob to a PCR policy (`TPM2_Create` /
`TPM2_Unseal`), typically Secure Boot state (PCR 7) or a custom-measured
policy. This is the right primitive for the headless Proxmox/SSH host in
`docs/roadmap.md`, which has no biometric and often no user session. Caveats:
PCR changes (firmware, Secure Boot, UKI updates) can make a sealed secret
un-unsealable, so a TPM-sealed tier always needs a documented recovery path
(re-seal from a gate-key/passphrase tier).

---

## 8. Isolation (process and OS boundaries)

- **Desktop (macOS/Linux/Windows):** the plaintext should live in a dedicated
  broker process, not the UI. The in-process SSH agent / Matrix daemon socket is
  the natural transport; extend it with a small request/response protocol
  (unlock → lease id; op(lease id, input) → output; lock). The UI never receives
  tier-2/tier-3 plaintext. This is deferred to phase P4 but the trait boundary
  (`SecretBroker`) is designed so the in-process implementation can be swapped
  for an IPC client without changing callers.
- **macOS:** optionally an XPC service with a restricted entitlement; code
  signing + hardened runtime so `task_for_pid` requires authorisation.
- **Linux:** a `systemd --user` service with `MemoryDenyWriteExecute`,
  `ProtectSystem`, `LimitMEMLOCK`, `SystemCallFilter`, and the socket under the
  store root. TPM sealing lives here.
- **Android:** an isolated `:secret` process in addition to the sandbox; secrets
  bound to Keystore with `setUserAuthenticationRequired(true)` and
  `setUnlockedDeviceRequired(true)`.
- **iOS:** app sandbox + SEP; separate processes are constrained, so rely on the
  keystore and per-use access control.

---

## 9. Secret-to-secrets

The relation already exists at rest: `KeyRef` in `lib/src/sync_store/item.rs:48`
(`direct`, `indirect_l2`, `indirect_card`, `chain_share`). The tiers layer adds
the in-use edge: `EntryKind::Derived { parent }` and `TierPolicy.delegates`.

Examples:

- `tier3-card-pin` (single-use) is required to release a `tier2-screen`
  vault key via `indirect_card` — using the vault key therefore requires the
  PIN, and the PIN is never retained.
- A `tier3-guard` "yubikey unlock" secret (e.g. an HMAC secret or soft-key
  passphrase, from `key-material`) delegates to the card; the card's key slot is
  the thing actually unlocked, per the product description of tier 3.

The meet rule (§4) means a child can only ever be *more* restricted than its
parents, and the resolution is bounded and cycle-checked.

---

## 10. Mapping today's code to tiers

| Today | Location | Becomes |
|---|---|---|
| `CredentialCache` (plaintext `String`, one global sliding TTL) | `lib/src/credential_cache.rs` | `tier1-session` (sliding 15 m) on the broker; no `String` clones |
| `SIGNING_KEY_CACHE` (Ed25519) / RSA cache | `ui/rust/src/api/simple.rs:255`, `:2171` | `tier2-screen` (until screen lock, cap 5 m), opt-in `reuse: auto_approve` |
| `AUTHORITY_SESSION` | `ui/rust/src/api/simple.rs:183` | `tier2-screen`, `scope: session` |
| gate-key random while unlocked | `lib/src/gate_key/mod.rs:40` | entry `GateKey`; held as a lease under `tier1-session` |
| `YubikeyRef.pin` | `lib/src/wallet/entry.rs:109` | `tier3-guard` (single-use) lease; not returned to callers |
| `FilePgpKey.passphrase` | `lib/src/wallet/entry.rs:138` | `tier3-guard` (single-use) |
| card PIN per call | `lib/src/pkcs11/card.rs:228` (`SecretString`) | route through `tier3-guard`; keep `secrecy` |
| `lock_all` / Dart cache timer | `ui/rust/src/api/simple.rs:2272`, `ui/lib/main.dart:337` | `broker.lock()` → epoch bump |
| `autoApproveWhenCached` | `ui/lib/src/services/settings_service.dart:31` | `Reuse::AutoApprove` on the policy + lease presence |
| at-rest `.sealed` / sync-store items | `lib/src/gate_key/`, `lib/src/sync_store/` | unchanged; the `Sealer`/`EntryKind` front-ends for them |

### Worked example — per-secret assignment

Four secrets, four different assignments, one model:

| Secret | Assigned tier | What the user experiences |
|---|---|---|
| `vault:github.com` password | `tier1-session` | one unlock; reused for 15 min of autofill, then re-prompt |
| `vault:bank.example` password | `tier3-guard` | re-prompt on every retrieve; single-use, never retained |
| `ssh-agent-internal-key` | `tier2-screen` (default) | unlocked once per session; wiped on screen lock / app background |
| `matrix-session` | `tier0-public` (default) | never prompts; still OS-keychain-wrapped at rest |

The registry stores the rules; the bindings store the choices; the broker enforces
`effective = meet(binding, floor, delegation, surface)` at unlock time. Adding a
fifth secret (or a new *kind* of secret) needs no new code — only a binding and,
if it is a new kind, a default/min_tier row.

---

## 11. Threat model and honest limitations

**What this defends against**

- Accidental exposure: swap, hibernation, core dumps, fork, over-copy, logging
  (`zeroize` + `mlock` + no-dump + no plaintext-returning API).
- Unauthorised *use* after a lock, including the timer-vs-event race (epochs).
- Secrets retained beyond their intended window, and children outliving parents
  (meet rule).
- Silent **tier downgrade**: because the binding lives inside the authenticated
  record and is clamped by `min_tier`, rewriting metadata cannot turn a
  `tier3-guard` secret into a `tier0-public` one; the mismatch fails closed.
- Physical theft of a locked device, where the OS keystore / SE / TPM keeps the
  material unusable without the user's auth.

**What it does not defend against**

- A compromised process running as the same user and able to read its memory
  (`ptrace`, debugging, malicious same-uid code). `mlock`/no-dump raise the bar
  but do not defeat this; only the process boundary (§8) plus OS hardening does,
  and only partially.
- Plaintext during an operation: `with_secret` necessarily exposes the bytes to
  the closure for the duration of the op.
- A malicious platform keystore / compromised TEE / rooted phone.
- "Encrypted in RAM" is not a hardware guarantee: the `EPK` must exist in the
  running process to decrypt retained blobs, so a full memory capture of the
  broker can recover them. Hardware sealers protect the *at-rest* wrapping key
  and the *release* decision, not arbitrary in-process crypto.
- TPM availability/durability: PCR changes can brick a sealed secret without a
  recovery path.

These limits are the reason `on_lock` and `surfaces` are first-class: the
architecture makes the intent explicit rather than implying a strength it does
not have.

---

## 12. Proposed module layout and phasing

```
lib/src/secrets/
  mod.rs         ← SecretBroker trait, SecretRef, LockEpoch, in-process Broker
  policy.rs      ← TierPolicy, AuthRequirement, Retention, Isolation, registry
  binding.rs     ← SecretBinding, resolution order, min_tier floors, reassignment
  lease.rs       ← Lease, LeaseTable, epoch/expiry/single-use checks
  epk.rs         ← process ephemeral key + AES-GCM envelope + zeroize
  memlock.rs     ← feature-gated mlock/madvise/prctl/VirtualLock helpers
  seal/
    mod.rs       ← Sealer trait, SealerKind dispatch, capability negotiation
    soft.rs      ← in-process sealer (zeroize + optional lock/no-dump)
    gate_key.rs  ← wraps lib/src/gate_key
    os_keychain.rs  ← desktop keychain (security-framework/libsecret/windows)
    enclave.rs      ← Secure Enclave (via platform bridge)
    tpm.rs          ← TPM 2.0 (tss-esapi / systemd-creds)
    platform.rs     ← bridge to Dart/Kotlin/Swift sealers on mobile
```

Phases (each independently shippable):

- **P0 — model.** `policy.rs` + `binding.rs` + `lease.rs` + `epk.rs` + an
  in-process broker; seed the per-kind defaults/min_tier table and bind the
  existing internal secrets (`ssh-agent-internal-key` → `tier2-screen`,
  `matrix-session` → `tier0-public`, …); re-express `CredentialCache` on top
  with identical observable behaviour (sliding 15 m, keyed by fingerprint /
  card AID) plus zeroize/mlock.
- **P1 — epochs.** Wire `lock_all` and the Dart screen-lock/app-background
  handlers to `broker.lock()`; add `tier2-screen` for the signing-key and
  authority caches.
- **P2 — sealers.** `gate_key` (exists) → `soft` hardening → desktop
  `os_keychain` → `tpm`; record the sealer used per lease.
- **P3 — tiers for wallet material.** Move `card-pin` and `passphrase` uses to
  `tier3-guard` single-use leases; add the `delegates` edges used by
  `IndirectCard` flows.
- **P4 — out-of-process broker.** Extract the broker into the daemon; IPC over
  the existing socket; UI/CLI become clients. Mobile stays in-process against
  Keystore/SE.
- **P5 — surfaces, reuse, and user assignment.** Enforce `surfaces`, implement
  `Reuse::AutoApprove` in terms of active leases, and expose per-secret tier
  assignment in the UI (tier selector on each entry) and CLI
  (`p43 secret assign <ref> --tier …`), including the reassignment/audit path.

---

## 13. Open questions

- Bindings assign a *tier*; do we also want per-secret `PolicyOverlay`
  (the `tighten` field) exposed to users, or keep overrides to a small fixed set
  (e.g. "never cache" / "single-use")? (Current design: tier + optional
  tightening, effective policy computed.)
- Group/category defaults (all `banking` → `tier3-guard`) are convenient but a
  policy leak risk if a secret moves category; decide whether assignment is
  always per-secret at rest, with groups only as a bulk-edit helper.
- Where does the per-secret assignment UI live for non-vault secrets (keys,
  device identities) without crowding the existing Keys/Devices screens?
- Should `surfaces` be enforced in Rust or also reflected in the platform layer
  (the CLI genuinely cannot prompt for biometrics, so it should not even try)?
- Is a separate desktop broker process justified for this threat model, or is
  in-process with hardening sufficient for v1? (Phased as P4 so it can be
  deferred.)
- TPM PCR policy choice for the Proxmox target, and the recovery UX when the
  measured state changes.
