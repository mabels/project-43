# project-43 — Decisions, Gotchas & Known Issues

## Architecture decisions

### Why `CardQueue` lives in `lib`, not `cli`
The queue serialises hardware-card ops. Any future UI (desktop app, daemon, etc.) will need the same serialisation, so it belongs in the library. Path: `lib/src/pkcs11/card_queue.rs`, exported as `p43::pkcs11::card_queue::CardQueue`.

### Why the SSH agent uses the **auth** slot, not the signing slot
The OpenPGP card spec defines INTERNAL AUTHENTICATE for SSH authentication. The signing slot (PSO:CDS) is for document signing (e.g. `git commit -S`). Using the signing slot for SSH is incorrect and was the original mistake. The correct flow:
```
tx.verify_user_pin(pin) → tx.to_user_card(None) → user_card.authenticator(&touch_fn) → auth.sign(...)
```

### RSA key support on the auth slot
The user's YubiKey has an RSA 4096 auth key. RSA requires pre-hashing on the host (the card only executes PKCS#1 v1.5 signing, not hashing). SSH clients signal hash choice via `SignRequest.flags`:
- `flags & 0x04 != 0` → SHA-512 (`rsa-sha2-512`)
- otherwise → SHA-256 (`rsa-sha2-256`)

Ed25519 does PureEdDSA — pass raw data, the card hashes internally.

### Default socket path
The SSH agent socket is placed beside the key store's parent directory, not inside `keys/`. So with the default store `~/.config/project-43/keys/`, the socket is `~/.config/project-43/p43-ssh-agent.sock`. Override with `--socket`.

### Matrix session persistence
`MatrixSession` from matrix-sdk 0.16 implements `Serialize`/`Deserialize` with `#[serde(flatten)]` so the JSON is a flat object:
```json
{"user_id":"@user:matrix.org","device_id":"ABCDEF","access_token":"...","refresh_token":null}
```
Stored at `~/.config/project-43/matrix-session.json`. Created on first `p43 matrix login`, reused by `send` and `listen` automatically.

---

## Known compiler / dependency issues

### matrix-sdk 0.16.0 + Rust ≥ 1.92: recursion limit overflow
`matrix_sdk::Client::sync()` has a deeply-nested async state machine. Type-system query analysis overflows the default recursion limit of 128, producing:

```
error: queries overflow the depth limit!
  = help: consider increasing the recursion limit by adding a
    `#![recursion_limit = "256"]` attribute to your crate (`matrix_sdk`)
  = note: query depth increased by 130 when computing layout of
    `{async fn body of client::<impl ...>::sync()}`
```

This reproduces on rustc 1.92, 1.93, and 1.94 with our minimal
`default-features = false, features = ["rustls-tls"]` feature set — so
downgrading the toolchain is not a workaround for us. The depth-overshoot
is a constant (130) tied to the way `#[tracing::instrument]` attributes
interact with async state-machine layout; raising the crate's own
`recursion_limit` is what actually makes the build pass.

Upstream considers this a rustc regression, cross-referenced to
[rust-lang/rust#152942](https://github.com/rust-lang/rust/issues/152942).
Tracking issue:
[matrix-org/matrix-rust-sdk#6254](https://github.com/matrix-org/matrix-rust-sdk/issues/6254).
Upstream is working on gating the `#[tracing::instrument]` attributes
behind a cargo feature, which should let us drop the patch in a future
matrix-sdk release.

**Fix**: vendor a copy of matrix-sdk and add the attribute.

```toml
# workspace Cargo.toml
[patch.crates-io]
matrix-sdk = { path = "vendor/matrix-sdk" }
```

```rust
// vendor/matrix-sdk/src/lib.rs  (line added after existing #![...] attributes)
#![recursion_limit = "256"]
```

The vendored copy is at `vendor/matrix-sdk/` and is a verbatim copy of the 0.16.0 crate registry source with only this one-line change. See [ADR-0003](decisions/0003-vendored-matrix-sdk.md) for the full rationale (including alternatives considered and rejected — notably a toolchain pin, which was tried empirically and does not work for our feature set). Remove the patch when upstream releases a fix.

---

## Common compile errors and fixes

### `use openpgp::crypto::Signer as _` is required
`CardSigner` (from `openpgp_card_sequoia`) implements the `openpgp::crypto::Signer` trait. Calling `.sign()` or `.public()` on it fails with "method not found" unless the trait is imported. The `as _` form brings it into scope without polluting the namespace.

### `restore_session` takes two arguments
In matrix-sdk 0.16.0, `MatrixAuth::restore_session` has signature:
```rust
pub async fn restore_session(&self, session: MatrixSession, room_load_settings: RoomLoadSettings) -> Result<()>
```
Always pass `RoomLoadSettings::default()` as the second argument.

### `MatrixSession` import path
`matrix_sdk::matrix_auth` does not exist. Use:
```rust
use matrix_sdk::authentication::matrix::MatrixSession;
```

### `Mpint::from_bytes` vs `from_positive_bytes`
`from_bytes` expects SSH wire format (with leading 0x00 when MSB is set). OpenPGP MPI values from `.value()` are raw big-endian positive integers without the SSH length/sign byte. Always use `Mpint::from_positive_bytes(mpi.value())`.

### `anyhow::Error` does not implement `std::error::Error`
`AgentError::other()` requires `impl Error`. Convert with:
```rust
.map_err(|e| AgentError::other(std::io::Error::other(e.to_string())))
```

### Type annotation needed in `anyhow::bail!` expressions
In test contexts without an explicit return type, `bail!` needs a hint:
```rust
|| anyhow::bail!("msg") as anyhow::Result<()>
```

---

## What is NOT yet implemented

- **E2EE on Matrix**: the `listen` and `send` commands work on unencrypted rooms only. The `matrix-sdk` crate supports E2EE via the `e2e-encryption` feature (not enabled). Adding it requires device verification and key storage.
- **RSA software keys for SSH agent**: `load_ssh_key` currently only handles Ed25519 from `.sec.asc` files. The code bails with an explicit error for other algorithms.
- **Multiple cards**: `CardQueue` supports `concurrency > 1` but `open_first_card()` always opens the first PC/SC reader. Multi-card support needs reader enumeration.
- **Matrix room aliases**: `RoomId::parse` only accepts canonical room IDs (`!id:server`), not aliases (`#room:server`). Alias resolution requires a `client.resolve_room_alias()` call before parsing.

---

## Environment variables
| Variable | Used by | Purpose |
|----------|---------|---------|
| `YK_PIN` | `ssh-agent --card`, `pgp` | YubiKey user PIN |
| `YK_KEY_FILE` | `ssh-agent`, `pgp` | Path to software key `.sec.asc` |
| `YK_PASSPHRASE` | `ssh-agent`, `pgp` | Passphrase for software key |

If `YK_PIN` is not set and `--pin` is not passed, the SSH agent prompts interactively via `rpassword::prompt_password`.
