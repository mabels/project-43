# CLAUDE.md — project-43 orientation for Claude agents

This file is auto-loaded by Claude Code / Cowork when working in this repo.
Read it first, then follow the pointers into `docs/` for detail.

## What this project is

`project-43` (binary: `p43`) is the early Rust scaffolding for a longer-term
vision: a **distributed single-key password manager** where a mobile device
holds the root key and acts as a remote pinentry for a stateless desktop
agent, coordinated over Matrix.

What is **implemented today** is the foundation layer only:
OpenPGP key management (soft keys + YubiKey/OpenPGP card via PC/SC), a PGP
operations CLI, an SSH agent that signs via the card's auth slot, and a thin
Matrix client with `login` / `send` / `listen` (no E2EE yet, no sign-request
protocol yet).

See `docs/vision.md` for the gap between the product vision and the current
codebase, and `docs/roadmap.md` for the ordered work list.

## Where to find things

| If you need…                       | Read                              |
|------------------------------------|-----------------------------------|
| Workspace layout & module map      | `docs/project-overview.md`        |
| Exact API shapes of key crates     | `docs/api-surface.md`             |
| Why decisions were made + errors   | `docs/decisions-and-gotchas.md`   |
| Product vision & what's missing    | `docs/vision.md`                  |
| Structured open threads            | `docs/roadmap.md`                 |
| Individual architecture decisions  | `docs/decisions/`                 |
| Usage examples & env vars          | `README.md`                       |

Before editing a crate API call, check `docs/api-surface.md` — the exact
shapes for `matrix-sdk` 0.16, `openpgp-card-sequoia` 0.2, `ssh-key` 0.6
and `ssh-agent-lib` 0.5 are recorded there. They are not obvious from
the crate docs.

## Build & test

```bash
cargo build --release          # release binary at target/release/p43
cargo test                     # software-key integration tests, no hardware
cargo fmt --all -- --check
cargo clippy -- -D warnings

# YubiKey end-to-end (requires card + gpg-agent killed beforehand)
./cli/tests/test-sign-verify.sh
./cli/tests/test-crypt-decrypt.sh
./cli/tests/test-sign-crypt.sh
```

macOS needs `nettle` via Homebrew (already pointed at by
`.cargo/config.toml`). Ubuntu CI needs `nettle-dev` (not `libnettle-dev`),
`clang`, `pkg-config`, `libpcsclite-dev`.

## Non-obvious things that will bite you

**Vendored matrix-sdk.** `vendor/matrix-sdk/` is a verbatim copy of
matrix-sdk 0.16.0 with `#![recursion_limit = "256"]` added to work around
a type-layout query-depth overflow in `Client::sync()` that breaks the
build on rustc ≥ 1.92 (confirmed: 1.92, 1.93 and 1.94 all hit the same
"query depth increased by 130" error with our minimal
`default-features = false, features = ["rustls-tls"]` feature set — so
a toolchain pin is not a viable alternative for us). Wired via
`[patch.crates-io]` in the workspace `Cargo.toml`. Tracking issue:
[matrix-org/matrix-rust-sdk#6254](https://github.com/matrix-org/matrix-rust-sdk/issues/6254).
Full rationale in `docs/decisions/0003-vendored-matrix-sdk.md`. Remove
only after an upstream release fixes this (the `instrument`
feature-gate workaround under discussion on #6254).

**`gpg-agent` holds exclusive PC/SC access.** Any `p43 pgp` or `p43 ssh-agent`
operation that touches the YubiKey will fail with a resource-busy error
if `gpg-agent` is running. The shell tests kill it and restart it around
every card op — follow that pattern.

**SSH uses the auth slot, not the signing slot.** The signing slot stays
untouched for `git commit -S` and similar. See
`docs/decisions-and-gotchas.md#why-the-ssh-agent-uses-the-auth-slot-not-the-signing-slot`.

**Secrets never go on the command line.** PIN / passphrase resolution
priority is: explicit flag → env var → interactive `rpassword` prompt.
Do not add shell-history-visible ways to pass secrets.

## Conventions

**Lib vs CLI layering.** Everything non-trivial lives in the `lib` crate.
`cli/` is only clap wrappers and stdin/stdout plumbing. If a future GUI
or daemon would need the code, it belongs in `lib`. This was enforced
during scaffolding — `CardQueue` and the Matrix client were explicitly
moved or placed in `lib` for this reason.

**Runtime files live under the store root.** Default is
`~/.config/project-43/`. The SSH agent socket, Matrix session JSON, and
`keys/` directory are all co-located there. `--store PATH` moves the whole
set; do not hard-code separate paths for sibling artifacts.

**Each CLI subcommand group is its own module.** `cli/src/<group>/mod.rs`
(dispatch) + `subcmd.rs` (clap args). Current groups: `key_mgmt`, `pgp`,
`ssh_agent_cmd`, `matrix_cmd`.

**Env vars.** `YK_PIN` (card PIN), `YK_PASSPHRASE` (soft-key passphrase),
`YK_KEY_FILE` (soft-key path). These names are load-bearing across
`p43 pgp` and `p43 ssh-agent`.

**Tests.** Rust integration tests use `VirtualCard` so CI never needs
hardware. YubiKey-touching behaviour is validated via shell scripts that
cross-check `p43` output against `gpg` — verify both directions.

## Working with the user

The user (meno) prefers:

- **Ask before committing.** Never run `git add`, `git commit`, `git push`,
  or anything that modifies repo state without explicit confirmation.
  Show the diff first, ask "should I commit these?", wait for yes.
- **Use `mcp-shell` for builds.** The workspace bash sandbox can't
  compile nettle-dependent crates. When you need `cargo build` / `cargo test`
  to actually run, use the `mcp-shell` tool, not the in-process bash.
- **Respect layering.** If you catch yourself putting reusable logic in
  `cli/`, move it to `lib/` first.
- **TypeScript outside this repo.** Where TS is involved (future Chrome
  extension, desktop UI frontend), prefer interfaces over type declarations
  and use `readonly` on all interface/class fields.

## Non-goals (for now)

- Threshold / MPC / Shamir cryptography. "Distributed single-key" here
  means **one key, held on the phone, remotely usable by desktops via
  Matrix**. It does **not** mean splitting the key. Don't shoehorn in
  FROST or Shamir unless the roadmap changes.
- A browser password-autofill extension. That's a later surface; see
  `docs/roadmap.md`.
- Ed448 / X25519 on the card (SSH doesn't support them anyway).
