# ADR-0003 — Vendored copy of matrix-sdk 0.16.0

- **Status:** Accepted (temporary workaround)
- **Date:** 2026-04 (scaffolding phase)

## Context

`matrix_sdk::Client::sync()` contains a deeply-nested async state
machine. On recent rustc versions (reproduced on 1.94; the lower bound
where it first breaks is not precisely pinned — the workspace comment
says "≥ 1.90"), type-system analysis overflows the default recursion
limit of 128 and the crate fails to compile with:

```
error: queries overflow the depth limit!
  = help: consider increasing the recursion limit by adding a
    `#![recursion_limit = "256"]` attribute to your crate (`matrix_sdk`)
```

There is no released version of `matrix-sdk` that raises this attribute,
and adding it to our own crate does not help — the overflow happens
during compilation *of* `matrix_sdk`, which can only raise its own
recursion limit.

## Decision

Vendor a verbatim copy of `matrix-sdk` 0.16.0 into
`vendor/matrix-sdk/`, with exactly one change: add
`#![recursion_limit = "256"]` after the existing `#![...]` attributes
in `vendor/matrix-sdk/src/lib.rs`. Wire it in via the workspace
`Cargo.toml`:

```toml
[patch.crates-io]
matrix-sdk = { path = "vendor/matrix-sdk" }
```

## Alternatives considered

- **Pin to an older matrix-sdk.** The overflow reproduces on versions
  compatible with our rustc, so downgrading does not help and would
  lose features.
- **Fork publicly on GitHub and depend on the fork.** Slightly cleaner,
  but the workaround is meant to be temporary and a private fork
  adds ceremony we would then have to undo.
- **Pin to an older rustc.** Tested empirically on 2026-04-17 —
  `matrix-sdk` 0.16.0 hits the exact same `query depth increased by 130`
  error on rustc 1.92.0, 1.93.0, and 1.94.1 with our
  `default-features = false, features = ["rustls-tls"]` feature set.
  The depth overshoot is a constant tied to the way
  `#[tracing::instrument]` interacts with async state-machine layout,
  and raising the crate's own `recursion_limit` is what actually makes
  the build pass — not the rustc version. Rejected on evidence.

## Consequences

- `vendor/matrix-sdk/` is a permanent-looking directory but is not
  intended to live beyond an upstream release that fixes the issue.
- Bumping `matrix-sdk` requires re-vendoring: copy the new version,
  re-add the recursion-limit line, verify the patch still resolves.
- Anyone auditing dependencies needs to know the patched copy exists.
  Called out in `README.md`, `CLAUDE.md`, and the workspace
  `Cargo.toml` comment.
- Removal criterion: upstream `matrix-sdk` publishes a release whose
  own `src/lib.rs` carries `#![recursion_limit = "256"]` or has
  refactored the state machine enough that the default limit suffices.
  At that point, delete `vendor/matrix-sdk/` and drop the `[patch]`.
