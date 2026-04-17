# ADR-0001 — Lib/CLI split with all non-trivial logic in `lib`

- **Status:** Accepted
- **Date:** 2026-04 (scaffolding phase)

## Context

The long-term plan for project-43 includes a desktop GUI, a mobile app,
and potentially a daemon — all of which need access to the same crypto
and Matrix primitives as the CLI. If that logic lives in the `cli`
crate, every additional surface has to reimplement or bridge it.

During scaffolding the agent initially placed `CardQueue` in `cli/`,
and the SSH-agent entry point straddled both crates. The user pushed
back: "should the card_queue in cli[?] is that not a library feature",
and "we need it in the lib later anyways --- for the ui".

## Decision

All reusable logic lives in the `lib` crate (`p43`). The `cli` crate
contains only:

- `clap` argument structs and parsers (`subcmd.rs`)
- stdin/stdout/env-var/interactive-prompt plumbing
- dispatch into `lib`

If a future consumer (GUI, daemon, gRPC service, mobile app) would also
need a given piece of code, it belongs in `lib` from day one.

## Alternatives considered

- **Single `p43` crate with a `cli` feature flag.** Rejected as
  awkward for future clients that want the lib without the CLI deps.
- **Three crates (lib, cli, ffi).** Premature; adopt when FFI or a
  second binary target actually exists.

## Consequences

- `CardQueue` lives at `lib/src/pkcs11/card_queue.rs`.
- Matrix client was placed in `lib/src/matrix/` from the start, not
  added to `cli`.
- Every new CLI subcommand group gets a `cli/src/<group>/mod.rs` +
  `subcmd.rs` and calls into `lib`.
- Reviewers should reject PRs that add business logic under `cli/src/`.
