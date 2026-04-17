# ADR-0005 — Software-key fallback and `VirtualCard` test double

- **Status:** Accepted
- **Date:** 2026-04 (scaffolding phase)

## Context

Every real card op touches hardware that CI runners do not have. If
integration tests required a YubiKey, CI could only run on a dedicated
self-hosted runner, which is operational overhead nobody wants for a
personal project. And a developer without a card would be unable to
run tests at all.

A separate `card-backend-virtual` crate does not exist on crates.io.

Additionally, there is a real product need for a software-key mode:
key rotation / migration, emergency access when the card is lost,
staging environments, and scripted flows where touch-to-sign is not
acceptable.

## Decision

Two complementary affordances:

1. **Software-key mode in `lib`.** `pkcs11::soft_ops` handles sign /
   encrypt / decrypt / verify entirely against a `.sec.asc` file loaded
   via Sequoia. The CLI accepts `--key-file` (or `YK_KEY_FILE`) to
   switch into this mode. Same subcommands, same flags, different
   code path.
2. **`VirtualCard` test double.** A Rust type in
   `lib/src/pkcs11/virtual_card.rs` that implements the same
   card-operation API as the real PC/SC card, backed by an in-memory
   Sequoia key. Integration tests in `lib/tests/` use this; no
   hardware required.

A `CardOps` trait that both backends implement is on the roadmap (see
`docs/roadmap.md`); today the two paths are parallel rather than
polymorphic.

## Consequences

- `cargo test` runs against software keys only — completes on any
  machine, including CI.
- Hardware-specific behaviour (touch policy, PIN retry counter, card
  lockout) is **not** exercised by `cargo test`. That is covered by the
  shell tests in `cli/tests/` which require an inserted card and cross-
  check against `gpg`.
- The two code paths can drift. Any new card operation must be
  implemented on both `ops.rs` (real card) and `soft_ops.rs` (software)
  and tested through `VirtualCard`.
- Mobile card access (NFC, USB-OTG) will also plug in as a third
  backend once the `CardOps` trait exists.

## Related

- `../decisions-and-gotchas.md` for env vars (`YK_KEY_FILE`,
  `YK_PASSPHRASE`) that select the software-key path.
