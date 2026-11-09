# Architecture Decision Records

Each ADR captures *why* a specific design choice was made, what was
considered, and the consequences we are living with. Mechanical details
(exact API calls, workarounds, error patches) live in
`../decisions-and-gotchas.md` and `../api-surface.md`; ADRs link into
those rather than duplicate them.

## Index

| #    | Title                                          | Status   |
|------|------------------------------------------------|----------|
| 0001 | [Lib/CLI split with logic in lib](0001-lib-cli-split.md) | Accepted |
| 0002 | [Matrix as coordination transport](0002-matrix-as-transport.md) | Accepted |
| 0003 | [Vendored matrix-sdk 0.16.0](0003-vendored-matrix-sdk.md) | Accepted (temporary) |
| 0004 | [Gate-key and secret store architecture](0004-gate-key-and-secret-store-architecture.md) | Accepted |
| 0004 | [YubiKey auth slot for SSH](0004-yubikey-auth-slot.md) | Accepted |
| 0005 | [Software-key fallback + VirtualCard](0005-software-key-fallback.md) | Accepted |
| 0005 | [Keys page redesign](0005-ui-keys-page-redesign-deferred.md) | Deferred |
| 0006 | [Level 2 secret store](0006-level2-secret-store.md) | Accepted |
| 0006 | [Synapse message retention](0006-synapse-message-retention.md) | Accepted |
| 0007 | [Wallet payload layer](0007-wallet-payload-layer.md) | Accepted |
| 0007 | [Synapse rate-limit tuning](0007-synapse-rate-limit.md) | Accepted |
| 0008 | [Multi-tier secret retention (auth × TTL × isolation)](0008-multi-tier-secret-retention.md) | Proposed |

> Note: numbers 0004–0007 are each used twice (two independent ADR streams
> merged without renumbering). New ADRs continue from 0008.

## Adding a new ADR

Copy the shape of an existing file. Number sequentially. Prefer short:
context, decision, alternatives considered, consequences. If an ADR is
superseded, leave the file in place and mark its status, plus link to
the successor.
