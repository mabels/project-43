# ADR-0002 — Matrix as the coordination transport

- **Status:** Accepted
- **Date:** 2026-04 (scaffolding phase)

## Context

The product vision (see `docs/vision.md`) is a distributed
single-key password manager where the phone holds the root key and
desktop agents remote-sign through it. That requires a bidirectional,
authenticated, federated messaging layer between the phone and one or
more desktops.

Options considered:

- **Matrix** — federated, open, off-the-shelf clients, E2EE (Olm/Megolm)
  and cross-signing are battle-tested, `matrix-sdk` in pure Rust.
- **MQTT over a self-hosted broker** — lightweight, but adds ops
  burden (user must run a broker) and E2EE is not baked in.
- **Direct P2P (libp2p)** — no third party, but NAT traversal and
  discovery are non-trivial, and you still need a rendezvous server.
- **gRPC to a custom server** — burdens us with running infrastructure
  and reinventing federation + E2EE.

## Decision

Use Matrix as the transport. Both phone and desktop join a shared
Matrix room. Sign-requests and sign-responses are Matrix events. E2EE
via Olm/Megolm is required for the sign-request rooms; device
authentication uses cross-signing.

MVP explicitly ships without E2EE on a plaintext room to de-risk the
plumbing. E2EE is added as a second pass once the transport surface is
stable.

## Alternatives considered

See context above.

## Consequences

- `matrix-sdk` is a core dependency in `lib`, not an optional one.
- The user needs a Matrix account (homeserver can be public or
  self-hosted). Documented as a runtime prerequisite.
- A Matrix outage or federation problem is a password-manager outage.
  Acceptable for MVP; mitigations (fallback direct-connection path,
  cached recent approvals) noted in `docs/roadmap.md`.
- The `e2e-encryption` feature flag on `matrix-sdk` is currently
  disabled. Before any password-vault functionality ships, E2EE must
  be re-enabled and verified to compile alongside ADR-0003's workaround.
- See `../decisions-and-gotchas.md#matrix-session-persistence` for
  session storage format.
