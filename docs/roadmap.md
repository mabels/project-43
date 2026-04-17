# project-43 — Roadmap

Structured open threads, grouped by area. Not a commitment to order or
scope — an inventory so nothing gets lost between sessions.

The single biggest gap is the **sign-request protocol** (see
`docs/vision.md`). Most entries below are subordinate to that, because
without it the distributed aspect of the product is just aspiration.

## Protocol layer — the core missing thing

- Define the sign-request / sign-response message schema (versioned
  envelope, algorithm, payload, nonce, requester identity, reason
  string).
- Decide transport framing: one Matrix event per request? Custom event
  type `p43.sign.request.v1` / `p43.sign.response.v1`? Specify and
  document.
- Freshness & replay protection (nonce + short expiry; reject replays
  across a rolling window).
- Consent semantics on the responder side (auto-approve vs prompt per
  request vs prompt once per requester per TTL).
- Audit log format on both sides (append-only journal of requests
  received, approved, denied).

## Desktop agent

- Remote-sign path in `p43 ssh-agent`: on `Session::sign`, if a Matrix
  responder is configured, send the digest as a sign-request instead of
  signing locally.
- Same wiring for `p43 pgp` operations once the protocol is stable.
- Connection liveness: what does the agent do when the phone is offline?
  Timeout values, fallback behaviour, UX for the SSH client.
- Daemon mode so the Matrix client stays connected across CLI
  invocations instead of relogging each time.

## Phone runtime

- Android app that joins the Matrix room, holds the OpenPGP card via
  NFC / USB-OTG, and shows a consent UI per sign-request. This is the
  first concrete phone target — `openpgp-card-sequoia` + `pcsc` do not
  run on mobile, so the card backend has to be abstracted behind a trait
  before this lands. See ADR-0005.
- iOS app — later. OpenPGP-card access on iOS is constrained and will
  require dedicated hardware paths.
- Biometric gate on the phone before surfacing the PIN prompt.

## E2EE on Matrix

- Enable the `e2e-encryption` feature on `matrix-sdk` once the
  recursion-limit workaround is either removed (upstream fix) or verified
  to still apply with that feature on.
- Device verification flow on first pairing (emoji verification or
  QR-code + cross-signing).
- Key backup / recovery on the Matrix side, or an explicit decision that
  E2EE keys are scoped to the single paired device pair.

## Card backend abstraction

- Introduce a `CardOps` trait in `lib/src/pkcs11/` so the PCSC card, the
  `VirtualCard`, and a future mobile (NFC / USB-OTG) backend all
  implement the same interface.
- Move `open_first_card()` behind the trait.
- Multi-reader support: `CardQueue` already supports concurrency > 1,
  but reader enumeration is not plumbed through.

## Crypto algorithms currently stubbed

- ECDSA on YubiKey (NIST P-256 / P-384 / P-521) — `sign()` currently
  bails with an explicit error on non-RSA / non-Ed25519 auth keys.
  Moderate work, not research.
- RSA software-key path for the SSH agent — `load_ssh_key` handles only
  Ed25519 from `.sec.asc` files.
- Ed448 / X25519 — bail arms. SSH doesn't support them; leave alone.

## Password-vault surface

- Pick a record format (age-encrypted-to-cert, OpenPGP ASCII-armored
  literal packets, something CRDT-shaped for mobile sync, etc.).
- Schema for vault entries (URL, username, secret, notes, tags, TOTP
  seed, rotation history).
- Sync model. Matrix rooms as the sync substrate is the natural choice
  given the rest of the stack, but this has capacity and latency
  implications worth validating with real data.
- CLI: `p43 vault get/put/list/search`.

## Browser extension (Chrome MV3, Firefox later)

- Extension UI + MV3 service worker.
- Native-messaging host that bridges the extension to the local `p43`
  agent (no browser-side keys).
- Decision point: compile the sensitive parts of `lib` to WASM for the
  extension, vs. always route through the native host. WASM path keeps
  the security boundary identical across targets; native-host path is
  simpler.

## Proxmox SSH-key configuration

The nominal task that spawned the session that built all of the above.
Still unimplemented. Intended shape once the agent is working:

- `p43 ssh configure-proxmox --host X --api-token Y --key ID` that
  pushes the public SSH key to `/root/.ssh/authorized_keys` via the
  PVE API or a bootstrapped SSH session.
- Rotation support: revoke old auth-slot public keys on the Proxmox
  side when the user rotates the card.
- Batched across cluster nodes (pvecm copies `authorized_keys`
  cluster-wide, but verify on each node).

## Operational / quality

- CI matrix: Linux today; add macOS once nettle / Homebrew caching is
  sorted.
- Release pipeline: signed release artifacts (dogfood `p43 pgp sign`).
- Broader integration testing of `CardQueue` under contention —
  concurrency=1 is unit-tested; concurrency>1 has no test.
- Audit `useless_conversion` patterns across the codebase — four were
  fixed in the scaffolding session, there may be more.

## Deferred / explicitly out of scope today

- Threshold / MPC / Shamir crypto. Unless the vision changes (record as
  ADR if it does), do not pursue.
- Cloud vault / server-side keyed storage. See `docs/vision.md#anti-goals`.
- gpg-agent compatibility shim. `p43` replaces, not augments.
