# ADR-0004 — Use the YubiKey auth slot (not signing slot) for SSH

- **Status:** Accepted
- **Date:** 2026-04 (scaffolding phase)

## Context

The OpenPGP card specification defines three slots with distinct roles:

| Slot   | Purpose                             | APDU                  |
|--------|-------------------------------------|------------------------|
| Sign   | Document signing (e.g. `git commit -S`, detached PGP signatures) | PSO:CDS                |
| Decrypt| Decryption                          | PSO:DEC                |
| Auth   | Authentication (e.g. SSH)           | INTERNAL AUTHENTICATE  |

The first SSH-agent implementation in project-43 routed through the
signing slot. This works cryptographically (RSA is RSA) but is
semantically wrong and creates operational coupling: revoking or
rotating the signing subkey would also break SSH access; touch-policy
differences between slots become hard to reason about.

The user caught this: the auth slot is the one designed for SSH.

## Decision

The SSH agent uses the auth slot exclusively via
`openpgp-card-sequoia`'s `authenticator()`, which calls
`INTERNAL AUTHENTICATE`. The signing slot is untouched by `p43 ssh-agent`
and reserved for PGP operations.

Public key is read with `KeyType::Authentication` and does *not* require
a PIN — this lets the agent respond to `request_identities` without
any user interaction.

## Consequences

- The user's YubiKey currently has an RSA 4096 auth key. RSA requires
  the host to pre-hash data; the card executes PKCS#1 v1.5 only.
- SSH clients signal hash choice via `SignRequest.flags`; `flag & 0x04`
  means SHA-512, otherwise SHA-256. Implementation in
  `lib/src/ssh_agent/`.
- Ed25519 auth keys are supported: the card performs PureEdDSA and the
  host passes raw data (`HashAlgorithm::SHA512` is a naming artefact of
  the API — the card does not actually hash with SHA-512).
- ECDSA auth keys are not yet supported; the sign path bails explicitly.
  See `docs/roadmap.md`.

## Related

- `../decisions-and-gotchas.md#why-the-ssh-agent-uses-the-auth-slot-not-the-signing-slot`
- `../api-surface.md#openpgp-card-sequoia-02` for the exact APIs.
