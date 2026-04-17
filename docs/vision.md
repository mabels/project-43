# project-43 — Product vision and the gap to today

This document is the long-horizon goal for `project-43` and an honest
assessment of how much of it has actually been built. Keep it in sync
with reality; do not let it become marketing.

## The vision

A **distributed single-key password manager**:

- **One root key.** OpenPGP on a YubiKey, held by the user's mobile device
  (or equivalent secure-element hardware). The key never leaves the device
  that owns it.
- **Stateless desktop / terminal agents.** A laptop, server, or SSH host
  does not hold key material. When it needs a signature or a decryption
  (PGP, SSH, password-vault unlock), it asks the phone, which prompts the
  user for consent and performs the operation.
- **Matrix as the coordination plane.** Sign-request / sign-response
  messages travel over a Matrix room that both the phone and the agent
  have joined. E2EE (Olm/Megolm) + cross-signing provide confidentiality
  and device authentication.
- **Password vault on top.** Once the sign-and-decrypt primitives are
  reliable, a password vault is built as encrypted records that only the
  phone-held key can unlock. Browsers / desktops access the vault by
  asking the phone.

Compared to a classical password manager, the trade-offs are:

- No cloud vault, no server-side encryption gymnastics: the phone is the
  source of truth.
- No per-device master passwords to keep in sync: the user authorises on
  the phone.
- Loss / replacement of the phone is the single biggest risk and must be
  explicitly designed for (paper backup of the key, recovery card, etc.).

## "Distributed single-key" means what, exactly

A recurring point of confusion: **the key is not split.** There is no
threshold signing (FROST), no Shamir secret sharing, no MPC. The word
"distributed" describes the *use* of the key, not its storage. The key
exists once, on one device. Other devices distribute *requests* to it.

If a future decision introduces threshold crypto, record it as an ADR
and update this file.

## Where we are today

### Built and working

- OpenPGP key lifecycle: `p43 key generate|list|import|export|delete`
  against a local `~/.config/project-43/keys/` store.
- PGP operations (`p43 pgp sign|verify|encrypt|decrypt|sign-encrypt|
  decrypt-verify`) against either a YubiKey (PC/SC) or a local `.sec.asc`
  file.
- SSH agent (`p43 ssh-agent --card`) that exposes the YubiKey's auth-slot
  key over a Unix socket, with `CardQueue` serialising card access so
  concurrent SSH sessions cannot collide on the hardware.
- Matrix plumbing: `p43 matrix login|send|listen` with persisted session
  JSON. Plaintext rooms only, no E2EE.
- `VirtualCard` test double so integration tests run in CI without
  hardware.

### The protocol layer is not built

The thing that actually makes this a *distributed* password manager —
the sign-request / consent / sign-response protocol between phone and
desktop — does not exist yet. What exists is a Matrix transport that
can move plaintext strings and a card-signing API that runs locally.

Nothing wires these together. There is no message schema, no device
pairing, no consent UI on any platform, no audit log, no replay
protection, and no E2EE.

### The phone side does not exist at all

There is no Android app, no iOS app. The "phone holds the key" story
is entirely a desktop-side assumption at the moment: the current code
reads the card locally and there is no runtime in which the card lives
on a different device from the agent that uses it.

### The password-vault layer does not exist

No secret storage, no record format, no autofill, no browser extension.
The CLI is a PGP/SSH toolkit today, not a password manager.

## What the vision therefore requires, at minimum

The rest of the list lives in `docs/roadmap.md` with ordering and
rough sizing, but the load-bearing gaps are:

1. A **sign-request protocol** over Matrix: message schemas, versioning,
   replay and freshness guarantees, consent semantics.
2. **Device pairing and authentication** so a desktop can only ask the
   phone that has been paired with it. Cross-signing on Matrix is a
   reasonable substrate.
3. **Olm/Megolm E2EE** on the Matrix rooms used for sign-requests. The
   transport today is plaintext; shipping a password manager on top of
   plaintext Matrix is not an option.
4. A **phone runtime** — likely Android first, given it can talk NFC to
   an external OpenPGP card. iOS OpenPGP-card access is constrained to
   Lightning hardware and specialised bundles; plan accordingly.
5. A **password-vault record format** (probably age-encrypted-to-pgp-cert
   or equivalent) with schemaed entries, plus a syncing story that does
   not require the cloud.
6. A **Chrome/Firefox extension** and companion native-messaging host so
   browsers can request vault records.

## Anti-goals

- Adding a cloud component that holds any ciphertext keyed to the user's
  root key. The vision is local-first.
- Sharing keys across devices via cross-device export. The phone is the
  only device that holds the key.
- Porting GPG or gpg-agent semantics wholesale. `p43` replaces them for
  this user's flow, not augments them.

## Honest status line

Today, `project-43` is a well-organised Rust scaffold for the foundation
crypto and transport primitives of a distributed single-key password
manager. It is not itself a password manager. The README's "personal
security toolkit" framing is accurate; the "distributed single-key
password manager" framing is the goal this scaffold is built toward.
