# project-43

A personal security toolkit for OpenPGP key management and cryptographic operations —
designed to work with a physical YubiKey (OpenPGP card) or a software key stored locally.
No GPG daemon dependency for crypto operations.

## Overview

project-43 provides two things:

- **`lib/`** — a Rust library crate (`p43`) with two modules:
  - `pkcs11` — sign, encrypt, decrypt, verify operations via YubiKey OpenPGP card (PC/SC) or software key
  - `key_store` — generate, store, and manage OpenPGP key pairs on disk

- **`cli/`** — a single binary (`p43`) that composes both into two subcommand groups:
  - `p43 key ...` — key management
  - `p43 pgp ...` — cryptographic operations

## Requirements

- Rust toolchain (stable)
- `pcscd` running for YubiKey operations
- macOS: Xcode command line tools (for nettle compilation)

## Build

```bash
cargo build --release
```

The binary is at `target/release/p43`.

## Usage

### Key management

```bash
# Generate a new key pair (ed25519 by default, prompts for passphrase)
p43 key generate --uid "Alice <alice@example.com>"

# Generate RSA 4096 without passphrase protection
p43 key generate --uid "Alice <alice@example.com>" --algo rsa4096 --no-encrypt

# List all keys in the store
p43 key list

# Export public key
p43 key export-pub --key alice

# Export private key (prompts for passphrase)
p43 key export-priv --key alice

# Import an existing key
p43 key import --file mykey.asc

# Delete a key
p43 key delete --key alice
```

Keys are stored in `~/.config/project-43/keys/` as `<FINGERPRINT>.pub.asc` and
`<FINGERPRINT>.sec.asc`. Use `--store <path>` to override.

### Cryptographic operations

Operations work in two modes depending on whether `--key-file` is provided:

**YubiKey mode** (physical card via PC/SC):
```bash
p43 pgp list                          # show card info and fingerprints
p43 pgp sign --message "hello"        # sign, prompts for card PIN
p43 pgp decrypt --file msg.asc        # decrypt, prompts for card PIN
```

**Software key mode** (`.sec.asc` file from key store):
```bash
p43 pgp sign --message "hello" \
    --key-file ~/.config/project-43/keys/<FP>.sec.asc

p43 pgp decrypt --file msg.asc \
    --key-file ~/.config/project-43/keys/<FP>.sec.asc
```

**Full operation reference:**
```bash
# Sign (detached armored signature)
p43 pgp sign [--message <MSG>] [--file <FILE>]

# Verify detached signature
p43 pgp verify --file <FILE> --sig <SIG> --signer <PUBKEY>

# Encrypt to recipient's public key
p43 pgp encrypt [--message <MSG>] [--file <FILE>] --recipient <PUBKEY>

# Decrypt
p43 pgp decrypt [--file <FILE>]

# Sign then encrypt
p43 pgp sign-encrypt [--message <MSG>] [--file <FILE>] --recipient <PUBKEY>

# Decrypt and verify
p43 pgp decrypt-verify [--file <FILE>] --signer <PUBKEY>
```

### Environment variables

| Variable        | Description                              |
|-----------------|------------------------------------------|
| `YK_PIN`        | Card PIN (avoids interactive prompt)     |
| `YK_PASSPHRASE` | Software key passphrase                  |
| `YK_KEY_FILE`   | Path to `.sec.asc` (software key mode)   |

### gpg-agent conflict

`gpg-agent` holds exclusive PC/SC access to the card. Kill it before YubiKey operations:

```bash
gpgconf --kill gpg-agent
p43 pgp sign --message "hello"
gpgconf --launch gpg-agent
```

## Tests

Automated integration tests (no hardware required — use software keys):

```bash
cargo test
```

YubiKey end-to-end shell tests (requires card inserted):

```bash
# Import card's public key into gpg keyring once:
gpg --card-edit  # then: fetch, quit

chmod +x cli/tests/*.sh
./cli/tests/test-sign-verify.sh
./cli/tests/test-crypt-decrypt.sh
./cli/tests/test-sign-crypt.sh
```

Each shell test runs a full pipeline — our implementation sign/encrypt, our verify/decrypt,
then cross-checks with `gpg` to confirm interoperability.

## Project structure

```
project-43/
├── Cargo.toml           workspace
├── lib/                 crate "p43"
│   ├── src/
│   │   ├── pkcs11/      card.rs · ops.rs · soft_ops.rs
│   │   └── key_store/   keygen.rs · store.rs
│   └── tests/ops.rs     integration tests
└── cli/                 crate "p43-cli", binary "p43"
    ├── src/
    │   ├── main.rs
    │   ├── key_mgmt/    subcmd.rs · keygen.rs · store.rs
    │   └── pgp/         subcmd.rs · mod.rs
    └── tests/           *.sh  YubiKey shell tests
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 Meno Abels <meno.abels@adviser.com>
