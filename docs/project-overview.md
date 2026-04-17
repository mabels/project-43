# project-43 — Overview & Architecture

## Purpose
`project-43` (binary: `p43`) is a personal security / automation tool written in Rust. It manages OpenPGP keys stored on a YubiKey or as software key files (`.sec.asc`), exposes them as an SSH agent, and communicates with Matrix rooms. A future GUI is planned, which is why all real logic lives in `lib` rather than `cli`.

## Workspace layout
```
project-43/
├── Cargo.toml          # workspace + [patch.crates-io] for matrix-sdk
├── Cargo.lock
├── lib/                # crate "p43"  — all reusable logic
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # pub mod key_store; matrix; pkcs11; ssh_agent;
│       ├── key_store/      # generate / list / import / export / delete keys
│       ├── pkcs11/         # YubiKey card access + CardQueue concurrency helper
│       │   ├── card.rs         # open_first_card()
│       │   ├── card_queue.rs   # CardQueue — tokio Semaphore serialiser
│       │   ├── ops.rs          # low-level OpenPGP card signing
│       │   ├── soft_ops.rs     # software key signing (load .sec.asc)
│       │   └── virtual_card.rs # test double for card ops
│       ├── ssh_agent/      # SSH key conversion + card SSH signing
│       │   └── mod.rs
│       └── matrix/         # Matrix client (login / restore / send / listen)
│           ├── mod.rs
│           ├── client.rs
│           └── room.rs
├── cli/                # crate "p43-cli" — thin clap wrappers
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── key_mgmt/   # p43 key {generate,list,import,export,delete}
│       ├── pgp/        # p43 pgp {sign,encrypt,decrypt,verify}
│       ├── ssh_agent_cmd/  # p43 ssh-agent
│       └── matrix_cmd/    # p43 matrix {login,send,listen}
└── vendor/
    └── matrix-sdk/     # patched copy of matrix-sdk 0.16.0 (see known issues)
```

## Key dependencies (lib)
| Crate | Version | Purpose |
|-------|---------|---------|
| `sequoia-openpgp` | 1 | OpenPGP cert parsing, signing, encryption |
| `openpgp-card-sequoia` | 0.2 | YubiKey OpenPGP card access (wraps sequoia) |
| `card-backend-pcsc` | 0.5 | PC/SC transport for the card backend |
| `ssh-key` | 0.6 | SSH key/signature types and encoding |
| `tokio` | 1 (sync, rt) | Async runtime + Semaphore for CardQueue |
| `matrix-sdk` | 0.16.0 (patched) | Matrix client |
| `serde` / `serde_json` | 1 | Session serialisation |

## Key dependencies (cli, in addition)
| Crate | Purpose |
|-------|---------|
| `clap` 4 (derive) | Argument parsing |
| `ssh-agent-lib` 0.5 | Unix socket SSH agent protocol |
| `rpassword` 7 | Interactive PIN / password prompts |
| `dirs` 6 | `~` home directory expansion |
| `signature` 2 | `Signer` trait for SSH signing |

## CLI commands
```
p43 key  {generate,list,import,export,delete}
p43 pgp  {sign,encrypt,decrypt,verify}
p43 ssh-agent [--card] [--socket PATH] [--pin PIN] [--concurrency N]
p43 matrix login   --homeserver URL --user @id:server [--password PW]
p43 matrix send    --homeserver URL --room !id:server --message TEXT
p43 matrix listen  --homeserver URL --room !id:server
```

## Runtime file layout (`~/.config/project-43/`)
```
keys/                  # KeyStore directory (--store overrides)
p43-ssh-agent.sock     # SSH agent socket (default, beside keys/)
matrix-session.json    # Persisted MatrixSession (JSON, auto-created on login)
```

## Design rules
- All non-trivial logic lives in `lib` so a future GUI can reuse it without touching `cli`.
- No hard-coded credentials anywhere; PIN/password always from `--flag`, env var, or interactive prompt.
- `CardQueue` lives in `lib` (`pkcs11::card_queue`) so any consumer (CLI or future UI) can serialise card ops.
- Software key path and YubiKey path are separate code paths throughout; they share the same CLI flags.
