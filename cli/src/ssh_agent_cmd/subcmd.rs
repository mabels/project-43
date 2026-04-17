use clap::{Args, ValueEnum};
use p43::ssh_agent::SshKeySlot;
use std::fmt;

/// Which OpenPGP subkey to expose as the SSH identity.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum KeySlot {
    /// Authentication subkey (falls back to signing subkey if absent)
    #[default]
    Auth,
    /// Signing subkey
    Sign,
}

impl fmt::Display for KeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySlot::Auth => write!(f, "auth"),
            KeySlot::Sign => write!(f, "sign"),
        }
    }
}

impl From<KeySlot> for SshKeySlot {
    fn from(k: KeySlot) -> SshKeySlot {
        match k {
            KeySlot::Auth => SshKeySlot::Auth,
            KeySlot::Sign => SshKeySlot::Sign,
        }
    }
}

/// Arguments for `p43 ssh-agent`.
#[derive(Args, Debug)]
pub struct SshAgentArgs {
    /// Unix socket path to listen on.
    ///
    /// Defaults to `p43-ssh-agent.sock` in the same directory as the key
    /// store (usually ~/.config/project-43/).  Set SSH_AUTH_SOCK to this
    /// path so SSH clients can find the agent.
    #[arg(long)]
    pub socket: Option<String>,

    /// Which subkey to expose: `auth` (default, falls back to `sign`) or `sign`.
    ///
    /// Only used for software-key mode (--key-file).
    #[arg(long, default_value_t = KeySlot::Auth)]
    pub key_slot: KeySlot,

    /// Use a YubiKey (OpenPGP card) instead of a software key file.
    ///
    /// Requires --pin / YK_PIN.  The signing slot (PSO:CDS) is used.
    #[arg(long)]
    pub card: bool,

    /// Maximum number of card operations allowed to run in parallel.
    ///
    /// A YubiKey can only process one PC/SC command at a time, so the default
    /// of 1 serialises all requests through an in-memory queue.  Raise this
    /// only if you have multiple cards that can be addressed simultaneously.
    #[arg(long, default_value_t = 1)]
    pub concurrency: usize,
}
