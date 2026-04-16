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
    /// Set SSH_AUTH_SOCK to this path so SSH clients can find the agent.
    #[arg(long, default_value = "~/.p43-ssh-agent.sock")]
    pub socket: String,

    /// Which subkey to expose: `auth` (default, falls back to `sign`) or `sign`.
    #[arg(long, default_value_t = KeySlot::Auth)]
    pub key_slot: KeySlot,
}
