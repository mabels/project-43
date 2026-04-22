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

    /// Sign locally using --card or --key-file instead of proxying through Matrix.
    ///
    /// Without this flag the agent forwards every SSH request as a p43 protocol
    /// message into a Matrix room and waits for a response from the phone.
    #[arg(long)]
    pub local: bool,

    /// Matrix room to proxy requests through (Matrix mode only).
    ///
    /// May be a room ID (!abc:matrix.org), alias (#room:matrix.org), or bare
    /// name.  If omitted and exactly one room is joined, that room is used.
    #[arg(long)]
    pub room: Option<String>,

    /// Which subkey to expose: `auth` (default, falls back to `sign`) or `sign`.
    ///
    /// Only used in local software-key mode (--local --key-file).
    #[arg(long, default_value_t = KeySlot::Auth)]
    pub key_slot: KeySlot,

    /// Use a YubiKey (OpenPGP card) instead of a software key file.
    ///
    /// Only used in local mode (--local).  Requires --pin / YK_PIN.
    #[arg(long)]
    pub card: bool,

    /// Maximum number of card operations allowed to run in parallel.
    ///
    /// Only used in local YubiKey mode (--local --card).
    #[arg(long, default_value_t = 1)]
    pub concurrency: usize,

    /// Device label to use for bus registration (Matrix mode only).
    ///
    /// Selects which key in <bus_dir>/devices/ represents this machine.
    /// Auto-detected when exactly one device key exists.
    #[arg(long)]
    pub device: Option<String>,
}
