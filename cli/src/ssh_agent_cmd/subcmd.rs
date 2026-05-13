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

    /// Log send / forward timestamps with transaction IDs to stderr (Matrix mode only).
    ///
    /// Each line looks like:
    ///   [p43::ssh_agent] send     <txid> at <ISO-8601>
    ///   [p43::ssh_agent] forward  <txid> at <ISO-8601>  (+<elapsed_ms> ms)
    #[arg(long)]
    pub verbose: bool,

    /// Timeout for a single sign / list-keys round-trip (seconds, Matrix mode only).
    ///
    /// If the phone does not respond within this interval the agent returns
    /// "agent refused operation" for that request.  The pending-map entry is
    /// reclaimed immediately so no memory leaks.
    #[arg(long, default_value_t = 60)]
    pub timeout_secs: u64,

    /// Redact both the request and response Matrix events after a transaction
    /// completes successfully (Matrix mode only).
    ///
    /// When enabled, the agent queues both event IDs for deferred redaction
    /// (batched, at most once per minute) as soon as the response is received.
    /// Timed-out requests are never redacted.
    ///
    /// Disabled by default because the Synapse server-side retention policy
    /// (m.room.retention) handles cleanup automatically.  Enable this flag
    /// only if you need faster per-transaction cleanup without a server policy.
    #[arg(long)]
    pub redact_on_complete: bool,

    /// Run as a background daemon and write a PID file.
    ///
    /// The agent re-execs itself without this flag, redirecting stdin/stdout/stderr
    /// to /dev/null.  The parent writes the daemon's PID to --pid-file and exits.
    /// Stop the daemon with `p43 ssh-agent --stop`.
    #[arg(long)]
    pub daemon: bool,

    /// Stop a running daemon by sending SIGTERM via its PID file, then exit.
    ///
    /// Reads the PID from --pid-file (or the default path) and sends SIGTERM.
    /// Mutually exclusive with actually starting the agent.
    #[arg(long)]
    pub stop: bool,

    /// Path for the PID file used by --daemon and --stop.
    ///
    /// Defaults to `p43-ssh-agent.pid` next to the key store
    /// (usually ~/.config/project-43/p43-ssh-agent.pid).
    #[arg(long, value_name = "FILE")]
    pub pid_file: Option<String>,

    /// Path for the log file that captures the daemon's stdout and stderr.
    ///
    /// Only used when --daemon is set.  The file is opened in append mode so
    /// successive restarts accumulate rather than overwrite.
    /// Defaults to `p43-ssh-agent.log` next to the key store.
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<String>,
}
