use clap::{Args, Subcommand};

/// Top-level `matrix` subcommand.
#[derive(Subcommand, Debug)]
pub enum MatrixCmd {
    /// Log in to a Matrix homeserver and save the session.
    Login(LoginArgs),

    /// Invalidate the current session and delete the local config.
    Logout,

    /// List devices registered to this account.
    Devices(DevicesArgs),

    /// Delete one or more devices (requires password re-authentication).
    DeleteDevice(DeleteDeviceArgs),

    /// List joined rooms.
    Rooms(RoomsArgs),

    /// Join a room (by ID, alias, or bare name).
    Join(JoinArgs),

    /// Register a room alias in the homeserver directory.
    SetAlias(SetAliasArgs),

    /// Send a plain-text message to a room.
    Send(SendArgs),

    /// Listen for new messages in a room (Ctrl-C to stop).
    Listen(ListenArgs),

    /// Verify this device via SAS emoji comparison with another session.
    Verify,
}

// ── Login ─────────────────────────────────────────────────────────────────────

/// Required once.  Saves homeserver + session so all other commands need no
/// connection flags.
#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Matrix homeserver URL, e.g. https://matrix.org
    #[arg(long)]
    pub homeserver: String,

    /// Full Matrix user ID, e.g. @alice:matrix.org
    #[arg(long)]
    pub user: String,

    /// Password (omit to be prompted interactively)
    #[arg(long)]
    pub password: Option<String>,
}

// ── Devices ───────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct DevicesArgs {}

// ── DeleteDevice ──────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct DeleteDeviceArgs {
    /// Device IDs to delete.  May be repeated.
    /// Example: --device ZXXBFHYDHA --device MOWTQOHFUJ
    #[arg(long = "device")]
    pub devices: Vec<String>,

    /// Delete all non-current p43 devices automatically.
    #[arg(long, conflicts_with = "devices")]
    pub stale: bool,

    /// Password for re-authentication (prompted if omitted).
    #[arg(long)]
    pub password: Option<String>,
}

// ── Rooms ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct RoomsArgs {}

// ── Join ──────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct JoinArgs {
    /// Room ID, alias, or bare name.
    /// Examples: !abc123:matrix.org  |  #room:matrix.org  |  my-room
    /// Bare names are resolved as aliases on the saved homeserver domain.
    #[arg(long)]
    pub room: String,
}

// ── SetAlias ──────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct SetAliasArgs {
    /// Room to attach the alias to — ID, existing alias, or bare name.
    #[arg(long)]
    pub room: String,

    /// Alias to register, e.g. `#my-room:matrix.org` or bare `my-room`.
    /// Bare names are qualified against the saved homeserver domain.
    #[arg(long)]
    pub alias: String,
}

// ── Send ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct SendArgs {
    /// Room ID, alias, or bare name.
    /// Examples: !abc123:matrix.org  |  #room:matrix.org  |  my-room
    /// Bare names are resolved as aliases on the saved homeserver domain.
    #[arg(long)]
    pub room: String,

    /// Message text to send.
    #[arg(long)]
    pub message: String,
}

// ── Listen ────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ListenArgs {
    /// Room ID, alias, or bare name.
    /// Examples: !abc123:matrix.org  |  #room:matrix.org  |  my-room
    /// Bare names are resolved as aliases on the saved homeserver domain.
    #[arg(long)]
    pub room: String,

    /// Print the last N messages before tailing live messages.
    /// 0 (default) skips history entirely.
    #[arg(long, default_value_t = 0)]
    pub history: u64,
}
