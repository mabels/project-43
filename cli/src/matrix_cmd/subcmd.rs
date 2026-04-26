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

    /// Redact room messages older than a given age.
    Purge(PurgeArgs),
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

    /// Do not store the joined room as the default agent room in matrix-config.json.
    ///
    /// Useful when joining an auxiliary room that `p43 ssh-agent` should not
    /// use by default.
    #[arg(long)]
    pub skip_session: bool,
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

// ── Purge ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct PurgeArgs {
    /// Room to purge — ID, alias, or bare name.
    /// Defaults to the agent room saved by `p43 matrix join`.
    #[arg(long)]
    pub room: Option<String>,

    /// Redact messages older than this many hours (default: 8).
    #[arg(long, default_value = "8")]
    pub older_than_hours: u64,
}

// ── Listen ────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ListenArgs {
    /// Room ID, alias, or bare name.
    /// Examples: !abc123:matrix.org  |  #room:matrix.org  |  my-room
    /// Bare names are resolved as aliases on the saved homeserver domain.
    #[arg(long)]
    pub room: String,

    /// Resume from a previously saved read-until pointer (sync token).
    ///
    /// Omit to receive the full room history before going live.
    /// When the listener exits it prints the current pointer to stderr
    /// so you can capture it and pass it back next time:
    ///
    ///   p43 matrix listen --room #my-room --since <TOKEN>
    #[arg(long)]
    pub since: Option<String>,
}
