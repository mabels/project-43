use clap::{Args, Subcommand};

/// Top-level `matrix` subcommand.
#[derive(Subcommand, Debug)]
pub enum MatrixCmd {
    /// Log in to a Matrix homeserver and save the session.
    Login(LoginArgs),

    /// List joined rooms.
    Rooms(RoomsArgs),

    /// Send a plain-text message to a room.
    Send(SendArgs),

    /// Listen for new messages in a room (Ctrl-C to stop).
    Listen(ListenArgs),
}

// ── Login ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Matrix homeserver URL, e.g. https://matrix.org
    #[arg(long)]
    pub homeserver: String,

    /// Full Matrix user ID, e.g. @alice:matrix.org
    #[arg(long)]
    pub user: String,

    /// Password (omit to be prompted)
    #[arg(long)]
    pub password: Option<String>,
}

// ── Rooms ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct RoomsArgs {
    /// Matrix homeserver URL
    #[arg(long)]
    pub homeserver: String,

    /// Matrix user ID (needed when no saved session exists yet)
    #[arg(long)]
    pub user: Option<String>,

    /// Password (needed when no saved session exists yet)
    #[arg(long)]
    pub password: Option<String>,
}

// ── Send ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct SendArgs {
    /// Matrix homeserver URL
    #[arg(long)]
    pub homeserver: String,

    /// Room ID, alias, or bare name.
    /// Examples: !abc123:matrix.org  |  #room:matrix.org  |  my-room
    /// Bare names are resolved as aliases on the homeserver domain.
    #[arg(long)]
    pub room: String,

    /// Message text to send
    #[arg(long)]
    pub message: String,

    /// Matrix user ID (needed when no saved session exists yet)
    #[arg(long)]
    pub user: Option<String>,

    /// Password (needed when no saved session exists yet)
    #[arg(long)]
    pub password: Option<String>,
}

// ── Listen ────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct ListenArgs {
    /// Matrix homeserver URL
    #[arg(long)]
    pub homeserver: String,

    /// Room ID, alias, or bare name.
    /// Examples: !abc123:matrix.org  |  #room:matrix.org  |  my-room
    /// Bare names are resolved as aliases on the homeserver domain.
    #[arg(long)]
    pub room: String,

    /// Matrix user ID (needed when no saved session exists yet)
    #[arg(long)]
    pub user: Option<String>,

    /// Password (needed when no saved session exists yet)
    #[arg(long)]
    pub password: Option<String>,
}
