use anyhow::{Context, Result};
use matrix_sdk::{
    authentication::matrix::MatrixSession,
    config::SyncSettings,
    store::RoomLoadSettings,
    Client,
};
use serde_json;
use std::path::{Path, PathBuf};

// ── MatrixConfig ──────────────────────────────────────────────────────────────

/// Paths and settings derived from the store directory.
pub struct MatrixConfig {
    /// Path where the Matrix session JSON is persisted.
    pub session_path: PathBuf,
}

impl MatrixConfig {
    /// Build from the key-store directory.  The session file lands in the
    /// *parent* of the store dir (e.g. `~/.config/project-43/`) alongside the
    /// SSH agent socket.
    pub fn from_store_dir(store_dir: &Path) -> Self {
        let base = store_dir.parent().unwrap_or(store_dir);
        Self {
            session_path: base.join("matrix-session.json"),
        }
    }
}

// ── Session persistence ───────────────────────────────────────────────────────

/// Persist a `MatrixSession` to disk as JSON.
pub fn save_session(session: &MatrixSession, path: &Path) -> Result<()> {
    let json =
        serde_json::to_string_pretty(session).context("Failed to serialise Matrix session")?;
    std::fs::write(path, json).with_context(|| format!("Failed to write session to {}", path.display()))
}

/// Load a previously saved `MatrixSession` from disk.
pub fn load_session(path: &Path) -> Result<Option<MatrixSession>> {
    if !path.exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read session from {}", path.display()))?;
    let session: MatrixSession =
        serde_json::from_str(&json).context("Failed to deserialise Matrix session")?;
    Ok(Some(session))
}

// ── Login ─────────────────────────────────────────────────────────────────────

/// Full password login.  Saves the resulting session to `session_path`.
///
/// Returns the connected [`Client`] ready for further operations.
pub async fn login(
    homeserver_url: &str,
    username: &str,
    password: &str,
    session_path: &Path,
) -> Result<Client> {
    let client = Client::builder()
        .homeserver_url(homeserver_url)
        .build()
        .await
        .context("Failed to build Matrix client")?;

    let response = client
        .matrix_auth()
        .login_username(username, password)
        .initial_device_display_name("p43")
        .await
        .context("Matrix login failed")?;

    // `From<&login::v3::Response>` is implemented by MatrixSession.
    let session = MatrixSession::from(&response);

    save_session(&session, session_path)
        .context("Login succeeded but session could not be saved")?;

    // One sync so room state is populated before callers act on it.
    client
        .sync_once(SyncSettings::default())
        .await
        .context("Initial sync after login failed")?;

    Ok(client)
}

// ── Restore ───────────────────────────────────────────────────────────────────

/// Restore a saved session.  Returns `None` if no session file exists.
pub async fn restore(homeserver_url: &str, session_path: &Path) -> Result<Option<Client>> {
    let Some(session) = load_session(session_path)? else {
        return Ok(None);
    };

    let client = Client::builder()
        .homeserver_url(homeserver_url)
        .build()
        .await
        .context("Failed to build Matrix client")?;

    client
        .matrix_auth()
        .restore_session(session, RoomLoadSettings::default())
        .await
        .context("Failed to restore Matrix session")?;

    // One sync to make room state available.
    client
        .sync_once(SyncSettings::default())
        .await
        .context("Initial sync after restore failed")?;

    Ok(Some(client))
}

/// Try to restore an existing session; fall back to a password login if none
/// exists.  Always returns a ready-to-use [`Client`].
pub async fn restore_or_login(
    homeserver_url: &str,
    username: &str,
    password: &str,
    session_path: &Path,
) -> Result<Client> {
    if let Some(client) = restore(homeserver_url, session_path).await? {
        return Ok(client);
    }
    login(homeserver_url, username, password, session_path).await
}
