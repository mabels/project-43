use anyhow::{Context, Result};
use matrix_sdk::{
    authentication::matrix::MatrixSession,
    config::SyncSettings,
    store::RoomLoadSettings,
    Client,
};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, time::Duration};

// ── Sync helpers ──────────────────────────────────────────────────────────────

/// A one-shot sync that returns immediately instead of long-polling.
///
/// `SyncSettings::default()` leaves `timeout` unset, which tells the server to
/// wait up to ~30 s for new events before replying.  Setting it to zero makes
/// the server return straight away, so commands like `send` or `rooms` don't
/// pay a multi-second penalty just to hydrate local state.
fn quick_sync() -> SyncSettings {
    SyncSettings::default().timeout(Duration::ZERO)
}

// ── SavedConfig ───────────────────────────────────────────────────────────────

/// Everything needed to reconnect across sessions, persisted as JSON.
///
/// Stored at `~/.config/project-43/matrix-config.json`.
#[derive(Serialize, Deserialize)]
pub struct SavedConfig {
    /// Matrix homeserver URL, e.g. `https://matrix.org`.
    pub homeserver: String,
    /// Fully-qualified Matrix user ID, e.g. `@alice:matrix.org`.
    pub user_id: String,
    /// SDK session tokens (access token, device ID, etc.).
    pub session: MatrixSession,
}

// ── MatrixConfig ──────────────────────────────────────────────────────────────

/// Paths derived from the store directory.
pub struct MatrixConfig {
    /// Path where [`SavedConfig`] is persisted.
    pub config_path: PathBuf,
    /// Directory for the persistent crypto store (Olm/Megolm keys).
    /// Used when the binary is built with the `e2e-encryption` feature.
    pub crypto_store_path: PathBuf,
}

impl MatrixConfig {
    /// Build from the key-store directory.  Runtime files land in the
    /// *parent* of the store dir (e.g. `~/.config/project-43/`) alongside
    /// the SSH agent socket.
    pub fn from_store_dir(store_dir: &Path) -> Self {
        let base = store_dir.parent().unwrap_or(store_dir);
        Self {
            config_path: base.join("matrix-config.json"),
            crypto_store_path: base.join("matrix-crypto"),
        }
    }
}

// ── Config persistence ────────────────────────────────────────────────────────

/// Persist a [`SavedConfig`] to disk as pretty-printed JSON.
pub fn save_config(config: &SavedConfig, path: &Path) -> Result<()> {
    let json =
        serde_json::to_string_pretty(config).context("Failed to serialise Matrix config")?;
    std::fs::write(path, json)
        .with_context(|| format!("Failed to write Matrix config to {}", path.display()))
}

/// Load a previously saved [`SavedConfig`] from disk.
///
/// Returns `None` if the file does not exist yet.
pub fn load_config(path: &Path) -> Result<Option<SavedConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Matrix config from {}", path.display()))?;
    let config: SavedConfig =
        serde_json::from_str(&json).context("Failed to deserialise Matrix config")?;
    Ok(Some(config))
}

// ── Client builder ────────────────────────────────────────────────────────────

/// Build a [`Client`] pointed at `homeserver_url`.
///
/// When compiled with the `e2e-encryption` feature (the default) the client
/// is backed by a persistent SQLite store so that Olm keys survive across
/// sessions.
async fn build_client(homeserver_url: &str, cfg: &MatrixConfig) -> Result<Client> {
    let builder = Client::builder().homeserver_url(homeserver_url);

    // `sqlite_store` is gated on matrix-sdk's `sqlite` feature, which is
    // activated by our `e2e-encryption` feature.  The store persists both
    // room state and Olm/Megolm keys across sessions.
    #[cfg(feature = "e2e-encryption")]
    let builder = builder.sqlite_store(&cfg.crypto_store_path, None);

    let client: Client = builder
        .build()
        .await
        .context("Failed to build Matrix client")?;

    Ok(client)
}

// ── Login ─────────────────────────────────────────────────────────────────────

/// Returns `true` when any error in `e`'s cause chain mentions a crypto-store
/// device-ID mismatch.
///
/// `anyhow::Error::to_string()` returns only the *outermost* context string,
/// so we must walk the full `chain()` to find the message that lives deeper.
fn stale_crypto_store(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|cause| cause.to_string().contains("account in the store doesn't match"))
}

/// Full password login.
///
/// Saves homeserver, user ID and session tokens to [`MatrixConfig::config_path`]
/// so that [`restore`] can reconnect without any arguments.
pub async fn login(
    homeserver_url: &str,
    username: &str,
    password: &str,
    cfg: &MatrixConfig,
) -> Result<Client> {
    match do_login(homeserver_url, username, password, cfg).await {
        Ok(client) => Ok(client),
        Err(e) if stale_crypto_store(&e) => {
            // The crypto store holds keys for a different device — this
            // happens when the config was deleted (e.g. manual logout) but
            // the store was not, or when Element resets the session.
            // Clear it and try once more.
            if cfg.crypto_store_path.exists() {
                std::fs::remove_dir_all(&cfg.crypto_store_path).with_context(|| {
                    format!(
                        "Stale crypto store at {} could not be removed",
                        cfg.crypto_store_path.display()
                    )
                })?;
            }
            do_login(homeserver_url, username, password, cfg)
                .await
                .context("Matrix login failed after clearing stale crypto store")
        }
        Err(e) => Err(e),
    }
}

/// Single login attempt — builds a fresh client and authenticates.
async fn do_login(
    homeserver_url: &str,
    username: &str,
    password: &str,
    cfg: &MatrixConfig,
) -> Result<Client> {
    let client = build_client(homeserver_url, cfg).await?;

    let response = client
        .matrix_auth()
        .login_username(username, password)
        .initial_device_display_name("p43")
        .await
        .context("Matrix login failed")?;

    let saved = SavedConfig {
        homeserver: homeserver_url.to_owned(),
        user_id: response.user_id.to_string(),
        session: MatrixSession::from(&response),
    };

    save_config(&saved, &cfg.config_path)
        .context("Login succeeded but config could not be saved")?;

    // One sync so room state is populated and Olm keys are uploaded.
    client
        .sync_once(quick_sync())
        .await
        .context("Initial sync after login failed")?;

    Ok(client)
}

// ── Logout ────────────────────────────────────────────────────────────────────

/// Invalidate the current session on the homeserver and delete all local
/// state (config file + crypto store).
///
/// The crypto store is device-scoped: it cannot be reused after logout
/// because the next login receives a new device ID.  Leaving it behind
/// causes a mismatch error on the next `login` call.
///
/// Returns an error if no saved session exists.
pub async fn logout(cfg: &MatrixConfig) -> Result<()> {
    let client = restore(cfg)
        .await?
        .context("No saved session found — nothing to log out from.")?;

    client
        .matrix_auth()
        .logout()
        .await
        .context("Homeserver rejected logout request")?;

    std::fs::remove_file(&cfg.config_path)
        .with_context(|| {
            format!("Logged out but could not remove {}", cfg.config_path.display())
        })?;

    // Remove the crypto store so a subsequent login starts with a clean
    // store matching the new device ID.
    if cfg.crypto_store_path.exists() {
        std::fs::remove_dir_all(&cfg.crypto_store_path).with_context(|| {
            format!(
                "Logged out but could not remove crypto store at {}",
                cfg.crypto_store_path.display()
            )
        })?;
    }

    Ok(())
}

// ── Restore ───────────────────────────────────────────────────────────────────

/// Restore a saved session.
///
/// Reads the homeserver URL and session tokens from [`MatrixConfig::config_path`].
/// Returns `None` if no config file exists yet — caller should prompt for
/// `p43 matrix login`.
pub async fn restore(cfg: &MatrixConfig) -> Result<Option<Client>> {
    let Some(saved) = load_config(&cfg.config_path)? else {
        return Ok(None);
    };

    let client = build_client(&saved.homeserver, cfg).await?;

    client
        .matrix_auth()
        .restore_session(saved.session, RoomLoadSettings::default())
        .await
        .context("Failed to restore Matrix session")?;

    // One sync to make room state available.
    client
        .sync_once(quick_sync())
        .await
        .context("Initial sync after restore failed")?;

    Ok(Some(client))
}
