//! Persistent Matrix client for long-running contexts (Flutter bridge, daemon).
//!
//! The CLI creates a fresh client per invocation; the Flutter bridge and any
//! future daemon process use [`login`] / [`restore`] here to keep a single
//! `Client` alive for the lifetime of the process.

use anyhow::{Context, Result};
use matrix_sdk::{config::SyncSettings, ruma::RoomId, Client};
use std::{path::Path, sync::OnceLock};
use tokio::sync::Mutex;

// ── Global client store ───────────────────────────────────────────────────────

static GLOBAL_CLIENT: OnceLock<Mutex<Option<Client>>> = OnceLock::new();

fn client_slot() -> &'static Mutex<Option<Client>> {
    GLOBAL_CLIENT.get_or_init(|| Mutex::new(None))
}

async fn store_client(c: Client) {
    *client_slot().lock().await = Some(c);
}

/// Clone the stored client, if any.
pub async fn take_client() -> Option<Client> {
    client_slot().lock().await.clone()
}

/// `true` if a client is currently stored (non-blocking, best-effort).
pub fn is_logged_in() -> bool {
    client_slot()
        .try_lock()
        .map(|g| g.is_some())
        .unwrap_or(true) // conservative: if lock is held, assume it exists
}

// ── Bridge-friendly types ─────────────────────────────────────────────────────

pub struct BridgeRoomInfo {
    pub room_id: String,
    pub name: String,
    pub is_encrypted: bool,
}

pub struct BridgeDeviceInfo {
    pub device_id: String,
    pub display_name: String,
    pub is_current: bool,
}

// ── Session management ────────────────────────────────────────────────────────

/// Full password login; stores the resulting client globally.
pub async fn login(
    homeserver: &str,
    username: &str,
    password: &str,
    store_dir: &Path,
) -> Result<()> {
    let cfg = super::client::MatrixConfig::from_store_dir(store_dir);
    let client = super::client::login(homeserver, username, password, &cfg).await?;
    store_client(client).await;
    Ok(())
}

/// Restore a saved session; stores the client globally.
/// Returns `true` if a session was found, `false` if no config exists yet.
pub async fn restore(store_dir: &Path) -> Result<bool> {
    let cfg = super::client::MatrixConfig::from_store_dir(store_dir);
    match super::client::restore(&cfg).await? {
        Some(c) => {
            store_client(c).await;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Logout and clear the stored client.
pub async fn logout(store_dir: &Path) -> Result<()> {
    let cfg = super::client::MatrixConfig::from_store_dir(store_dir);
    super::client::logout(&cfg).await?;
    *client_slot().lock().await = None;
    Ok(())
}

// ── Room operations ───────────────────────────────────────────────────────────

/// List all joined rooms with encryption status.
pub async fn list_rooms() -> Result<Vec<BridgeRoomInfo>> {
    let client = take_client().await.context("Not logged in to Matrix")?;
    let mut rooms = Vec::new();
    for room in client.joined_rooms() {
        let is_encrypted = room
            .latest_encryption_state()
            .await
            .map(|s| s.is_encrypted())
            .unwrap_or(false);
        rooms.push(BridgeRoomInfo {
            room_id: room.room_id().to_string(),
            name: room.name().unwrap_or_else(|| room.room_id().to_string()),
            is_encrypted,
        });
    }
    Ok(rooms)
}

/// Join a room and return its basic info.
pub async fn join_room(room_spec: &str) -> Result<BridgeRoomInfo> {
    let client = take_client().await.context("Not logged in to Matrix")?;
    let result = super::room::join_room(&client, room_spec).await?;
    Ok(BridgeRoomInfo {
        room_id: result.room_id.to_string(),
        name: result.name.unwrap_or_else(|| result.room_id.to_string()),
        is_encrypted: result.is_encrypted,
    })
}

/// Send a plain-text message to a room.
pub async fn send_message(room_id: &str, text: &str) -> Result<()> {
    let client = take_client().await.context("Not logged in to Matrix")?;
    let rid = RoomId::parse(room_id).with_context(|| format!("Invalid room ID: {room_id}"))?;
    super::room::send_message(&client, &rid, text).await
}

/// List devices registered on this account.
pub async fn list_devices() -> Result<Vec<BridgeDeviceInfo>> {
    let client = take_client().await.context("Not logged in to Matrix")?;
    Ok(super::device::list_devices(&client)
        .await?
        .into_iter()
        .map(|d| BridgeDeviceInfo {
            device_id: d.device_id.to_string(),
            display_name: d.display_name.unwrap_or_default(),
            is_current: d.is_current,
        })
        .collect())
}

// ── Listen ────────────────────────────────────────────────────────────────────

/// Subscribe to messages in `room_id`, calling `on_message(sender, body)` for
/// each one (catch-up history then live).  Blocks until the sync loop breaks.
pub async fn listen_room<F>(room_id: &str, on_message: F) -> Result<()>
where
    F: Fn(String, String) + Send + Sync + 'static,
{
    let client = take_client().await.context("Not logged in to Matrix")?;
    let rid = RoomId::parse(room_id).with_context(|| format!("Invalid room ID: {room_id}"))?;
    super::room::listen(&client, &rid, None, move |sender, body| {
        on_message(sender.to_string(), body);
    })
    .await?;
    Ok(())
}

// ── Background sync ───────────────────────────────────────────────────────────

/// Spawn a background sync loop required during device verification.
/// Abort the returned handle when verification completes.
pub async fn start_background_sync() -> Option<tokio::task::JoinHandle<()>> {
    let client = take_client().await?;
    Some(tokio::spawn(async move {
        let _ = client.sync(SyncSettings::default()).await;
    }))
}

// ── Verification ──────────────────────────────────────────────────────────────

/// Run the non-interactive SAS verification flow.
///
/// Calls `on_emojis` once the seven emojis are ready, then waits for
/// `confirm_rx` to receive `true` (match) or `false` (mismatch).
pub async fn run_verify<F>(
    on_emojis: F,
    confirm_rx: tokio::sync::oneshot::Receiver<bool>,
) -> Result<()>
where
    F: FnOnce(Vec<super::verification::EmojiItem>) + Send + 'static,
{
    let client = take_client().await.context("Not logged in to Matrix")?;
    super::verification::verify_non_interactive(&client, on_emojis, confirm_rx).await
}
