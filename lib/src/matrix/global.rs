//! Persistent Matrix client for long-running contexts (Flutter bridge, daemon).
//!
//! The CLI creates a fresh client per invocation; the Flutter bridge and any
//! future daemon process use [`login`] / [`restore`] here to keep a single
//! `Client` alive for the lifetime of the process.

use anyhow::{Context, Result};
use matrix_sdk::{config::SyncSettings, ruma::RoomId, Client};
use std::{path::Path, sync::OnceLock, time::Duration};
use tokio::sync::{mpsc, Mutex};

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
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip_all, fields(homeserver, username))
)]
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
#[cfg_attr(feature = "telemetry", tracing::instrument(skip_all))]
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
#[cfg_attr(feature = "telemetry", tracing::instrument(skip_all))]
pub async fn logout(store_dir: &Path) -> Result<()> {
    let cfg = super::client::MatrixConfig::from_store_dir(store_dir);
    super::client::logout(&cfg).await?;
    *client_slot().lock().await = None;
    Ok(())
}

// ── Room operations ───────────────────────────────────────────────────────────

/// List all joined rooms with encryption status.
#[cfg_attr(feature = "telemetry", tracing::instrument(skip_all))]
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

/// Resolve which Matrix room the SSH agent should use.
///
/// Priority:
/// 1. `room_arg` — explicit `--room` flag value.
/// 2. `agent_room` saved in `matrix-config.json` by `p43 matrix join`.
/// 3. If exactly one room is joined, use it (convenience).
/// 4. Otherwise print the list and return an error.
pub async fn resolve_agent_room(
    room_arg: Option<&str>,
    store_dir: &std::path::Path,
) -> Result<String> {
    if let Some(r) = room_arg {
        return Ok(r.to_string());
    }

    // Check the saved agent_room in the config.
    let cfg = super::client::MatrixConfig::from_store_dir(store_dir);
    if let Some(saved) = super::client::load_config(&cfg.config_path)? {
        if let Some(room_id) = saved.agent_room {
            eprintln!("Using saved agent_room: {room_id}");
            return Ok(room_id);
        }
    }

    // Fall back to listing rooms.
    let rooms = list_rooms().await?;
    match rooms.as_slice() {
        [] => anyhow::bail!(
            "No rooms joined yet.\n\
             Run:  p43 matrix join --room <#room:server>"
        ),
        [room] => {
            eprintln!("Using room: {} ({})", room.name, room.room_id);
            Ok(room.room_id.clone())
        }
        _ => {
            eprintln!(
                "Multiple rooms joined — run  p43 matrix join --room <ID>  to set a default,"
            );
            eprintln!("or pass --room to ssh-agent directly.  Joined rooms:");
            for r in &rooms {
                eprintln!("  {}  {}", r.room_id, r.name);
            }
            anyhow::bail!("Ambiguous room; use --room to specify")
        }
    }
}

/// Join a room and return its basic info.
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip_all, fields(room_spec))
)]
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
#[cfg_attr(feature = "telemetry", tracing::instrument(skip_all, fields(room_id, text_len = text.len())))]
/// Send a plain-text message to a room and return its Matrix event ID.
pub async fn send_message(room_id: &str, text: &str) -> Result<String> {
    let client = take_client().await.context("Not logged in to Matrix")?;
    let rid = RoomId::parse(room_id).with_context(|| format!("Invalid room ID: {room_id}"))?;
    super::room::send_message(&client, &rid, text).await
}

/// Redact a single Matrix event by its ID.
///
/// Consumers (e.g. the SSH agent) call this after processing a completed
/// transaction to clean up the handled message from the room history.
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip_all, fields(room_id, event_id))
)]
pub async fn redact_room_event(room_id: &str, event_id: &str) -> Result<()> {
    let client = take_client().await.context("Not logged in to Matrix")?;
    let rid = RoomId::parse(room_id).with_context(|| format!("Invalid room ID: {room_id}"))?;
    super::room::redact_event(&client, &rid, event_id).await
}

// ── Async redact worker ───────────────────────────────────────────────────────

/// Spawn a background task that batches Matrix event redactions and executes
/// them at most once per minute.
///
/// Push `(room_id, event_id)` pairs onto the returned [`mpsc::Sender`] as
/// transactions complete; the worker collects them and flushes to the
/// homeserver on a 60-second timer.  This keeps redactions entirely off the
/// transaction hot-path.
///
/// The worker exits (and does a final flush) when the last sender is dropped.
pub fn spawn_redact_worker() -> (mpsc::Sender<(String, String)>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<(String, String)>(256);
    let handle = tokio::spawn(async move {
        let mut pending: Vec<(String, String)> = Vec::new();
        // First tick fires after 60 s, not immediately.
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(60),
            Duration::from_secs(60),
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let batch = std::mem::take(&mut pending);
                    if !batch.is_empty() {
                        eprintln!(
                            "[p43::matrix] redact worker: flushing {} event(s)",
                            batch.len()
                        );
                        for (room_id, event_id) in batch {
                            if let Err(e) = redact_room_event(&room_id, &event_id).await {
                                eprintln!("[p43::matrix] redact {event_id}: {e}");
                            }
                        }
                    }
                }
                item = rx.recv() => {
                    match item {
                        Some(pair) => pending.push(pair),
                        None => break, // all senders dropped — exit loop
                    }
                }
            }
        }

        // Final flush on shutdown.
        if !pending.is_empty() {
            eprintln!(
                "[p43::matrix] redact worker: final flush of {} event(s)",
                pending.len()
            );
            for (room_id, event_id) in pending {
                if let Err(e) = redact_room_event(&room_id, &event_id).await {
                    eprintln!("[p43::matrix] redact {event_id}: {e}");
                }
            }
        }
    });
    (tx, handle)
}

/// List devices registered on this account.
#[cfg_attr(feature = "telemetry", tracing::instrument(skip_all))]
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
///
/// `since` is an optional Matrix `next_batch` token; when provided only messages
/// that arrived after that token are delivered (no full-history replay).
///
/// `on_pointer` is called with the latest sync token on **every** sync batch.
/// Pass `|_| {}` to ignore.  The agent bridge uses this to persist the token to
/// disk on every cycle so reconnects never replay old messages.
///
/// Returns the last [`super::room::ListenPointer`] observed so the caller can
/// use it as a final `since` on the next invocation.
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip_all, fields(room_id, since))
)]
pub async fn listen_room<F, P>(
    room_id: &str,
    since: Option<&str>,
    on_pointer: P,
    on_message: F,
) -> Result<super::room::ListenPointer>
where
    // F: called with (sender, body, origin_server_ts_ms, event_id).
    F: Fn(String, String, u64, String) + Send + Sync + 'static,
    P: Fn(String) + Send + Sync + 'static,
{
    let client = take_client().await.context("Not logged in to Matrix")?;
    let rid = RoomId::parse(room_id).with_context(|| format!("Invalid room ID: {room_id}"))?;
    super::room::listen(
        &client,
        &rid,
        since,
        move |sender, body, ts_ms, event_id| {
            on_message(sender.to_string(), body, ts_ms, event_id);
        },
        on_pointer,
    )
    .await
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
