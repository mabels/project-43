use crate::frb_generated::StreamSink;
use flutter_rust_bridge::frb;
use p43::key_store::{keygen, store::KeyStore};
use std::path::PathBuf;
use std::sync::OnceLock;

// ── Global Tokio runtime ──────────────────────────────────────────────────────
// FRB only provides a Tokio context for async bridge functions.  Sync functions
// that need to spawn tasks (mx_listen, mx_start_verify) use this runtime instead.

static TOKIO_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn tokio_rt() -> &'static tokio::runtime::Runtime {
    TOKIO_RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build Tokio runtime")
    })
}

/// Required frb initialiser — do not remove.
#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
    // Eagerly boot the runtime so the first mx_listen/mx_start_verify call
    // doesn't pay the cold-start cost on the UI thread.
    let _ = tokio_rt();
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// A key entry returned to Dart — mirrors p43::key_store::store::KeyEntry.
pub struct KeyInfo {
    pub fingerprint: String,
    pub uid: String,
    pub algo: String,
    pub has_secret: bool,
}

// ── Store-dir initialisation ──────────────────────────────────────────────────

/// Platform-provided store root (set once by Dart via path_provider).
/// Falls back to ~/.config/project-43/keys on platforms that have a home dir.
static STORE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Must be called once from Dart before any key operation.
/// Pass `getApplicationSupportDirectory().path` (or equivalent).
#[frb]
pub fn set_store_dir(dir: String) {
    let _ = STORE_DIR.set(PathBuf::from(dir).join("keys"));
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn default_store_dir() -> PathBuf {
    STORE_DIR.get().cloned().unwrap_or_else(|| {
        dirs::home_dir()
            .expect("cannot find home dir — call set_store_dir() first on mobile")
            .join(".config")
            .join("project-43")
            .join("keys")
    })
}

fn open_store() -> anyhow::Result<KeyStore> {
    KeyStore::open(&default_store_dir())
}

fn to_key_info(e: p43::key_store::store::KeyEntry) -> KeyInfo {
    KeyInfo {
        fingerprint: e.fingerprint,
        uid: e.uid,
        algo: e.algo,
        has_secret: e.has_secret,
    }
}

// ── API ───────────────────────────────────────────────────────────────────────

/// Returns all keys in the local store (~/.config/project-43/keys).
#[frb]
pub fn list_keys() -> anyhow::Result<Vec<KeyInfo>> {
    Ok(open_store()?.list()?.into_iter().map(to_key_info).collect())
}

/// Generates a new soft key, saves it, and returns the updated key list.
/// `passphrase: None` skips encryption (not recommended).
#[frb]
pub fn generate_key(
    uid: String,
    algo: String,
    passphrase: Option<String>,
) -> anyhow::Result<Vec<KeyInfo>> {
    let ks = open_store()?;
    let cert = keygen::generate(&uid, &algo, passphrase.as_deref())?;
    ks.save(&cert, None)?;
    Ok(ks.list()?.into_iter().map(to_key_info).collect())
}

// ── Matrix ─────────────────────────────────────────────────────────────────────
//
// All heavy lifting lives in p43::matrix::global; the bridge is thin plumbing.

fn mx_store_dir() -> anyhow::Result<PathBuf> {
    // STORE_DIR is set to <appSupportDir>/keys; go one level up for Matrix files.
    Ok(default_store_dir())
}

// ── Matrix types ──────────────────────────────────────────────────────────────

pub struct MxRoomInfo {
    pub room_id: String,
    pub name: String,
    pub is_encrypted: bool,
}

pub struct MxMessage {
    pub sender: String,
    pub body: String,
}

#[derive(Clone)]
pub struct MxEmojiInfo {
    pub symbol: String,
    pub description: String,
}

#[derive(Clone)]
pub enum MxVerifyEvent {
    Waiting,
    RequestReceived,
    Emojis { emojis: Vec<MxEmojiInfo> },
    Done,
    Cancelled { reason: String },
}

pub struct MxDeviceInfo {
    pub device_id: String,
    pub display_name: String,
    pub is_current: bool,
}

// ── Verify confirm channel ────────────────────────────────────────────────────

static MX_VERIFY_CONFIRM: OnceLock<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<bool>>>> =
    OnceLock::new();

fn mx_verify_slot() -> &'static tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<bool>>> {
    MX_VERIFY_CONFIRM.get_or_init(|| tokio::sync::Mutex::new(None))
}

// ── Session ───────────────────────────────────────────────────────────────────

/// Password login.  Persists session under the app support directory.
#[frb]
pub async fn mx_login(
    homeserver: String,
    username: String,
    password: String,
) -> anyhow::Result<()> {
    p43::matrix::global::login(&homeserver, &username, &password, &mx_store_dir()?).await
}

/// Restore a previously saved session.  Returns `true` if one was found.
/// Call at startup before showing the chat UI.
#[frb]
pub async fn mx_restore() -> anyhow::Result<bool> {
    p43::matrix::global::restore(&mx_store_dir()?).await
}

/// Logout and delete the local session.
#[frb]
pub async fn mx_logout() -> anyhow::Result<()> {
    p43::matrix::global::logout(&mx_store_dir()?).await
}

/// `true` if a Matrix session is currently active (non-blocking).
#[frb]
pub fn mx_is_logged_in() -> bool {
    p43::matrix::global::is_logged_in()
}

// ── Rooms ─────────────────────────────────────────────────────────────────────

#[frb]
pub async fn mx_list_rooms() -> anyhow::Result<Vec<MxRoomInfo>> {
    Ok(p43::matrix::global::list_rooms()
        .await?
        .into_iter()
        .map(|r| MxRoomInfo {
            room_id: r.room_id,
            name: r.name,
            is_encrypted: r.is_encrypted,
        })
        .collect())
}

#[frb]
pub async fn mx_join_room(room: String) -> anyhow::Result<MxRoomInfo> {
    let r = p43::matrix::global::join_room(&room).await?;
    Ok(MxRoomInfo {
        room_id: r.room_id,
        name: r.name,
        is_encrypted: r.is_encrypted,
    })
}

// ── Messages ──────────────────────────────────────────────────────────────────

#[frb]
pub async fn mx_send(room_id: String, text: String) -> anyhow::Result<()> {
    p43::matrix::global::send_message(&room_id, &text).await
}

/// Stream all messages in `room_id` (history + live).
/// Dart receives each message as an `MxMessage` event.
#[frb]
pub fn mx_listen(room_id: String, sink: StreamSink<MxMessage>) {
    tokio_rt().spawn(async move {
        let _ = p43::matrix::global::listen_room(&room_id, move |sender, body| {
            let _ = sink.add(MxMessage { sender, body });
        })
        .await;
    });
}

// ── Agent room ────────────────────────────────────────────────────────────────

/// Incoming p43 protocol request decoded from a Matrix room message.
#[derive(Clone)]
pub enum AgentRequest {
    /// The desktop wants the list of available SSH public keys.
    ListKeys { request_id: String },
    /// The desktop wants to sign `data` (base64) with the key at `fingerprint`.
    Sign {
        request_id: String,
        fingerprint: String,
        description: String,
    },
}

/// Return the room ID saved as the agent room in matrix-config.json, if any.
#[frb]
pub fn mx_get_agent_room() -> Option<String> {
    let store_dir = STORE_DIR.get()?;
    let cfg = p43::matrix::MatrixConfig::from_store_dir(store_dir);
    let saved = p43::matrix::client::load_config(&cfg.config_path).ok()??;
    saved.agent_room
}

/// Persist `room_id` as the default agent room in matrix-config.json.
#[frb]
pub async fn mx_set_agent_room(room_id: String) -> anyhow::Result<()> {
    let store_dir = mx_store_dir()?;
    let cfg = p43::matrix::MatrixConfig::from_store_dir(&store_dir);
    let mut saved = p43::matrix::client::load_config(&cfg.config_path)?
        .ok_or_else(|| anyhow::anyhow!("No Matrix session found"))?;
    saved.agent_room = Some(room_id);
    p43::matrix::client::save_config(&saved, &cfg.config_path)?;
    Ok(())
}

/// Subscribe to p43 protocol request messages arriving in `room_id`.
///
/// Only `ssh.list_keys_request` and `ssh.sign_request` events are forwarded;
/// all other room traffic is silently ignored.
#[frb]
pub fn mx_listen_agent(room_id: String, sink: StreamSink<AgentRequest>) {
    tokio_rt().spawn(async move {
        let _ = p43::matrix::global::listen_room(&room_id, move |_sender, body| {
            let event = match p43::protocol::Message::from_json(&body) {
                Ok(p43::protocol::Message::SshListKeysRequest(r)) => Some(AgentRequest::ListKeys {
                    request_id: r.request_id,
                }),
                Ok(p43::protocol::Message::SshSignRequest(r)) => Some(AgentRequest::Sign {
                    request_id: r.request_id,
                    fingerprint: r.fingerprint,
                    description: r.description,
                }),
                _ => None,
            };
            if let Some(ev) = event {
                let _ = sink.add(ev);
            }
        })
        .await;
    });
}

/// Respond to an `ssh.list_keys_request` with the keys held in the local store.
#[frb]
pub async fn mx_respond_list_keys(room_id: String, request_id: String) -> anyhow::Result<()> {
    let store_dir = default_store_dir();
    let keys = p43::ssh_agent::list_ssh_public_keys(&store_dir);
    let response =
        p43::protocol::Message::SshListKeysResponse(p43::protocol::SshListKeysResponse {
            request_id,
            keys,
        });
    p43::matrix::global::send_message(&room_id, &response.to_json()?).await
}

// ── Devices ───────────────────────────────────────────────────────────────────

#[frb]
pub async fn mx_list_devices() -> anyhow::Result<Vec<MxDeviceInfo>> {
    Ok(p43::matrix::global::list_devices()
        .await?
        .into_iter()
        .map(|d| MxDeviceInfo {
            device_id: d.device_id,
            display_name: d.display_name,
            is_current: d.is_current,
        })
        .collect())
}

// ── Verification ──────────────────────────────────────────────────────────────

/// Start a SAS device verification flow.  Events are pushed to `sink`:
///   1. `Waiting`          — waiting for a request from another session
///   2. `RequestReceived`  — request accepted, SAS key exchange in progress
///   3. `Emojis { … }`    — show these seven emojis to the user
///   4. `Done`             — emojis matched, device now verified
///   5. `Cancelled { … }` — flow failed or user said no match
///
/// After receiving `Emojis`, call `mx_confirm_verify(true/false)` to proceed.
#[frb]
pub fn mx_start_verify(sink: StreamSink<MxVerifyEvent>) {
    tokio_rt().spawn(async move {
        let _ = sink.add(MxVerifyEvent::Waiting);

        let (confirm_tx, confirm_rx) = tokio::sync::oneshot::channel::<bool>();
        *mx_verify_slot().lock().await = Some(confirm_tx);

        let sync_handle = p43::matrix::global::start_background_sync().await;

        let sink_clone = sink.clone();
        let result = p43::matrix::global::run_verify(
            move |emojis| {
                let _ = sink_clone.add(MxVerifyEvent::RequestReceived);
                let _ = sink_clone.add(MxVerifyEvent::Emojis {
                    emojis: emojis
                        .into_iter()
                        .map(|e| MxEmojiInfo {
                            symbol: e.symbol,
                            description: e.description,
                        })
                        .collect(),
                });
            },
            confirm_rx,
        )
        .await;

        if let Some(h) = sync_handle {
            h.abort();
        }

        match result {
            Ok(()) => {
                let _ = sink.add(MxVerifyEvent::Done);
            }
            Err(e) => {
                let _ = sink.add(MxVerifyEvent::Cancelled {
                    reason: e.to_string(),
                });
            }
        }

        // sink is dropped here — FRB v2 closes the stream automatically.
    });
}

/// Respond to an active verification after seeing the emojis.
/// `confirmed = true` means the emojis match; `false` means mismatch.
#[frb]
pub async fn mx_confirm_verify(confirmed: bool) -> anyhow::Result<()> {
    let mut guard = mx_verify_slot().lock().await;
    let tx = guard
        .take()
        .ok_or_else(|| anyhow::anyhow!("No active verification"))?;
    tx.send(confirmed)
        .map_err(|_| anyhow::anyhow!("Verification already completed"))
}
