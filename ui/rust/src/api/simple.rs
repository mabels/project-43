use crate::frb_generated::StreamSink;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use flutter_rust_bridge::frb;
use p43::key_store::{keygen, store::KeyStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

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

/// One subkey inside an OpenPGP cert — role + algorithm + SSH key for display.
pub struct SubkeyInfo {
    /// Human-readable role string: "certify", "sign", "auth", "encrypt",
    /// "certify+sign", or combinations thereof.
    pub role: String,
    /// Algorithm name from OpenPGP, e.g. "RSA4096", "EdDSA", "ECDH".
    pub algo: String,
    /// OpenSSH `authorized_keys` line for this subkey, or `None` when the
    /// algorithm has no SSH equivalent (e.g. ECDH encryption keys).
    pub openssh_key: Option<String>,
}

/// A key entry returned to Dart — mirrors p43::key_store::store::KeyEntry.
pub struct KeyInfo {
    pub fingerprint: String,
    pub uid: String,
    pub algo: String,
    pub has_secret: bool,
    /// Whether this key is active in the SSH agent.
    pub enabled: bool,
    /// Application Identifier strings of YubiKeys registered against this key.
    /// Empty for pure soft keys.
    pub card_idents: Vec<String>,
    /// All subkeys (including primary) with their roles and algorithms.
    pub subkeys: Vec<SubkeyInfo>,
}

// ── Store-dir initialisation ──────────────────────────────────────────────────

/// Platform-provided store root (set once by Dart via path_provider).
/// Falls back to ~/.config/project-43/keys on platforms that have a home dir.
static STORE_DIR: OnceLock<PathBuf> = OnceLock::new();

// ── Pending sign map ──────────────────────────────────────────────────────────

/// Data held on the Rust side for an in-flight `ssh.sign_request`.
/// The Flutter layer only receives `fingerprint` and `description` for display;
/// `data` (base64) and `flags` are kept here and looked up on approval.
struct PendingSign {
    fingerprint: String,
    data_b64: String,
    flags: u32,
}

static PENDING_SIGNS: OnceLock<Mutex<HashMap<String, PendingSign>>> = OnceLock::new();

fn pending_signs() -> &'static Mutex<HashMap<String, PendingSign>> {
    PENDING_SIGNS.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Passphrase cache ──────────────────────────────────────────────────────────
//
// Keyed by SSH fingerprint (`SHA256:…`).  Lives in memory only — never written
// to disk.  A successful `mx_respond_sign` populates the cache; subsequent
// approvals for the same key skip the passphrase dialog.
//
// When biometric approval is added later, the biometric success path calls
// `mx_respond_sign_cached` directly — no changes to this Rust layer needed.

static PASSPHRASE_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn passphrase_cache() -> &'static Mutex<HashMap<String, String>> {
    PASSPHRASE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Card PIN cache ────────────────────────────────────────────────────────────
//
// Keyed by card AID ident string (e.g. `"0006:17684870"`).  Populated on a
// successful `mx_respond_sign_card`; cleared by `mx_clear_caches`.

static CARD_PIN_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn card_pin_cache() -> &'static Mutex<HashMap<String, String>> {
    CARD_PIN_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Signing-key cache ─────────────────────────────────────────────────────────
//
// Optional fast path: stores the 64-byte Ed25519 keypair (priv || pub) after
// the first successful passphrase-based sign.  Enabled only when the user opts
// in via Settings → "Cache decrypted key".
//
// When enabled, `mx_respond_sign_cached` skips the expensive KDF entirely —
// sign time drops from ~9 s to microseconds.  When disabled (default), the
// cache is empty and the slow passphrase path is used instead.
//
// Security note: the decrypted private key bytes live in process memory for
// the lifetime of the session, same as any secret manager agent would do.

static SIGNING_KEY_CACHE: OnceLock<Mutex<HashMap<String, Box<[u8; 64]>>>> = OnceLock::new();
static KEY_CACHE_ENABLED: AtomicBool = AtomicBool::new(false);

fn signing_key_cache() -> &'static Mutex<HashMap<String, Box<[u8; 64]>>> {
    SIGNING_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

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

fn subkeys_for(fingerprint: &str, store_dir: &std::path::Path) -> Vec<SubkeyInfo> {
    let ks = match p43::key_store::store::KeyStore::open(store_dir) {
        Ok(ks) => ks,
        Err(_) => return vec![],
    };
    ks.list_subkeys(fingerprint)
        .into_iter()
        .map(|m| SubkeyInfo {
            role: m.role,
            algo: m.algo,
            openssh_key: m.openssh_key,
        })
        .collect()
}

fn to_key_info(e: p43::key_store::store::KeyEntry, store_dir: &std::path::Path) -> KeyInfo {
    let subkeys = subkeys_for(&e.fingerprint, store_dir);
    KeyInfo {
        fingerprint: e.fingerprint,
        uid: e.uid,
        algo: e.algo,
        has_secret: e.has_secret,
        enabled: e.enabled,
        card_idents: e.card_idents,
        subkeys,
    }
}

// ── API ───────────────────────────────────────────────────────────────────────

/// Returns all keys in the local store (~/.config/project-43/keys).
#[frb]
pub fn list_keys() -> anyhow::Result<Vec<KeyInfo>> {
    let store_dir = default_store_dir();
    Ok(open_store()?
        .list()?
        .into_iter()
        .map(|e| to_key_info(e, &store_dir))
        .collect())
}

/// Verify that `passphrase` correctly decrypts the secret key at `fingerprint`.
///
/// Returns `Ok(())` on success, or an error whose message can be shown to
/// the user (e.g. "Failed to decrypt secret keys — wrong passphrase?").
#[frb]
pub fn verify_key_passphrase(fingerprint: String, passphrase: String) -> anyhow::Result<()> {
    open_store()?.find_with_secret(&fingerprint, &passphrase)?;
    Ok(())
}

/// Delete a key (public + secret files + index entry) from the local store.
#[frb]
pub fn delete_key(fingerprint: String) -> anyhow::Result<()> {
    open_store()?.delete(&fingerprint)?;
    Ok(())
}

/// Enable or disable a key in the SSH agent.
///
/// Disabled keys are not advertised by `ssh-add -l` and cannot be used
/// for signing.  The key files are not modified.
#[frb]
pub fn set_key_enabled(fingerprint: String, enabled: bool) -> anyhow::Result<()> {
    open_store()?.set_key_enabled(&fingerprint, enabled)?;
    Ok(())
}

/// Returns the armored OpenPGP public key for the given fingerprint.
#[frb]
pub fn get_public_key_armored(fingerprint: String) -> anyhow::Result<String> {
    let cert = open_store()?.find(&fingerprint)?;
    p43::key_store::store::export_pub(&cert)
}

/// Returns the OpenSSH `authorized_keys` line for the given fingerprint.
///
/// Uses the authentication subkey (falling back to the signing subkey).
#[frb]
pub fn get_public_key_openssh(fingerprint: String) -> anyhow::Result<String> {
    p43::ssh_agent::get_openssh_pubkey_string(&default_store_dir(), &fingerprint)
}

/// Key identity returned by [`get_ssh_key_details`].
pub struct SshKeyDetails {
    /// Human-readable UID, e.g. `"Alice <alice@example.com>"`.
    pub name: String,
    /// Algorithm string, e.g. `"ed25519"`, `"rsa4096"`.
    pub algo: String,
    /// AID ident strings of any OpenPGP cards (YubiKeys, etc.) associated
    /// with this key entry.  Empty for pure soft keys.
    pub card_idents: Vec<String>,
}

/// Resolve an SSH SHA-256 fingerprint (e.g. `SHA256:AbCd…`) to the key's
/// human-readable UID, algorithm, and associated card ident(s).
///
/// Returns `None` if no matching key is found.  Used by sign-request tiles and
/// the passphrase dialog to display key identity alongside the fingerprint.
#[frb]
pub fn get_ssh_key_details(fingerprint: String) -> Option<SshKeyDetails> {
    let store_dir = default_store_dir();
    p43::ssh_agent::get_ssh_key_meta(&store_dir, &fingerprint).map(|m| SshKeyDetails {
        name: m.uid,
        algo: m.algo,
        card_idents: m.card_idents,
    })
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
    let store_dir = default_store_dir();
    Ok(ks
        .list()?
        .into_iter()
        .map(|e| to_key_info(e, &store_dir))
        .collect())
}

// ── Card (PC/SC) ──────────────────────────────────────────────────────────────

/// Summary of a connected OpenPGP card returned by [list_connected_cards].
pub struct ConnectedCardInfo {
    pub ident: String,
    pub cardholder_name: String,
    pub sig_fingerprint: Option<String>,
    pub auth_fingerprint: Option<String>,
}

/// Return a summary of every connected OpenPGP card (no PIN required).
///
/// On macOS the system PC/SC daemon handles the transport; no additional
/// setup is needed.  Returns an empty list when no cards are present.
#[frb]
pub fn list_connected_cards() -> anyhow::Result<Vec<ConnectedCardInfo>> {
    Ok(p43::pkcs11::card::list_connected_cards()?
        .into_iter()
        .map(|c| ConnectedCardInfo {
            ident: c.ident,
            cardholder_name: c.cardholder_name,
            sig_fingerprint: c.sig_fingerprint,
            auth_fingerprint: c.auth_fingerprint,
        })
        .collect())
}

/// Import a key from a connected OpenPGP card into the local key store.
///
/// Reads the signing-slot public key, uses the card to self-certify the UID
/// binding, saves `<fingerprint>.pub.asc` and `<fingerprint>.card.json`, and
/// returns the updated key list.
///
/// - `card_ident`: AID ident string from [list_connected_cards].
/// - `uid`: user ID string for the cert (e.g. `"Alice <alice@example.com>"`).
///   Pass the empty string to fall back to the cardholder name on the card.
/// - `pin`: card User Signing PIN (unlocks the SIG slot).
#[frb]
pub fn import_card(card_ident: String, uid: String, pin: String) -> anyhow::Result<Vec<KeyInfo>> {
    let ks = open_store()?;
    let uid_opt = if uid.is_empty() {
        None
    } else {
        Some(uid.as_str())
    };
    p43::pkcs11::import_card::import_card_cert(&ks, Some(&card_ident), uid_opt, &pin)?;
    let store_dir = default_store_dir();
    Ok(ks
        .list()?
        .into_iter()
        .map(|e| to_key_info(e, &store_dir))
        .collect())
}

/// Import an OpenSSH private key file into the local key store as an OpenPGP
/// cert.
///
/// - `pem_bytes`: raw contents of the `id_ed25519` / `id_rsa` file.
/// - `uid_override`: UID string (e.g. `"Alice <alice@example.com>"`).  Pass the
///   empty string to derive from the SSH key's comment field.
/// - `ssh_passphrase`: passphrase that protects the SSH file itself (if any).
/// - `openpgp_passphrase`: passphrase to encrypt the stored OpenPGP secret key.
///   Pass `None` to store the key unencrypted (only do this on a secure device).
///
/// Returns the hex fingerprint of the newly imported cert and the updated key
/// list.
#[frb]
pub fn import_ssh_key(
    pem_bytes: Vec<u8>,
    uid_override: String,
    ssh_passphrase: Option<String>,
    openpgp_passphrase: Option<String>,
) -> anyhow::Result<Vec<KeyInfo>> {
    let ks = open_store()?;
    let uid_opt = if uid_override.is_empty() {
        None
    } else {
        Some(uid_override.as_str())
    };
    p43::key_store::import_ssh::import_ssh_private_key(
        &ks,
        &pem_bytes,
        uid_opt,
        ssh_passphrase.as_deref(),
        openpgp_passphrase.as_deref(),
    )?;
    let store_dir = default_store_dir();
    Ok(ks
        .list()?
        .into_iter()
        .map(|e| to_key_info(e, &store_dir))
        .collect())
}

/// Import an armored OpenPGP private key (TSK) into the local key store.
///
/// `armored` is the full text of a `-----BEGIN PGP PRIVATE KEY BLOCK-----`
/// message.  The passphrase (if any) is not required at import time.
///
/// Returns the updated key list.
#[frb]
pub fn import_openpgp_key(armored: String) -> anyhow::Result<Vec<KeyInfo>> {
    let ks = open_store()?;
    p43::key_store::import_ssh::import_openpgp_private_key(&ks, armored.as_bytes())?;
    let store_dir = default_store_dir();
    Ok(ks
        .list()?
        .into_iter()
        .map(|e| to_key_info(e, &store_dir))
        .collect())
}

/// Register a YubiKey (or other OpenPGP card) AID with a key entry.
///
/// Creates or updates `<fingerprint>.card.json` in the key store.  The same
/// key can be associated with multiple card AIDs — useful when a user has two
/// identical-content YubiKeys.
///
/// `card_ident` should be the AID string shown by `p43 key list --verbose`
/// or returned by `tx.application_identifier()?.ident()` in the card layer.
#[frb]
pub fn register_card_ident(fingerprint: String, card_ident: String) -> anyhow::Result<()> {
    open_store()?.register_card(&fingerprint, &card_ident)
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
        let _ = p43::matrix::global::listen_room(
            &room_id,
            None,
            |_| {},
            move |sender, body| {
                let _ = sink.add(MxMessage { sender, body });
            },
        )
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
///
/// On startup the last persisted `agent_since` token (if any) is loaded from
/// `matrix-config.json` and passed to the sync so old messages are not replayed.
/// The token is saved on **every** sync batch so it survives process kills and
/// crashes — no history replay on reconnect regardless of how the app exited.
#[frb]
pub fn mx_listen_agent(room_id: String, sink: StreamSink<AgentRequest>) {
    tokio_rt().spawn(async move {
        // Load the persisted since-token for this room, if any.
        let since: Option<String> = (|| -> Option<String> {
            let store_dir = STORE_DIR.get()?;
            let cfg = p43::matrix::MatrixConfig::from_store_dir(store_dir);
            let saved = p43::matrix::client::load_config(&cfg.config_path).ok()??;
            saved.agent_since
        })();

        // Save the token to disk on every sync batch so reconnects never
        // replay messages that have already been seen, even after a crash.
        let pointer_store_dir = STORE_DIR.get().cloned();
        let on_pointer = move |token: String| {
            let Some(ref store_dir) = pointer_store_dir else {
                return;
            };
            let cfg = p43::matrix::MatrixConfig::from_store_dir(store_dir);
            let Ok(Some(mut saved)) = p43::matrix::client::load_config(&cfg.config_path) else {
                return;
            };
            saved.agent_since = Some(token);
            let _ = p43::matrix::client::save_config(&saved, &cfg.config_path);
        };

        let _ = p43::matrix::global::listen_room(
            &room_id,
            since.as_deref(),
            on_pointer,
            move |_sender, body| {
                let event = match p43::protocol::Message::from_json(&body) {
                    Ok(p43::protocol::Message::SshListKeysRequest(r)) => {
                        Some(AgentRequest::ListKeys {
                            request_id: r.request_id,
                        })
                    }
                    Ok(p43::protocol::Message::SshSignRequest(r)) => {
                        // Store signing payload so Flutter can approve later.
                        if let Ok(mut map) = pending_signs().lock() {
                            map.insert(
                                r.request_id.clone(),
                                PendingSign {
                                    fingerprint: r.fingerprint.clone(),
                                    data_b64: r.data.clone(),
                                    flags: r.flags,
                                },
                            );
                        }
                        Some(AgentRequest::Sign {
                            request_id: r.request_id,
                            fingerprint: r.fingerprint,
                            description: r.description,
                        })
                    }
                    _ => None,
                };
                if let Some(ev) = event {
                    let _ = sink.add(ev);
                }
            },
        )
        .await;
    });
}

/// Respond to an `ssh.list_keys_request` with the keys held in the local store.
#[frb]
pub async fn mx_respond_list_keys(room_id: String, request_id: String) -> anyhow::Result<()> {
    let store_dir = default_store_dir();
    let keys = p43::ssh_agent::list_ssh_public_keys(&store_dir);
    let json = p43::protocol::Message::SshListKeysResponse(p43::protocol::SshListKeysResponse {
        request_id,
        keys,
    })
    .to_json()?;
    p43::matrix::global::send_message(&room_id, &json).await
}

/// Returns `true` if cached credentials exist for the given SSH fingerprint,
/// meaning `mx_respond_sign_cached` can proceed without a passphrase dialog.
///
/// Returns `true` when either:
/// - A decrypted keypair is cached (key-cache enabled) → fast, microseconds.
/// - A passphrase is cached (key-cache disabled) → slow, re-runs KDF (~9 s).
///
/// Dart uses this to decide whether to auto-approve or show the dialog.
/// When biometric approval is added, this is also the gate for whether
/// biometric confirmation suffices or the user must type their passphrase.
#[frb]
pub fn has_cached_passphrase(fingerprint: String) -> bool {
    let has_key = signing_key_cache()
        .lock()
        .map(|m| m.contains_key(&fingerprint))
        .unwrap_or(false);
    let has_passphrase = passphrase_cache()
        .lock()
        .map(|m| m.contains_key(&fingerprint))
        .unwrap_or(false);
    // RSA keys are too large for the 64-byte Ed25519 slot; they have their own cache.
    let has_rsa_key = p43::ssh_agent::has_cached_rsa_key(&fingerprint);
    has_key || has_passphrase || has_rsa_key
}

/// Enable or disable the in-memory signing-key cache.
///
/// When `enabled`:
/// - `mx_respond_sign` extracts and caches the decrypted Ed25519 keypair bytes
///   so subsequent `mx_respond_sign_cached` calls skip the KDF entirely.
///
/// When `disabled`:
/// - The signing-key cache is cleared immediately.
/// - `mx_respond_sign_cached` falls back to the passphrase cache + KDF.
///
/// Call at startup with the persisted setting value, and again whenever the
/// user toggles the setting.
#[frb]
pub fn mx_set_cache_key_enabled(enabled: bool) {
    KEY_CACHE_ENABLED.store(enabled, Ordering::Relaxed);
    if !enabled {
        if let Ok(mut cache) = signing_key_cache().lock() {
            cache.clear();
        }
    }
}

/// Clear all in-memory credential caches (passphrase + signing key).
///
/// Does **not** affect the `KEY_CACHE_ENABLED` flag — the next successful
/// `mx_respond_sign` will repopulate the caches if caching is still enabled.
///
/// Call when the configured session timeout expires or the screen locks.
#[frb]
pub fn mx_clear_caches() {
    if let Ok(mut cache) = passphrase_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = signing_key_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = card_pin_cache().lock() {
        cache.clear();
    }
    p43::ssh_agent::clear_rsa_key_cache();
}

/// Approve an `ssh.sign_request` using an explicitly supplied passphrase.
///
/// On success:
/// - The passphrase is stored in the in-memory cache (slow fallback path).
/// - If "cache decrypted key" is enabled, the decrypted Ed25519 keypair bytes
///   are also cached so subsequent auto-approve signs skip the KDF entirely.
#[frb]
pub async fn mx_respond_sign(
    room_id: String,
    request_id: String,
    passphrase: String,
) -> anyhow::Result<()> {
    // Remove from pending map — consume the request exactly once.
    let pending = pending_signs()
        .lock()
        .map_err(|e| anyhow::anyhow!("pending-sign lock poisoned: {e}"))?
        .remove(&request_id)
        .ok_or_else(|| anyhow::anyhow!("Unknown or already-handled request_id {request_id}"))?;

    let store_dir = default_store_dir();
    let data = B64
        .decode(&pending.data_b64)
        .map_err(|e| anyhow::anyhow!("Bad base64 in sign request: {e}"))?;

    let signature_b64 = if KEY_CACHE_ENABLED.load(Ordering::Relaxed) {
        // Extract and cache the keypair bytes while we're decrypting anyway.
        // RSA keys return None (too large for the 64-byte slot); they fall
        // back to the passphrase cache for subsequent auto-approvals.
        let (sig, keypair_bytes) = p43::ssh_agent::sign_with_soft_key_and_extract(
            &store_dir,
            &pending.fingerprint,
            &passphrase,
            &data,
        )?;
        if let (Ok(mut cache), Some(bytes)) = (signing_key_cache().lock(), keypair_bytes) {
            cache.insert(pending.fingerprint.clone(), Box::new(bytes));
        }
        sig
    } else {
        p43::ssh_agent::sign_with_soft_key(&store_dir, &pending.fingerprint, &passphrase, &data)?
    };

    // Always cache the passphrase as a fallback for when key-cache is later disabled.
    if let Ok(mut cache) = passphrase_cache().lock() {
        cache.insert(pending.fingerprint, passphrase);
    }

    let json = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
        request_id,
        signature: signature_b64,
    })
    .to_json()?;
    p43::matrix::global::send_message(&room_id, &json).await
}

/// Approve an `ssh.sign_request` for a card-backed key using the card's User PIN.
///
/// The card's AUTH slot is used for signing (same slot the SSH agent uses).
/// The User PIN (typically 6+ digits on YubiKey) unlocks the AUTH slot — it
/// is NOT the Admin PIN or the Signing PIN.
///
/// On success the PIN is cached in memory keyed by card AID ident so that
/// `mx_respond_sign_card_cached` can skip the PIN dialog for subsequent requests.
#[frb]
pub async fn mx_respond_sign_card(
    room_id: String,
    request_id: String,
    pin: String,
) -> anyhow::Result<()> {
    let pending = pending_signs()
        .lock()
        .map_err(|e| anyhow::anyhow!("pending-sign lock poisoned: {e}"))?
        .remove(&request_id)
        .ok_or_else(|| anyhow::anyhow!("Unknown or already-handled request_id {request_id}"))?;

    let store_dir = default_store_dir();
    let data = B64
        .decode(&pending.data_b64)
        .map_err(|e| anyhow::anyhow!("Bad base64 in sign request: {e}"))?;

    let signature_b64 = p43::ssh_agent::sign_with_card_key(
        &store_dir,
        &pending.fingerprint,
        &pin,
        &data,
        pending.flags,
    )?;

    // Cache the PIN keyed by each card AID associated with this fingerprint.
    if let Some(meta) = p43::ssh_agent::get_ssh_key_meta(&store_dir, &pending.fingerprint) {
        if let Ok(mut cache) = card_pin_cache().lock() {
            for ident in &meta.card_idents {
                cache.insert(ident.clone(), pin.clone());
            }
        }
    }

    let json = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
        request_id,
        signature: signature_b64,
    })
    .to_json()?;
    p43::matrix::global::send_message(&room_id, &json).await
}

/// Returns `true` if a cached PIN exists for the given card AID ident,
/// meaning `mx_respond_sign_card_cached` can proceed without a PIN dialog.
///
/// `card_ident` is one of the strings from `KeyInfo.cardIdents`.
#[frb]
pub fn has_cached_card_pin(card_ident: String) -> bool {
    card_pin_cache()
        .lock()
        .map(|m| m.contains_key(&card_ident))
        .unwrap_or(false)
}

/// Approve an `ssh.sign_request` for a card-backed key using a cached PIN.
///
/// Returns an error if no PIN is cached for any card associated with this key.
/// This is the auto-approve path after the first successful `mx_respond_sign_card`.
#[frb]
pub async fn mx_respond_sign_card_cached(
    room_id: String,
    request_id: String,
) -> anyhow::Result<()> {
    let pending = pending_signs()
        .lock()
        .map_err(|e| anyhow::anyhow!("pending-sign lock poisoned: {e}"))?
        .remove(&request_id)
        .ok_or_else(|| anyhow::anyhow!("Unknown or already-handled request_id {request_id}"))?;

    let store_dir = default_store_dir();
    let data = B64
        .decode(&pending.data_b64)
        .map_err(|e| anyhow::anyhow!("Bad base64 in sign request: {e}"))?;

    // Resolve card idents for this fingerprint, then look up a cached PIN.
    let meta = p43::ssh_agent::get_ssh_key_meta(&store_dir, &pending.fingerprint)
        .ok_or_else(|| anyhow::anyhow!("No key metadata found for fingerprint"))?;

    let pin = {
        let cache = card_pin_cache()
            .lock()
            .map_err(|e| anyhow::anyhow!("card PIN cache lock poisoned: {e}"))?;
        meta.card_idents
            .iter()
            .find_map(|id| cache.get(id).cloned())
            .ok_or_else(|| anyhow::anyhow!("No cached PIN for this card — enter PIN first"))?
    };

    let signature_b64 = p43::ssh_agent::sign_with_card_key(
        &store_dir,
        &pending.fingerprint,
        &pin,
        &data,
        pending.flags,
    )?;

    let json = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
        request_id,
        signature: signature_b64,
    })
    .to_json()?;
    p43::matrix::global::send_message(&room_id, &json).await
}

/// Return the number of User PIN attempts remaining for a connected YubiKey /
/// OpenPGP card.  No PIN is required — this only reads PW status bytes.
///
/// `card_ident` is one of the strings from `KeyInfo.cardIdents`
/// (e.g. `"0006:17684870"`).  Returns an error if no card with that ident is
/// currently connected or accessible.
#[frb]
pub fn get_card_pin_retries(card_ident: String) -> anyhow::Result<u8> {
    p43::pkcs11::card::card_pin_retries(Some(&card_ident))
}

/// Approve an `ssh.sign_request` without a passphrase dialog.
///
/// Fast path: if a decrypted keypair is cached (key-cache enabled and at least
/// one prior `mx_respond_sign` succeeded), signs in microseconds.
///
/// Slow fallback: if only the passphrase is cached, re-runs the KDF (~9 s on
/// a Mac; same cost as a fresh `mx_respond_sign`).
///
/// Returns an error if neither cache has an entry for this key.
///
/// This is also the entry point for biometric-gated approval: once the
/// platform biometric check succeeds, call this directly.
#[frb]
pub async fn mx_respond_sign_cached(room_id: String, request_id: String) -> anyhow::Result<()> {
    let pending = pending_signs()
        .lock()
        .map_err(|e| anyhow::anyhow!("pending-sign lock poisoned: {e}"))?
        .remove(&request_id)
        .ok_or_else(|| anyhow::anyhow!("Unknown or already-handled request_id {request_id}"))?;

    let data = B64
        .decode(&pending.data_b64)
        .map_err(|e| anyhow::anyhow!("Bad base64 in sign request: {e}"))?;

    // ── Fast path 1: cached decrypted RSA key (zero-KDF for RSA keys) ─────────
    if p43::ssh_agent::has_cached_rsa_key(&pending.fingerprint) {
        let signature_b64 = p43::ssh_agent::sign_rsa_cached(&pending.fingerprint, &data)?;
        let json = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
            request_id,
            signature: signature_b64,
        })
        .to_json()?;
        return p43::matrix::global::send_message(&room_id, &json).await;
    }

    // ── Fast path 2: cached decrypted Ed25519 keypair ─────────────────────────
    let cached_keypair: Option<Box<[u8; 64]>> = signing_key_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.get(&pending.fingerprint).cloned());

    let signature_b64 = if let Some(keypair_bytes) = cached_keypair {
        p43::ssh_agent::sign_with_cached_keypair(&keypair_bytes, &data)?
    } else {
        // ── Slow fallback: re-run KDF with cached passphrase ─────────────────
        let passphrase = passphrase_cache()
            .lock()
            .map_err(|e| anyhow::anyhow!("passphrase cache lock poisoned: {e}"))?
            .get(&pending.fingerprint)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No cached passphrase for this key"))?;

        let store_dir = default_store_dir();
        p43::ssh_agent::sign_with_soft_key(&store_dir, &pending.fingerprint, &passphrase, &data)?
    };

    let json = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
        request_id,
        signature: signature_b64,
    })
    .to_json()?;

    p43::matrix::global::send_message(&room_id, &json).await
}

/// Reject an `ssh.sign_request`: send an error response and discard the request.
#[frb]
pub async fn mx_reject_sign(room_id: String, request_id: String) -> anyhow::Result<()> {
    // Discard from pending map.
    let _ = pending_signs()
        .lock()
        .ok()
        .and_then(|mut m| m.remove(&request_id));

    let json = p43::protocol::Message::Error(p43::protocol::ErrorResponse {
        request_id: Some(request_id),
        message: "User rejected the sign request".into(),
    })
    .to_json()?;

    p43::matrix::global::send_message(&room_id, &json).await
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
