use crate::frb_generated::StreamSink;
use anyhow::Context as _;
use base64::Engine as _;
use flutter_rust_bridge::frb;
use p43::bus::BusSigner as _;
use p43::key_store::{keygen, store::KeyStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc;

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

// ── Telemetry ─────────────────────────────────────────────────────────────────

/// Initialise tracing.
///
/// Pass an empty string for **local mode** (fmt output, zero network overhead).
/// Pass `"https://otel.adviser.com"` to export spans to the OTel Collector.
///
/// If the endpoint is unreachable the SDK retries silently and drops spans
/// after the retry budget — the app is never blocked.
///
/// Compiled as a no-op when the `p43` library is built without
/// `--features telemetry`.
#[frb]
pub fn init_telemetry(endpoint: String) -> anyhow::Result<()> {
    // Enter our static runtime so the OTel batch exporter can spawn its
    // background task inside it.
    let _guard = tokio_rt().enter();
    p43::telemetry::init(&endpoint)
}

/// Shut down the OTel provider and flush all pending spans.
/// Call before the app exits.
#[frb]
pub fn shutdown_telemetry() {
    p43::telemetry::shutdown();
}

/// Inject a W3C `traceparent` header for the current thread.
///
/// Dart should call this **immediately before** any FRB function that creates
/// a tracing span, then call [clearActiveTraceparent] once the call returns.
/// This stitches the Flutter span tree and the Rust span tree into a single
/// distributed trace in Jaeger.
///
/// The value must follow the W3C Trace Context format:
/// `00-<trace-id-32hex>-<parent-id-16hex>-<flags-2hex>`
#[frb]
pub fn set_active_traceparent(traceparent: String) {
    p43::telemetry::set_active_traceparent(traceparent);
}

/// Clear the stored traceparent for the current thread.
/// Call after every FRB call that was preceded by [setActiveTraceparent].
#[frb]
pub fn clear_active_traceparent() {
    p43::telemetry::clear_active_traceparent();
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
/// `data` and `flags` are kept here and looked up on approval.
struct PendingSign {
    fingerprint: String,
    data: Vec<u8>,
    flags: u32,
    /// Sender's verified [`p43::bus::CertPayload`] when the request arrived
    /// inside a `BusSecure` envelope.  Used to encrypt the response back to
    /// the requesting device.  `None` for plaintext requests (legacy / tests).
    sender_cert: Option<p43::bus::CertPayload>,
}

static PENDING_SIGNS: OnceLock<Mutex<HashMap<String, PendingSign>>> = OnceLock::new();

fn pending_signs() -> &'static Mutex<HashMap<String, PendingSign>> {
    PENDING_SIGNS.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Credential cache ──────────────────────────────────────────────────────────
//
// Unified store for PINs and passphrases.  Keyed by:
//   - OpenPGP hex fingerprint for soft keys
//   - Card AID ident (e.g. `"0006:17684870"`) for card keys
//
// Default timeout: 15 minutes (mirrors AgentSettings.cacheTimeoutMinutes).
// Call `credential_cache_set_timeout` whenever the setting changes.
//
// `get` resets the sliding-window expiry timer; `peek` does not.
// `purge` is called by `lock_all` (screen-lock / global lock button).
//
// Designed for biometric protection: a future revision will seal each
// entry with a biometric-unlocked key — the public API is unchanged.

static CREDENTIAL_CACHE: OnceLock<Mutex<p43::credential_cache::CredentialCache>> = OnceLock::new();

fn credential_cache() -> &'static Mutex<p43::credential_cache::CredentialCache> {
    CREDENTIAL_CACHE
        .get_or_init(|| Mutex::new(p43::credential_cache::CredentialCache::new(15 * 60u32)))
}

// ── Authority session ─────────────────────────────────────────────────────────
//
// The unlocked authority key + its COSE_Sign1 cert bytes.  Held in memory so
// incoming `BusSecure` messages can be decrypted without a passphrase prompt
// and outgoing responses can be sealed before sending.
//
// Cleared by `bus_lock_session` and `mx_clear_caches`.

type AuthoritySession = Mutex<Option<(p43::bus::AuthorityKey, Vec<u8>)>>;
static AUTHORITY_SESSION: OnceLock<AuthoritySession> = OnceLock::new();

fn authority_session() -> &'static Mutex<Option<(p43::bus::AuthorityKey, Vec<u8>)>> {
    AUTHORITY_SESSION.get_or_init(|| Mutex::new(None))
}

// ── Outbound queue sender ─────────────────────────────────────────────────────
//
// Populated by `mx_listen_all` when the bridge is set up.  All `mx_respond_*`
// functions send through here so that encryption is handled by the worker task
// rather than inline.  Protected by a Mutex so it can be replaced on reconnect.

static OUTBOUND_TX: OnceLock<Mutex<Option<mpsc::Sender<p43::bus::OutboundBusMessage>>>> =
    OnceLock::new();

fn outbound_tx_cell() -> &'static Mutex<Option<mpsc::Sender<p43::bus::OutboundBusMessage>>> {
    OUTBOUND_TX.get_or_init(|| Mutex::new(None))
}

// ── External bus sender (for locked-message replay) ───────────────────────────
//
// A clone of the external-bus broadcast sender kept so that `bus_unlock_session`
// can re-inject `BusSecure` messages that arrived while the session was locked.

static EXTERNAL_TX: OnceLock<
    Mutex<Option<tokio::sync::broadcast::Sender<p43::bus::ExternalBusMessage>>>,
> = OnceLock::new();

fn external_tx_cell(
) -> &'static Mutex<Option<tokio::sync::broadcast::Sender<p43::bus::ExternalBusMessage>>> {
    EXTERNAL_TX.get_or_init(|| Mutex::new(None))
}

// ── Locked-message queue ──────────────────────────────────────────────────────
//
// `BusSecure` messages that arrived while the authority session was locked are
// pushed here by the `on_locked` callback in `mx_listen_all`.
// `bus_unlock_session` drains this queue and replays each message onto the
// external bus so the full decrypt → internal-bus → AppMessage pipeline runs.

static LOCKED_MSG_QUEUE: OnceLock<Mutex<std::collections::VecDeque<p43::bus::ExternalBusMessage>>> =
    OnceLock::new();

fn locked_msg_queue() -> &'static Mutex<std::collections::VecDeque<p43::bus::ExternalBusMessage>> {
    LOCKED_MSG_QUEUE.get_or_init(|| Mutex::new(std::collections::VecDeque::new()))
}

// ── Pending list-keys map ─────────────────────────────────────────────────────
//
// Keyed by `request_id` of an in-flight `ssh.list_keys_request`.  Stores the
// sender cert (if the request arrived encrypted) so the response can be sealed.

static PENDING_LIST_KEYS: OnceLock<Mutex<HashMap<String, Option<p43::bus::CertPayload>>>> =
    OnceLock::new();

fn pending_list_keys() -> &'static Mutex<HashMap<String, Option<p43::bus::CertPayload>>> {
    PENDING_LIST_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
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

// ── Message age filter ────────────────────────────────────────────────────────
//
// Maximum age of messages that the UI will process, in hours.
// Messages older than this are silently dropped before they reach the bus.
// Default: 8 h.  Controlled by the Settings screen.

static MESSAGE_MAX_AGE_HOURS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(8);

fn signing_key_cache() -> &'static Mutex<HashMap<String, Box<[u8; 64]>>> {
    SIGNING_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Must be called once from Dart before any key operation.
/// Pass `getApplicationSupportDirectory().path` (or equivalent).
#[frb]
pub fn set_store_dir(dir: String) {
    let _ = STORE_DIR.set(PathBuf::from(dir).join("keys"));
}

// ── Listener stop signal ──────────────────────────────────────────────────────
//
// Each `mx_listen_all` invocation creates a fresh `Arc<Notify>` and stores it
// here.  `mx_force_reconnect` fires the notify, which causes `tokio::select!`
// inside `mx_listen_all` to break the listener loop.  The normal teardown
// path then runs, the FRB stream closes, and Dart's `onDone` fires
// `_scheduleReconnect` — which re-enters `mx_listen_all` with the latest
// persisted pointer so no messages are missed.

static LISTENER_STOP: OnceLock<Mutex<std::sync::Arc<tokio::sync::Notify>>> = OnceLock::new();

fn listener_stop_cell() -> &'static Mutex<std::sync::Arc<tokio::sync::Notify>> {
    LISTENER_STOP.get_or_init(|| Mutex::new(std::sync::Arc::new(tokio::sync::Notify::new())))
}

/// Signal the running Matrix listener to stop immediately.
///
/// Dart calls this from `didChangeAppLifecycleState(resumed)` so that messages
/// that arrived while the app was backgrounded are caught up on reconnect.
/// The listener tears down, the FRB stream fires `onDone`, and
/// `_scheduleReconnect` re-opens the connection with the last saved pointer.
#[frb]
pub fn mx_force_reconnect() {
    if let Ok(guard) = listener_stop_cell().lock() {
        guard.notify_one();
    }
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
#[cfg_attr(feature = "telemetry", tracing::instrument)]
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

/// Returns the armored OpenPGP private key for `fingerprint`.
///
/// `passphrase` must match the key's stored passphrase (or be empty for
/// unencrypted keys).  Verification is performed before returning the armor so
/// that the caller knows the passphrase is correct before writing to disk.
#[frb]
pub fn get_private_key_armored(fingerprint: String, passphrase: String) -> anyhow::Result<String> {
    // find_with_secret verifies the passphrase and returns Err on mismatch.
    let key = open_store()?.find_with_secret(&fingerprint, &passphrase)?;
    p43::key_store::store::export_priv(&key)
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
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(passphrase), fields(uid, algo))
)]
pub fn generate_key(
    uid: String,
    algo: String,
    passphrase: Option<String>,
) -> anyhow::Result<Vec<KeyInfo>> {
    let ks = open_store()?;
    let cert = keygen::generate(&uid, &algo, passphrase.as_deref())?;
    ks.save_secret(&cert)?;
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
///
/// Not available on Android / iOS (no PC/SC subsystem) — returns an empty list.
#[frb]
pub fn list_connected_cards() -> anyhow::Result<Vec<ConnectedCardInfo>> {
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        return Ok(p43::pkcs11::card::list_connected_cards()?
            .into_iter()
            .map(|c| ConnectedCardInfo {
                ident: c.ident,
                cardholder_name: c.cardholder_name,
                sig_fingerprint: c.sig_fingerprint,
                auth_fingerprint: c.auth_fingerprint,
            })
            .collect());
    }
    Ok(vec![])
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
///
/// Not available on Android / iOS (no PC/SC subsystem).
#[frb]
pub fn import_card(card_ident: String, uid: String, pin: String) -> anyhow::Result<Vec<KeyInfo>> {
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let ks = open_store()?;
        let uid_opt = if uid.is_empty() {
            None
        } else {
            Some(uid.as_str())
        };
        p43::pkcs11::import_card::import_card_cert(&ks, Some(&card_ident), uid_opt, &pin)?;
        let store_dir = default_store_dir();
        return Ok(ks
            .list()?
            .into_iter()
            .map(|e| to_key_info(e, &store_dir))
            .collect());
    }
    #[cfg(any(target_os = "ios", target_os = "android"))]
    anyhow::bail!("PC/SC card operations are not supported on this platform")
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
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(password), fields(homeserver, username))
)]
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
#[cfg_attr(feature = "telemetry", tracing::instrument)]
pub async fn mx_restore() -> anyhow::Result<bool> {
    p43::matrix::global::restore(&mx_store_dir()?).await
}

/// Logout and delete the local session.
#[frb]
#[cfg_attr(feature = "telemetry", tracing::instrument)]
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
    p43::matrix::global::send_message(&room_id, &text)
        .await
        .map(|_| ())
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
            move |sender, body, _ts_ms, _event_id| {
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
        /// Label from the sender's bus certificate (empty if unauthenticated).
        device_label: String,
        /// Stable device identifier from the sender's bus certificate (empty if unauthenticated).
        device_id: String,
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

/// Respond to an `ssh.list_keys_request` with the keys held in the local store.
#[frb]
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(fields(request_id, room_id))
)]
pub async fn mx_respond_list_keys(room_id: String, request_id: String) -> anyhow::Result<()> {
    // Consume the sender cert so the response can be sealed if available.
    let sender_cert = pending_list_keys()
        .lock()
        .ok()
        .and_then(|mut m| m.remove(&request_id))
        .flatten();

    let store_dir = default_store_dir();
    let keys = p43::ssh_agent::list_ssh_public_keys(&store_dir);
    let response =
        p43::protocol::Message::SshListKeysResponse(p43::protocol::SshListKeysResponse {
            request_id,
            keys,
        });
    send_via_bridge(&room_id, response, sender_cert).await
}

// ── Bus registration (authority side) ────────────────────────────────────────

/// A pending device registration request surfaced from the Matrix room.
#[derive(Clone)]
pub struct BusCsrEvent {
    pub request_id: String,
    pub device_label: String,
    pub device_id: String,
    /// Base64-encoded COSE_Sign1 CSR bytes — passed back to mx_respond_csr.
    pub csr_b64: String,
}

/// Unified app-level event emitted by [`mx_listen_all`].
///
/// The Flutter root shell subscribes once and fans out to per-screen broadcast
/// `StreamController`s:
/// - [`AppMessage::AgentEvent`] → `AgentScreen`
/// - [`AppMessage::BusEvent`]   → `DevicesScreen`
/// - [`AppMessage::SessionLockRequired`] → root shell (switch to Devices tab)
#[derive(Clone)]
pub enum AppMessage {
    /// An SSH-agent protocol event (list-keys or sign request).
    AgentEvent { event: AgentRequest },
    /// A bus device-registration CSR event.
    BusEvent { event: BusCsrEvent },
    /// A `BusSecure` message arrived but the authority session is locked.
    /// The UI should navigate to Devices → Authority so the user can unlock.
    SessionLockRequired,
}

/// Subscribe to **all** p43 protocol messages in `room_id` with a single
/// Matrix sync loop.
///
/// Replaces the pair `mx_listen_agent` + `mx_listen_bus`.  The Flutter root
/// shell subscribes once here and fans out:
///   [`AppMessage::AgentEvent`] → `AgentScreen`
///   [`AppMessage::BusEvent`]   → `DevicesScreen`
///
/// Internally sets up the two-layer bus bridge:
///   - Raw Matrix messages → **external bus** (broadcast)
///   - Decrypt middleware → **internal bus** (broadcast, plaintext)
///   - Application dispatcher subscribes to internal bus → `AppMessage` stream
///   - **Outbound queue** (mpsc) → encrypt worker → Matrix send
///
/// The `agent_since` pointer (persisted in `matrix-config.json`) is respected
/// and updated on every sync batch so reconnects never replay seen messages.
#[allow(clippy::question_mark)]
#[frb]
pub fn mx_listen_all(room_id: String, sink: StreamSink<AppMessage>) {
    tokio_rt().spawn(async move {
        // ── Since token ───────────────────────────────────────────────────────
        //
        // Each reader (cli, ui) has its own pointer file so they never consume
        // each other's cursor.  Layout:
        //   <store_root>/app-state/<device_id>/ui.json → { "<room_id>": "<token>" }
        let ptr_store: Option<std::sync::Arc<p43::matrix::RoomPointerStore>> = (|| {
            let store_dir = STORE_DIR.get()?;
            let store_root = store_dir.parent()?;
            let cfg = p43::matrix::MatrixConfig::from_store_dir(store_dir);
            let device_id = p43::matrix::device_id_from_config(&cfg.config_path).ok()?;
            Some(std::sync::Arc::new(p43::matrix::RoomPointerStore::new(
                store_root,
                &device_id,
                "ui",
            )))
        })();

        let since: Option<String> = ptr_store
            .as_ref()
            .and_then(|s| s.get(&room_id));

        match &since {
            Some(token) => eprintln!("[p43::bridge] Resuming from pointer: {token}"),
            None => eprintln!("[p43::bridge] No stored pointer — replaying full room history"),
        }

        // Throttle pointer writes to at most once every 60 s to save
        // flash I/O and battery on iOS/Android.
        let pointer_last_write: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let on_pointer = {
            let last_write = std::sync::Arc::clone(&pointer_last_write);
            let room_id_for_ptr = room_id.clone();
            move |token: String| {
                let Some(ref store) = ptr_store else { return };
                let Ok(mut guard) = last_write.lock() else { return };
                let due = match *guard {
                    None => true,
                    Some(t) => t.elapsed() >= std::time::Duration::from_secs(60),
                };
                if !due { return; }
                if store.set(&room_id_for_ptr, &token).is_ok() {
                    *guard = Some(std::time::Instant::now());
                }
            }
        };

        // ── Bridge channels ───────────────────────────────────────────────────
        let (external_tx, external_rx) = p43::bus::new_external_bus();
        let (internal_tx, _initial_rx) = p43::bus::new_internal_bus();
        let (outbound_tx, outbound_rx) = p43::bus::new_outbound_queue();

        // Store the outbound sender so respond functions can enqueue responses.
        if let Ok(mut guard) = outbound_tx_cell().lock() {
            *guard = Some(outbound_tx);
        }

        // Store the external bus sender so bus_unlock_session can replay
        // messages that arrived while the session was locked.
        if let Ok(mut guard) = external_tx_cell().lock() {
            *guard = Some(external_tx.clone());
        }

        // ── Decrypt middleware: external bus → internal bus ───────────────────
        //
        // Determine the authority's own fingerprint so echoed outbound messages
        // (encrypted to the device, not to us) can be skipped.  Read from the
        // authority pub file; fall back to empty string when not yet initialised.
        let own_auth_fp: String = (|| -> Option<String> {
            let store_dir = STORE_DIR.get()?;
            let bus_dir = p43::bus::bus_dir(store_dir);
            let authority_pub =
                p43::bus::AuthorityPub::load(&p43::bus::authority_pub_path(&bus_dir)).ok()?;
            Some(hex::encode(&authority_pub.fingerprint()))
        })()
        .unwrap_or_default();

        let decrypt_handle = {
            let sink_locked = sink.clone();
            p43::bus::spawn_decrypt_middleware(
                move |env| {
                    // Drop our own echoed outbound messages.
                    if env.from == own_auth_fp {
                        return p43::bus::DecryptResult::Skip;
                    }
                    let Ok(guard) = authority_session().lock() else {
                        return p43::bus::DecryptResult::Err("mutex poisoned".into());
                    };
                    let Some((ref auth_key, _)) = *guard else {
                        return p43::bus::DecryptResult::Locked;
                    };
                    let auth_sign_pub: [u8; 32] = auth_key.sign_pubkey();
                    match p43::bus::open_protocol_message(auth_key, &auth_sign_pub, env) {
                        Ok((inner, cert)) => p43::bus::DecryptResult::Ok(inner, Box::new(cert)),
                        Err(e) => p43::bus::DecryptResult::Err(e.to_string()),
                    }
                },
                move |locked_ext_msg| {
                    // Buffer the raw BusSecure message (with its event_id) so
                    // it can be replayed through the external bus once unlocked.
                    if let Ok(mut queue) = locked_msg_queue().lock() {
                        queue.push_back(locked_ext_msg);
                    }
                    let _ = sink_locked.add(AppMessage::SessionLockRequired);
                },
                external_rx,
                internal_tx.clone(),
            )
        };

        // ── Encrypt worker: outbound queue → seal → Matrix send ───────────────
        let encrypt_handle = p43::bus::spawn_encrypt_worker(
            |msg, recipient| {
                let Ok(guard) = authority_session().lock() else {
                    return None;
                };
                let Some((ref auth_key, ref auth_cert)) = *guard else {
                    return None;
                };
                p43::bus::seal_protocol_message(auth_key, auth_cert, recipient, msg).ok()
            },
            room_id.clone(),
            outbound_rx,
            None, // UI does not redact individual messages
        );

        // ── Internal bus dispatcher → AppMessage stream ───────────────────────
        let dispatcher_handle = {
            let sink_dispatch = sink.clone();
            let mut internal_rx = internal_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    let inbound = match internal_rx.recv().await {
                        Ok(m) => m,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("[p43::bridge] internal_rx lagged, dropped {n} messages");
                            continue;
                        }
                    };
                    let sender_cert = inbound.sender_cert;
                    let event = match inbound.message {
                        p43::protocol::Message::SshListKeysRequest(r) => {
                            if let Ok(mut map) = pending_list_keys().lock() {
                                map.insert(r.request_id.clone(), sender_cert);
                            }
                            Some(AppMessage::AgentEvent {
                                event: AgentRequest::ListKeys {
                                    request_id: r.request_id,
                                },
                            })
                        }
                        p43::protocol::Message::SshSignRequest(r) => {
                            let dev_label = sender_cert
                                .as_ref()
                                .map(|c| c.label.clone())
                                .unwrap_or_default();
                            let dev_id = sender_cert
                                .as_ref()
                                .map(|c| c.device_id.clone())
                                .unwrap_or_default();
                            if let Ok(mut map) = pending_signs().lock() {
                                map.insert(
                                    r.request_id.clone(),
                                    PendingSign {
                                        fingerprint: r.fingerprint.clone(),
                                        data: r.data.clone(),
                                        flags: r.flags,
                                        sender_cert,
                                    },
                                );
                            }
                            Some(AppMessage::AgentEvent {
                                event: AgentRequest::Sign {
                                    request_id: r.request_id,
                                    fingerprint: r.fingerprint,
                                    description: r.description,
                                    device_label: dev_label,
                                    device_id: dev_id,
                                },
                            })
                        }
                        p43::protocol::Message::BusCsrRequest(r) => Some(AppMessage::BusEvent {
                            event: BusCsrEvent {
                                request_id: r.request_id,
                                device_label: r.device_label,
                                device_id: r.device_id,
                                csr_b64: r.csr_b64,
                            },
                        }),
                        _ => None,
                    };
                    if let Some(m) = event {
                        let _ = sink_dispatch.add(m);
                    }
                }
            })
        };

        // ── Raw Matrix listener → external bus ────────────────────────────────
        //
        // A fresh stop-signal is installed on every invocation so that
        // `mx_force_reconnect` (called from Dart's `resumed` lifecycle handler)
        // can break this specific listener without affecting a future one.
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        if let Ok(mut guard) = listener_stop_cell().lock() {
            *guard = std::sync::Arc::clone(&stop);
        }
        let stop_rx = std::sync::Arc::clone(&stop);

        // Age filter: ignore messages older than messageMaxAgeHours.
        let max_age_hours = MESSAGE_MAX_AGE_HOURS.load(Ordering::Relaxed);
        let cutoff_ms: u64 = {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            now_ms.saturating_sub(max_age_hours * 3_600_000)
        };
        eprintln!("[p43::bridge] message age filter: ignore messages older than {max_age_hours} h");

        tokio::select! {
            _ = stop_rx.notified() => {
                eprintln!("[p43::bridge] Reconnect requested — stopping listener for catch-up");
            }
            _ = p43::matrix::global::listen_room(
                &room_id,
                since.as_deref(),
                on_pointer,
                move |_sender, body, ts_ms, event_id| {
                    if ts_ms < cutoff_ms {
                        eprintln!("[p43::bridge] skipping message older than {max_age_hours} h (ts={ts_ms})");
                        return;
                    }
                    if let Ok(msg) = p43::protocol::Message::from_json(&body) {
                        let _ = external_tx
                            .send(p43::bus::ExternalBusMessage { message: msg, event_id });
                    }
                },
            ) => {}
        }

        // ── Teardown ──────────────────────────────────────────────────────────
        // The sync loop exited (timeout, network drop, or server close).
        // Abort all bus tasks immediately so their sink clones are dropped,
        // which closes the FRB stream and fires onDone in Dart, triggering
        // _scheduleReconnect after 5 s.
        //
        // Also clear the shared cell senders: external_tx_cell() held a clone
        // of external_tx that would otherwise keep the decrypt middleware's
        // external_rx alive even after the event handler was deregistered in
        // room::listen (Fix 1), preventing the bus pipeline from draining.
        decrypt_handle.abort();
        encrypt_handle.abort();
        dispatcher_handle.abort();
        if let Ok(mut guard) = external_tx_cell().lock() {
            *guard = None;
        }
        if let Ok(mut guard) = outbound_tx_cell().lock() {
            *guard = None;
        }
    });
}

/// Approve a device registration: verify the CSR, sign a cert with the
/// authority key, and send `bus.cert_response` back into the room.
///
/// The authority key is unlocked using the card PIN (YubiKey) or passphrase
/// (soft key), following the same priority as other operations:
///   card=true  → PIN  (YK_PIN env or prompt)
///   card=false → passphrase (YK_PASSPHRASE env or prompt)
#[allow(clippy::too_many_arguments)]
#[frb]
pub async fn mx_respond_csr(
    room_id: String,
    request_id: String,
    csr_b64: String,
    ttl_secs: Option<i64>,
    use_card: bool,
    // Keystore fingerprint — resolves card AID (card) or key file (soft key).
    fingerprint: Option<String>,
    pin: Option<String>,
    passphrase: Option<String>,
) -> anyhow::Result<()> {
    use base64::Engine as _;
    use p43::bus::{self, DeviceCert, DeviceCsr};

    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);

    // Decode and verify the CSR self-signature.
    let csr_bytes = base64::engine::general_purpose::STANDARD
        .decode(&csr_b64)
        .context("decode CSR base64")?;
    let csr_payload = DeviceCsr::verify(&csr_bytes)?;

    // Unlock the authority key via the shared helper (resolves card AID /
    // key file path from the keystore by fingerprint — no env vars needed).
    let enc_path = bus::authority_enc_path(&bus_dir);
    let encrypted =
        std::fs::read(&enc_path).context("read authority.key.enc — run `p43 bus init` first")?;

    let authority_key = unlock_authority(
        &encrypted,
        use_card,
        fingerprint.as_deref(),
        pin.as_deref(),
        passphrase.as_deref(),
    )?;

    // Issue cert.
    let cert = DeviceCert::issue(&csr_payload, &authority_key, ttl_secs)?;

    // Derive the authority public bundle from the key we just unlocked —
    // this guarantees the pub bundle is always consistent with the signing key,
    // even if authority.pub.cbor on disk is stale (e.g. after bus init --force).
    let authority_pub = authority_key.authority_pub();
    let authority_pub_cbor = authority_pub
        .to_cbor_bytes()
        .context("CBOR encode AuthorityPub for response")?;

    // Send response.
    let msg = p43::protocol::Message::BusCertResponse(p43::protocol::BusCertResponse {
        request_id,
        device_id: cert.payload.device_id.clone(),
        cert_b64: base64::engine::general_purpose::STANDARD.encode(&cert.cose_bytes),
        authority_pub_b64: base64::engine::general_purpose::STANDARD.encode(&authority_pub_cbor),
    });
    p43::matrix::global::send_message(&room_id, &msg.to_json()?).await?;

    // Re-sync authority.pub.cbor on disk — if it was stale (e.g. from a previous
    // bus init --force), this brings it back in line with authority.key.enc.
    authority_pub.save(&bus::authority_pub_path(&bus_dir))?;

    // Also store the cert in peers/ so the authority can later encrypt to this device.
    let peer_path = bus::peer_cert_path(&bus_dir, &cert.payload.device_id);
    cert.save(&peer_path)?;

    Ok(())
}

/// Return the authority's public key bundle as a base64-encoded CBOR blob.
///
/// The returned string is suitable for embedding in a QR code and scanning
/// on a desktop device to bootstrap bus trust.  The format is:
///   `p43:bus:authority:<base64(CBOR AuthorityPub)>`
#[frb]
pub fn bus_authority_pub_qr_data() -> anyhow::Result<String> {
    use p43::bus::{self, AuthorityPub};
    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);
    let authority_pub = AuthorityPub::load(&bus::authority_pub_path(&bus_dir))
        .context("authority not initialised — run `p43 bus init` first")?;
    let cbor = authority_pub.to_cbor_bytes()?;
    Ok(format!(
        "p43:bus:authority:{}",
        base64::engine::general_purpose::STANDARD.encode(&cbor)
    ))
}

/// Returns `true` when the bus authority has been initialised
/// (`authority.key.enc` exists in the bus directory).
#[frb]
pub fn bus_has_authority() -> bool {
    let store_dir = default_store_dir();
    let bus_dir = p43::bus::bus_dir(&store_dir);
    p43::bus::authority_enc_path(&bus_dir).exists()
}

/// Initialise the bus authority, sealing the encrypted key blob to **all**
/// currently-imported OpenPGP keys (card keys and soft keys alike).
///
/// This is a public-key-only operation — no passphrase or PIN is required.
/// Each imported key's `.pub.asc` file is used as a recipient.
///
/// Also writes `authority.pub.cbor` and a self-issued `authority.cert.cbor`.
#[frb]
pub fn bus_init_authority() -> anyhow::Result<()> {
    use p43::bus::{self, CsrPayload, DeviceCert};
    use p43::key_store::store::KeyStore;

    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);

    let ks = KeyStore::open(&store_dir)?;
    let entries = ks.list()?;
    anyhow::ensure!(
        !entries.is_empty(),
        "no keys imported yet — import at least one key first"
    );

    // Collect all public-key paths (card + soft) as recipients.
    let pub_paths: Vec<std::path::PathBuf> = entries
        .iter()
        .map(|e| ks.pub_file_path(&e.fingerprint))
        .collect();
    let pub_path_refs: Vec<&std::path::Path> = pub_paths.iter().map(|p| p.as_path()).collect();

    let (authority_key, authority_pub, encrypted) =
        p43::bus::authority::generate_and_encrypt(&pub_path_refs)?;

    // Write authority.key.enc.
    let enc_path = bus::authority_enc_path(&bus_dir);
    if let Some(parent) = enc_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&enc_path, &encrypted)
        .with_context(|| format!("write {}", enc_path.display()))?;

    // Write authority.pub.cbor.
    authority_pub.save(&bus::authority_pub_path(&bus_dir))?;

    // Self-issue authority.cert.cbor.
    let authority_pub_key = authority_key.authority_pub();
    let csr_payload = CsrPayload {
        version: 1,
        label: "authority".to_string(),
        sign_pubkey: authority_pub_key.ed25519_pub.clone(),
        ecdh_pubkey: authority_pub_key.x25519_pub.clone(),
        nonce: vec![0u8; 16], // synthetic — no peer verification needed
        timestamp: p43::bus::unix_now()?,
    };
    let cert = DeviceCert::issue(&csr_payload, &authority_key, None)?;
    cert.save(&bus::authority_cert_path(&bus_dir))?;

    Ok(())
}

// ── Authority unlock helper ───────────────────────────────────────────────────

/// Decrypt the existing `authority.key.enc` using either a soft key or a card.
fn unlock_authority(
    encrypted: &[u8],
    use_card: bool,
    unlock_fingerprint: Option<&str>,
    pin: Option<&str>,
    passphrase: Option<&str>,
) -> anyhow::Result<p43::bus::authority::AuthorityKey> {
    use p43::key_store::store::KeyStore;
    let store_dir = default_store_dir();

    if use_card {
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let card_pin = pin.ok_or_else(|| anyhow::anyhow!("pin required for card unlock"))?;
            let ident: Option<String> = unlock_fingerprint.and_then(|fp| {
                let ks = KeyStore::open(&store_dir).ok()?;
                let entry = ks.list().ok()?.into_iter().find(|e| e.fingerprint == fp)?;
                entry.card_idents.into_iter().next()
            });
            return p43::bus::authority::unlock_card(encrypted, card_pin, ident.as_deref());
        }
        anyhow::bail!("card unlock is not supported on this platform")
    } else {
        let fp = unlock_fingerprint
            .ok_or_else(|| anyhow::anyhow!("unlock_fingerprint required for soft-key unlock"))?;
        let phrase =
            passphrase.ok_or_else(|| anyhow::anyhow!("passphrase required for soft-key unlock"))?;
        let ks = KeyStore::open(&store_dir)?;
        let key_file = ks.sec_file_path(fp);
        anyhow::ensure!(
            key_file.exists(),
            "secret key file not found for fingerprint {fp}"
        );
        p43::bus::authority::unlock_soft(encrypted, &key_file, phrase)
    }
}

// ── Key seal status ───────────────────────────────────────────────────────────

/// Sealing status for a single keystore key.
pub struct KeySealStatus {
    pub fingerprint: String,
    pub uid: String,
    pub is_sealed: bool,
    /// `true` → card key (unlock with PIN); `false` → soft key (unlock with passphrase).
    pub has_card: bool,
}

/// Return the sealing status of every keystore key against the current
/// `authority.key.enc`.  Returns an empty list when no authority exists.
#[frb]
pub fn bus_authority_key_seal_status() -> anyhow::Result<Vec<KeySealStatus>> {
    use p43::bus;
    use p43::key_store::store::KeyStore;
    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);
    let enc_path = bus::authority_enc_path(&bus_dir);
    let ks = KeyStore::open(&store_dir)?;
    let statuses = p43::bus::authority::key_seal_status(&enc_path, &ks)?;
    Ok(statuses
        .into_iter()
        .map(|s| KeySealStatus {
            fingerprint: s.fingerprint,
            uid: s.uid,
            is_sealed: s.is_sealed,
            has_card: s.has_card,
        })
        .collect())
}

// ── Reseal ────────────────────────────────────────────────────────────────────

/// Re-seal the authority key to **all** currently-imported keys.
///
/// The caller must supply credentials to unlock the existing authority:
/// - `use_card = true`:  unlock via connected YubiKey using `pin`.
/// - `use_card = false`: unlock via soft key at `unlock_fingerprint` using
///   `passphrase`.
#[frb]
pub fn bus_reseal_authority(
    use_card: bool,
    unlock_fingerprint: Option<String>,
    pin: Option<String>,
    passphrase: Option<String>,
) -> anyhow::Result<()> {
    use p43::bus;
    use p43::key_store::store::KeyStore;

    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);
    let enc_path = bus::authority_enc_path(&bus_dir);

    let encrypted = std::fs::read(&enc_path)
        .context("authority not initialised — run bus_init_authority() first")?;

    let authority_key = unlock_authority(
        &encrypted,
        use_card,
        unlock_fingerprint.as_deref(),
        pin.as_deref(),
        passphrase.as_deref(),
    )?;

    let ks = KeyStore::open(&store_dir)?;
    let entries = ks.list()?;
    anyhow::ensure!(
        !entries.is_empty(),
        "no keys in store — cannot reseal to empty recipient set"
    );
    let pub_paths: Vec<std::path::PathBuf> = entries
        .iter()
        .map(|e| ks.pub_file_path(&e.fingerprint))
        .collect();
    let pub_path_refs: Vec<&std::path::Path> = pub_paths.iter().map(|p| p.as_path()).collect();

    let new_encrypted = p43::bus::authority::reseal(&authority_key, &pub_path_refs)?;
    std::fs::write(&enc_path, &new_encrypted)
        .with_context(|| format!("write {}", enc_path.display()))?;

    Ok(())
}

/// Re-seal the authority key to all keys **except** `exclude_fingerprint`.
///
/// Use this when a key has been compromised and must be revoked from authority
/// access.  At least one other sealed key must remain.
///
/// Credentials unlock the existing authority (use a key *other* than the one
/// being excluded).
#[frb]
pub fn bus_reseal_authority_excluding(
    exclude_fingerprint: String,
    use_card: bool,
    unlock_fingerprint: Option<String>,
    pin: Option<String>,
    passphrase: Option<String>,
) -> anyhow::Result<()> {
    use p43::bus;
    use p43::key_store::store::KeyStore;

    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);
    let enc_path = bus::authority_enc_path(&bus_dir);

    let encrypted = std::fs::read(&enc_path)
        .context("authority not initialised — run bus_init_authority() first")?;

    let authority_key = unlock_authority(
        &encrypted,
        use_card,
        unlock_fingerprint.as_deref(),
        pin.as_deref(),
        passphrase.as_deref(),
    )?;

    let ks = KeyStore::open(&store_dir)?;
    let entries = ks.list()?;
    let remaining: Vec<_> = entries
        .iter()
        .filter(|e| e.fingerprint != exclude_fingerprint)
        .collect();
    anyhow::ensure!(
        !remaining.is_empty(),
        "cannot remove the last key — at least one recipient is required"
    );
    let pub_paths: Vec<std::path::PathBuf> = remaining
        .iter()
        .map(|e| ks.pub_file_path(&e.fingerprint))
        .collect();
    let pub_path_refs: Vec<&std::path::Path> = pub_paths.iter().map(|p| p.as_path()).collect();

    let new_encrypted = p43::bus::authority::reseal(&authority_key, &pub_path_refs)?;
    std::fs::write(&enc_path, &new_encrypted)
        .with_context(|| format!("write {}", enc_path.display()))?;

    Ok(())
}

/// Exported authority key bundle — encrypted private scalar + public key.
///
/// Both fields are required to fully restore the authority on another device.
pub struct AuthorityKeyExport {
    /// Raw bytes of `authority.key.enc` (OpenPGP-encrypted CBOR blob).
    pub key_enc: Vec<u8>,
    /// Raw bytes of `authority.pub.cbor` (CBOR-encoded [`AuthorityPub`]).
    pub pub_cbor: Vec<u8>,
}

/// Export the authority key bundle so it can be backed up or transferred.
///
/// Returns an error if the authority has not been initialised.
#[frb]
pub fn bus_export_authority() -> anyhow::Result<AuthorityKeyExport> {
    use p43::bus;
    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);

    let key_enc = std::fs::read(bus::authority_enc_path(&bus_dir))
        .context("authority.key.enc not found — initialise the authority first")?;
    let pub_cbor = std::fs::read(bus::authority_pub_path(&bus_dir))
        .context("authority.pub.cbor not found — initialise the authority first")?;

    Ok(AuthorityKeyExport { key_enc, pub_cbor })
}

/// Import an authority key bundle (overwriting any existing authority files).
///
/// Use this to restore an authority from a backup or to move it to a new
/// device.  Both `key_enc` and `pub_cbor` must come from a prior
/// [`bus_export_authority`] call.
#[frb]
pub fn bus_import_authority(key_enc: Vec<u8>, pub_cbor: Vec<u8>) -> anyhow::Result<()> {
    use p43::bus;
    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);

    // Validate pub_cbor by round-tripping through AuthorityPub before writing.
    p43::bus::AuthorityPub::from_cbor_bytes(&pub_cbor)
        .context("pub_cbor is not a valid CBOR AuthorityPub")?;

    if let Some(parent) = bus::authority_enc_path(&bus_dir).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(bus::authority_enc_path(&bus_dir), &key_enc)
        .context("write authority.key.enc")?;
    std::fs::write(bus::authority_pub_path(&bus_dir), &pub_cbor)
        .context("write authority.pub.cbor")?;

    Ok(())
}

/// Check whether any currently-imported keystore key can decrypt `key_enc`.
///
/// Returns the UIDs of all matching keys (could be more than one when the
/// blob was sealed to multiple recipients).  Returns an **error** if no
/// keystore key matches — the blob would be unrecoverable on this device.
///
/// Call this before writing the imported bundle to disk so users cannot
/// accidentally import a bundle that none of their keys can open.
#[frb]
pub fn bus_authority_check_importable(key_enc: Vec<u8>) -> anyhow::Result<Vec<String>> {
    use p43::key_store::store::KeyStore;
    let ks = KeyStore::open(&default_store_dir())?;
    p43::bus::authority::check_importable(&key_enc, &ks)
}

/// Return fingerprints of keystore keys whose encryption subkeys are **not**
/// listed as recipients in the current `authority.key.enc`.
///
/// Returns an empty `Vec` when no authority exists yet or all keys are sealed.
/// A non-empty return value means the Reseal tile should show a warning badge.
#[frb]
pub fn bus_authority_keys_not_sealed() -> anyhow::Result<Vec<String>> {
    use p43::bus;
    use p43::key_store::store::KeyStore;
    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);
    let enc_path = bus::authority_enc_path(&bus_dir);
    let ks = KeyStore::open(&store_dir)?;
    let statuses = p43::bus::authority::key_seal_status(&enc_path, &ks)?;
    Ok(statuses
        .into_iter()
        .filter(|s| !s.is_sealed)
        .map(|s| s.fingerprint)
        .collect())
}

// ── Authority session management (FRB) ───────────────────────────────────────

/// Unlock the bus authority session.
///
/// The authority key is decrypted from `authority.key.enc` and held in memory
/// until [`bus_lock_session`] or [`mx_clear_caches`] is called.  While unlocked
/// the app can decrypt incoming `BusSecure` messages and seal outgoing responses.
#[frb]
pub fn bus_unlock_session(
    use_card: bool,
    fingerprint: Option<String>,
    pin: Option<String>,
    passphrase: Option<String>,
) -> anyhow::Result<()> {
    use p43::bus;

    let store_dir = default_store_dir();
    let bus_dir = bus::bus_dir(&store_dir);

    let encrypted = std::fs::read(bus::authority_enc_path(&bus_dir))
        .context("authority.key.enc not found — run bus_init_authority first")?;
    let authority_key = unlock_authority(
        &encrypted,
        use_card,
        fingerprint.as_deref(),
        pin.as_deref(),
        passphrase.as_deref(),
    )?;

    // Load authority self-cert bytes so we can sign/seal outgoing responses.
    let cert_bytes = std::fs::read(bus::authority_cert_path(&bus_dir))
        .context("authority.cert.cbor not found — run bus_init_authority first")?;

    if let Ok(mut guard) = authority_session().lock() {
        *guard = Some((authority_key, cert_bytes));
    }

    // Prime the signing-credential caches with the credentials just used so
    // that any replayed sign requests (see below) can be auto-approved without
    // showing a second PIN / passphrase dialog.
    //
    // For card keys: the unlock dialog hands us an OpenPGP hex fingerprint, NOT
    // an SSH SHA-256 fingerprint.  `get_ssh_key_meta` matches by SSH fingerprint
    // and would return None here.  Instead we look up `card_idents` directly from
    // the KeyStore by OpenPGP fingerprint — the AID ident is the same for all
    // three card slots (SIG / AUTH / ENC), so one PIN entry covers all of them.
    let store_dir = default_store_dir();
    if use_card {
        if let (Some(fp), Some(ref pin_val)) = (fingerprint.as_deref(), &pin) {
            if let Ok(ks) = p43::key_store::store::KeyStore::open(&store_dir) {
                if let Ok(entries) = ks.list() {
                    if let Some(entry) = entries.into_iter().find(|e| e.fingerprint == fp) {
                        if let Ok(mut cache) = credential_cache().lock() {
                            for ident in &entry.card_idents {
                                cache.insert(ident.clone(), pin_val.clone());
                            }
                        }
                    }
                }
            }
        }
    } else if let (Some(fp), Some(ref phrase)) = (fingerprint.as_deref(), &passphrase) {
        // Sign requests carry SSH SHA-256 fingerprints; convert so the cache key
        // matches what mx_respond_sign_cached will look up.
        let cache_key =
            p43::ssh_agent::ssh_fp_for_openpgp_fp(&store_dir, fp).unwrap_or_else(|| fp.to_string());
        if let Ok(mut cache) = credential_cache().lock() {
            cache.insert(cache_key, phrase.clone());
        }
    }

    // Replay any BusSecure messages that arrived while the session was locked.
    // We drain the queue first, then inject each message back onto the external
    // bus so the full decrypt → internal-bus → AppMessage pipeline handles them.
    let buffered: Vec<p43::bus::ExternalBusMessage> = locked_msg_queue()
        .lock()
        .map(|mut q| q.drain(..).collect())
        .unwrap_or_default();

    if !buffered.is_empty() {
        if let Ok(guard) = external_tx_cell().lock() {
            if let Some(ref tx) = *guard {
                for ext_msg in buffered {
                    let _ = tx.send(ext_msg);
                }
            }
        }
    }

    Ok(())
}

/// Clear the in-memory authority session key.
///
/// After this call the app can no longer decrypt `BusSecure` messages or seal
/// outgoing responses until [`bus_unlock_session`] is called again.
#[frb]
pub fn bus_lock_session() {
    if let Ok(mut guard) = authority_session().lock() {
        *guard = None;
    }
}

/// Returns `true` if the authority session key is currently unlocked.
#[frb]
pub fn bus_is_session_unlocked() -> bool {
    authority_session()
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false)
}

// ── Outbound helper ───────────────────────────────────────────────────────────

/// Enqueue `msg` on the outbound bus (encrypt worker handles sealing + send).
///
/// When `sender_cert` is `Some`, the message will be sealed to that recipient
/// by the encrypt worker.  When `None`, it is sent as plain JSON.
///
/// Falls back to a direct `send_message` call if the outbound queue has not
/// been set up yet (e.g. during early startup before `mx_listen_all` runs).
async fn send_via_bridge(
    room_id: &str,
    msg: p43::protocol::Message,
    sender_cert: Option<p43::bus::CertPayload>,
) -> anyhow::Result<()> {
    let tx_opt: Option<mpsc::Sender<p43::bus::OutboundBusMessage>> =
        outbound_tx_cell().lock().ok().and_then(|g| g.clone());

    if let Some(tx) = tx_opt {
        tx.send(p43::bus::OutboundBusMessage {
            message: msg,
            recipient_cert: sender_cert,
        })
        .await
        .map_err(|_| anyhow::anyhow!("outbound queue closed"))?;
        return Ok(());
    }

    // Fallback: no bridge yet — inline seal + send.
    let json = if let Some(cert) = sender_cert.as_ref() {
        let sealed_opt = authority_session().lock().ok().and_then(|guard| {
            guard.as_ref().and_then(|(auth_key, auth_cert_bytes)| {
                p43::bus::seal_protocol_message(auth_key, auth_cert_bytes, cert, &msg).ok()
            })
        });
        sealed_opt
            .map(|s| s.to_json())
            .unwrap_or_else(|| msg.to_json())?
    } else {
        msg.to_json()?
    };
    p43::matrix::global::send_message(room_id, &json)
        .await
        .map(|_| ())
}

#[allow(dead_code)]
fn resolve_secret(explicit: Option<String>, env_var: &str, prompt: &str) -> anyhow::Result<String> {
    if let Some(v) = explicit {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_var) {
        return Ok(v);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

/// Returns `true` if cached credentials exist for the given SSH fingerprint,
/// meaning `mx_respond_sign_cached` can proceed without a passphrase dialog.
///
/// Returns `true` when any of:
/// - A passphrase is cached in the credential cache (slow KDF path).
/// - A decrypted Ed25519 keypair is cached (fast, microseconds).
/// - A decrypted RSA key is cached (fast, zero KDF).
///
/// Dart uses this to decide whether to auto-approve or show the dialog.
/// When biometric approval is added, this is also the gate for whether
/// biometric confirmation suffices or the user must type their passphrase.
#[frb]
pub fn has_cached_passphrase(fingerprint: String) -> bool {
    // peek: check existence without resetting the expiry timer.
    let has_credential = credential_cache()
        .lock()
        .map(|mut c| c.peek(&fingerprint))
        .unwrap_or(false);
    let has_key = signing_key_cache()
        .lock()
        .map(|m| m.contains_key(&fingerprint))
        .unwrap_or(false);
    let has_rsa_key = p43::ssh_agent::has_cached_rsa_key(&fingerprint);
    has_credential || has_key || has_rsa_key
}

/// Prime the credential cache for a given key fingerprint.
///
/// `bus_unlock_session` already calls this internally; use this function when
/// you need to prime the cache from a path that bypasses `bus_unlock_session`.
#[frb]
pub fn mx_prime_passphrase_cache(fingerprint: String, passphrase: String) {
    if let Ok(mut cache) = credential_cache().lock() {
        cache.insert(fingerprint, passphrase);
    }
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

/// Set the maximum age of Matrix messages the UI will process.
///
/// Messages with `origin_server_ts` older than `hours` before *now* are
/// silently dropped before they reach the bus pipeline.
/// Default is 8 h.  Pass 0 to disable the filter (accept all messages).
///
/// Call at startup with the persisted setting value, and again whenever the
/// user changes it in Settings.
#[frb]
pub fn mx_set_message_max_age_hours(hours: u64) {
    MESSAGE_MAX_AGE_HOURS.store(hours, Ordering::Relaxed);
}

/// Update the credential cache timeout.
///
/// Pass the value of `AgentSettings.cacheTimeoutMinutes * 60` (converted to
/// seconds), or `0` to disable automatic expiry.
///
/// Call at startup and whenever the setting changes.
#[frb]
pub fn credential_cache_set_timeout(timeout_secs: u64) {
    if let Ok(mut cache) = credential_cache().lock() {
        // Saturate at u32::MAX (~136 years) — any realistic timeout fits easily.
        cache.set_timeout(timeout_secs.min(u32::MAX as u64) as u32);
    }
}

/// Lock the session and purge **all** in-memory credentials.
///
/// Clears:
/// - Credential cache (all PINs and passphrases)
/// - Derived signing-key cache (decrypted Ed25519 / RSA keypairs)
/// - Authority session key
///
/// Does **not** affect `KEY_CACHE_ENABLED` — caching resumes on the next
/// successful sign if still enabled.
///
/// Call from the global lock button and on screen-lock / app-background events.
#[frb]
pub fn lock_all() {
    if let Ok(mut cache) = credential_cache().lock() {
        cache.purge();
    }
    if let Ok(mut cache) = signing_key_cache().lock() {
        cache.clear();
    }
    p43::ssh_agent::clear_rsa_key_cache();
    if let Ok(mut session) = authority_session().lock() {
        *session = None;
    }
}

/// Clear all in-memory credential caches.
///
/// Delegates to [`lock_all`].  Kept for backwards compatibility.
#[frb]
pub fn mx_clear_caches() {
    lock_all();
}

/// Approve an `ssh.sign_request` using an explicitly supplied passphrase.
///
/// On success:
/// - The passphrase is stored in the in-memory cache (slow fallback path).
/// - If "cache decrypted key" is enabled, the decrypted Ed25519 keypair bytes
///   are also cached so subsequent auto-approve signs skip the KDF entirely.
#[frb]
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(passphrase), fields(request_id, room_id))
)]
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

    let sig = if KEY_CACHE_ENABLED.load(Ordering::Relaxed) {
        // Extract and cache the keypair bytes while we're decrypting anyway.
        // RSA keys return None (too large for the 64-byte slot); they fall
        // back to the passphrase cache for subsequent auto-approvals.
        let (sig, keypair_bytes) = p43::ssh_agent::sign_with_soft_key_and_extract(
            &store_dir,
            &pending.fingerprint,
            &passphrase,
            &pending.data,
        )?;
        if let (Ok(mut cache), Some(bytes)) = (signing_key_cache().lock(), keypair_bytes) {
            cache.insert(pending.fingerprint.clone(), Box::new(bytes));
        }
        sig
    } else {
        p43::ssh_agent::sign_with_soft_key(
            &store_dir,
            &pending.fingerprint,
            &passphrase,
            &pending.data,
        )?
    };

    // Cache the passphrase so subsequent signs can be auto-approved.
    if let Ok(mut cache) = credential_cache().lock() {
        cache.insert(pending.fingerprint, passphrase);
    }

    let response = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
        request_id,
        signature: sig,
    });
    send_via_bridge(&room_id, response, pending.sender_cert).await
}

/// Approve an `ssh.sign_request` for a card-backed key using the card's User PIN.
///
/// The card's AUTH slot is used for signing (same slot the SSH agent uses).
/// The User PIN (typically 6+ digits on YubiKey) unlocks the AUTH slot — it
/// is NOT the Admin PIN or the Signing PIN.
///
/// On success the PIN is cached in memory keyed by card AID ident so that
/// `mx_respond_sign_card_cached` can skip the PIN dialog for subsequent requests.
///
/// Not available on Android / iOS (no PC/SC subsystem).
#[frb]
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(skip(pin), fields(request_id, room_id))
)]
pub async fn mx_respond_sign_card(
    room_id: String,
    request_id: String,
    pin: String,
) -> anyhow::Result<()> {
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let pending = pending_signs()
            .lock()
            .map_err(|e| anyhow::anyhow!("pending-sign lock poisoned: {e}"))?
            .remove(&request_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown or already-handled request_id {request_id}"))?;

        let store_dir = default_store_dir();

        let sig = p43::ssh_agent::sign_with_card_key(
            &store_dir,
            &pending.fingerprint,
            &pin,
            &pending.data,
            pending.flags,
        )?;

        // Cache the PIN keyed by each card AID associated with this fingerprint.
        if let Some(meta) = p43::ssh_agent::get_ssh_key_meta(&store_dir, &pending.fingerprint) {
            if let Ok(mut cache) = credential_cache().lock() {
                for ident in &meta.card_idents {
                    cache.insert(ident.clone(), pin.clone());
                }
            }
        }

        let response = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
            request_id,
            signature: sig,
        });
        return send_via_bridge(&room_id, response, pending.sender_cert).await;
    }
    #[cfg(any(target_os = "ios", target_os = "android"))]
    anyhow::bail!("PC/SC card operations are not supported on this platform")
}

/// Returns `true` if a cached PIN exists for the given card AID ident,
/// meaning `mx_respond_sign_card_cached` can proceed without a PIN dialog.
///
/// `card_ident` is one of the strings from `KeyInfo.cardIdents`.
#[frb]
pub fn has_cached_card_pin(card_ident: String) -> bool {
    // peek: check existence without resetting the expiry timer.
    credential_cache()
        .lock()
        .map(|mut c| c.peek(&card_ident))
        .unwrap_or(false)
}

/// Approve an `ssh.sign_request` for a card-backed key using a cached PIN.
///
/// Returns an error if no PIN is cached for any card associated with this key.
/// This is the auto-approve path after the first successful `mx_respond_sign_card`.
///
/// Not available on Android / iOS (no PC/SC subsystem).
#[frb]
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(fields(request_id, room_id))
)]
pub async fn mx_respond_sign_card_cached(
    room_id: String,
    request_id: String,
) -> anyhow::Result<()> {
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let pending = pending_signs()
            .lock()
            .map_err(|e| anyhow::anyhow!("pending-sign lock poisoned: {e}"))?
            .remove(&request_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown or already-handled request_id {request_id}"))?;

        let store_dir = default_store_dir();

        // Resolve card idents for this fingerprint, then look up a cached PIN.
        let meta = p43::ssh_agent::get_ssh_key_meta(&store_dir, &pending.fingerprint)
            .ok_or_else(|| anyhow::anyhow!("No key metadata found for fingerprint"))?;

        let pin = {
            let mut cache = credential_cache()
                .lock()
                .map_err(|e| anyhow::anyhow!("credential cache lock poisoned: {e}"))?;
            meta.card_idents
                .iter()
                // get: retrieves credential and resets its expiry timer.
                .find_map(|id| cache.get(id))
                .ok_or_else(|| anyhow::anyhow!("No cached PIN for this card — enter PIN first"))?
        };

        let sig = p43::ssh_agent::sign_with_card_key(
            &store_dir,
            &pending.fingerprint,
            &pin,
            &pending.data,
            pending.flags,
        )?;

        let response = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
            request_id,
            signature: sig,
        });
        return send_via_bridge(&room_id, response, pending.sender_cert).await;
    }
    #[cfg(any(target_os = "ios", target_os = "android"))]
    anyhow::bail!("PC/SC card operations are not supported on this platform")
}

/// Return the number of User PIN attempts remaining for a connected YubiKey /
/// OpenPGP card.  No PIN is required — this only reads PW status bytes.
///
/// `card_ident` is one of the strings from `KeyInfo.cardIdents`
/// (e.g. `"0006:17684870"`).  Returns an error if no card with that ident is
/// currently connected or accessible.
///
/// Not available on Android / iOS (no PC/SC subsystem).
#[frb]
pub fn get_card_pin_retries(card_ident: String) -> anyhow::Result<u8> {
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        return p43::pkcs11::card::card_pin_retries(Some(&card_ident));
    }
    #[cfg(any(target_os = "ios", target_os = "android"))]
    anyhow::bail!("PC/SC card operations are not supported on this platform")
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
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(fields(request_id, room_id))
)]
pub async fn mx_respond_sign_cached(room_id: String, request_id: String) -> anyhow::Result<()> {
    let pending = pending_signs()
        .lock()
        .map_err(|e| anyhow::anyhow!("pending-sign lock poisoned: {e}"))?
        .remove(&request_id)
        .ok_or_else(|| anyhow::anyhow!("Unknown or already-handled request_id {request_id}"))?;

    // ── Fast path 1: cached decrypted RSA key (zero-KDF for RSA keys) ─────────
    if p43::ssh_agent::has_cached_rsa_key(&pending.fingerprint) {
        let sig = p43::ssh_agent::sign_rsa_cached(&pending.fingerprint, &pending.data)?;
        let response = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
            request_id,
            signature: sig,
        });
        return send_via_bridge(&room_id, response, pending.sender_cert).await;
    }

    // ── Fast path 2: cached decrypted Ed25519 keypair ─────────────────────────
    let cached_keypair: Option<Box<[u8; 64]>> = signing_key_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.get(&pending.fingerprint).cloned());

    let sig = if let Some(keypair_bytes) = cached_keypair {
        p43::ssh_agent::sign_with_cached_keypair(&keypair_bytes, &pending.data)?
    } else {
        // ── Slow fallback: re-run KDF with cached passphrase ─────────────────
        // get: retrieves the passphrase and resets its expiry timer.
        let passphrase = credential_cache()
            .lock()
            .map_err(|e| anyhow::anyhow!("credential cache lock poisoned: {e}"))?
            .get(&pending.fingerprint)
            .ok_or_else(|| anyhow::anyhow!("No cached passphrase for this key"))?;

        let store_dir = default_store_dir();
        p43::ssh_agent::sign_with_soft_key(
            &store_dir,
            &pending.fingerprint,
            &passphrase,
            &pending.data,
        )?
    };

    let response = p43::protocol::Message::SshSignResponse(p43::protocol::SshSignResponse {
        request_id,
        signature: sig,
    });
    send_via_bridge(&room_id, response, pending.sender_cert).await
}

/// Reject an `ssh.sign_request`: send an error response and discard the request.
#[frb]
#[cfg_attr(
    feature = "telemetry",
    tracing::instrument(fields(request_id, room_id))
)]
pub async fn mx_reject_sign(room_id: String, request_id: String) -> anyhow::Result<()> {
    // Discard from pending map.
    let _ = pending_signs()
        .lock()
        .ok()
        .and_then(|mut m| m.remove(&request_id));

    let msg = p43::protocol::Message::Error(p43::protocol::ErrorResponse {
        request_id: Some(request_id),
        message: "User rejected the sign request".into(),
    });

    // Rejection is always plaintext — no recipient cert needed.
    send_via_bridge(&room_id, msg, None).await
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

// ── Bus device list ───────────────────────────────────────────────────────────

/// Summary of a locally-owned device key (own side).
pub struct BusOwnDevice {
    pub label: String,
    pub device_id: String,
    pub has_cert: bool,
    pub has_csr: bool,
    /// Unix timestamp of cert expiry, or `None` if absent / never expires.
    pub cert_exp: Option<i64>,
}

/// Summary of a registered peer device (authority side).
pub struct BusPeer {
    pub device_id: String,
    pub label: String,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
}

/// List all locally-owned device keys under `<store>/bus/devices/`.
#[frb]
pub fn bus_list_own_devices() -> anyhow::Result<Vec<BusOwnDevice>> {
    let bus_dir = p43::bus::bus_dir(&default_store_dir());
    Ok(p43::bus::list_own_devices(&bus_dir)?
        .into_iter()
        .map(|d| BusOwnDevice {
            label: d.label,
            device_id: d.device_id,
            has_cert: d.has_cert,
            has_csr: d.has_csr,
            cert_exp: d.cert_exp,
        })
        .collect())
}

/// List all peer certs registered under `<store>/bus/peers/`.
#[frb]
pub fn bus_list_peers() -> anyhow::Result<Vec<BusPeer>> {
    let bus_dir = p43::bus::bus_dir(&default_store_dir());
    Ok(p43::bus::list_peers(&bus_dir)?
        .into_iter()
        .map(|p| BusPeer {
            device_id: p.device_id,
            label: p.label,
            issued_at: p.issued_at,
            expires_at: p.expires_at,
        })
        .collect())
}

/// Remove a peer cert by device_id from `<store>/bus/peers/`.
/// Returns `true` if the cert was found and deleted, `false` if it did not exist.
#[frb]
pub fn bus_remove_peer(device_id: String) -> anyhow::Result<bool> {
    let bus_dir = p43::bus::bus_dir(&default_store_dir());
    p43::bus::remove_peer(&bus_dir, &device_id)
}
