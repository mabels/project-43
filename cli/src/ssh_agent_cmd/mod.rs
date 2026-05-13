pub mod subcmd;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use p43::bus::ExternalBusMessage;
use p43::bus::{self, load_or_generate_device_key, AuthorityPub, DeviceCsr, DeviceKey};
use p43::matrix::{device_id_from_config, resolve_agent_room, MatrixConfig, RoomPointerStore};
use p43::protocol::{BusCsrRequest, Message};
use p43::ssh_agent::{card_auth_sign_ssh, load_card_auth_key_info, load_ssh_key, SshKeySlot};
use signature::Signer;
use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, Signature};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use subcmd::SshAgentArgs;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
#[cfg(feature = "telemetry")]
use tracing::Instrument as _;

use p43::pkcs11::card_queue::CardQueue;

// ── Session ───────────────────────────────────────────────────────────────────

/// A stateless SSH agent session backed by a single software key.
///
/// `Clone` is cheap — the private key bytes live inside an `Arc`.
#[derive(Clone)]
struct P43SshSession {
    private_key: Arc<PrivateKey>,
    comment: String,
}

impl P43SshSession {
    fn new(key: PrivateKey, comment: impl Into<String>) -> Self {
        Self {
            private_key: Arc::new(key),
            comment: comment.into(),
        }
    }

    fn from_file(key_file: &std::path::Path, passphrase: &str, slot: SshKeySlot) -> Result<Self> {
        let key = load_ssh_key(key_file, passphrase, slot)?;
        let comment = format!("p43:{}", key_file.display());
        Ok(Self::new(key, comment))
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for P43SshSession {
    async fn request_identities(&mut self) -> std::result::Result<Vec<Identity>, AgentError> {
        let pubkey = self.private_key.public_key().key_data().clone();
        Ok(vec![Identity {
            pubkey,
            comment: self.comment.clone(),
        }])
    }

    #[cfg_attr(feature = "telemetry", tracing::instrument(skip(self, request), fields(mode = "soft_key", comment = %self.comment)))]
    async fn sign(&mut self, request: SignRequest) -> std::result::Result<Signature, AgentError> {
        self.private_key
            .try_sign(request.data.as_ref())
            .map_err(AgentError::other)
    }
}

// ── Card session ──────────────────────────────────────────────────────────────

/// SSH agent session backed by a YubiKey (OpenPGP signing slot).
///
/// All sign requests are routed through a [`CardQueue`] so that at most
/// `concurrency` PC/SC operations run simultaneously, preventing the card
/// from being overwhelmed by parallel callers (e.g. `git rebase` with
/// GPG auto-signing piped into SSH).
#[derive(Clone)]
struct P43CardSession {
    pubkey: Arc<KeyData>,
    comment: Arc<String>,
    pin: Arc<String>,
    queue: Arc<CardQueue>,
    /// `true` when the auth key is RSA (affects pre-hashing and SSH algo name).
    is_rsa: bool,
}

impl P43CardSession {
    fn from_card(pin: String, concurrency: usize) -> Result<Self> {
        // Public key is read without PIN — card serves it in base state.
        let info = load_card_auth_key_info().context("Failed to read auth key from YubiKey")?;
        Ok(Self {
            pubkey: Arc::new(info.pubkey),
            comment: Arc::new(info.comment),
            pin: Arc::new(pin),
            queue: Arc::new(CardQueue::new(concurrency)),
            is_rsa: info.is_rsa,
        })
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for P43CardSession {
    async fn request_identities(&mut self) -> std::result::Result<Vec<Identity>, AgentError> {
        Ok(vec![Identity {
            pubkey: (*self.pubkey).clone(),
            comment: (*self.comment).clone(),
        }])
    }

    #[cfg_attr(feature = "telemetry", tracing::instrument(skip(self, request), fields(mode = "card", is_rsa = self.is_rsa)))]
    async fn sign(&mut self, request: SignRequest) -> std::result::Result<Signature, AgentError> {
        let pin = Arc::clone(&self.pin);
        let data = request.data.to_vec();
        let flags = request.flags;
        let is_rsa = self.is_rsa;

        self.queue
            .run(move || card_auth_sign_ssh(&data, &pin, flags, is_rsa))
            .await
            .map_err(|e| AgentError::other(std::io::Error::other(e.to_string())))
    }
}

// ── Matrix proxy session ──────────────────────────────────────────────────────

/// Pending request map: request_id → oneshot sender for the response.
type PendingMap = Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<p43::protocol::Message>>>>;

/// Decryption context shared between the Matrix listener middleware and the
/// session.  Populated after [`ensure_registered`] completes; `None` during
/// registration (when only plaintext messages are exchanged).
type DecryptState = std::sync::Mutex<Option<(Arc<DeviceKey>, [u8; 32])>>;

/// SSH agent session that forwards every request as a p43 protocol message
/// into a Matrix room and waits for the response from the phone.
///
/// Outgoing messages are enqueued on `outbound_tx`; the shared
/// [`p43::bus::bridge::spawn_encrypt_worker`] task seals and sends them.
/// Incoming responses arrive on the internal bus (decrypted by the shared
/// middleware) and are dispatched to the pending map.
#[derive(Clone)]
struct MatrixProxySession {
    pending: PendingMap,
    /// Outbound queue — sends plaintext messages for the encrypt worker.
    /// Unbounded so parallel requests never block on enqueue.
    outbound_tx: mpsc::UnboundedSender<p43::bus::OutboundBusMessage>,
    /// X25519 public key of the authority — used as the seal recipient.
    authority_ecdh_pub: [u8; 32],
    /// How long to wait for the phone to respond before returning an error.
    /// The pending-map entry is removed on timeout so no memory leaks.
    timeout: std::time::Duration,
    /// When true, log send / txd / forward timestamps + transaction IDs to stderr.
    verbose: bool,
    /// Instant each request was enqueued, keyed by request_id.
    /// Populated in `forward()` when verbose; cleared by the on_sent consumer.
    send_instants: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
}

impl MatrixProxySession {
    fn new(
        pending: PendingMap,
        outbound_tx: mpsc::UnboundedSender<p43::bus::OutboundBusMessage>,
        authority_ecdh_pub: [u8; 32],
        timeout: std::time::Duration,
        verbose: bool,
        send_instants: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>>,
    ) -> Self {
        Self {
            pending,
            outbound_tx,
            authority_ecdh_pub,
            timeout,
            verbose,
            send_instants,
        }
    }

    /// Enqueue `msg` for encryption and delivery, then block until a matching
    /// response arrives on the internal bus (or the timeout expires).
    async fn forward(
        &self,
        msg: p43::protocol::Message,
    ) -> std::result::Result<p43::protocol::Message, AgentError> {
        let request_id = match &msg {
            p43::protocol::Message::SshListKeysRequest(r) => r.request_id.clone(),
            p43::protocol::Message::SshSignRequest(r) => r.request_id.clone(),
            _ => return Err(aerr("not a request type")),
        };

        // Register the oneshot *before* enqueuing so we never miss a fast reply.
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().await.insert(request_id.clone(), tx);

        // Build a recipient cert stub carrying only the ECDH pub so the
        // encrypt worker can seal to the authority without knowing its full cert.
        let recipient_cert = p43::bus::CertPayload {
            version: 1,
            device_id: String::new(),
            label: String::new(),
            sign_pubkey: vec![0u8; 32],
            ecdh_pubkey: self.authority_ecdh_pub.to_vec(),
            issuer_fp: vec![],
            iat: 0,
            exp: None,
        };

        let outbound = p43::bus::OutboundBusMessage {
            message: msg,
            recipient_cert: Some(recipient_cert),
        };

        // Unbounded sender — send never blocks or returns a capacity error.
        self.outbound_tx
            .send(outbound)
            .map_err(|_| aerr("outbound queue closed"))?;

        let sent_at = std::time::Instant::now();
        if self.verbose {
            eprintln!(
                "[p43::ssh_agent] send     {} at {}",
                request_id,
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            );
            if let Ok(mut m) = self.send_instants.lock() {
                m.insert(request_id.clone(), sent_at);
            }
        }

        let timeout_secs = self.timeout.as_secs();

        // Span: time waiting for the phone to respond (phone round-trip latency).
        #[cfg(feature = "telemetry")]
        let wait_fut = tokio::time::timeout(self.timeout, rx)
            .instrument(tracing::info_span!("ssh_agent.matrix_wait", timeout_secs));
        #[cfg(not(feature = "telemetry"))]
        let wait_fut = tokio::time::timeout(self.timeout, rx);

        match wait_fut.await {
            Ok(Ok(msg)) => {
                if self.verbose {
                    eprintln!(
                        "[p43::ssh_agent] forward  {} at {}  (+{} ms)",
                        request_id,
                        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                        sent_at.elapsed().as_millis(),
                    );
                }
                Ok(msg)
            }
            Err(_elapsed) => {
                // Timed out — reclaim the pending-map slot so it never grows
                // unbounded under a stream of unanswered requests.
                self.pending.lock().await.remove(&request_id);
                Err(aerr(format!(
                    "p43 request timed out ({timeout_secs} s) — is the phone online?"
                )))
            }
            Ok(Err(_)) => Err(aerr("response channel closed")),
        }
    }
}

fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Wrap a string into an `AgentError` (AgentError::other needs `std::error::Error`).
fn aerr(msg: impl Into<String>) -> AgentError {
    AgentError::other(std::io::Error::other(msg.into()))
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for MatrixProxySession {
    async fn request_identities(&mut self) -> std::result::Result<Vec<Identity>, AgentError> {
        let req = p43::protocol::Message::SshListKeysRequest(p43::protocol::SshListKeysRequest {
            request_id: new_request_id(),
        });
        match self.forward(req).await? {
            p43::protocol::Message::SshListKeysResponse(r) => r
                .keys
                .iter()
                .map(|k| {
                    let pk = ssh_key::public::PublicKey::from_bytes(&k.public_key)
                        .map_err(|e| aerr(e.to_string()))?;
                    Ok(Identity {
                        pubkey: pk.key_data().clone(),
                        comment: k.comment.clone(),
                    })
                })
                .collect(),
            p43::protocol::Message::Error(e) => Err(aerr(e.message)),
            _ => Err(aerr("unexpected response type")),
        }
    }

    #[cfg_attr(
        feature = "telemetry",
        tracing::instrument(
            skip(self, request),
            fields(
                data_len = request.data.len(),
                fingerprint = tracing::field::Empty,
            )
        )
    )]
    async fn sign(&mut self, request: SignRequest) -> std::result::Result<Signature, AgentError> {
        // Derive fingerprint from the KeyData so the phone knows which key to use.
        let pk = ssh_key::public::PublicKey::new(request.pubkey.clone(), "");
        let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();
        #[cfg(feature = "telemetry")]
        tracing::Span::current().record("fingerprint", fingerprint.as_str());

        let req = p43::protocol::Message::SshSignRequest(p43::protocol::SshSignRequest {
            request_id: new_request_id(),
            fingerprint,
            data: request.data.to_vec(),
            flags: request.flags,
            description: "SSH sign request".into(),
        });

        match self.forward(req).await? {
            p43::protocol::Message::SshSignResponse(r) => {
                Signature::try_from(r.signature.as_slice()).map_err(|e| aerr(e.to_string()))
            }
            p43::protocol::Message::Error(e) => Err(aerr(e.message)),
            _ => Err(aerr("unexpected response type")),
        }
    }
}

// ── Run ───────────────────────────────────────────────────────────────────────

/// Expand a leading `~/` to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .expect("cannot determine home directory")
            .join(rest)
    } else {
        PathBuf::from(path)
    }
}

/// Resolve the socket path: use the explicit value if given, otherwise place
/// `p43-ssh-agent.sock` in the store's **parent** directory (e.g.
/// `~/.config/project-43/`) so the socket lives alongside the configuration.
fn resolve_socket(socket: Option<&str>, store_dir: &Path) -> PathBuf {
    match socket {
        Some(s) => expand_tilde(s),
        None => {
            let base = store_dir.parent().unwrap_or(store_dir);
            base.join("p43-ssh-agent.sock")
        }
    }
}

/// Resolve the PID file path: explicit value wins, otherwise
/// `p43-ssh-agent.pid` next to the key store.
fn resolve_pid_file(pid_file: Option<&str>, store_dir: &Path) -> PathBuf {
    match pid_file {
        Some(s) => expand_tilde(s),
        None => {
            let base = store_dir.parent().unwrap_or(store_dir);
            base.join("p43-ssh-agent.pid")
        }
    }
}

/// Resolve the log file path: explicit value wins, otherwise
/// `p43-ssh-agent.log` next to the key store.
fn resolve_log_file(log_file: Option<&str>, store_dir: &Path) -> PathBuf {
    match log_file {
        Some(s) => expand_tilde(s),
        None => {
            let base = store_dir.parent().unwrap_or(store_dir);
            base.join("p43-ssh-agent.log")
        }
    }
}

/// Write `pid` to `path`, creating parent directories as needed.
fn write_pid_file(path: &Path, pid: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dirs for {}", path.display()))?;
    }
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("write PID file {}", path.display()))
}

/// Re-exec the current binary without `--daemon`, redirect its stdio to
/// `log_path` (stdout + stderr, append mode), write the child PID to
/// `pid_path`, then return so the caller (parent process) can exit cleanly.
fn spawn_daemon(pid_path: &Path, log_path: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("resolve current executable path")?;

    // Collect all argv tokens except the program name and any "--daemon" flag.
    let child_args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--daemon")
        .collect();

    // Open the log file in append mode so successive restarts accumulate.
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dirs for {}", log_path.display()))?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;
    // Both stdout and stderr go to the same file.
    let log_out = log_file.try_clone().context("clone log file handle")?;

    let child = std::process::Command::new(&exe)
        .args(&child_args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_file))
        .spawn()
        .context("spawn daemon child process")?;

    let pid = child.id();
    write_pid_file(pid_path, pid)?;

    // On Unix, dropping `Child` without calling wait() does NOT kill the
    // child — it simply becomes orphaned and is re-parented to init/PID 1.
    drop(child);

    eprintln!(
        "p43 ssh-agent daemon started (PID {pid})\nPID file: {}\nLog file: {}",
        pid_path.display(),
        log_path.display(),
    );
    Ok(())
}

// ── Run ───────────────────────────────────────────────────────────────────────

pub fn run(
    args: SshAgentArgs,
    store_dir: &Path,
    key_file: Option<PathBuf>,
    passphrase: String,
    pin: Option<String>,
    rt: &tokio::runtime::Runtime,
) -> Result<()> {
    // ── Stop mode ─────────────────────────────────────────────────────────────
    // Read the PID file, send SIGTERM, remove the file, and exit.
    if args.stop {
        let pid_path = resolve_pid_file(args.pid_file.as_deref(), store_dir);
        let raw = std::fs::read_to_string(&pid_path)
            .with_context(|| format!("Cannot read PID file: {}", pid_path.display()))?;
        let pid: i32 = raw
            .trim()
            .parse()
            .context("PID file does not contain a valid integer")?;
        // SAFETY: kill(2) is always safe with a known signal constant; we
        // check the return value immediately.
        let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            bail!("Failed to send SIGTERM to PID {pid}: {err}");
        }
        eprintln!("Sent SIGTERM to p43 ssh-agent (PID {pid})");
        // Best-effort cleanup so a subsequent --daemon doesn't see a stale file.
        if let Err(e) = std::fs::remove_file(&pid_path) {
            eprintln!(
                "Warning: could not remove PID file {}: {e}",
                pid_path.display()
            );
        }
        return Ok(());
    }

    let socket_path = resolve_socket(args.socket.as_deref(), store_dir);
    let _ = std::fs::remove_file(&socket_path);

    // ── Daemon mode ───────────────────────────────────────────────────────────
    // Re-exec ourselves without --daemon, write the child PID, and exit the
    // parent.  The child continues below in normal (foreground) mode.
    if args.daemon {
        let pid_path = resolve_pid_file(args.pid_file.as_deref(), store_dir);
        let log_path = resolve_log_file(args.log_file.as_deref(), store_dir);
        spawn_daemon(&pid_path, &log_path)?;
        return Ok(());
    }

    // ── Foreground PID file ───────────────────────────────────────────────────
    // When --pid-file is set but --daemon is not, write our own PID so that
    // `p43 ssh-agent --stop` can still find us.
    if let Some(ref pf) = args.pid_file {
        let pid_path = expand_tilde(pf);
        write_pid_file(&pid_path, std::process::id())?;
    }

    // A synchronous span that closes immediately — confirms the OTel pipeline
    // is live within the first batch flush (≤5 s) without waiting for a sign.
    #[cfg(feature = "telemetry")]
    {
        eprintln!("[p43::ssh_agent] creating startup span");
        {
            let _s = tracing::info_span!(
                "ssh_agent.started",
                socket = %socket_path.display(),
                local  = args.local,
                card   = args.card,
            )
            .entered();
            // _s drops here → span complete → enqueued for export
        }
        eprintln!("[p43::ssh_agent] startup span dropped");
    }

    if args.local {
        run_local(args, socket_path, key_file, passphrase, pin, rt)
    } else {
        run_matrix(args, socket_path, store_dir, rt)
    }
}

// ── Local mode ────────────────────────────────────────────────────────────────

fn run_local(
    args: SshAgentArgs,
    socket_path: PathBuf,
    key_file: Option<PathBuf>,
    passphrase: String,
    pin: Option<String>,
    rt: &tokio::runtime::Runtime,
) -> Result<()> {
    if args.card {
        let pin = match pin.or_else(|| std::env::var("YK_PIN").ok()) {
            Some(p) => p,
            None => rpassword::prompt_password("YubiKey PIN: ")
                .context("Failed to read PIN from terminal")?,
        };
        let session = P43CardSession::from_card(pin, args.concurrency)
            .context("Failed to initialise YubiKey SSH session")?;
        eprintln!(
            "p43 ssh-agent (local / YubiKey, concurrency={}): listening on {}\n\
             Run:  export SSH_AUTH_SOCK={}",
            args.concurrency,
            socket_path.display(),
            socket_path.display(),
        );
        rt.block_on(async move {
            let listener = UnixListener::bind(&socket_path)
                .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;
            listen(listener, session).await?;
            Ok::<_, anyhow::Error>(())
        })
    } else {
        let key_file = key_file.context(
            "ssh-agent --local requires --key-file <FILE> (or YK_KEY_FILE),\n\
             or add --card to use a YubiKey",
        )?;
        let session = P43SshSession::from_file(&key_file, &passphrase, args.key_slot.into())
            .context("Failed to load SSH key from key file")?;
        eprintln!(
            "p43 ssh-agent (local / software key): listening on {}\n\
             Run:  export SSH_AUTH_SOCK={}",
            socket_path.display(),
            socket_path.display(),
        );
        rt.block_on(async move {
            let listener = UnixListener::bind(&socket_path)
                .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;
            listen(listener, session).await?;
            Ok::<_, anyhow::Error>(())
        })
    }
}

// ── Matrix proxy mode ─────────────────────────────────────────────────────────

fn run_matrix(
    args: SshAgentArgs,
    socket_path: PathBuf,
    store_dir: &Path,
    rt: &tokio::runtime::Runtime,
) -> Result<()> {
    let store_dir = store_dir.to_path_buf();

    rt.block_on(async move {
        // 1. Restore saved Matrix session.
        let logged_in = p43::matrix::global::restore(&store_dir)
            .await
            .context("Failed to read Matrix session")?;

        if !logged_in {
            eprintln!(
                "No Matrix session found.  Run:\n\
                     \n  p43 matrix login --homeserver <URL> --user <@you:server>\n\
                     \n  p43 matrix join  --room <#room:server>\n\
                     \nThen re-run p43 ssh-agent."
            );
            return Ok(());
        }

        // 2. Resolve which room to use.
        let room_id = resolve_agent_room(args.room.as_deref(), &store_dir).await?;

        // 3. Shared pending-request map.
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        // Shared decryption context — populated after `ensure_registered` returns.
        // The decrypt middleware closure reads this via try_lock on each message.
        let decrypt_state: Arc<DecryptState> = Arc::new(std::sync::Mutex::new(None));

        // 4. Set up the two-layer bus bridge.
        //
        //   external_bus  ← raw Matrix messages
        //   internal_bus  ← decrypted plaintext messages
        //   outbound_queue ← plaintext messages waiting to be sealed + sent
        let (external_tx, external_rx) = p43::bus::new_external_bus();
        let (internal_tx, _initial_rx) = p43::bus::new_internal_bus();
        let (outbound_tx, outbound_rx) = p43::bus::new_outbound_queue();

        // 4a. Background task: listen_room → external bus.
        //     Reconnects automatically when the sync loop exits (zombie TCP,
        //     server restart, network drop).  Tracks the last next_batch token
        //     via on_pointer so reconnects never replay already-seen messages.
        let ext_tx_for_task = external_tx.clone();
        let listen_room_id = room_id.clone();

        // Per-reader pointer: app-state/<device_id>/cli.json → { room_id: since }
        // Each reader (cli, ui) has its own file so they never share cursors.
        let mx_cfg = MatrixConfig::from_store_dir(&store_dir);
        let store_root = store_dir.parent().unwrap_or(&store_dir).to_path_buf();
        let device_id =
            device_id_from_config(&mx_cfg.config_path).unwrap_or_else(|_| "unknown".into());
        let ptr_store = Arc::new(RoomPointerStore::new(&store_root, &device_id, "cli"));
        let initial_since: Option<String> = ptr_store.get(&room_id);
        match &initial_since {
            Some(token) => eprintln!(
                "[p43::ssh_agent] Resuming from pointer: {token}\n  ({})",
                ptr_store.path().display()
            ),
            None => eprintln!(
                "[p43::ssh_agent] No stored pointer — replaying full room history\n  ({})",
                ptr_store.path().display()
            ),
        }

        tokio::spawn(async move {
            let since: Arc<std::sync::Mutex<Option<String>>> =
                Arc::new(std::sync::Mutex::new(initial_since));
            loop {
                let ext_tx = ext_tx_for_task.clone();
                let since_val = since.lock().ok().and_then(|g| g.clone());
                let since_ptr = Arc::clone(&since);
                let ptr_store_inner = Arc::clone(&ptr_store);
                let room_id_inner = listen_room_id.clone();
                let _ = p43::matrix::global::listen_room(
                    &listen_room_id,
                    since_val.as_deref(),
                    move |token| {
                        if let Ok(mut g) = since_ptr.lock() {
                            *g = Some(token.clone());
                        }
                        if let Err(e) = ptr_store_inner.set(&room_id_inner, &token) {
                            eprintln!("[p43::ssh_agent] warning: could not persist pointer: {e}");
                        }
                    },
                    move |_sender, body, _ts_ms, event_id| {
                        if let Ok(msg) = p43::protocol::Message::from_json(&body) {
                            let _ = ext_tx.send(ExternalBusMessage {
                                message: msg,
                                event_id,
                            });
                        }
                    },
                )
                .await;
                eprintln!("[p43::ssh_agent] Matrix sync loop exited — reconnecting in 5 s…");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        // 4b. Decrypt middleware: external bus → internal bus.
        //     The closure captures the shared decrypt_state and reads it each time.
        {
            let ds = Arc::clone(&decrypt_state);
            p43::bus::spawn_decrypt_middleware(
                move |env| {
                    // Skip messages sent by ourselves (echoed back by the room).
                    // device_id() is stable once the key exists in decrypt_state.
                    let Ok(guard) = ds.try_lock() else {
                        return p43::bus::DecryptResult::Skip;
                    };
                    let Some((ref key, ref auth_pub)) = *guard else {
                        // Not yet registered — ignore encrypted messages.
                        return p43::bus::DecryptResult::Skip;
                    };
                    if env.from == key.device_id() {
                        return p43::bus::DecryptResult::Skip;
                    }
                    match p43::bus::open_protocol_message(key.as_ref(), auth_pub, env) {
                        Ok((inner, cert)) => p43::bus::DecryptResult::Ok(inner, Box::new(cert)),
                        Err(e) => p43::bus::DecryptResult::Err(e.to_string()),
                    }
                },
                |_locked_ext_msg| { /* CLI: no UI to notify about locked session */ },
                external_rx,
                internal_tx.clone(),
            );
        }

        // Async redact worker + request event-id registry — only active when
        // --redact-on-complete is set.  When the flag is off the server-side
        // Synapse retention policy handles cleanup; no per-transaction redaction
        // is performed and `on_sent` is not wired into the encrypt worker.
        let redact_tx_opt: Option<mpsc::Sender<(String, String)>> = if args.redact_on_complete {
            let (tx, _handle) = p43::matrix::global::spawn_redact_worker();
            Some(tx)
        } else {
            None
        };

        let req_event_map: Arc<std::sync::Mutex<HashMap<String, String>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Wire the on_sent channel when redaction or verbose is enabled.
        // The consumer logs "txd" (transmitted to Matrix) when verbose, and stores
        // (request_id → event_id) in req_event_map when --redact-on-complete.
        let send_instants: Arc<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        let req_ev_tx_opt: Option<mpsc::Sender<(String, String)>> = if args.redact_on_complete
            || args.verbose
        {
            let (req_ev_tx, mut req_ev_rx) = tokio::sync::mpsc::channel::<(String, String)>(256);
            let map = Arc::clone(&req_event_map);
            let instants = Arc::clone(&send_instants);
            let verbose = args.verbose;
            let redact = args.redact_on_complete;
            tokio::spawn(async move {
                while let Some((req_id, _ev_id)) = req_ev_rx.recv().await {
                    if verbose {
                        let elapsed_ms = instants
                            .lock()
                            .ok()
                            .and_then(|mut m| m.remove(&req_id))
                            .map(|t| t.elapsed().as_millis());
                        if let Some(ms) = elapsed_ms {
                            eprintln!(
                                "[p43::ssh_agent] txd      {} at {}  (+{} ms)",
                                req_id,
                                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                                ms,
                            );
                        }
                    }
                    if redact {
                        if let Ok(mut guard) = map.lock() {
                            guard.insert(req_id, _ev_id);
                        }
                    }
                }
            });
            Some(req_ev_tx)
        } else {
            None
        };

        // 4c. Internal bus dispatcher: route responses to the pending map.
        //     When --redact-on-complete is set, also queue both the request and
        //     response event_ids for deferred redaction on each completed transaction.
        {
            let dispatch_pending = Arc::clone(&pending);
            let dispatch_room_id = room_id.clone();
            let dispatch_req_map = Arc::clone(&req_event_map);
            let dispatch_redact_tx = redact_tx_opt.clone();
            let mut internal_rx = internal_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    let inbound = match internal_rx.recv().await {
                        Ok(m) => m,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("[p43::bus] internal_rx lagged, dropped {n} messages");
                            continue;
                        }
                    };
                    let request_id = match &inbound.message {
                        p43::protocol::Message::SshListKeysResponse(r) => {
                            Some(r.request_id.clone())
                        }
                        p43::protocol::Message::SshSignResponse(r) => Some(r.request_id.clone()),
                        p43::protocol::Message::BusCertResponse(r) => Some(r.request_id.clone()),
                        p43::protocol::Message::Error(e) => e.request_id.clone(),
                        _ => None,
                    };
                    if let Some(id) = request_id {
                        {
                            let mut guard = dispatch_pending.lock().await;
                            if let Some(tx) = guard.remove(&id) {
                                let _ = tx.send(inbound.message);
                            }
                        }
                        // Queue both req + res for deferred redaction only when
                        // --redact-on-complete is enabled and both event_ids are known.
                        if let Some(ref redact_tx) = dispatch_redact_tx {
                            let res_eid = inbound.event_id.clone();
                            if !res_eid.is_empty() {
                                if let Ok(mut map) = dispatch_req_map.lock() {
                                    if let Some(req_eid) = map.remove(&id) {
                                        let _ =
                                            redact_tx.try_send((dispatch_room_id.clone(), req_eid));
                                        let _ =
                                            redact_tx.try_send((dispatch_room_id.clone(), res_eid));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        // 5. Ensure this device is registered with the bus authority.
        let bus_dir = bus::bus_dir(&store_dir);
        let (device_label, device_key) =
            ensure_registered(&bus_dir, args.device.as_deref(), &room_id, &pending).await?;

        // Load the device cert and authority pub for sealing outgoing messages.
        let cert_bytes = Arc::new(
            std::fs::read(bus::device_cert_path(&bus_dir, &device_label))
                .context("read device cert after registration")?,
        );
        let authority_pub = AuthorityPub::load(&bus::authority_pub_path(&bus_dir))
            .context("read authority.pub.cbor after registration")?;
        let authority_sign_pub = authority_pub
            .ed25519_pub_array()
            .context("extract Ed25519 authority signing pubkey")?;
        let authority_ecdh_pub = authority_pub
            .x25519_pub_array()
            .context("extract X25519 authority pub")?;
        let device_key = Arc::new(device_key);

        // Activate the decrypt context so the middleware can now unwrap
        // encrypted responses.
        if let Ok(mut guard) = decrypt_state.lock() {
            *guard = Some((Arc::clone(&device_key), authority_sign_pub));
        }

        // 4d. Encrypt worker: outbound queue → seal → Matrix send.
        //     Spawned after registration so that cert_bytes and device_key are
        //     available; the worker runs for the lifetime of the agent.
        //     `req_ev_tx_opt` is Some only when --redact-on-complete is set,
        //     routing (request_id, event_id) pairs to the registry task.
        {
            let dk = Arc::clone(&device_key);
            let cb = Arc::clone(&cert_bytes);
            p43::bus::spawn_encrypt_worker(
                move |msg, recipient| {
                    p43::bus::seal_protocol_message(dk.as_ref(), &cb, recipient, msg).ok()
                },
                room_id.clone(),
                outbound_rx,
                req_ev_tx_opt,
            );
        }

        // 6. Bind the Unix socket and start the agent.
        let session = MatrixProxySession::new(
            Arc::clone(&pending),
            outbound_tx,
            authority_ecdh_pub,
            std::time::Duration::from_secs(args.timeout_secs),
            args.verbose,
            send_instants,
        );

        eprintln!(
            "p43 ssh-agent (Matrix proxy → {room_id}): listening on {sock}\n\
                 Run:  export SSH_AUTH_SOCK={sock}",
            room_id = room_id,
            sock = socket_path.display(),
        );

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;
        listen(listener, session).await?;
        Ok::<_, anyhow::Error>(())
    })
}

// ── Bus registration ──────────────────────────────────────────────────────────

/// Check that this device has a valid cert; if not, run the CSR flow.
///
/// Blocks until the UI approves the request and sends back a `bus.cert_response`.
/// Returns `(label, device_key)` for the caller to use when sealing messages.
async fn ensure_registered(
    bus_dir: &Path,
    device_label: Option<&str>,
    room_id: &str,
    pending: &PendingMap,
) -> Result<(String, DeviceKey)> {
    std::fs::create_dir_all(bus_dir)?;

    // ── Find or generate the device key ───────────────────────────────────────
    let (label, key) = load_or_generate_device_key(bus_dir, device_label)?;

    // ── Check cert validity ───────────────────────────────────────────────────
    let cert_path = bus::device_cert_path(bus_dir, &label);
    if cert_path.exists() {
        match p43::bus::DeviceCert::load(&cert_path) {
            Ok(cert) => {
                // Check expiry.
                let now = p43::bus::unix_now()?;
                let expired = cert.payload.exp.map(|e| now > e).unwrap_or(false);
                if !expired {
                    eprintln!(
                        "[p43::bus] device '{}' already registered (cert valid)",
                        label
                    );
                    return Ok((label, key));
                }
                eprintln!(
                    "[p43::bus] cert for '{}' has expired — re-registering",
                    label
                );
            }
            Err(e) => {
                eprintln!(
                    "[p43::bus] could not load cert for '{}': {} — re-registering",
                    label, e
                );
            }
        }
    }

    // ── Generate CSR ──────────────────────────────────────────────────────────
    let csr = DeviceCsr::generate(&key)?;
    let request_id = uuid::Uuid::new_v4().to_string();

    // Register a oneshot in the pending map *before* sending, so we don't miss
    // a very fast response.
    let (tx, rx) = tokio::sync::oneshot::channel::<Message>();
    pending.lock().await.insert(request_id.clone(), tx);

    // ── Send csr_request ──────────────────────────────────────────────────────
    let msg = Message::BusCsrRequest(BusCsrRequest {
        request_id: request_id.clone(),
        device_label: label.clone(),
        device_id: key.device_id(),
        csr_b64: B64.encode(&csr.cose_bytes),
    });
    p43::matrix::global::send_message(room_id, &msg.to_json()?).await?;

    eprintln!(
        "[p43::bus] CSR sent for device '{}' ({})\n\
         Waiting for approval in the p43 app…",
        label,
        key.device_id()
    );

    // ── Block until cert_response arrives ─────────────────────────────────────
    let response = rx.await.context("bus registration channel closed")?;
    let cert_resp = match response {
        Message::BusCertResponse(r) => r,
        Message::Error(e) => bail!("bus registration rejected: {}", e.message),
        other => bail!(
            "unexpected message during registration: {}",
            other.type_name()
        ),
    };

    // ── Persist cert + authority pubkey ───────────────────────────────────────
    let cert_bytes = B64
        .decode(&cert_resp.cert_b64)
        .context("decode cert base64")?;
    let authority_pub_bytes = B64
        .decode(&cert_resp.authority_pub_b64)
        .context("decode authority_pub base64")?;

    // Parse CBOR AuthorityPub and verify the cert against its Ed25519 key.
    let authority_pub = AuthorityPub::from_cbor_bytes(&authority_pub_bytes)
        .context("decode CBOR AuthorityPub from BusCertResponse")?;
    let authority_sign_pub = authority_pub.ed25519_pub_array()?;
    let cert_payload = p43::bus::DeviceCert::verify(&cert_bytes, &authority_sign_pub)?;

    // Write cert alongside the device key.
    std::fs::write(&cert_path, &cert_bytes)
        .with_context(|| format!("write cert to {}", cert_path.display()))?;

    // Write authority pub.cbor alongside the cert (canonical bus location).
    let auth_pub_path = bus::authority_pub_path(bus_dir);
    authority_pub
        .save(&auth_pub_path)
        .with_context(|| format!("write authority pubkey to {}", auth_pub_path.display()))?;

    eprintln!(
        "[p43::bus] registered: device_id={} label={}\n  cert: {}\n  authority: {}",
        cert_payload.device_id,
        cert_payload.label,
        cert_path.display(),
        auth_pub_path.display(),
    );

    Ok((label, key))
}
