pub mod subcmd;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use p43::ssh_agent::{card_auth_sign_ssh, load_card_auth_key_info, load_ssh_key, SshKeySlot};
use signature::Signer;
use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, Signature};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subcmd::SshAgentArgs;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

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

/// SSH agent session that forwards every request as a p43 protocol message
/// into a Matrix room and waits for the response from the phone.
#[derive(Clone)]
struct MatrixProxySession {
    room_id: String,
    pending: PendingMap,
}

impl MatrixProxySession {
    fn new(room_id: String, pending: PendingMap) -> Self {
        Self { room_id, pending }
    }

    /// Send `msg` to the Matrix room and block until a matching response
    /// arrives (or the 30-second deadline expires).
    async fn forward(
        &self,
        msg: p43::protocol::Message,
    ) -> std::result::Result<p43::protocol::Message, AgentError> {
        let request_id = match &msg {
            p43::protocol::Message::SshListKeysRequest(r) => r.request_id.clone(),
            p43::protocol::Message::SshSignRequest(r) => r.request_id.clone(),
            _ => return Err(aerr("not a request type")),
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().await.insert(request_id, tx);

        let json = msg.to_json().map_err(|e| aerr(e.to_string()))?;
        p43::matrix::global::send_message(&self.room_id, &json)
            .await
            .map_err(|e| aerr(e.to_string()))?;

        tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .map_err(|_| aerr("p43 request timed out (30 s) — is the phone online?"))?
            .map_err(|_| aerr("response channel closed"))
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
                    let bytes = B64.decode(&k.public_key).map_err(|e| aerr(e.to_string()))?;
                    let pk = ssh_key::public::PublicKey::from_bytes(&bytes)
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

    async fn sign(&mut self, request: SignRequest) -> std::result::Result<Signature, AgentError> {
        // Derive fingerprint from the KeyData so the phone knows which key to use.
        let pk = ssh_key::public::PublicKey::new(request.pubkey.clone(), "");
        let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

        // Encode the raw data as base64 for the JSON payload.
        let data_b64 = B64.encode(request.data.as_slice());

        let req = p43::protocol::Message::SshSignRequest(p43::protocol::SshSignRequest {
            request_id: new_request_id(),
            fingerprint,
            data: data_b64,
            flags: request.flags,
            description: "SSH sign request".into(),
        });

        match self.forward(req).await? {
            p43::protocol::Message::SshSignResponse(r) => {
                let sig_bytes = B64.decode(&r.signature).map_err(|e| aerr(e.to_string()))?;
                Signature::try_from(sig_bytes.as_slice()).map_err(|e| aerr(e.to_string()))
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

pub fn run(
    args: SshAgentArgs,
    store_dir: &Path,
    key_file: Option<PathBuf>,
    passphrase: String,
    pin: Option<String>,
) -> Result<()> {
    let socket_path = resolve_socket(args.socket.as_deref(), store_dir);
    let _ = std::fs::remove_file(&socket_path);

    if args.local {
        run_local(args, socket_path, key_file, passphrase, pin)
    } else {
        run_matrix(args, socket_path, store_dir)
    }
}

// ── Local mode ────────────────────────────────────────────────────────────────

fn run_local(
    args: SshAgentArgs,
    socket_path: PathBuf,
    key_file: Option<PathBuf>,
    passphrase: String,
    pin: Option<String>,
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
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async move {
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
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let listener = UnixListener::bind(&socket_path)
                    .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;
                listen(listener, session).await?;
                Ok::<_, anyhow::Error>(())
            })
    }
}

// ── Matrix proxy mode ─────────────────────────────────────────────────────────

fn run_matrix(args: SshAgentArgs, socket_path: PathBuf, store_dir: &Path) -> Result<()> {
    let store_dir = store_dir.to_path_buf();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
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

            // 4. Start a background task that reads incoming Matrix messages and
            //    resolves any pending oneshot channels.
            let dispatch_pending = Arc::clone(&pending);
            let listen_room_id = room_id.clone();
            tokio::spawn(async move {
                let _ = p43::matrix::global::listen_room(&listen_room_id, move |_sender, body| {
                    if let Ok(msg) = p43::protocol::Message::from_json(&body) {
                        let request_id = match &msg {
                            p43::protocol::Message::SshListKeysResponse(r) => {
                                Some(r.request_id.clone())
                            }
                            p43::protocol::Message::SshSignResponse(r) => {
                                Some(r.request_id.clone())
                            }
                            p43::protocol::Message::Error(e) => e.request_id.clone(),
                            _ => None,
                        };
                        if let Some(id) = request_id {
                            // Use try_lock to avoid blocking the sync thread.
                            if let Ok(mut guard) = dispatch_pending.try_lock() {
                                if let Some(tx) = guard.remove(&id) {
                                    let _ = tx.send(msg);
                                }
                            }
                        }
                    }
                })
                .await;
            });

            // 5. Bind the Unix socket and start the agent.
            let session = MatrixProxySession::new(room_id.clone(), pending);

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

/// Resolve which room the agent should use.
///
/// Priority:
/// 1. `--room` flag (explicit override)
/// 2. `agent_room` saved in `matrix-config.json` by `p43 matrix join`
/// 3. If exactly one room is joined, use it (convenience)
/// 4. Otherwise print the room list and error
async fn resolve_agent_room(room_arg: Option<&str>, store_dir: &std::path::Path) -> Result<String> {
    if let Some(r) = room_arg {
        return Ok(r.to_string());
    }

    // Check the saved agent_room in the config.
    let cfg = p43::matrix::MatrixConfig::from_store_dir(store_dir);
    if let Some(saved) = p43::matrix::client::load_config(&cfg.config_path)? {
        if let Some(room_id) = saved.agent_room {
            eprintln!("Using saved agent_room: {room_id}");
            return Ok(room_id);
        }
    }

    // Fall back to listing rooms.
    let rooms = p43::matrix::global::list_rooms().await?;
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
