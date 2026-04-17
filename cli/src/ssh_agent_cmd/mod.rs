pub mod subcmd;

use anyhow::{Context, Result};
use p43::ssh_agent::{card_auth_sign_ssh, load_card_auth_key_info, load_ssh_key, SshKeySlot};
use signature::Signer;
use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::public::KeyData;
use ssh_key::{PrivateKey, Signature};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subcmd::SshAgentArgs;
use tokio::net::UnixListener;

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

    if args.card {
        // ── YubiKey path ──────────────────────────────────────────────────────
        let pin = match pin.or_else(|| std::env::var("YK_PIN").ok()) {
            Some(p) => p,
            None => rpassword::prompt_password("YubiKey PIN: ")
                .context("Failed to read PIN from terminal")?,
        };

        let concurrency = args.concurrency;
        let session = P43CardSession::from_card(pin, concurrency)
            .context("Failed to initialise YubiKey SSH session")?;

        eprintln!(
            "p43 ssh-agent (YubiKey, concurrency={concurrency}): listening on {sock}\n\
             Run:  export SSH_AUTH_SOCK={sock}",
            concurrency = concurrency,
            sock = socket_path.display(),
        );

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to build Tokio runtime")?
            .block_on(async move {
                let listener = UnixListener::bind(&socket_path)
                    .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;
                listen(listener, session).await?;
                Ok::<_, anyhow::Error>(())
            })
    } else {
        // ── Software-key path ─────────────────────────────────────────────────
        let key_file = key_file.context(
            "ssh-agent requires --key-file <FILE> (or YK_KEY_FILE) for software keys,\n\
             or pass --card to use a YubiKey",
        )?;

        let slot: SshKeySlot = args.key_slot.into();
        let session = P43SshSession::from_file(&key_file, &passphrase, slot)
            .context("Failed to load SSH key from key file")?;

        eprintln!(
            "p43 ssh-agent (software key): listening on {sock}\n\
             Run:  export SSH_AUTH_SOCK={sock}",
            sock = socket_path.display(),
        );

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to build Tokio runtime")?
            .block_on(async move {
                let listener = UnixListener::bind(&socket_path)
                    .with_context(|| format!("Failed to bind to {}", socket_path.display()))?;
                listen(listener, session).await?;
                Ok::<_, anyhow::Error>(())
            })
    }
}
