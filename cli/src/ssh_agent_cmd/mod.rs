pub mod subcmd;

use anyhow::{Context, Result};
use p43::ssh_agent::{load_ssh_key, SshKeySlot};
use signature::Signer;
use ssh_agent_lib::agent::listen;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::{PrivateKey, Signature};
use std::path::PathBuf;
use std::sync::Arc;
use subcmd::SshAgentArgs;
use tokio::net::UnixListener;

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

pub fn run(args: SshAgentArgs, key_file: Option<PathBuf>, passphrase: String) -> Result<()> {
    let key_file = key_file.context(
        "ssh-agent requires a key file; provide --key-file <FILE> or set YK_KEY_FILE\n\
         (YubiKey card support for ssh-agent is planned for a future release)",
    )?;

    let slot: SshKeySlot = args.key_slot.into();
    let session = P43SshSession::from_file(&key_file, &passphrase, slot)
        .context("Failed to load SSH key from key file")?;

    let socket_path = expand_tilde(&args.socket);
    let _ = std::fs::remove_file(&socket_path);

    eprintln!(
        "p43 ssh-agent: listening on {}\n\
         Run:  export SSH_AUTH_SOCK={}",
        socket_path.display(),
        socket_path.display(),
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
