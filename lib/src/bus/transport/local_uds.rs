//! Unix Domain Socket transport backend for same-machine IPC.
//!
//! Exposes:
//! - [`LocalUdsServer`]: Hosted by the responder (Flutter UI / authority). Binds
//!   `local-bus.sock` and receives requests from local clients.
//! - [`LocalUdsClient`]: Hosted by the requester (`p43 ssh-agent`). Connects to
//!   `local-bus.sock` and forwards requests to the local UI.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, watch};

use super::{BackendState, BackendStatus, TransportBackend};
use crate::bus::bridge::ExternalBusMessage;
use crate::protocol;

/// Default socket filename placed in the store root (`~/.config/project-43/local-bus.sock`).
pub const LOCAL_BUS_SOCK_NAME: &str = "local-bus.sock";

/// Resolve the path to `local-bus.sock` given the store root or keys dir.
pub fn local_bus_socket_path(store_root: &Path) -> PathBuf {
    let base = if store_root.ends_with("keys") {
        store_root.parent().unwrap_or(store_root)
    } else {
        store_root
    };
    base.join(LOCAL_BUS_SOCK_NAME)
}

// ── LocalUdsServer ────────────────────────────────────────────────────────────

/// Server running in the UI / authority process.
///
/// Binds `local-bus.sock` and accepts connections from local CLI clients (such as
/// `p43 ssh-agent`).
pub struct LocalUdsServer {
    sock_path: PathBuf,
    _state_tx: watch::Sender<BackendState>,
    state_rx: watch::Receiver<BackendState>,
    clients: Arc<Mutex<Vec<mpsc::UnboundedSender<String>>>>,
    seq: AtomicU64,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl LocalUdsServer {
    /// Bind `local-bus.sock` and start accepting connections, routing received messages
    /// into `inbound_tx`.
    pub fn start(
        sock_path: PathBuf,
        inbound_tx: broadcast::Sender<ExternalBusMessage>,
    ) -> anyhow::Result<Arc<Self>> {
        // Clean up stale socket file if it exists.
        if sock_path.exists() {
            let _ = std::fs::remove_file(&sock_path);
        }

        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&sock_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to bind local UDS socket {}: {e}",
                sock_path.display()
            )
        })?;

        // Restrict permissions to user only (0600).
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
        }

        let (state_tx, state_rx) = watch::channel(BackendState::Disconnected);
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let clients: Arc<Mutex<Vec<mpsc::UnboundedSender<String>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let server = Arc::new(Self {
            sock_path: sock_path.clone(),
            _state_tx: state_tx.clone(),
            state_rx,
            clients: Arc::clone(&clients),
            seq: AtomicU64::new(1),
            stop_tx: Some(stop_tx),
        });

        let sock_path_for_cleanup = sock_path.clone();
        let clients_for_loop = Arc::clone(&clients);
        let state_tx_loop = state_tx.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, _addr)) => {
                                let (client_tx, mut client_rx) = mpsc::unbounded_channel::<String>();
                                if let Ok(mut g) = clients_for_loop.lock() {
                                    g.push(client_tx);
                                }
                                let _ = state_tx_loop.send_if_modified(|curr| {
                                    if *curr != BackendState::Connected {
                                        *curr = BackendState::Connected;
                                        true
                                    } else {
                                        false
                                    }
                                });

                                let (reader, mut writer) = stream.into_split();
                                let in_tx = inbound_tx.clone();
                                let clients_cleanup = Arc::clone(&clients_for_loop);
                                let state_tx_cleanup = state_tx_loop.clone();

                                // Client read task: read line-delimited JSON.
                                tokio::spawn(async move {
                                    let mut lines = BufReader::new(reader).lines();
                                    let mut msg_seq: u64 = 0;
                                    while let Ok(Some(line)) = lines.next_line().await {
                                        msg_seq += 1;
                                        if let Ok(msg) = protocol::Message::from_json(&line) {
                                            let _ = in_tx.send(ExternalBusMessage {
                                                message: msg,
                                                event_id: format!("local_uds:req:{}", msg_seq),
                                            });
                                        }
                                    }
                                });

                                // Client write task: send line-delimited JSON.
                                tokio::spawn(async move {
                                    while let Some(line) = client_rx.recv().await {
                                        let data = format!("{line}\n");
                                        if writer.write_all(data.as_bytes()).await.is_err() {
                                            break;
                                        }
                                        let _ = writer.flush().await;
                                    }
                                    // Remove disconnected client from pool.
                                    if let Ok(mut g) = clients_cleanup.lock() {
                                        g.retain(|c| !c.is_closed());
                                        if g.is_empty() {
                                            let _ = state_tx_cleanup.send_if_modified(|curr| {
                                                if *curr != BackendState::Disconnected {
                                                    *curr = BackendState::Disconnected;
                                                    true
                                                } else {
                                                    false
                                                }
                                            });
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("[p43::transport::local_uds] accept error: {e}");
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }

            // Clean up socket file on server exit.
            let _ = std::fs::remove_file(&sock_path_for_cleanup);
        });

        Ok(server)
    }

    /// Number of active connected clients.
    pub fn active_clients(&self) -> usize {
        if let Ok(mut g) = self.clients.lock() {
            g.retain(|c| !c.is_closed());
            g.len()
        } else {
            0
        }
    }
}

impl Drop for LocalUdsServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop_tx.take() {
            let _ = stop.send(());
        }
        let _ = std::fs::remove_file(&self.sock_path);
    }
}

#[async_trait::async_trait]
impl TransportBackend for LocalUdsServer {
    fn name(&self) -> &'static str {
        "local_uds"
    }

    fn status(&self) -> BackendStatus {
        let active = self.active_clients();
        let state = if active > 0 {
            BackendState::Connected
        } else {
            BackendState::Disconnected
        };
        BackendStatus {
            name: "local_uds".into(),
            state,
            is_active: false,
            latency_ms: Some(0),
            last_seen_ms: 0,
            detail: Some(format!(
                "Listening on {} ({} client{})",
                self.sock_path.display(),
                active,
                if active == 1 { "" } else { "s" }
            )),
        }
    }

    fn is_available(&self) -> bool {
        self.active_clients() > 0
    }

    fn watch_state(&self) -> watch::Receiver<BackendState> {
        self.state_rx.clone()
    }

    async fn send(&self, raw_frame: &str) -> anyhow::Result<String> {
        let mut active = Vec::new();
        if let Ok(mut g) = self.clients.lock() {
            g.retain(|c| !c.is_closed());
            for c in g.iter() {
                active.push(c.clone());
            }
        }

        if active.is_empty() {
            anyhow::bail!("no local UDS clients connected to receive response");
        }

        for c in active {
            let _ = c.send(raw_frame.to_string());
        }

        let id = self.seq.fetch_add(1, Ordering::Relaxed);
        Ok(format!("local_uds:res:{id}"))
    }
}

// ── LocalUdsClient ────────────────────────────────────────────────────────────

/// Client running in the SSH agent / requester process.
///
/// Connects to `local-bus.sock` and delivers outgoing requests.
pub struct LocalUdsClient {
    sock_path: PathBuf,
    _state_tx: watch::Sender<BackendState>,
    state_rx: watch::Receiver<BackendState>,
    outbound_tx: Arc<Mutex<Option<mpsc::UnboundedSender<String>>>>,
    seq: AtomicU64,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl LocalUdsClient {
    /// Create and start the client connection loop.
    pub fn start(
        sock_path: PathBuf,
        inbound_tx: broadcast::Sender<ExternalBusMessage>,
    ) -> Arc<Self> {
        let (state_tx, state_rx) = watch::channel(BackendState::Disconnected);
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let outbound_tx: Arc<Mutex<Option<mpsc::UnboundedSender<String>>>> =
            Arc::new(Mutex::new(None));

        let client = Arc::new(Self {
            sock_path: sock_path.clone(),
            _state_tx: state_tx.clone(),
            state_rx,
            outbound_tx: Arc::clone(&outbound_tx),
            seq: AtomicU64::new(1),
            stop_tx: Some(stop_tx),
        });

        tokio::spawn(async move {
            loop {
                // If stop requested, exit loop.
                if stop_rx.try_recv().is_ok() {
                    break;
                }

                // Attempt to connect.
                match UnixStream::connect(&sock_path).await {
                    Ok(stream) => {
                        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
                        if let Ok(mut g) = outbound_tx.lock() {
                            *g = Some(out_tx);
                        }
                        let _ = state_tx.send(BackendState::Connected);

                        let (reader, mut writer) = stream.into_split();
                        let in_tx = inbound_tx.clone();

                        let mut lines = BufReader::new(reader).lines();
                        let mut read_seq: u64 = 0;

                        loop {
                            tokio::select! {
                                _ = &mut stop_rx => {
                                    return;
                                }
                                line_res = lines.next_line() => {
                                    match line_res {
                                        Ok(Some(line)) => {
                                            read_seq += 1;
                                            if let Ok(msg) = protocol::Message::from_json(&line) {
                                                let _ = in_tx.send(ExternalBusMessage {
                                                    message: msg,
                                                    event_id: format!("local_uds:in:{}", read_seq),
                                                });
                                            }
                                        }
                                        _ => {
                                            // Socket closed or error.
                                            break;
                                        }
                                    }
                                }
                                out_msg = out_rx.recv() => {
                                    match out_msg {
                                        Some(line) => {
                                            let data = format!("{line}\n");
                                            if writer.write_all(data.as_bytes()).await.is_err() {
                                                break;
                                            }
                                            let _ = writer.flush().await;
                                        }
                                        None => break,
                                    }
                                }
                            }
                        }

                        // Disconnected.
                        if let Ok(mut g) = outbound_tx.lock() {
                            *g = None;
                        }
                        let _ = state_tx.send(BackendState::Disconnected);
                    }
                    Err(_) => {
                        let _ = state_tx.send(BackendState::Disconnected);
                    }
                }

                // Retry delay before trying to reconnect.
                tokio::select! {
                    _ = &mut stop_rx => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                }
            }
        });

        client
    }
}

impl Drop for LocalUdsClient {
    fn drop(&mut self) {
        if let Some(stop) = self.stop_tx.take() {
            let _ = stop.send(());
        }
    }
}

#[async_trait::async_trait]
impl TransportBackend for LocalUdsClient {
    fn name(&self) -> &'static str {
        "local_uds"
    }

    fn status(&self) -> BackendStatus {
        let state = self.state_rx.borrow().clone();
        BackendStatus {
            name: "local_uds".into(),
            state,
            is_active: false,
            latency_ms: Some(0),
            last_seen_ms: 0,
            detail: Some(format!("Target socket: {}", self.sock_path.display())),
        }
    }

    fn watch_state(&self) -> watch::Receiver<BackendState> {
        self.state_rx.clone()
    }

    async fn send(&self, raw_frame: &str) -> anyhow::Result<String> {
        let sender = {
            let g = self.outbound_tx.lock().unwrap();
            g.clone()
        };

        let tx = sender.ok_or_else(|| anyhow::anyhow!("local UDS client is not connected"))?;
        tx.send(raw_frame.to_string())
            .map_err(|_| anyhow::anyhow!("local UDS send queue closed"))?;

        let id = self.seq.fetch_add(1, Ordering::Relaxed);
        Ok(format!("local_uds:out:{id}"))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::bridge::new_external_bus;

    #[tokio::test]
    async fn test_local_uds_round_trip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("test-bus.sock");

        let (server_in_tx, mut server_in_rx) = new_external_bus();
        let (client_in_tx, mut client_in_rx) = new_external_bus();

        // 1. Start server.
        let server = LocalUdsServer::start(sock_path.clone(), server_in_tx).unwrap();

        // 2. Start client.
        let client = LocalUdsClient::start(sock_path.clone(), client_in_tx);

        // Wait for connection to establish.
        let watch_rx = client.watch_state();
        let mut connected = *watch_rx.borrow() == BackendState::Connected;
        for _ in 0..20 {
            if connected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            connected = *watch_rx.borrow() == BackendState::Connected;
        }
        assert!(connected, "client should connect to server");

        // 3. Client sends a request message.
        let req = protocol::Message::SshSignRequest(protocol::SshSignRequest {
            request_id: "test-req-123".into(),
            fingerprint: "fp123".into(),
            data: b"hello-uds".to_vec(),
            flags: 0,
            description: "test signature".into(),
            meta: Default::default(),
        });

        let send_res = client.send(&req.to_json().unwrap()).await;
        assert!(send_res.is_ok());

        // 4. Server receives request.
        let received_by_server =
            tokio::time::timeout(std::time::Duration::from_secs(2), server_in_rx.recv())
                .await
                .expect("server should receive within timeout")
                .expect("channel not closed");

        match received_by_server.message {
            protocol::Message::SshSignRequest(r) => {
                assert_eq!(r.request_id, "test-req-123");
            }
            other => panic!("unexpected message: {:?}", other),
        }

        // 5. Server sends a response message back to client.
        let res = protocol::Message::SshSignResponse(protocol::SshSignResponse {
            request_id: "test-req-123".into(),
            signature: b"sig-bytes".to_vec(),
        });

        let server_send_res = server.send(&res.to_json().unwrap()).await;
        assert!(server_send_res.is_ok());

        // 6. Client receives response.
        let received_by_client =
            tokio::time::timeout(std::time::Duration::from_secs(2), client_in_rx.recv())
                .await
                .expect("client should receive within timeout")
                .expect("channel not closed");

        match received_by_client.message {
            protocol::Message::SshSignResponse(r) => {
                assert_eq!(r.request_id, "test-req-123");
                assert_eq!(r.signature, b"sig-bytes");
            }
            other => panic!("unexpected message: {:?}", other),
        }
    }
}
