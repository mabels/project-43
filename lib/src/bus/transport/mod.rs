//! Multi-backend transport abstraction and routing for p43 bus.
//!
//! Decouples the cryptographic bus (`BusSecure`, decrypt middleware, encrypt worker)
//! from the underlying network/IPC carriers (Matrix, Local Unix Domain Socket, AWS SQS,
//! GCP Pub/Sub, etc.).

use std::sync::Arc;
use tokio::sync::{broadcast, watch};

use crate::bus::bridge::ExternalBusMessage;

pub mod dedup;
pub mod local_uds;
#[cfg(feature = "matrix")]
pub mod matrix;
pub mod virtual_transport;

pub use dedup::{message_dedup_id, MessageDeduplicator};

/// Emission strategy for outbound transport routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SendStrategy {
    /// Send to ALL available backends concurrently; fastest delivery wins and
    /// subsequent duplicates are dropped by the deduplicator (default).
    #[default]
    Parallel,
    /// Try backends sequentially: preferred/primary first, then fallback list.
    Sequential,
}

// ── Connection state ──────────────────────────────────────────────────────────

/// Health & connection state of a transport backend.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BackendState {
    /// Backend is not running, offline, or socket is disconnected.
    Disconnected,
    /// Actively trying to connect / reconnect.
    Connecting,
    /// Connected and ready for immediate message delivery.
    Connected,
    /// Partially reachable or high error rate.
    Degraded(String),
}

/// Detailed diagnostic snapshot of a backend.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackendStatus {
    /// Static identifier, e.g. "matrix", "local_uds", "aws_sqs".
    pub name: String,
    /// Current health state.
    pub state: BackendState,
    /// Whether this backend is currently the active (in-use) transport.
    pub is_active: bool,
    /// Round-trip time in milliseconds (if measured).
    pub latency_ms: Option<u64>,
    /// Last seen activity timestamp (unix ms).
    pub last_seen_ms: u64,
    /// Optional human-readable diagnostic detail.
    pub detail: Option<String>,
}

// ── TransportBackend trait ────────────────────────────────────────────────────

/// A pluggable message transport backend.
///
/// Implementors can be local (Unix Domain Socket, Named Pipe) or remote
/// (Matrix, SQS, Google Pub/Sub, Slack, Discord).
#[async_trait::async_trait]
pub trait TransportBackend: Send + Sync {
    /// Unique identifier for this backend (e.g. `"local_uds"`, `"matrix"`).
    fn name(&self) -> &'static str;

    /// Current status snapshot.
    fn status(&self) -> BackendStatus;

    /// Instant fast-path check: returns true if ready to send.
    fn is_available(&self) -> bool {
        matches!(self.status().state, BackendState::Connected)
    }

    /// Watch the backend's connection state reactively.
    fn watch_state(&self) -> watch::Receiver<BackendState>;

    /// Send a serialized protocol message frame over this transport.
    /// Returns a transport-specific tracking ID (e.g. Matrix event ID or local sequence ID).
    async fn send(&self, raw_frame: &str) -> anyhow::Result<String>;

    /// Redact or clean up a completed transaction event on this transport.
    /// Default implementation is a no-op (used by Local UDS, in-memory, etc.).
    async fn redact(&self, _event_id: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

// ── TransportRouter ───────────────────────────────────────────────────────────

/// Manages multiple transport backends, multiplexing inbound messages and
/// selecting the optimal backend for outbound messages with fallback.
pub struct TransportRouter {
    backends: Vec<Arc<dyn TransportBackend>>,
    inbound_tx: broadcast::Sender<ExternalBusMessage>,
    status_tx: watch::Sender<Vec<BackendStatus>>,
    status_rx: watch::Receiver<Vec<BackendStatus>>,
    deduplicator: dedup::MessageDeduplicator,
    strategy: SendStrategy,
}

impl TransportRouter {
    /// Create a new router feeding incoming messages into `inbound_tx`.
    pub fn new(inbound_tx: broadcast::Sender<ExternalBusMessage>) -> Self {
        let (status_tx, status_rx) = watch::channel(Vec::new());
        Self {
            backends: Vec::new(),
            inbound_tx,
            status_tx,
            status_rx,
            deduplicator: dedup::MessageDeduplicator::default(),
            strategy: SendStrategy::Parallel,
        }
    }

    /// Set the emission strategy (Parallel racing or Sequential fallback).
    pub fn set_strategy(&mut self, strategy: SendStrategy) {
        self.strategy = strategy;
    }

    /// Current emission strategy.
    pub fn strategy(&self) -> SendStrategy {
        self.strategy
    }

    /// Access the shared message deduplicator.
    pub fn deduplicator(&self) -> &dedup::MessageDeduplicator {
        &self.deduplicator
    }

    /// Register a backend with this router.
    /// Backends are prioritized in the order they are registered.
    pub fn register_backend(&mut self, backend: Arc<dyn TransportBackend>) {
        self.backends.push(backend);
        self.refresh_status();
    }

    /// Registered backends in priority order.
    pub fn backends(&self) -> &[Arc<dyn TransportBackend>] {
        &self.backends
    }

    /// Inbound message sender used by backends to deliver messages onto the external bus.
    pub fn inbound_sender(&self) -> broadcast::Sender<ExternalBusMessage> {
        self.inbound_tx.clone()
    }

    /// Returns the name of the currently active backend (first available in priority order).
    pub fn active_backend_name(&self) -> Option<&'static str> {
        self.backends
            .iter()
            .find(|b| b.is_available())
            .map(|b| b.name())
    }

    /// Snapshot of all registered backend statuses with active marker.
    pub fn status(&self) -> Vec<BackendStatus> {
        let active_name = self.active_backend_name();
        self.backends
            .iter()
            .map(|b| {
                let mut s = b.status();
                if Some(b.name()) == active_name {
                    s.is_active = true;
                }
                s
            })
            .collect()
    }

    /// Subscribe to aggregated status changes across all registered backends.
    pub fn watch_status(&self) -> watch::Receiver<Vec<BackendStatus>> {
        self.status_rx.clone()
    }

    fn refresh_status(&self) {
        let statuses = self.status();
        let _ = self.status_tx.send_if_modified(|curr| {
            if *curr != statuses {
                *curr = statuses;
                true
            } else {
                false
            }
        });
    }

    /// Send `raw_frame` over transport backends according to the configured [`SendStrategy`].
    pub async fn send(
        &self,
        raw_frame: &str,
        preferred_backend: Option<&str>,
    ) -> anyhow::Result<(String, &'static str)> {
        self.send_with_notifier(raw_frame, preferred_backend, |_id, _name| {})
            .await
    }

    /// Send `raw_frame` over transport backends, calling `on_sent` for every backend
    /// that successfully transmits (e.g. for logging/redaction).
    pub async fn send_with_notifier<F>(
        &self,
        raw_frame: &str,
        preferred_backend: Option<&str>,
        on_sent: F,
    ) -> anyhow::Result<(String, &'static str)>
    where
        F: Fn(&str, &'static str) + Send + Sync + 'static,
    {
        match self.strategy {
            SendStrategy::Parallel => {
                self.send_parallel_with_notifier(raw_frame, preferred_backend, on_sent)
                    .await
            }
            SendStrategy::Sequential => {
                let res = self.send_sequential(raw_frame, preferred_backend).await;
                if let Ok((ref id, name)) = res {
                    on_sent(id, name);
                }
                res
            }
        }
    }

    /// Parallel racing: sends to all available backends concurrently; fastest to succeed wins!
    pub async fn send_parallel(
        &self,
        raw_frame: &str,
        preferred_backend: Option<&str>,
    ) -> anyhow::Result<(String, &'static str)> {
        self.send_parallel_with_notifier(raw_frame, preferred_backend, |_id, _name| {})
            .await
    }

    /// Parallel racing with per-backend completion notifier.
    pub async fn send_parallel_with_notifier<F>(
        &self,
        raw_frame: &str,
        preferred_backend: Option<&str>,
        on_sent: F,
    ) -> anyhow::Result<(String, &'static str)>
    where
        F: Fn(&str, &'static str) + Send + Sync + 'static,
    {
        let available: Vec<_> = self
            .backends
            .iter()
            .filter(|b| b.is_available())
            .cloned()
            .collect();

        if available.is_empty() {
            // Fallback: if preferred backend is explicitly given, attempt it directly
            if let Some(pref) = preferred_backend {
                if let Some(b) = self.backends.iter().find(|b| b.name() == pref) {
                    let id = b.send(raw_frame).await?;
                    on_sent(&id, b.name());
                    return Ok((id, b.name()));
                }
            }
            anyhow::bail!("no transport backends available");
        }

        if available.len() == 1 {
            let b = &available[0];
            let id = b.send(raw_frame).await?;
            on_sent(&id, b.name());
            return Ok((id, b.name()));
        }

        let on_sent = Arc::new(on_sent);
        // Fan out concurrently to all available backends without cancelling slower ones; fastest wins!
        let (first_tx, mut first_rx) = tokio::sync::mpsc::channel::<(String, &'static str)>(1);

        for b in available {
            let name = b.name();
            let frame = raw_frame.to_string();
            let backend = Arc::clone(&b);
            let tx = first_tx.clone();
            let on_sent_cb = Arc::clone(&on_sent);
            tokio::spawn(async move {
                match backend.send(&frame).await {
                    Ok(id) => {
                        on_sent_cb(&id, name);
                        let _ = tx.send((id, name)).await;
                    }
                    Err(e) => {
                        eprintln!("[p43::transport] parallel send on {name} failed: {e}");
                    }
                }
            });
        }
        drop(first_tx);

        if let Some((id, name)) = first_rx.recv().await {
            Ok((id, name))
        } else {
            anyhow::bail!("all parallel sends failed");
        }
    }

    /// Sequential fallback: tries preferred/primary first, then fallback list.
    pub async fn send_sequential(
        &self,
        raw_frame: &str,
        preferred_backend: Option<&str>,
    ) -> anyhow::Result<(String, &'static str)> {
        // 1. Try preferred backend first if specified.
        if let Some(pref) = preferred_backend {
            if let Some(b) = self.backends.iter().find(|b| b.name() == pref) {
                match b.send(raw_frame).await {
                    Ok(id) => return Ok((id, b.name())),
                    Err(e) => {
                        eprintln!(
                            "[p43::transport] preferred backend {pref} send failed ({e}), falling back"
                        );
                    }
                }
            }
        }

        // 2. Iterate through available backends in priority order (skipping the preferred backend that already failed).
        let mut last_err = None;
        for b in &self.backends {
            if Some(b.name()) == preferred_backend {
                continue;
            }
            if b.is_available() {
                match b.send(raw_frame).await {
                    Ok(id) => return Ok((id, b.name())),
                    Err(e) => {
                        eprintln!("[p43::transport] backend {} send failed: {e}", b.name());
                        last_err = Some(e);
                    }
                }
            }
        }

        // 3. No available backend succeeded.
        let available_count = self.backends.iter().filter(|b| b.is_available()).count();
        if available_count == 0 {
            let statuses: Vec<String> = self
                .backends
                .iter()
                .map(|b| format!("{}: {:?}", b.name(), b.status().state))
                .collect();
            anyhow::bail!(
                "no transport backends available (status: {})",
                if statuses.is_empty() {
                    "no backends registered".into()
                } else {
                    statuses.join(", ")
                }
            );
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all available backends failed to send")))
    }

    /// Redact or clean up a completed transaction event on the appropriate transport.
    ///
    /// For Matrix events (starting with `$`), delegates to MatrixBackend.
    /// For other transports (like Local UDS), this safely no-ops.
    pub async fn redact(&self, event_id: &str) -> anyhow::Result<()> {
        if event_id.starts_with('$') {
            if let Some(b) = self.backends.iter().find(|b| b.name() == "matrix") {
                return b.redact(event_id).await;
            }
        }
        for b in &self.backends {
            if event_id.starts_with(&format!("{}:", b.name())) {
                return b.redact(event_id).await;
            }
        }
        Ok(())
    }

    /// Spawn a background task that watches all backends for state changes
    /// and broadcasts aggregated status updates via `watch_status()`.
    pub fn spawn_monitoring(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut receivers: Vec<watch::Receiver<BackendState>> =
                self.backends.iter().map(|b| b.watch_state()).collect();

            if receivers.is_empty() {
                return;
            }

            self.refresh_status();

            loop {
                // Wait for any receiver to change.
                let mut changed_any = false;
                for rx in &mut receivers {
                    if rx.has_changed().unwrap_or(false) {
                        rx.mark_unchanged();
                        changed_any = true;
                    }
                }

                if changed_any {
                    self.refresh_status();
                }

                // Sleep a tiny amount or select on changes
                // Wait on the first receiver that fires.
                tokio::select! {
                    _ = async {
                        // Future that resolves when any receiver changes.
                        let _ = futures_util::future::select_all(
                            receivers.iter_mut().map(|rx| Box::pin(rx.changed()))
                        ).await;
                    } => {
                        self.refresh_status();
                    }
                }
            }
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::bridge::new_external_bus;
    use virtual_transport::VirtualTransport;

    #[tokio::test]
    async fn test_router_priority_order() {
        let (inbound_tx, _inbound_rx) = new_external_bus();
        let mut router = TransportRouter::new(inbound_tx);
        router.set_strategy(SendStrategy::Sequential);

        let t1 = Arc::new(VirtualTransport::new("matrix"));
        let t2 = Arc::new(VirtualTransport::new("local_uds"));

        router.register_backend(t1.clone());
        router.register_backend(t2.clone());

        // Both are connected. In sequential mode, matrix (t1) has priority.
        let status = router.status();
        assert!(status[0].is_active, "matrix should be active");
        assert!(!status[1].is_active, "local_uds should be standby");

        let (id, name) = router.send("payload 1", None).await.unwrap();
        assert_eq!(name, "matrix");
        assert_eq!(id, "matrix:1");
        assert_eq!(t1.sent_frames(), vec!["payload 1"]);
        assert!(t2.sent_frames().is_empty());
    }

    #[tokio::test]
    async fn test_router_parallel_racing_fastest_wins() {
        let (inbound_tx, _inbound_rx) = new_external_bus();
        let mut router = TransportRouter::new(inbound_tx);
        // Default strategy is SendStrategy::Parallel

        let t1 = Arc::new(VirtualTransport::new("matrix"));
        let t2 = Arc::new(VirtualTransport::new("local_uds"));

        // Matrix is slow (50 ms), Local UDS is instant (0 ms).
        t1.set_latency_ms(Some(50));
        t2.set_latency_ms(None);

        router.register_backend(t1.clone());
        router.register_backend(t2.clone());

        let start = std::time::Instant::now();
        let (id, name) = router.send("payload parallel", None).await.unwrap();
        let elapsed = start.elapsed();

        // Local UDS wins immediately without waiting for Matrix!
        assert_eq!(name, "local_uds");
        assert_eq!(id, "local_uds:1");
        assert!(
            elapsed.as_millis() < 40,
            "parallel send should return immediately on fastest backend"
        );
    }

    #[tokio::test]
    async fn test_router_fallback_when_primary_disconnected() {
        let (inbound_tx, _inbound_rx) = new_external_bus();
        let mut router = TransportRouter::new(inbound_tx);

        let t1 = Arc::new(VirtualTransport::with_initial_state(
            "matrix",
            BackendState::Disconnected,
        ));
        let t2 = Arc::new(VirtualTransport::new("local_uds"));

        router.register_backend(t1.clone());
        router.register_backend(t2.clone());

        // matrix is disconnected, so local_uds is active.
        let status = router.status();
        assert!(!status[0].is_active, "matrix is disconnected");
        assert!(status[1].is_active, "local_uds should be active fallback");

        // Router seamlessly falls back to t2.
        let (id, name) = router.send("payload 2", None).await.unwrap();
        assert_eq!(name, "local_uds");
        assert_eq!(id, "local_uds:1");
        assert!(t1.sent_frames().is_empty());
        assert_eq!(t2.sent_frames(), vec!["payload 2"]);
    }

    #[tokio::test]
    async fn test_router_preferred_backend() {
        let (inbound_tx, _inbound_rx) = new_external_bus();
        let mut router = TransportRouter::new(inbound_tx);
        router.set_strategy(SendStrategy::Sequential);

        let t1 = Arc::new(VirtualTransport::new("local_uds"));
        let t2 = Arc::new(VirtualTransport::new("matrix"));

        router.register_backend(t1.clone());
        router.register_backend(t2.clone());

        // Explicitly prefer matrix even though local_uds is primary.
        let (id, name) = router.send("payload 3", Some("matrix")).await.unwrap();
        assert_eq!(name, "matrix");
        assert_eq!(id, "matrix:1");
        assert!(t1.sent_frames().is_empty());
        assert_eq!(t2.sent_frames(), vec!["payload 3"]);
    }

    #[tokio::test]
    async fn test_router_preferred_backend_fallback_when_preferred_fails() {
        let (inbound_tx, _inbound_rx) = new_external_bus();
        let mut router = TransportRouter::new(inbound_tx);
        router.set_strategy(SendStrategy::Sequential);

        let t1 = Arc::new(VirtualTransport::new("matrix"));
        let t2 = Arc::new(VirtualTransport::new("local_uds"));

        // Simulate matrix failing to send.
        t1.set_fail_send(true);

        router.register_backend(t1.clone());
        router.register_backend(t2.clone());

        // Preferred is matrix (incoming transport), but it fails to send.
        // Router should seamlessly fall back to the available fallback list (local_uds).
        let (id, name) = router
            .send("payload fallback", Some("matrix"))
            .await
            .unwrap();
        assert_eq!(name, "local_uds");
        assert_eq!(id, "local_uds:1");
        assert_eq!(t2.sent_frames(), vec!["payload fallback"]);
    }

    #[tokio::test]
    async fn test_router_all_offline_error() {
        let (inbound_tx, _inbound_rx) = new_external_bus();
        let mut router = TransportRouter::new(inbound_tx);

        let t1 = Arc::new(VirtualTransport::with_initial_state(
            "local_uds",
            BackendState::Disconnected,
        ));
        let t2 = Arc::new(VirtualTransport::with_initial_state(
            "matrix",
            BackendState::Disconnected,
        ));

        router.register_backend(t1);
        router.register_backend(t2);

        let err = router.send("payload 4", None).await.unwrap_err();
        assert!(err.to_string().contains("no transport backends available"));
    }

    #[tokio::test]
    async fn test_spawn_decrypt_middleware_deduplication() {
        use crate::bus::{
            new_external_bus, new_internal_bus, spawn_decrypt_middleware, DecryptResult,
            ExternalBusMessage,
        };
        use crate::protocol::{Message, SshSignRequest};

        let (ext_tx, ext_rx) = new_external_bus();
        let (int_tx, mut int_rx) = new_internal_bus();

        let _handle = spawn_decrypt_middleware(|_| DecryptResult::Skip, |_| {}, ext_rx, int_tx);

        let req = Message::SshSignRequest(SshSignRequest {
            request_id: "req-dedup-test".into(),
            fingerprint: "fp".into(),
            data: b"data".to_vec(),
            flags: 0,
            description: "test".into(),
            meta: Default::default(),
        });

        // Send same message twice (simulating arrival from both Local UDS and Matrix)
        ext_tx
            .send(ExternalBusMessage {
                message: req.clone(),
                event_id: "local_uds:1".into(),
            })
            .unwrap();

        ext_tx
            .send(ExternalBusMessage {
                message: req,
                event_id: "$matrix_duplicate_event".into(),
            })
            .unwrap();

        // 1st message arrives on internal bus
        let received = tokio::time::timeout(std::time::Duration::from_millis(500), int_rx.recv())
            .await
            .expect("first message should arrive")
            .unwrap();
        assert_eq!(received.event_id, "local_uds:1");

        // 2nd duplicate message is dropped: channel should timeout with no message
        let second_res =
            tokio::time::timeout(std::time::Duration::from_millis(150), int_rx.recv()).await;
        assert!(
            second_res.is_err(),
            "second duplicate message should be filtered out by deduplicator"
        );
    }

    #[tokio::test]
    async fn test_spawn_decrypt_middleware_locked_replay_not_dropped() {
        use crate::bus::{
            new_external_bus, new_internal_bus, spawn_decrypt_middleware, DecryptResult,
            ExternalBusMessage,
        };
        use crate::protocol::{BusSecureEnvelope, Message, SshSignRequest};
        use std::sync::atomic::{AtomicBool, Ordering};

        let (ext_tx, ext_rx) = new_external_bus();
        let (int_tx, mut int_rx) = new_internal_bus();

        let is_unlocked = Arc::new(AtomicBool::new(false));
        let is_unlocked_cb = Arc::clone(&is_unlocked);

        let locked_queue = Arc::new(std::sync::Mutex::new(Vec::new()));
        let locked_queue_cb = Arc::clone(&locked_queue);

        let _handle = spawn_decrypt_middleware(
            move |_env| {
                if is_unlocked_cb.load(Ordering::SeqCst) {
                    DecryptResult::Ok(
                        Message::SshSignRequest(SshSignRequest {
                            request_id: "req-locked-test".into(),
                            fingerprint: "fp".into(),
                            data: b"data".to_vec(),
                            flags: 0,
                            description: "desc".into(),
                            meta: Default::default(),
                        }),
                        Box::new(crate::bus::CertPayload {
                            version: 1,
                            device_id: "dev".into(),
                            label: "dev".into(),
                            sign_pubkey: vec![0; 32],
                            ecdh_pubkey: vec![0; 32],
                            issuer_fp: vec![],
                            iat: 0,
                            exp: None,
                            meta: Default::default(),
                        }),
                    )
                } else {
                    DecryptResult::Locked
                }
            },
            move |locked_msg| {
                locked_queue_cb.lock().unwrap().push(locked_msg);
            },
            ext_rx,
            int_tx,
        );

        let raw_msg = Message::BusSecure(BusSecureEnvelope {
            v: 1,
            from: "dev".into(),
            envelope_b64: "ENVELOPE_LOCKED_TEST".into(),
        });

        // 1. Message arrives while locked: should be buffered in locked_queue, not delivered to internal bus
        ext_tx
            .send(ExternalBusMessage {
                message: raw_msg.clone(),
                event_id: "$matrix_locked_event".into(),
            })
            .unwrap();

        // Yield to allow middleware to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let locked_items = locked_queue.lock().unwrap().clone();
        assert_eq!(
            locked_items.len(),
            1,
            "message should be buffered in locked_queue"
        );

        // Internal bus should have received nothing yet
        let recv_none =
            tokio::time::timeout(std::time::Duration::from_millis(50), int_rx.recv()).await;
        assert!(recv_none.is_err(), "nothing on internal bus while locked");

        // 2. User unlocks!
        is_unlocked.store(true, Ordering::SeqCst);

        // Replay the buffered message onto ext_tx (just like wallet_unlock_session does)
        for item in locked_items {
            ext_tx.send(item).unwrap();
        }

        // 3. The replayed message MUST be processed and not dropped by deduplicator!
        let replayed = tokio::time::timeout(std::time::Duration::from_millis(500), int_rx.recv())
            .await
            .expect("replayed message should arrive on internal bus after unlock")
            .unwrap();
        assert_eq!(replayed.event_id, "$matrix_locked_event");
    }

    #[tokio::test]
    async fn test_end_to_end_local_uds_bus_secure_round_trip() {
        use crate::bus::{
            new_external_bus, new_internal_bus, new_outbound_queue, open_protocol_message,
            seal_protocol_message, spawn_decrypt_middleware, spawn_encrypt_worker_with_router,
            unix_now, AuthorityKey, AuthorityPub, CsrPayload, DecryptResult, DeviceCert, DeviceCsr,
            DeviceKey, OutboundBusMessage,
        };
        use crate::protocol::{Message, SshSignRequest, SshSignResponse};
        use local_uds::{LocalUdsClient, LocalUdsServer};
        use x25519_dalek::PublicKey as X25519Public;

        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("e2e-bus.sock");

        // 1. Generate authority and device keys
        let auth_key = Arc::new(AuthorityKey::generate());
        let auth_pub = AuthorityPub {
            version: 1,
            ed25519_pub: auth_key.signing.verifying_key().to_bytes().to_vec(),
            x25519_pub: X25519Public::from(&auth_key.ecdh).to_bytes().to_vec(),
        };
        let mut auth_sign_pub = [0u8; 32];
        auth_sign_pub.copy_from_slice(&auth_pub.ed25519_pub);

        let auth_csr_payload = CsrPayload {
            version: 1,
            label: "authority".to_string(),
            sign_pubkey: auth_pub.ed25519_pub.clone(),
            ecdh_pubkey: auth_pub.x25519_pub.clone(),
            nonce: vec![0u8; 16],
            timestamp: unix_now().unwrap(),
            meta: Default::default(),
        };
        let auth_cert = DeviceCert::issue(&auth_csr_payload, auth_key.as_ref(), None).unwrap();

        let dev_key = Arc::new(DeviceKey::generate("laptop-agent"));
        let dev_csr =
            DeviceCsr::generate_with_meta(dev_key.as_ref(), None, Default::default()).unwrap();
        let dev_cert = DeviceCert::issue(&dev_csr.payload, auth_key.as_ref(), None).unwrap();

        // 2. Set up Server side (UI / authority)
        let (server_ext_tx, server_ext_rx) = new_external_bus();
        let (server_int_tx, mut server_int_rx) = new_internal_bus();
        let (server_out_tx, server_out_rx) = new_outbound_queue();

        let server_uds = LocalUdsServer::start(sock_path.clone(), server_ext_tx.clone()).unwrap();
        let mut server_router = TransportRouter::new(server_ext_tx);
        server_router.register_backend(server_uds);
        let server_router = Arc::new(server_router);

        let ak = Arc::clone(&auth_key);
        let ac_bytes = auth_cert.cose_bytes.clone();
        spawn_encrypt_worker_with_router(
            move |msg, recipient| {
                seal_protocol_message(ak.as_ref(), &ac_bytes, recipient, msg).ok()
            },
            server_router,
            server_out_rx,
            None,
        );

        let ak_dec = Arc::clone(&auth_key);
        let asp = auth_sign_pub;
        spawn_decrypt_middleware(
            move |env| match open_protocol_message(ak_dec.as_ref(), &asp, env) {
                Ok((msg, cert)) => DecryptResult::Ok(msg, Box::new(cert)),
                Err(e) => DecryptResult::Err(e.to_string()),
            },
            |_| {},
            server_ext_rx,
            server_int_tx,
        );

        // 3. Set up Client side (SSH Agent / device)
        let (client_ext_tx, client_ext_rx) = new_external_bus();
        let (client_int_tx, mut client_int_rx) = new_internal_bus();
        let (client_out_tx, client_out_rx) = new_outbound_queue();

        let client_uds = LocalUdsClient::start(sock_path.clone(), client_ext_tx.clone());
        let mut client_router = TransportRouter::new(client_ext_tx);
        client_router.register_backend(client_uds.clone());
        let client_router = Arc::new(client_router);

        let dk = Arc::clone(&dev_key);
        let dc_bytes = dev_cert.cose_bytes.clone();
        spawn_encrypt_worker_with_router(
            move |msg, recipient| {
                seal_protocol_message(dk.as_ref(), &dc_bytes, recipient, msg).ok()
            },
            client_router,
            client_out_rx,
            None,
        );

        let dk_dec = Arc::clone(&dev_key);
        let asp2 = auth_sign_pub;
        spawn_decrypt_middleware(
            move |env| match open_protocol_message(dk_dec.as_ref(), &asp2, env) {
                Ok((msg, cert)) => DecryptResult::Ok(msg, Box::new(cert)),
                Err(e) => DecryptResult::Err(e.to_string()),
            },
            |_| {},
            client_ext_rx,
            client_int_tx,
        );

        // Wait for client to connect to server
        for _ in 0..20 {
            if client_uds.is_available() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            client_uds.is_available(),
            "Local UDS client should connect to server"
        );

        // 4. Client sends SshSignRequest sealed to authority
        let req = Message::SshSignRequest(SshSignRequest {
            request_id: "req-e2e-42".into(),
            fingerprint: "SHA256:abc".into(),
            data: b"sign-this-data".to_vec(),
            flags: 0,
            description: "test e2e".into(),
            meta: Default::default(),
        });
        client_out_tx
            .send(OutboundBusMessage::new(
                req,
                Some(auth_cert.payload.clone()),
            ))
            .unwrap();

        // 5. Server decrypts request on internal bus
        let received_req =
            tokio::time::timeout(std::time::Duration::from_secs(3), server_int_rx.recv())
                .await
                .unwrap()
                .unwrap();

        match received_req.message {
            Message::SshSignRequest(r) => {
                assert_eq!(r.request_id, "req-e2e-42");
                assert_eq!(r.data, b"sign-this-data");
            }
            other => panic!("expected SshSignRequest, got {other:?}"),
        }
        let sender_cert = received_req
            .sender_cert
            .expect("sender cert must be present");
        assert_eq!(sender_cert.label, "laptop-agent");

        // 6. Server responds with SshSignResponse sealed to device
        let res = Message::SshSignResponse(SshSignResponse {
            request_id: "req-e2e-42".into(),
            signature: b"valid-sig-bytes".to_vec(),
        });
        server_out_tx
            .send(OutboundBusMessage::new(res, Some(sender_cert)))
            .unwrap();

        // 7. Client decrypts response on internal bus
        let received_res =
            tokio::time::timeout(std::time::Duration::from_secs(3), client_int_rx.recv())
                .await
                .unwrap()
                .unwrap();

        match received_res.message {
            Message::SshSignResponse(r) => {
                assert_eq!(r.request_id, "req-e2e-42");
                assert_eq!(r.signature, b"valid-sig-bytes");
            }
            other => panic!("expected SshSignResponse, got {other:?}"),
        }
    }
}
