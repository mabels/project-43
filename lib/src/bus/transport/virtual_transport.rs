//! In-memory virtual transport for testing multi-backend routing.

use std::sync::{Arc, Mutex};
use tokio::sync::watch;

use super::{BackendState, BackendStatus, TransportBackend};

pub struct VirtualTransport {
    name: &'static str,
    state_tx: watch::Sender<BackendState>,
    state_rx: watch::Receiver<BackendState>,
    sent_frames: Arc<Mutex<Vec<String>>>,
    fail_send: Arc<Mutex<bool>>,
    latency_ms: Arc<Mutex<Option<u64>>>,
    counter: Arc<Mutex<u64>>,
}

impl VirtualTransport {
    pub fn new(name: &'static str) -> Self {
        let (state_tx, state_rx) = watch::channel(BackendState::Connected);
        Self {
            name,
            state_tx,
            state_rx,
            sent_frames: Arc::new(Mutex::new(Vec::new())),
            fail_send: Arc::new(Mutex::new(false)),
            latency_ms: Arc::new(Mutex::new(None)),
            counter: Arc::new(Mutex::new(0)),
        }
    }

    pub fn with_initial_state(name: &'static str, state: BackendState) -> Self {
        let (state_tx, state_rx) = watch::channel(state);
        Self {
            name,
            state_tx,
            state_rx,
            sent_frames: Arc::new(Mutex::new(Vec::new())),
            fail_send: Arc::new(Mutex::new(false)),
            latency_ms: Arc::new(Mutex::new(None)),
            counter: Arc::new(Mutex::new(0)),
        }
    }

    pub fn set_state(&self, state: BackendState) {
        let _ = self.state_tx.send(state);
    }

    pub fn set_fail_send(&self, fail: bool) {
        if let Ok(mut g) = self.fail_send.lock() {
            *g = fail;
        }
    }

    pub fn set_latency_ms(&self, ms: Option<u64>) {
        if let Ok(mut g) = self.latency_ms.lock() {
            *g = ms;
        }
    }

    pub fn sent_frames(&self) -> Vec<String> {
        self.sent_frames
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn clear_sent(&self) {
        if let Ok(mut g) = self.sent_frames.lock() {
            g.clear();
        }
    }
}

#[async_trait::async_trait]
impl TransportBackend for VirtualTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn status(&self) -> BackendStatus {
        let state = self.state_rx.borrow().clone();
        let latency_ms = self.latency_ms.lock().ok().and_then(|g| *g);
        BackendStatus {
            name: self.name.to_string(),
            state,
            is_active: false,
            latency_ms,
            last_seen_ms: 0,
            detail: None,
        }
    }

    fn watch_state(&self) -> watch::Receiver<BackendState> {
        self.state_rx.clone()
    }

    async fn send(&self, raw_frame: &str) -> anyhow::Result<String> {
        let lat = self.latency_ms.lock().ok().and_then(|g| *g);
        if let Some(ms) = lat {
            if ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            }
        }
        if *self.fail_send.lock().unwrap() {
            anyhow::bail!("VirtualTransport {} simulated send failure", self.name);
        }
        if !self.is_available() {
            anyhow::bail!("VirtualTransport {} is not connected", self.name);
        }
        self.sent_frames.lock().unwrap().push(raw_frame.to_string());
        let mut cnt = self.counter.lock().unwrap();
        *cnt += 1;
        Ok(format!("{}:{}", self.name, *cnt))
    }
}
