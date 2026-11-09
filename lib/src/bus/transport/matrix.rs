//! Matrix room transport backend.

use std::sync::Arc;
use tokio::sync::{broadcast, watch};

use super::{BackendState, BackendStatus, TransportBackend};
use crate::bus::bridge::ExternalBusMessage;
use crate::matrix::pointer::RoomPointerStore;
use crate::protocol;

pub struct MatrixBackend {
    room_id: String,
    state_tx: watch::Sender<BackendState>,
    state_rx: watch::Receiver<BackendState>,
}

impl MatrixBackend {
    pub fn new(room_id: String) -> Arc<Self> {
        let (state_tx, state_rx) = watch::channel(BackendState::Connecting);
        Arc::new(Self {
            room_id,
            state_tx,
            state_rx,
        })
    }

    /// Spawn the Matrix sync loop feeding incoming messages to `inbound_tx`
    /// and updating connection state reactively.
    pub fn start_listener(
        self: &Arc<Self>,
        inbound_tx: broadcast::Sender<ExternalBusMessage>,
        ptr_store: Option<Arc<RoomPointerStore>>,
    ) -> tokio::task::JoinHandle<()> {
        let room_id = self.room_id.clone();
        let state_tx = self.state_tx.clone();

        tokio::spawn(async move {
            let initial_since = ptr_store.as_ref().and_then(|s| s.get(&room_id));
            let since = Arc::new(std::sync::Mutex::new(initial_since));

            loop {
                let _ = state_tx.send(BackendState::Connecting);
                let in_tx = inbound_tx.clone();
                let since_val = since.lock().ok().and_then(|g| g.clone());
                let since_ptr = Arc::clone(&since);
                let ptr_store_inner = ptr_store.clone();
                let room_id_inner = room_id.clone();
                let state_tx_inner = state_tx.clone();

                let listen_res = crate::matrix::global::listen_room(
                    &room_id,
                    since_val.as_deref(),
                    move |token| {
                        // Successfully syncing with server.
                        let _ = state_tx_inner.send_if_modified(|curr| {
                            if *curr != BackendState::Connected {
                                *curr = BackendState::Connected;
                                true
                            } else {
                                false
                            }
                        });
                        if let Ok(mut g) = since_ptr.lock() {
                            *g = Some(token.clone());
                        }
                        if let Some(ref store) = ptr_store_inner {
                            let _ = store.set(&room_id_inner, &token);
                        }
                    },
                    move |_sender, body, _ts_ms, event_id| {
                        if let Ok(msg) = protocol::Message::from_json(&body) {
                            let _ = in_tx.send(ExternalBusMessage {
                                message: msg,
                                event_id,
                            });
                        }
                    },
                )
                .await;

                if let Err(e) = listen_res {
                    eprintln!("[p43::transport::matrix] listen_room error: {e}");
                }

                let _ = state_tx.send(BackendState::Disconnected);
                eprintln!("[p43::transport::matrix] sync loop exited — reconnecting in 5 s…");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        })
    }
}

#[async_trait::async_trait]
impl TransportBackend for MatrixBackend {
    fn name(&self) -> &'static str {
        "matrix"
    }

    fn status(&self) -> BackendStatus {
        let state = self.state_rx.borrow().clone();
        BackendStatus {
            name: "matrix".into(),
            state,
            is_active: false,
            latency_ms: None,
            last_seen_ms: 0,
            detail: Some(format!("Room: {}", self.room_id)),
        }
    }

    fn watch_state(&self) -> watch::Receiver<BackendState> {
        self.state_rx.clone()
    }

    async fn send(&self, raw_frame: &str) -> anyhow::Result<String> {
        crate::matrix::global::send_message(&self.room_id, raw_frame).await
    }
}
