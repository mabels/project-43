//! Two-layer message bus for the p43 Matrix protocol.
//!
//! Separates the raw Matrix wire layer from the application's plaintext layer:
//!
//! ```text
//! Matrix room (raw JSON)
//!       │
//!       ▼
//! external_bus  ── broadcast::channel<Message>
//!       │
//!  spawn_decrypt_middleware  ← on_bus_secure closure handles key access
//!       │
//!       ▼
//! internal_bus  ── broadcast::channel<InboundBusMessage>
//!       │
//!  application logic  (pending-map dispatch / AppMessage fan-out)
//!       │
//!       ▼
//! outbound_queue  ── mpsc::channel<OutboundBusMessage>
//!       │
//!  spawn_encrypt_worker  ← seal closure handles key access
//!       │
//!       ▼
//! Matrix room (send)
//! ```
//!
//! Both the decrypt middleware and encrypt worker receive their crypto context
//! via caller-provided closures so that neither the `AuthorityKey` (UI side)
//! nor the `DeviceKey` (CLI side) need to be `Clone` or leave their owning
//! `Mutex`/`Arc`.

use tokio::sync::{broadcast, mpsc};

use super::cert::CertPayload;
use crate::protocol;

// ── Channel capacity ──────────────────────────────────────────────────────────

pub const BUS_CHANNEL_CAPACITY: usize = 64;

// ── External bus message ──────────────────────────────────────────────────────

/// A raw message received from the Matrix room, bundled with its event ID.
///
/// Passed through the external bus so that the event ID can be threaded all the
/// way into [`InboundBusMessage`] and used by consumers (e.g. the SSH agent) to
/// redact the Matrix event once the transaction is complete.
#[derive(Clone, Debug)]
pub struct ExternalBusMessage {
    /// The raw (possibly encrypted) protocol message.
    pub message: protocol::Message,
    /// Matrix event ID (`$…`) of the m.room.message event that carried this
    /// message.  Used by consumers to redact the event after processing.
    pub event_id: String,
}

// ── Inbound message ───────────────────────────────────────────────────────────

/// A decrypted message on the *internal* bus.
///
/// The `sender_cert` is populated when the original wire message was
/// [`protocol::Message::BusSecure`]; it is `None` for plaintext messages
/// (e.g. the registration CSR/cert exchange).
#[derive(Clone, Debug)]
pub struct InboundBusMessage {
    /// The plaintext protocol message.
    pub message: protocol::Message,
    /// Verified sender cert, present when the original was `BusSecure`.
    pub sender_cert: Option<CertPayload>,
    /// Matrix event ID of the outer envelope (raw m.room.message event).
    ///
    /// Consumers can pass this to `p43::matrix::global::redact_room_event` to
    /// remove the event from the room once the transaction has been handled.
    pub event_id: String,
}

// ── Outbound message ──────────────────────────────────────────────────────────

/// A plaintext message to be (optionally) encrypted then sent to Matrix.
pub struct OutboundBusMessage {
    /// Plaintext protocol message.
    pub message: protocol::Message,
    /// Recipient cert to seal the message to.
    /// `Some` → call the `seal` closure before sending.
    /// `None` → send the JSON as-is (plaintext).
    pub recipient_cert: Option<CertPayload>,
}

// ── Result type for the decrypt callback ─────────────────────────────────────

/// Outcome returned by the `on_bus_secure` closure passed to
/// [`spawn_decrypt_middleware`].
pub enum DecryptResult {
    /// Successfully decrypted: inner message + verified sender cert.
    Ok(protocol::Message, Box<CertPayload>),
    /// Session is locked — the `on_locked` callback will be fired.
    Locked,
    /// Message should be silently dropped (e.g. own echo, not-yet-registered).
    Skip,
    /// Decryption failed; the error string is logged and the message is dropped.
    Err(String),
}

// ── Channel constructors ──────────────────────────────────────────────────────

/// Create a broadcast channel for the **external** bus (raw Matrix messages).
pub fn new_external_bus() -> (
    broadcast::Sender<ExternalBusMessage>,
    broadcast::Receiver<ExternalBusMessage>,
) {
    broadcast::channel(BUS_CHANNEL_CAPACITY)
}

/// Create a broadcast channel for the **internal** bus (decrypted messages).
pub fn new_internal_bus() -> (
    broadcast::Sender<InboundBusMessage>,
    broadcast::Receiver<InboundBusMessage>,
) {
    broadcast::channel(BUS_CHANNEL_CAPACITY)
}

/// Create an mpsc channel for the **outbound** queue.
pub fn new_outbound_queue() -> (
    mpsc::Sender<OutboundBusMessage>,
    mpsc::Receiver<OutboundBusMessage>,
) {
    mpsc::channel(BUS_CHANNEL_CAPACITY)
}

// ── Decrypt middleware ────────────────────────────────────────────────────────

/// Spawn the decryption middleware task.
///
/// Reads from `external_rx`, processes any [`protocol::Message::BusSecure`]
/// envelopes via the caller-supplied `on_bus_secure` closure, and publishes
/// plaintext [`InboundBusMessage`]s to `internal_tx`.
///
/// Plaintext messages pass through unchanged (with `sender_cert: None`).
///
/// # Parameters
///
/// - `on_bus_secure` — called for every `BusSecure` message.  The closure owns
///   its crypto context (key access via `Mutex`, `Arc`, etc.) and returns a
///   [`DecryptResult`].  Returning [`DecryptResult::Locked`] triggers
///   `on_locked`.
/// - `on_locked` — called when `on_bus_secure` returns `Locked`, receiving the
///   original [`ExternalBusMessage`] that could not be decrypted (including its
///   `event_id`).  The caller should buffer this message and replay it onto the
///   external bus once the session is unlocked, so the message is not lost.
pub fn spawn_decrypt_middleware(
    on_bus_secure: impl Fn(&protocol::BusSecureEnvelope) -> DecryptResult + Send + 'static,
    on_locked: impl Fn(ExternalBusMessage) + Send + 'static,
    mut external_rx: broadcast::Receiver<ExternalBusMessage>,
    internal_tx: broadcast::Sender<InboundBusMessage>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let ExternalBusMessage {
                message: raw_msg,
                event_id,
            } = match external_rx.recv().await {
                Ok(ext) => ext,
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("[p43::bus::bridge] external_rx lagged, dropped {n} messages");
                    continue;
                }
            };

            // Evaluate the decrypt callback using a shared reference so that
            // `raw_msg` remains owned and can be moved into `on_locked` if the
            // session is locked.
            let decrypt_result = match &raw_msg {
                protocol::Message::BusSecure(env) => Some(on_bus_secure(env)),
                _ => None,
            };
            // The borrow of `raw_msg` inside the match above ends here.

            let (msg, sender_cert) = match decrypt_result {
                Some(DecryptResult::Ok(inner, cert)) => (inner, Some(*cert)),
                Some(DecryptResult::Locked) => {
                    // Pass the original ExternalBusMessage (including event_id)
                    // to the caller so it can be buffered and replayed once the
                    // session is unlocked.
                    on_locked(ExternalBusMessage {
                        message: raw_msg,
                        event_id,
                    });
                    continue;
                }
                Some(DecryptResult::Skip) => continue,
                Some(DecryptResult::Err(e)) => {
                    eprintln!("[p43::bus::bridge] decrypt BusSecure: {e}");
                    continue;
                }
                // Plain (non-BusSecure) message — pass through as-is.
                None => (raw_msg, None),
            };

            // Drop the send result — no subscribers yet is fine (lagged receivers
            // will be warned via the recv side).
            let _ = internal_tx.send(InboundBusMessage {
                message: msg,
                sender_cert,
                event_id,
            });
        }
    })
}

// ── Encrypt worker ────────────────────────────────────────────────────────────

/// Spawn the encryption + send worker.
///
/// Reads from `outbound_rx`, optionally seals each message via the
/// caller-supplied `seal` closure, and delivers the resulting JSON to the
/// Matrix room.
///
/// # Parameters
///
/// - `seal` — called when `recipient_cert` is `Some`.  Receives a reference to
///   the plaintext message and the recipient's cert.  Returns `Some(sealed)`
///   on success or `None` when the signer is unavailable (message is dropped
///   with a warning).
/// - `room_id` — Matrix room ID to send into.
/// - `on_sent` — optional channel that receives `(request_id, event_id)` after
///   every successful send.  The `request_id` is extracted from the plaintext
///   message before encryption so it survives the `BusSecure` wrapping.
///   Consumers use this to correlate sent requests with their Matrix event IDs
///   for deferred redaction.  Pass `None` to ignore.
pub fn spawn_encrypt_worker(
    seal: impl Fn(&protocol::Message, &CertPayload) -> Option<protocol::Message> + Send + 'static,
    room_id: String,
    mut outbound_rx: mpsc::Receiver<OutboundBusMessage>,
    on_sent: Option<mpsc::Sender<(String, String)>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(outbound) = outbound_rx.recv().await {
            // Capture the request_id from the plaintext message *before*
            // encrypting — once sealed into BusSecure it is inaccessible.
            let request_id: Option<String> = outbound.message.request_id().map(str::to_string);

            let json_result = if let Some(ref cert) = outbound.recipient_cert {
                match seal(&outbound.message, cert) {
                    None => {
                        eprintln!(
                            "[p43::bus::bridge] encrypt_worker: signer unavailable, \
                             dropping outbound message"
                        );
                        continue;
                    }
                    Some(sealed) => sealed.to_json(),
                }
            } else {
                outbound.message.to_json()
            };

            match json_result {
                Ok(json) => {
                    match crate::matrix::global::send_message(&room_id, &json).await {
                        Ok(event_id) => {
                            // Notify the caller with (request_id, event_id) so
                            // it can track which Matrix event carries each request.
                            if let (Some(ref tx), Some(rid)) = (&on_sent, request_id) {
                                let _ = tx.try_send((rid, event_id));
                            }
                        }
                        Err(e) => eprintln!("[p43::bus::bridge] send_message: {e}"),
                    }
                }
                Err(e) => eprintln!("[p43::bus::bridge] to_json: {e}"),
            }
        }
    })
}
