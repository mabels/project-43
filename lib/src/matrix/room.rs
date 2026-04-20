use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use matrix_sdk::{
    config::SyncSettings,
    deserialized_responses::TimelineEventKind,
    room::{MessagesOptions, Room},
    ruma::{
        events::{
            room::message::{MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent},
            AnyMessageLikeEvent, AnyTimelineEvent,
        },
        OwnedRoomAliasId, OwnedRoomId, OwnedUserId, RoomAliasId, RoomId, RoomOrAliasId, UInt,
    },
    Client, LoopCtrl,
};
use tokio::sync::mpsc;

// ── JoinResult ────────────────────────────────────────────────────────────────

/// Result returned by [`join_room`].
pub struct JoinResult {
    /// Canonical ID of the room that was joined.
    pub room_id: OwnedRoomId,
    /// Whether the room has an active `m.room.encryption` state event.
    pub is_encrypted: bool,
    /// Human-readable room name, if set.
    pub name: Option<String>,
    /// Canonical alias, if set.
    pub alias: Option<String>,
}

// ── Room resolution ───────────────────────────────────────────────────────────

/// Resolve a room string to an [`OwnedRoomId`].
///
/// Accepts three formats:
/// - `!localpart:server` — canonical room ID, parsed directly.
/// - `#alias:server` — room alias, resolved via the homeserver.
/// - `#alias` or bare `alias` — appends `:` + the homeserver domain.
///
/// The client must be connected (session restored or login complete) for alias
/// resolution.
pub async fn resolve_room_id(client: &Client, room: &str) -> Result<OwnedRoomId> {
    // Canonical room ID — return immediately.
    if room.starts_with('!') {
        return RoomId::parse(room).with_context(|| format!("Invalid room ID: {room}"));
    }

    // Build a qualified alias string.
    let alias_str: String = if room.starts_with('#') {
        room.to_owned()
    } else {
        // Bare name — prepend '#' and append homeserver domain.
        let server = client
            .homeserver()
            .host_str()
            .context("Homeserver URL has no host")?
            .to_owned();
        format!("#{room}:{server}")
    };

    let alias = <&RoomAliasId>::try_from(alias_str.as_str())
        .with_context(|| format!("Invalid room alias: {alias_str}"))?;

    let response = client
        .resolve_room_alias(alias)
        .await
        .with_context(|| format!("Failed to resolve room alias {alias_str}"))?;

    Ok(response.room_id)
}

// ── List rooms ────────────────────────────────────────────────────────────────

/// A brief summary of a joined room.
pub struct RoomInfo {
    pub room_id: OwnedRoomId,
    /// Human-readable name, if the room has one set.
    pub name: Option<String>,
    /// Canonical alias, if the room has one set.
    pub alias: Option<String>,
}

/// Return summary info for every joined room the client knows about.
pub fn list_joined_rooms(client: &Client) -> Vec<RoomInfo> {
    client
        .joined_rooms()
        .into_iter()
        .map(|room| RoomInfo {
            room_id: room.room_id().to_owned(),
            name: room.name(),
            alias: room.canonical_alias().map(|a| a.to_string()),
        })
        .collect()
}

// ── Send ─────────────────────────────────────────────────────────────────────

/// Send a plain-text message to the given room ID.
///
/// The client must have been synced at least once so the room appears in
/// session state.
pub async fn send_message(client: &Client, room_id: &RoomId, text: &str) -> Result<()> {
    let room = get_room(client, room_id)?;
    room.send(RoomMessageEventContent::text_plain(text))
        .await
        .context("Failed to send message")?;
    Ok(())
}

// ── Listen ────────────────────────────────────────────────────────────────────

/// A sync token that marks how far through the room timeline the caller has
/// read.  Persist this between runs and pass it back as `since` to receive
/// only new messages.
pub type ListenPointer = String;

/// Subscribe to plain-text messages in `room_id`, blocking until interrupted.
///
/// ## Catch-up behaviour
///
/// - `since = None` — paginate the full room history from the beginning,
///   emit every plain-text message oldest-first via `on_message`, then go
///   live.
/// - `since = Some(token)` — perform a single forward sync from `token`,
///   emit any messages that arrived since that token, then go live.
///
/// ## Return value
///
/// Returns the last [`ListenPointer`] observed before the sync loop exits
/// (Ctrl-C or error).  Persist this and pass it back as `since` on the
/// next invocation so only new messages are delivered.
///
/// ## Callback
///
/// `on_message(sender: OwnedUserId, body: String)` is called for every
/// qualifying message — catch-up and live — oldest first.  The closure is
/// required to be `Send + Sync + 'static` because it is shared with the
/// event-handler thread.
pub async fn listen<F, P>(
    client: &Client,
    room_id: &RoomId,
    since: Option<&str>,
    on_message: F,
    on_pointer: P,
) -> Result<ListenPointer>
where
    F: Fn(OwnedUserId, String) + Send + Sync + 'static,
    // Called with the latest `next_batch` token on every sync batch.
    // Use this to persist the token so reconnects skip already-seen messages.
    // Pass `|_| {}` to ignore.
    P: Fn(String) + Send + Sync + 'static,
{
    let on_message = Arc::new(on_message);
    let on_pointer = Arc::new(on_pointer);

    // ── Catch-up ──────────────────────────────────────────────────────────
    let initial_token: String = match since {
        // ── Full history ─────────────────────────────────────────────────
        // Anchor current position with a quick sync, then backward-paginate
        // the entire timeline.  The sync token from this initial sync is
        // used to start the live loop so no events fall through the gap.
        None => {
            let sync_resp = client
                .sync_once(SyncSettings::default().timeout(Duration::ZERO))
                .await
                .context("Initial sync before history pagination failed")?;

            let room = get_room(client, room_id)?;
            let mut all: Vec<(OwnedUserId, String)> = Vec::new();
            let mut from: Option<String> = None;

            // Paginate backward until the server signals we've reached the
            // beginning (end == None).  The server caps `limit` per page;
            // we use 100 and loop.
            loop {
                // MessagesOptions is #[non_exhaustive].
                let mut opts = MessagesOptions::backward();
                opts.limit = UInt::try_from(100u64).unwrap_or(UInt::MAX);
                opts.from = from.clone();

                let page = room
                    .messages(opts)
                    .await
                    .context("Failed to fetch message history page")?;

                for ev in page.chunk {
                    if let Some(pair) = extract_text_event(&ev) {
                        all.push(pair);
                    }
                }

                match page.end {
                    None => break, // beginning of room reached
                    Some(t) => from = Some(t),
                }
            }

            // `backward()` yields newest-first; reverse to oldest-first.
            all.reverse();
            for (sender, body) in all {
                on_message(sender, body);
            }

            sync_resp.next_batch
        }

        // ── Since a previous pointer ──────────────────────────────────────
        // Register a temporary event handler to collect catch-up events,
        // then do a single zero-timeout sync from `token`.  This fires the
        // handler for every event that arrived after `token` was issued.
        Some(token) => {
            let (tx, mut rx) = mpsc::channel::<(OwnedUserId, String)>(256);
            let tx = Arc::new(tx);

            let handle = client.add_room_event_handler(room_id, {
                let tx = Arc::clone(&tx);
                move |ev: OriginalSyncRoomMessageEvent, _room: Room| {
                    let tx = Arc::clone(&tx);
                    async move {
                        let MessageType::Text(ref text) = ev.content.msgtype else {
                            return;
                        };
                        let _ = tx.send((ev.sender.clone(), text.body.clone())).await;
                    }
                }
            });

            let resp = client
                .sync_once(SyncSettings::default().token(token).timeout(Duration::ZERO))
                .await
                .context("Catch-up sync failed")?;

            // Remove the temporary handler before draining the channel so
            // the live handler registered below does not overlap with it.
            client.remove_event_handler(handle);
            drop(tx); // close sender; rx.recv() will return None once drained

            while let Some((sender, body)) = rx.recv().await {
                on_message(sender, body);
            }

            resp.next_batch
        }
    };

    // ── Live tail ─────────────────────────────────────────────────────────
    client.add_room_event_handler(room_id, {
        let cb = Arc::clone(&on_message);
        move |ev: OriginalSyncRoomMessageEvent, _room: Room| {
            let cb = Arc::clone(&cb);
            async move {
                let MessageType::Text(ref text) = ev.content.msgtype else {
                    return;
                };
                cb(ev.sender.clone(), text.body.clone());
            }
        }
    });

    // Track the latest sync token so we can return it when the loop exits.
    let last_token = Arc::new(Mutex::new(initial_token.clone()));

    // 2 s long-poll: server returns immediately on new events, timeout only
    // applies when the room is idle.  Keeps worst-case receive latency ≤ 2 s.
    client
        .sync_with_callback(
            SyncSettings::default()
                .token(initial_token)
                .timeout(Duration::from_secs(2)),
            {
                let last_token = Arc::clone(&last_token);
                let on_pointer = Arc::clone(&on_pointer);
                move |resp| {
                    let last_token = Arc::clone(&last_token);
                    let on_pointer = Arc::clone(&on_pointer);
                    async move {
                        let token = resp.next_batch.clone();
                        *last_token.lock().unwrap() = resp.next_batch;
                        // File I/O off the async path — the next poll starts
                        // immediately without waiting for the write to finish.
                        tokio::task::spawn_blocking(move || on_pointer(token));
                        LoopCtrl::Continue
                    }
                }
            },
        )
        .await
        .context("Sync loop terminated unexpectedly")?;

    let token = Arc::try_unwrap(last_token)
        .map_err(|_| anyhow::anyhow!("last_token Arc still shared after sync exit"))?
        .into_inner()
        .unwrap();

    Ok(token)
}

// ── Join ──────────────────────────────────────────────────────────────────────

/// Join a room and return its basic metadata.
///
/// Accepts three formats:
/// - `!localpart:server` — canonical room ID.
/// - `#alias:server`    — qualified room alias.
/// - bare `name`        — expanded to `#name:<homeserver>`.
///
/// Unlike [`resolve_room_id`], this function does **not** pre-resolve the
/// alias before joining.  It passes the alias directly to
/// `POST /join/{roomIdOrAlias}` so the homeserver handles federation
/// in-band — avoiding the 404 that `GET /directory/room/{alias}` can return
/// for aliases the local server hasn't cached yet.
pub async fn join_room(client: &Client, room_spec: &str) -> Result<JoinResult> {
    // Build a fully-qualified room ID or alias string.
    let id_or_alias_str: String = if room_spec.starts_with('!') || room_spec.starts_with('#') {
        room_spec.to_owned()
    } else {
        // Bare name → qualified alias on the homeserver domain.
        let server = client
            .homeserver()
            .host_str()
            .context("Homeserver URL has no host")?
            .to_owned();
        format!("#{room_spec}:{server}")
    };

    let id_or_alias = <&RoomOrAliasId>::try_from(id_or_alias_str.as_str())
        .with_context(|| format!("Invalid room ID or alias: {id_or_alias_str}"))?;

    // Single request: the homeserver resolves the alias and joins, including
    // federation to remote servers if needed.
    let joined = client
        .join_room_by_id_or_alias(id_or_alias, &[])
        .await
        .with_context(|| format!("Failed to join {id_or_alias_str}"))?;

    let room_id = joined.room_id().to_owned();

    // Pull down room state so encryption event, name and alias are visible.
    client
        .sync_once(SyncSettings::default().timeout(std::time::Duration::ZERO))
        .await
        .context("Sync after join failed")?;

    let room = get_room(client, &room_id)?;

    let enc = room
        .latest_encryption_state()
        .await
        .context("Could not determine room encryption state")?;

    Ok(JoinResult {
        room_id,
        is_encrypted: enc.is_encrypted(),
        name: room.name(),
        alias: room.canonical_alias().map(|a| a.to_string()),
    })
}

// ── Set alias ─────────────────────────────────────────────────────────────────

/// Register `alias_spec` as a room alias pointing at `room_spec`.
///
/// Both arguments accept the same formats as [`resolve_room_id`]:
/// canonical ID, qualified alias, or bare name.
///
/// The alias is qualified against the homeserver domain if no server part is
/// given (e.g. `my-room` → `#my-room:<homeserver>`).
///
/// Returns the canonical alias string that was registered.
pub async fn set_room_alias(
    client: &Client,
    room_spec: &str,
    alias_spec: &str,
) -> Result<OwnedRoomAliasId> {
    let room_id = resolve_room_id(client, room_spec).await?;

    // Build fully-qualified alias string.
    let alias_str: String = if alias_spec.starts_with('#') {
        alias_spec.to_owned()
    } else {
        let server = client
            .homeserver()
            .host_str()
            .context("Homeserver URL has no host")?
            .to_owned();
        format!("#{alias_spec}:{server}")
    };

    let alias = <&RoomAliasId>::try_from(alias_str.as_str())
        .with_context(|| format!("Invalid room alias: {alias_str}"))?;

    client
        .create_room_alias(alias, &room_id)
        .await
        .with_context(|| format!("Failed to register alias {alias_str} → {room_id}"))?;

    Ok(alias.to_owned())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_room(client: &Client, room_id: &RoomId) -> Result<Room> {
    client
        .get_room(room_id)
        .with_context(|| format!("Room {room_id} not found — are you a member?"))
}

/// Try to extract a `(sender, body)` pair from a [`TimelineEvent`].
///
/// Returns `Some` only for plain-text `m.room.message` events; silently
/// drops state events, redactions, reactions, and encrypted messages that
/// cannot be decrypted.
///
/// [`TimelineEvent`]: matrix_sdk::deserialized_responses::TimelineEvent
fn extract_text_event(
    ev: &matrix_sdk::deserialized_responses::TimelineEvent,
) -> Option<(OwnedUserId, String)> {
    // PlainText events carry a Raw<AnySyncTimelineEvent>; the outer
    // TimelineEvent wrapper does not implement AnyTimelineEvent directly,
    // so we round-trip via the raw JSON string.
    let parsed: AnyTimelineEvent = match &ev.kind {
        TimelineEventKind::PlainText { event } => serde_json::from_str(event.json().get()).ok()?,
        TimelineEventKind::Decrypted(dec) => dec.event.deserialize().ok()?,
        _ => return None,
    };

    if let AnyTimelineEvent::MessageLike(AnyMessageLikeEvent::RoomMessage(msg)) = parsed {
        if let Some(orig) = msg.as_original() {
            if let MessageType::Text(ref text) = orig.content.msgtype {
                return Some((msg.sender().to_owned(), text.body.clone()));
            }
        }
    }
    None
}
