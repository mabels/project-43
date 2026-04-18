use anyhow::{Context, Result};
use matrix_sdk::{
    config::SyncSettings,
    deserialized_responses::TimelineEventKind,
    room::Room,
    ruma::{
        events::{
            room::message::{
                MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent,
            },
            AnyMessageLikeEvent, AnyTimelineEvent,
        },
        OwnedRoomAliasId, OwnedRoomId, RoomAliasId, RoomId, RoomOrAliasId, UInt,
    },
    Client,
};
use matrix_sdk::room::MessagesOptions;

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
        return RoomId::parse(room)
            .with_context(|| format!("Invalid room ID: {room}"));
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

/// Stream incoming plain-text messages from `room_id` to stdout, blocking
/// until the process is interrupted (Ctrl-C / SIGINT).
///
/// If `history > 0` the last `history` messages are printed oldest-first
/// before the live tail begins.
///
/// Each message (history and live) is printed as:
/// ```text
/// [sender] body
/// ```
pub async fn listen(client: &Client, room_id: &RoomId, history: u64) -> Result<()> {
    let room = get_room(client, room_id)?;

    // ── History ───────────────────────────────────────────────────────────
    if history > 0 {
        let limit = UInt::try_from(history).unwrap_or(UInt::MAX);
        // MessagesOptions is #[non_exhaustive] so we can't use struct literal syntax.
        let mut opts = MessagesOptions::backward();
        opts.limit = limit;

        let messages = room
            .messages(opts)
            .await
            .context("Failed to fetch message history")?;

        // `backward()` returns newest-first; reverse for chronological display.
        let mut history_events: Vec<_> = messages
            .chunk
            .into_iter()
            .filter_map(|ev| {
                // Deserialise the raw event.
                // PlainText holds Raw<AnySyncTimelineEvent> (no JsonCastable to
                // AnyTimelineEvent), so go via the raw JSON string instead.
                let parsed: Option<AnyTimelineEvent> = match ev.kind {
                    TimelineEventKind::PlainText { event } => {
                        serde_json::from_str(event.json().get()).ok()
                    }
                    TimelineEventKind::Decrypted(dec) => dec.event.deserialize().ok(),
                    _ => None,
                };
                // Only keep plain-text room messages.
                if let Some(AnyTimelineEvent::MessageLike(AnyMessageLikeEvent::RoomMessage(
                    msg,
                ))) = parsed
                {
                    if let Some(orig) = msg.as_original() {
                        if let MessageType::Text(ref text) = orig.content.msgtype {
                            return Some((msg.sender().to_owned(), text.body.clone()));
                        }
                    }
                }
                None
            })
            .collect();

        history_events.reverse(); // oldest first

        if !history_events.is_empty() {
            eprintln!("── history ─────────────────────────────────────────────");
            for (sender, body) in history_events {
                println!("[{sender}] {body}");
            }
            eprintln!("── live ────────────────────────────────────────────────");
        }
    }

    // ── Live tail ─────────────────────────────────────────────────────────
    // `add_room_event_handler` already filters by room_id for us.
    client.add_room_event_handler(
        room_id,
        |event: OriginalSyncRoomMessageEvent, _room: Room| async move {
            let MessageType::Text(text_content) = &event.content.msgtype else {
                return;
            };
            println!("[{}] {}", event.sender, text_content.body);
        },
    );

    eprintln!("Listening for messages in {room_id} — press Ctrl-C to stop.");

    client
        .sync(SyncSettings::default())
        .await
        .context("Sync loop terminated unexpectedly")?;

    Ok(())
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
