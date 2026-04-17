use anyhow::{Context, Result};
use matrix_sdk::{
    config::SyncSettings,
    room::Room,
    ruma::{
        events::room::message::{
            MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent,
        },
        OwnedRoomId, RoomAliasId, RoomId,
    },
    Client,
};

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
/// Each message is printed as:
/// ```text
/// [sender] body
/// ```
pub async fn listen(client: &Client, room_id: &RoomId) -> Result<()> {
    // Validate the room is known before registering the handler.
    let _ = get_room(client, room_id)?;

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

    // Drive the sync loop; it only returns on error.
    client
        .sync(SyncSettings::default())
        .await
        .context("Sync loop terminated unexpectedly")?;

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_room(client: &Client, room_id: &RoomId) -> Result<Room> {
    client
        .get_room(room_id)
        .with_context(|| format!("Room {room_id} not found — are you a member?"))
}
