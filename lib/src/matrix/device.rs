use anyhow::{Context, Result};
use matrix_sdk::{
    ruma::{api::client::uiaa, OwnedDeviceId},
    Client,
};

// ── DeviceInfo ────────────────────────────────────────────────────────────────

/// A brief summary of a device registered to this Matrix account.
pub struct DeviceInfo {
    /// The device ID assigned by the homeserver.
    pub device_id: String,
    /// Human-readable label set on the device, if any.
    pub display_name: Option<String>,
    /// IP address from which the device last connected, as reported by the
    /// homeserver.
    pub last_seen_ip: Option<String>,
    /// `true` if this entry corresponds to the caller's current session.
    pub is_current: bool,
}

// ── list_devices ──────────────────────────────────────────────────────────────

/// Fetch all devices registered to the authenticated account.
///
/// Returns one [`DeviceInfo`] per device.  The entry matching the current
/// session has `is_current` set to `true`.
///
/// The client must already have an active session (login or restore complete).
pub async fn list_devices(client: &Client) -> Result<Vec<DeviceInfo>> {
    let current = client.device_id().map(|d| d.to_string());

    let response = client
        .devices()
        .await
        .context("Failed to fetch device list from homeserver")?;

    let devices = response
        .devices
        .into_iter()
        .map(|d| {
            let id = d.device_id.to_string();
            DeviceInfo {
                is_current: current.as_deref() == Some(&id),
                device_id: id,
                display_name: d.display_name,
                last_seen_ip: d.last_seen_ip,
            }
        })
        .collect();

    Ok(devices)
}

// ── delete_devices ────────────────────────────────────────────────────────────

/// Delete the given devices from the homeserver.
///
/// Device deletion requires the user to re-authenticate (UIA).  The
/// `password` argument is used to satisfy that challenge automatically
/// so the call is non-interactive once the caller has resolved it.
///
/// The current session's device ID must **not** appear in `device_ids`;
/// use `logout` to deregister the current device.
pub async fn delete_devices(
    client: &Client,
    device_ids: &[OwnedDeviceId],
    password: &str,
) -> Result<()> {
    if device_ids.is_empty() {
        return Ok(());
    }

    // First attempt — no auth.  The server returns a UIA challenge.
    let uiaa_info = match client.delete_devices(device_ids, None).await {
        Ok(_) => return Ok(()), // server accepted without auth (unusual but fine)
        Err(e) => e
            .as_uiaa_response()
            .cloned()
            .context("Device deletion failed with a non-UIA error")?,
    };

    // Build password auth using the UIA session token from the challenge.
    let user_id = client
        .user_id()
        .context("No user ID on current session")?
        .localpart()
        .to_owned();

    let mut pw_auth = uiaa::Password::new(
        uiaa::UserIdentifier::UserIdOrLocalpart(user_id),
        password.to_owned(),
    );
    pw_auth.session = uiaa_info.session.clone();

    client
        .delete_devices(device_ids, Some(uiaa::AuthData::Password(pw_auth)))
        .await
        .context("Device deletion failed after UIA")?;

    Ok(())
}
