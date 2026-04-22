use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::bus::{
    authority_cert_path, device_cert_path, device_csr_path, device_key_path, devices_dir,
    peer_cert_path, DeviceCert, DeviceKey,
};

// ── OwnDeviceInfo ─────────────────────────────────────────────────────────────

/// Summary of a locally-owned device key entry.
pub struct OwnDeviceInfo {
    /// Human-readable label given at `gen-key` time.
    pub label: String,
    /// 16-hex-char device fingerprint (first 8 bytes of sign pubkey).
    pub device_id: String,
    /// Whether a signed cert file exists for this device.
    pub has_cert: bool,
    /// Whether a pending CSR file exists for this device.
    pub has_csr: bool,
    /// Unix timestamp of cert expiry, or `None` if cert is absent or never expires.
    pub cert_exp: Option<i64>,
}

/// List all locally-owned device keys under `<bus_dir>/devices/`.
///
/// Returns one entry per `*.key.cbor` file, sorted by label.
/// Files that cannot be parsed are silently skipped (a warning is emitted to
/// stderr so operators can diagnose corrupt files without aborting the list).
pub fn list_own_devices(bus_dir: &Path) -> Result<Vec<OwnDeviceInfo>> {
    let dir = devices_dir(bus_dir);
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut items: Vec<OwnDeviceInfo> = Vec::new();

    for entry in std::fs::read_dir(&dir)
        .map_err(|e| anyhow::anyhow!("Cannot read devices dir {}: {}", dir.display(), e))?
    {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("cbor") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if !stem.ends_with(".key") {
            continue;
        }

        let label = stem.trim_end_matches(".key").to_string();

        // Load key — skip silently on parse error but warn.
        let key = match DeviceKey::load(&device_key_path(bus_dir, &label)) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("warn: skipping device key {label}: {e}");
                continue;
            }
        };

        let has_csr = device_csr_path(bus_dir, &label).exists();
        let cert_path = crate::bus::device_cert_path(bus_dir, &label);
        let (has_cert, cert_exp) = if cert_path.exists() {
            match DeviceCert::load(&cert_path) {
                Ok(c) => (true, c.payload.exp),
                Err(_) => (true, None),
            }
        } else {
            (false, None)
        };

        items.push(OwnDeviceInfo {
            device_id: key.device_id(),
            label,
            has_cert,
            has_csr,
            cert_exp,
        });
    }

    items.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(items)
}

// ── PeerInfo ──────────────────────────────────────────────────────────────────

/// Summary of a peer device whose cert has been registered with this authority.
pub struct PeerInfo {
    /// Device fingerprint (16 hex chars).
    pub device_id: String,
    /// Label the device chose at key-generation time.
    pub label: String,
    /// Unix timestamp of cert issuance.
    pub issued_at: i64,
    /// Unix timestamp of cert expiry, or `None` if it never expires.
    pub expires_at: Option<i64>,
}

/// List all peer certs registered under `<bus_dir>/peers/`.
///
/// Returns one entry per `*.cert.cbor` file, sorted by label then device_id.
/// Files that cannot be parsed are silently skipped.
pub fn list_peers(bus_dir: &Path) -> Result<Vec<PeerInfo>> {
    let peers_dir = bus_dir.join("peers");
    if !peers_dir.exists() {
        return Ok(vec![]);
    }

    let mut items: Vec<PeerInfo> = Vec::new();

    for entry in std::fs::read_dir(&peers_dir)
        .map_err(|e| anyhow::anyhow!("Cannot read peers dir {}: {}", peers_dir.display(), e))?
    {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("cbor") {
            continue;
        }

        match DeviceCert::load(&path) {
            Ok(cert) => items.push(PeerInfo {
                device_id: cert.payload.device_id.clone(),
                label: cert.payload.label.clone(),
                issued_at: cert.payload.iat,
                expires_at: cert.payload.exp,
            }),
            Err(e) => {
                eprintln!("warn: skipping peer cert {}: {e}", path.display());
            }
        }
    }

    items.sort_by(|a, b| a.label.cmp(&b.label).then(a.device_id.cmp(&b.device_id)));
    Ok(items)
}

/// Remove a peer cert from `<bus_dir>/peers/` by device_id.
///
/// Returns `Ok(true)` if the file was deleted, `Ok(false)` if it did not exist.
pub fn remove_peer(bus_dir: &Path, device_id: &str) -> Result<bool> {
    let path = peer_cert_path(bus_dir, device_id);
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| anyhow::anyhow!("Cannot remove peer cert {}: {e}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ── Delete device key ─────────────────────────────────────────────────────────

/// Resolve a device key label from either an exact label or a device-id prefix.
///
/// - `label = Some(s)` — verify `devices/<s>.key.cbor` exists and return `s`.
/// - `device_id = Some(id)` — scan `devices/` for a key whose `device_id()`
///   starts with `id` (case-insensitive prefix match).  Errors on ambiguity.
/// - Both `None` — returns an error asking for one to be supplied.
///
/// Does **not** delete anything; use [`delete_device_key`] after confirming.
pub fn resolve_own_device_label(
    bus_dir: &Path,
    label: Option<&str>,
    device_id: Option<&str>,
) -> Result<String> {
    match (label, device_id) {
        (Some(lbl), _) => {
            let path = device_key_path(bus_dir, lbl);
            if !path.exists() {
                anyhow::bail!(
                    "no device key found for label {:?} at {}",
                    lbl,
                    path.display()
                );
            }
            Ok(lbl.to_string())
        }
        (None, Some(id)) => {
            let id_lower = id.to_lowercase();
            let dir = devices_dir(bus_dir);
            if !dir.exists() {
                anyhow::bail!("no devices directory at {}", dir.display());
            }
            let mut matches: Vec<String> = Vec::new();
            for entry in std::fs::read_dir(&dir)
                .map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?
            {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some("cbor") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if !stem.ends_with(".key") {
                    continue;
                }
                let lbl = stem.trim_end_matches(".key").to_string();
                if let Ok(key) = DeviceKey::load(&device_key_path(bus_dir, &lbl)) {
                    if key.device_id().to_lowercase().starts_with(&id_lower) {
                        matches.push(lbl);
                    }
                }
            }
            match matches.len() {
                0 => anyhow::bail!("no device key with id starting with {:?}", id),
                1 => Ok(matches.remove(0)),
                n => anyhow::bail!(
                    "{n} device keys match id prefix {:?}: {}",
                    id,
                    matches.join(", ")
                ),
            }
        }
        (None, None) => anyhow::bail!("provide --label or --id to identify the device key"),
    }
}

/// Delete a locally-owned device key by its **resolved label**, plus any
/// associated CSR and cert files.
///
/// Call [`resolve_own_device_label`] first (and confirm with the user if
/// interactive), then pass the resolved label here.
///
/// Silently skips CSR/cert removal if those files do not exist.
pub fn delete_device_key(bus_dir: &Path, label: &str) -> Result<()> {
    let key_path = device_key_path(bus_dir, label);
    std::fs::remove_file(&key_path)
        .map_err(|e| anyhow::anyhow!("remove {}: {e}", key_path.display()))?;

    let csr_path = device_csr_path(bus_dir, label);
    if csr_path.exists() {
        let _ = std::fs::remove_file(&csr_path);
    }
    let cert_path = device_cert_path(bus_dir, label);
    if cert_path.exists() {
        let _ = std::fs::remove_file(&cert_path);
    }
    Ok(())
}

// ── Device key resolution ─────────────────────────────────────────────────────

/// Resolve a device key from `<bus_dir>/devices/`.
///
/// - `label = Some(s)` → load `devices/<s>.key.cbor` directly.
/// - `label = None`    → scan `devices/` for exactly one `*.key.cbor`; error if
///   zero or more than one key is found (with the list of available labels).
///
/// Returns `(label, key_path, key)`.
pub fn resolve_device_key(
    bus_dir: &Path,
    label: Option<&str>,
) -> Result<(String, PathBuf, DeviceKey)> {
    if let Some(lbl) = label {
        let path = device_key_path(bus_dir, lbl);
        let key = DeviceKey::load(&path)
            .map_err(|e| anyhow::anyhow!("load device key from {}: {e}", path.display()))?;
        return Ok((lbl.to_string(), path, key));
    }

    let dir = devices_dir(bus_dir);
    if !dir.exists() {
        bail!(
            "no devices directory found at {}; run `bus gen-key` first",
            dir.display()
        );
    }

    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    for entry in
        std::fs::read_dir(&dir).map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("cbor") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.ends_with(".key") {
                    candidates.push((stem.trim_end_matches(".key").to_string(), path));
                }
            }
        }
    }

    match candidates.len() {
        0 => bail!(
            "no device keys found in {}; run `bus gen-key` first",
            dir.display()
        ),
        1 => {
            let (lbl, path) = candidates.remove(0);
            let key = DeviceKey::load(&path)
                .map_err(|e| anyhow::anyhow!("load device key from {}: {e}", path.display()))?;
            Ok((lbl, path, key))
        }
        n => {
            let labels: Vec<_> = candidates.iter().map(|(l, _)| l.as_str()).collect();
            bail!(
                "{n} device keys found in {}; specify one with --label (or --device): {}",
                dir.display(),
                labels.join(", ")
            )
        }
    }
}

// ── Recipient cert resolution ─────────────────────────────────────────────────

/// Resolve a `--to` value to a cert file path via four-step fallback:
///
/// 1. The special token `"authority"` → `authority.cert.cbor`.
/// 2. A literal file path that already exists on disk.
/// 3. A label / device-id looked up in `peers/<label>.cert.cbor`.
/// 4. A label / device-id looked up in `devices/<label>.cert.cbor`.
pub fn resolve_recipient_cert(bus_dir: &Path, to: &str) -> Result<PathBuf> {
    if to == "authority" {
        let path = authority_cert_path(bus_dir);
        if !path.exists() {
            bail!(
                "authority cert not found at {}; run `bus init` first",
                path.display()
            );
        }
        return Ok(path);
    }

    let as_path = PathBuf::from(to);
    if as_path.exists() {
        return Ok(as_path);
    }

    let peer = peer_cert_path(bus_dir, to);
    if peer.exists() {
        return Ok(peer);
    }

    let dev = device_cert_path(bus_dir, to);
    if dev.exists() {
        return Ok(dev);
    }

    bail!(
        "could not resolve recipient {:?}: not a file path, \
         not found in peers/ or devices/",
        to
    )
}
