use anyhow::{bail, Result};
use std::path::Path;

use crate::bus::{device_key_path, devices_dir, DeviceKey};

/// Load the device key for `label`, or generate a new one if it does not exist.
///
/// - `label = Some(s)` → load `devices/<s>.key.cbor`; generate it if missing.
/// - `label = None`    → auto-detect exactly one existing key in `devices/`;
///   if none exist, generate a new key using the sanitised system hostname.
///
/// Returns `(label, key)`.
pub fn load_or_generate_device_key(
    bus_dir: &Path,
    label: Option<&str>,
) -> Result<(String, DeviceKey)> {
    if let Some(lbl) = label {
        let path = device_key_path(bus_dir, lbl);
        if path.exists() {
            let key = DeviceKey::load(&path)
                .map_err(|e| anyhow::anyhow!("load device key {}: {e}", path.display()))?;
            return Ok((lbl.to_string(), key));
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        let key = DeviceKey::generate(lbl);
        key.save(&path)?;
        eprintln!(
            "[p43::bus] generated new device key '{}' at {}",
            lbl,
            path.display()
        );
        return Ok((lbl.to_string(), key));
    }

    // No label: auto-detect exactly one existing key.
    let dir = devices_dir(bus_dir);
    if dir.exists() {
        let mut found: Vec<(String, std::path::PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("cbor") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if stem.ends_with(".key") {
                        found.push((stem.trim_end_matches(".key").to_string(), path));
                    }
                }
            }
        }
        if found.len() == 1 {
            let (lbl, path) = found.remove(0);
            let key = DeviceKey::load(&path)?;
            return Ok((lbl, key));
        }
        if found.len() > 1 {
            let labels: Vec<_> = found.iter().map(|(l, _)| l.as_str()).collect();
            bail!(
                "multiple device keys found; specify one with --device: {}",
                labels.join(", ")
            );
        }
    }

    // No keys at all: generate one from hostname.
    let lbl = hostname_label();
    let path = device_key_path(bus_dir, &lbl);
    std::fs::create_dir_all(path.parent().unwrap())?;
    let key = DeviceKey::generate(&lbl);
    key.save(&path)?;
    eprintln!(
        "[p43::bus] generated new device key '{}' at {}",
        lbl,
        path.display()
    );
    Ok((lbl, key))
}

/// Return the system hostname sanitised for use as a device label.
///
/// Keeps alphanumerics, `-` and `_`; replaces everything else with `-`.
/// Falls back to `"device"` when the hostname cannot be read.
pub fn hostname_label() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "device".to_string())
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}
