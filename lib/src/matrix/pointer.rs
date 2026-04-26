//! Per-reader, per-room Matrix sync-pointer store.
//!
//! Each component that reads from a Matrix room keeps its own `since` token so
//! they never share state and never advance each other's cursor.
//!
//! Layout on disk:
//!
//! ```text
//! <store_root>/app-state/<device_id>/<reader>.json
//! ```
//!
//! where the JSON payload is `{ "<room_id>": "<since_token>" }`.
//!
//! Typical values for `reader`: `"cli"`, `"ui"`.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

// ── RoomPointerStore ──────────────────────────────────────────────────────────

pub struct RoomPointerStore {
    path: PathBuf,
}

impl RoomPointerStore {
    /// Construct the store for `reader` on `device_id`.
    ///
    /// `store_root` — directory containing `matrix-config.json`
    ///                (e.g. `~/.config/project-43/`).
    /// `device_id`  — Matrix device ID string (e.g. `"ABCDEFGH"`).
    /// `reader`     — `"cli"` or `"ui"`.
    pub fn new(store_root: &Path, device_id: &str, reader: &str) -> Self {
        let path = store_root
            .join("app-state")
            .join(device_id)
            .join(format!("{reader}.json"));
        Self { path }
    }

    fn load_map(&self) -> HashMap<String, String> {
        if !self.path.exists() {
            return HashMap::new();
        }
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Return the saved since-token for `room_id`, if any.
    pub fn get(&self, room_id: &str) -> Option<String> {
        self.load_map().remove(room_id)
    }

    /// Persist `token` as the since-pointer for `room_id`.
    pub fn set(&self, room_id: &str, token: &str) -> Result<()> {
        let mut map = self.load_map();
        map.insert(room_id.to_owned(), token.to_owned());
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create app-state dir {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(&map).context("serialise room pointer map")?;
        std::fs::write(&self.path, &json)
            .with_context(|| format!("write room pointer to {}", self.path.display()))?;
        Ok(())
    }

    /// Path of the underlying JSON file (for log messages).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Read the Matrix device ID from the saved session config without opening a
/// live Matrix connection.
///
/// Returns an error if `matrix-config.json` does not exist yet.
pub fn device_id_from_config(config_path: &Path) -> Result<String> {
    let saved = super::client::load_config(config_path)?
        .context("no Matrix session found — run `p43 matrix login` first")?;
    Ok(saved.session.meta.device_id.to_string())
}
