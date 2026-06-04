//! Abstract object store and filesystem implementation.
//!
//! The object store is the only I/O surface the chain logic touches.
//! Swapping it out (for testing or alternative backends) requires no changes
//! to the chain or crypto code.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

// ── Trait ─────────────────────────────────────────────────────────────────────

/// A flat, content-addressed key-value store.
///
/// - [`put`] fails if the id already exists (immutability guarantee).
/// - [`get`] fails if the id does not exist.
/// - Objects are opaque byte blobs; callers own serialisation.
pub trait ObjectStore: Send + Sync {
    fn list(&self) -> Result<Vec<String>>;
    /// Write a new immutable object — fails if id already exists.
    fn put(&self, id: &str, data: &[u8]) -> Result<()>;
    /// Overwrite an existing object (for mutable meta refs).
    fn update(&self, id: &str, data: &[u8]) -> Result<()>;
    fn get(&self, id: &str) -> Result<Vec<u8>>;
    fn exists(&self, id: &str) -> bool;
}

// ── FileObjectStore ───────────────────────────────────────────────────────────

/// Filesystem-backed object store.
///
/// Objects are stored as files under `base/`.  `put` uses write-then-rename
/// for atomicity.  A second `put` for the same id fails immediately.
pub struct FileObjectStore {
    base: PathBuf,
}

impl FileObjectStore {
    /// Open (or create) the store at `base`.
    pub fn open(base: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&base)
            .with_context(|| format!("cannot create object store at {}", base.display()))?;
        Ok(Self { base })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.base.join(id)
    }
}

/// Recursively walk `dir`, collecting paths relative to `base`.
fn walk_dir(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            walk_dir(base, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/"); // normalise on Windows
            out.push(rel);
        }
    }
    Ok(())
}

impl FileObjectStore {
    fn write_atomic(&self, id: &str, data: &[u8]) -> Result<()> {
        let dest = self.path(id);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create dir for {id}"))?;
        }
        let tmp = self.base.join(format!("{id}.tmp"));
        std::fs::write(&tmp, data).with_context(|| format!("cannot write tmp file for {id}"))?;
        std::fs::rename(&tmp, &dest).with_context(|| format!("cannot rename tmp to {id}"))?;
        Ok(())
    }
}

impl ObjectStore for FileObjectStore {
    fn list(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        walk_dir(&self.base, &self.base, &mut ids)?;
        Ok(ids)
    }

    fn put(&self, id: &str, data: &[u8]) -> Result<()> {
        let dest = self.path(id);
        if dest.exists() {
            bail!("object {id} already exists (immutability violation)");
        }
        self.write_atomic(id, data)
    }

    fn update(&self, id: &str, data: &[u8]) -> Result<()> {
        self.write_atomic(id, data)
    }

    fn get(&self, id: &str) -> Result<Vec<u8>> {
        let path = self.path(id);
        std::fs::read(&path).with_context(|| format!("object {id} not found"))
    }

    fn exists(&self, id: &str) -> bool {
        self.path(id).exists()
    }
}

// ── In-memory store (testing) ─────────────────────────────────────────────────

#[cfg(test)]
pub mod mem {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Thread-safe in-memory object store for tests.
    pub struct MemObjectStore(Mutex<HashMap<String, Vec<u8>>>);

    impl MemObjectStore {
        pub fn new() -> Self {
            Self(Mutex::new(HashMap::new()))
        }
    }

    impl ObjectStore for MemObjectStore {
        fn list(&self) -> Result<Vec<String>> {
            Ok(self.0.lock().unwrap().keys().cloned().collect())
        }

        fn put(&self, id: &str, data: &[u8]) -> Result<()> {
            let mut map = self.0.lock().unwrap();
            if map.contains_key(id) {
                bail!("object {id} already exists");
            }
            map.insert(id.to_owned(), data.to_vec());
            Ok(())
        }

        fn update(&self, id: &str, data: &[u8]) -> Result<()> {
            self.0.lock().unwrap().insert(id.to_owned(), data.to_vec());
            Ok(())
        }

        fn get(&self, id: &str) -> Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .with_context(|| format!("object {id} not found"))
        }

        fn exists(&self, id: &str) -> bool {
            self.0.lock().unwrap().contains_key(id)
        }
    }
}
