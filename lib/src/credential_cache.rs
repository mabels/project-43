//! In-memory credential cache keyed by SSH fingerprint or card AID ident.
//!
//! Entries expire `timeout` after their **last access** (sliding window).
//! [`get`] resets the expiry timer; [`peek`] does not.
//! A zero timeout means "never expire automatically".
//!
//! # Future: biometric protection
//!
//! The cache is designed so that a future revision can seal each entry's
//! credential string with a biometric-unlocked symmetric key before storing
//! it.  The public API (`insert` / `get` / `peek` / `purge`) will remain
//! unchanged; only the internal `CacheEntry` representation will change.

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Entry ─────────────────────────────────────────────────────────────────────

struct CacheEntry {
    /// Plaintext credential (PIN or passphrase).
    ///
    /// Future: replace with an encrypted blob sealed by a biometric key.
    credential: String,
    /// Wall-clock time of the last access (reset by [`CredentialCache::get`]).
    last_accessed: Instant,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// In-memory store for PINs and passphrases with sliding-window expiry.
///
/// Keys are opaque identifier strings:
/// - OpenPGP hex fingerprint for soft keys
/// - Card AID ident (e.g. `"0006:17684870"`) for card keys
///
/// Thread-safety: wrap in a `std::sync::Mutex` — the struct itself is not
/// `Sync`.
pub struct CredentialCache {
    entries: HashMap<String, CacheEntry>,
    timeout: Duration,
}

impl CredentialCache {
    /// Create a cache with the given timeout in seconds.
    ///
    /// Pass `0` to disable automatic expiry (entries live until [`purge`]).
    pub fn new(timeout_secs: u32) -> Self {
        Self {
            entries: HashMap::new(),
            timeout: Duration::from_secs(timeout_secs as u64),
        }
    }

    /// Update the expiry timeout.  Takes effect on the next access or eviction.
    pub fn set_timeout(&mut self, secs: u32) {
        self.timeout = Duration::from_secs(secs as u64);
    }

    /// Store (or replace) a credential under `key_id`.
    pub fn insert(&mut self, key_id: impl Into<String>, credential: impl Into<String>) {
        self.entries.insert(
            key_id.into(),
            CacheEntry {
                credential: credential.into(),
                last_accessed: Instant::now(),
            },
        );
    }

    /// Retrieve a credential and reset its expiry timer (sliding window).
    ///
    /// Returns `None` when the key is absent or the entry has expired.
    pub fn get(&mut self, key_id: &str) -> Option<String> {
        if self.is_expired_key(key_id) {
            self.entries.remove(key_id);
            return None;
        }
        let entry = self.entries.get_mut(key_id)?;
        entry.last_accessed = Instant::now();
        Some(entry.credential.clone())
    }

    /// Check whether a non-expired credential exists without resetting the timer.
    ///
    /// Use this for UI decisions (e.g. whether to show the auto-approve path).
    /// Use [`get`] when actually consuming the credential so the timer resets.
    pub fn peek(&mut self, key_id: &str) -> bool {
        if self.is_expired_key(key_id) {
            self.entries.remove(key_id);
            return false;
        }
        self.entries.contains_key(key_id)
    }

    /// Remove all entries from the cache.
    pub fn purge(&mut self) {
        self.entries.clear();
    }

    /// Remove all entries that have exceeded the timeout.
    ///
    /// [`get`] and [`peek`] already perform lazy per-entry eviction; call
    /// this for a full sweep after a timeout change or on a periodic timer.
    pub fn evict_expired(&mut self) {
        if self.timeout.is_zero() {
            return;
        }
        let timeout = self.timeout;
        self.entries
            .retain(|_, e| e.last_accessed.elapsed() <= timeout);
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn is_expired_key(&self, key_id: &str) -> bool {
        match self.entries.get(key_id) {
            Some(e) => self.is_expired(e),
            None => false,
        }
    }

    fn is_expired(&self, entry: &CacheEntry) -> bool {
        !self.timeout.is_zero() && entry.last_accessed.elapsed() > self.timeout
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn insert_and_get() {
        let mut c = CredentialCache::new(60);
        c.insert("fp1", "secret");
        assert_eq!(c.get("fp1").as_deref(), Some("secret"));
    }

    #[test]
    fn missing_key_returns_none() {
        let mut c = CredentialCache::new(60);
        assert!(c.get("nope").is_none());
    }

    #[test]
    fn peek_does_not_reset_timer() {
        let mut c = CredentialCache::new(60);
        c.insert("fp1", "secret");
        assert!(c.peek("fp1"));
        // Peek should not affect the last_accessed timestamp in a meaningful
        // way we can observe here, but it should still return true.
        assert_eq!(c.get("fp1").as_deref(), Some("secret"));
    }

    #[test]
    fn purge_clears_all() {
        let mut c = CredentialCache::new(60);
        c.insert("a", "x");
        c.insert("b", "y");
        c.purge();
        assert!(c.get("a").is_none());
        assert!(c.get("b").is_none());
    }

    #[test]
    fn zero_timeout_never_expires() {
        let mut c = CredentialCache::new(0);
        c.insert("fp1", "secret");
        // Sleep a tiny bit — zero timeout means never expire.
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(c.get("fp1").as_deref(), Some("secret"));
    }
}
