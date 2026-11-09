//! Message deduplication for multi-backend transport racing.
//!
//! Tracks recently seen message IDs and ciphertext envelope hashes to filter
//! out duplicates when messages are emitted in parallel across multiple transports.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::protocol::Message;

/// Default maximum number of message IDs to remember.
pub const DEFAULT_DEDUP_CAPACITY: usize = 4096;

/// Default time-to-live for recorded message IDs (10 minutes).
pub const DEFAULT_DEDUP_TTL: Duration = Duration::from_secs(600);

/// Extract a unique deduplication identifier for a protocol message.
pub fn message_dedup_id(msg: &Message) -> String {
    match msg {
        Message::BusSecure(env) => {
            let mut hasher = Sha256::new();
            hasher.update(env.envelope_b64.as_bytes());
            format!("sec:{}", hex::encode(hasher.finalize()))
        }
        other => {
            if let Some(rid) = other.request_id() {
                format!("{}:{}", other.type_name(), rid)
            } else {
                let mut hasher = Sha256::new();
                hasher.update(other.to_json().unwrap_or_default().as_bytes());
                format!("raw:{}", hex::encode(hasher.finalize()))
            }
        }
    }
}

/// Sliding-window deduplication store with O(1) membership check and FIFO TTL eviction.
pub struct MessageDeduplicator {
    inner: Arc<Mutex<DedupInner>>,
}

struct DedupInner {
    set: HashSet<String>,
    queue: VecDeque<(String, Instant)>,
    capacity: usize,
    ttl: Duration,
}

impl MessageDeduplicator {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DedupInner {
                set: HashSet::with_capacity(capacity),
                queue: VecDeque::with_capacity(capacity),
                capacity,
                ttl,
            })),
        }
    }

    /// Check if an ID has already been seen.
    ///
    /// Returns `true` if this ID is a duplicate (already seen within TTL).
    /// Returns `false` if this is the first time seeing this ID (and records it).
    pub fn is_duplicate(&self, id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();

        // 1. Evict expired entries from the front of the queue.
        while let Some((_, ts)) = inner.queue.front() {
            if now.duration_since(*ts) > inner.ttl {
                if let Some((old_id, _)) = inner.queue.pop_front() {
                    inner.set.remove(&old_id);
                }
            } else {
                break;
            }
        }

        // 2. Check if already present.
        if inner.set.contains(id) {
            return true;
        }

        // 3. Evict oldest if at capacity.
        if inner.set.len() >= inner.capacity {
            if let Some((old_id, _)) = inner.queue.pop_front() {
                inner.set.remove(&old_id);
            }
        }

        // 4. Record new ID.
        inner.set.insert(id.to_string());
        inner.queue.push_back((id.to_string(), now));
        false
    }

    /// Convenience helper that checks deduplication for a protocol message.
    pub fn is_duplicate_message(&self, msg: &Message) -> bool {
        let id = message_dedup_id(msg);
        self.is_duplicate(&id)
    }
}

impl Default for MessageDeduplicator {
    fn default() -> Self {
        Self::new(DEFAULT_DEDUP_CAPACITY, DEFAULT_DEDUP_TTL)
    }
}

impl Clone for MessageDeduplicator {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{BusSecureEnvelope, SshSignRequest};

    #[test]
    fn test_dedup_plain_message() {
        let dedup = MessageDeduplicator::new(100, Duration::from_secs(60));

        let req1 = Message::SshSignRequest(SshSignRequest {
            request_id: "req-1".into(),
            fingerprint: "fp1".into(),
            data: b"data".to_vec(),
            flags: 0,
            description: "desc".into(),
            meta: Default::default(),
        });

        let req2 = Message::SshSignRequest(SshSignRequest {
            request_id: "req-2".into(),
            fingerprint: "fp2".into(),
            data: b"data".to_vec(),
            flags: 0,
            description: "desc".into(),
            meta: Default::default(),
        });

        // First time seeing req1: not duplicate.
        assert!(!dedup.is_duplicate_message(&req1));
        // Second time seeing req1: duplicate!
        assert!(dedup.is_duplicate_message(&req1));

        // Different request_id: not duplicate.
        assert!(!dedup.is_duplicate_message(&req2));
        assert!(dedup.is_duplicate_message(&req2));
    }

    #[test]
    fn test_dedup_bus_secure_envelope() {
        let dedup = MessageDeduplicator::new(100, Duration::from_secs(60));

        let env1 = Message::BusSecure(BusSecureEnvelope {
            v: 1,
            from: "dev1".into(),
            envelope_b64: "AAAA_CIPHERTEXT_1".into(),
        });

        let env2 = Message::BusSecure(BusSecureEnvelope {
            v: 1,
            from: "dev1".into(),
            envelope_b64: "BBBB_CIPHERTEXT_2".into(),
        });

        // env1 first time
        assert!(!dedup.is_duplicate_message(&env1));
        // env1 duplicate
        assert!(dedup.is_duplicate_message(&env1));

        // env2 first time
        assert!(!dedup.is_duplicate_message(&env2));
    }

    #[test]
    fn test_dedup_ttl_expiration() {
        // Very short TTL for test
        let dedup = MessageDeduplicator::new(100, Duration::from_millis(50));

        assert!(!dedup.is_duplicate("test-id"));
        assert!(dedup.is_duplicate("test-id"));

        // Sleep past TTL
        std::thread::sleep(Duration::from_millis(60));

        // Should have expired, so not duplicate anymore
        assert!(!dedup.is_duplicate("test-id"));
    }
}
