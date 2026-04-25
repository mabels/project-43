use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Semaphore;

// ── CardQueue ─────────────────────────────────────────────────────────────────

/// Serialising queue for hardware-card (YubiKey) operations.
///
/// A YubiKey can only handle one PC/SC command at a time.  When multiple
/// callers race to sign concurrently (e.g. `git rebase --exec` with GPG
/// auto-signing, or many parallel SSH clients), sending them all straight to
/// the card causes failures and hangs.  `CardQueue` wraps a [`Semaphore`] so
/// that at most `concurrency` blocking card operations run simultaneously —
/// the rest wait in an async queue until a slot is free.
///
/// For a single YubiKey set `concurrency = 1` (the default via
/// `--concurrency`).  Raise it only if you have multiple cards that can be
/// addressed independently.
#[derive(Clone)]
pub struct CardQueue {
    semaphore: Arc<Semaphore>,
}

impl CardQueue {
    /// Create a new queue that allows at most `concurrency` parallel card
    /// operations.
    pub fn new(concurrency: usize) -> Self {
        assert!(concurrency > 0, "concurrency must be at least 1");
        Self {
            semaphore: Arc::new(Semaphore::new(concurrency)),
        }
    }

    /// Run `op` on a blocking thread-pool thread, waiting for a queue slot
    /// first.  The closure receives exclusive access to the card hardware for
    /// the duration of the call.
    pub async fn run<F, T>(&self, op: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| anyhow::anyhow!("Card queue closed unexpectedly: {e}"))?;

        tokio::task::spawn_blocking(op)
            .await
            .map_err(|e| anyhow::anyhow!("Card operation panicked: {e}"))?
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn concurrency_one_serialises_ops() {
        let queue = CardQueue::new(1);
        let inflight = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let q = queue.clone();
            let c = Arc::clone(&inflight);
            handles.push(tokio::spawn(async move {
                q.run(move || {
                    let prev = c.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(prev, 0, "more than one op ran concurrently");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    c.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, anyhow::Error>(())
                })
                .await
            }));
        }

        for handle in handles {
            handle.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn errors_propagate() {
        let queue = CardQueue::new(1);
        let result = queue
            .run(|| anyhow::bail!("card exploded") as anyhow::Result<()>)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("card exploded"));
    }
}
