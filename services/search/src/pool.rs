// CSP actor pool.
//
// Spawns N independent worker tasks at construction time. Each worker owns its
// own resources (HTTP client, connection pool) and receives commands through a
// dedicated bounded mpsc channel. No state is shared between workers.
//
// Dispatch is lock-free: an AtomicUsize selects the target worker via
// round-robin, and the async `send` provides natural backpressure if every
// worker is at capacity.

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

pub const CHANNEL_CAP: usize = 128;

pub struct Pool<T: Send + 'static> {
    senders: Box<[mpsc::Sender<T>]>,
    next:    AtomicUsize,
}

#[derive(Debug)]
pub enum PoolError {
    /// All workers have exited (channel closed). Signals a fatal runtime error.
    Shutdown,
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("worker pool has shut down")
    }
}

impl std::error::Error for PoolError {}

impl<T: Send + 'static> Pool<T> {
    /// Build a pool from a pre-created list of senders.
    ///
    /// Callers are responsible for spawning one worker task per sender before
    /// constructing the pool (the receivers are passed to those tasks).
    pub fn from_senders(senders: Vec<mpsc::Sender<T>>) -> Self {
        assert!(!senders.is_empty(), "pool must have at least one worker");
        Self {
            senders: senders.into_boxed_slice(),
            next:    AtomicUsize::new(0),
        }
    }

    /// Send `cmd` to the next worker via lock-free round-robin.
    ///
    /// Yields to the Tokio executor while the target channel is full (natural
    /// backpressure). Returns `Err(PoolError::Shutdown)` only if the worker
    /// has permanently exited.
    pub async fn dispatch(&self, cmd: T) -> Result<(), PoolError> {
        let n   = self.senders.len();
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % n;
        self.senders[idx]
            .send(cmd)
            .await
            .map_err(|_| PoolError::Shutdown)
    }

    pub fn worker_count(&self) -> usize {
        self.senders.len()
    }
}
