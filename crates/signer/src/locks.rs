//! Per-validator async lock map for serializing signing operations.
//!
//! Prevents TOCTOU races where two concurrent sign requests for the same
//! validator could both pass the slashing check before either records.
//! Different validators are NOT blocked by each other.
//!
//! The map is size-bounded (ARCH-P2-1 / ARCH-5n). Eviction is an internal
//! sweep of unheld entries — not a key-admission hook (C4).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::OwnedMutexGuard;
use tracing::warn;

/// Scale target from plan A-9. Default capacity is 4× this so a fully loaded
/// signing set plus key rotation is not evicted by transient churn.
const SUPPORTED_KEY_COUNT: usize = 200;

/// Map contents plus a one-shot overflow flag. Protected by a short-held
/// `parking_lot` mutex; never `.await` while this is held.
struct Inner {
    map: HashMap<[u8; 48], Arc<tokio::sync::Mutex<()>>>,
    overflow_warned: bool,
}

/// A map of per-pubkey async mutexes.
///
/// The outer map is protected by a short-held `parking_lot::Mutex` (sync,
/// non-async) used only to get-or-insert an `Arc<tokio::sync::Mutex<()>>`.
/// The per-pubkey async lock is then acquired with `lock_owned().await`,
/// which is `Send` and can be held across `.await` points.
///
/// This serializes concurrent signs for the **same** pubkey while allowing
/// different pubkeys to proceed in parallel.
///
/// Entries whose `Arc` is held only by the map (`strong_count == 1`) may be
/// evicted when a new key would exceed [`Self::DEFAULT_CAPACITY`]. Held
/// entries (`strong_count > 1`) are never evicted; if every entry is held the
/// map grows rather than blocking a sign.
pub struct ValidatorLockMap {
    locks: parking_lot::Mutex<Inner>,
    capacity: usize,
}

impl ValidatorLockMap {
    /// 4× the A-9 supported key count (200): hygiene bound, not a hard admission limit.
    pub const DEFAULT_CAPACITY: usize = SUPPORTED_KEY_COUNT * 4;

    /// Create a new, empty lock map with [`Self::DEFAULT_CAPACITY`].
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// Create an empty lock map with an explicit entry bound.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            locks: parking_lot::Mutex::new(Inner { map: HashMap::new(), overflow_warned: false }),
            capacity,
        }
    }

    /// Current number of cached per-pubkey locks (held and unheld).
    pub fn len(&self) -> usize {
        self.locks.lock().map.len()
    }

    /// `true` when no per-pubkey locks are cached.
    pub fn is_empty(&self) -> bool {
        self.locks.lock().map.is_empty()
    }

    /// Configured entry bound. The map may grow past this if every entry is held.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the `Arc<tokio::sync::Mutex<()>>` for a pubkey, inserting a new one
    /// if it does not yet exist.  The outer map lock is released before returning.
    pub fn get(&self, pubkey: &[u8; 48]) -> Arc<tokio::sync::Mutex<()>> {
        let mut inner = self.locks.lock();
        if let Some(existing) = inner.map.get(pubkey) {
            return existing.clone();
        }

        if inner.map.len() >= self.capacity {
            // Held iff a caller still owns an Arc (`strong_count > 1`; the map
            // holds one). Sync only — never `.await` under this lock.
            inner.map.retain(|_, lock| Arc::strong_count(lock) > 1);
            if inner.map.len() >= self.capacity {
                if !inner.overflow_warned {
                    warn!(
                        entries = inner.map.len(),
                        capacity = self.capacity,
                        "ValidatorLockMap grew past capacity because every entry is held; not blocking the sign"
                    );
                    inner.overflow_warned = true;
                }
            } else {
                inner.overflow_warned = false;
            }
        }

        let lock = Arc::new(tokio::sync::Mutex::new(()));
        inner.map.insert(*pubkey, lock.clone());
        lock
    }

    /// Acquire the per-pubkey async lock, returning an `OwnedMutexGuard` that
    /// is `Send` and can be held across `.await` points.
    ///
    /// The outer map lock is held only briefly during the get-or-insert; the
    /// async lock acquisition happens after it is released.
    pub async fn lock(&self, pubkey: &[u8; 48]) -> OwnedMutexGuard<()> {
        self.get(pubkey).lock_owned().await
    }
}

impl Default for ValidatorLockMap {
    fn default() -> Self {
        Self::new()
    }
}
