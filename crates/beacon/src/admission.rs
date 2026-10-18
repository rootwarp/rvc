//! Duty fence: the revocation generation at duty start or chain-data capture.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Generation observed when a duty started or chain data was captured.
#[derive(Clone, Debug)]
pub struct DutyFence {
    seen: u64,
    current: Option<Arc<AtomicU64>>,
}

impl DutyFence {
    pub fn open() -> Self {
        Self { seen: 0, current: None }
    }

    pub fn closed() -> Self {
        Self { seen: 0, current: Some(Arc::new(AtomicU64::new(1))) }
    }

    pub fn at(seen: u64, current: Arc<AtomicU64>) -> Self {
        Self { seen, current: Some(current) }
    }

    pub fn holds(&self) -> bool {
        self.current.as_ref().is_none_or(|current| current.load(Ordering::Acquire) == self.seen)
    }

    pub fn seen(&self) -> u64 {
        self.seen
    }

    pub fn generation(&self) -> Option<Arc<AtomicU64>> {
        self.current.clone()
    }
}
