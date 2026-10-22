//! Duty fence: the revocation generation at duty start or chain-data capture.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// One revocation generation captured with the value it must keep.
#[derive(Clone, Debug)]
struct WatchedGeneration {
    seen: u64,
    current: Arc<AtomicU64>,
}

/// Generation observed when a duty started or chain data was captured.
///
/// [`Self::and_fence`] keeps every generation from both fences. [`Self::holds`]
/// is false when any of them has moved. Block production uses that for the
/// main pool and the proposer pool together.
#[derive(Clone, Debug)]
pub struct DutyFence {
    watches: Vec<WatchedGeneration>,
}

impl DutyFence {
    pub fn open() -> Self {
        Self { watches: Vec::new() }
    }

    pub fn closed() -> Self {
        Self { watches: vec![WatchedGeneration { seen: 0, current: Arc::new(AtomicU64::new(1)) }] }
    }

    pub fn at(seen: u64, current: Arc<AtomicU64>) -> Self {
        Self { watches: vec![WatchedGeneration { seen, current }] }
    }

    /// Hold only while every generation on this fence and `other` still matches.
    pub fn and_fence(mut self, other: Self) -> Self {
        self.watches.extend(other.watches);
        self
    }

    pub fn holds(&self) -> bool {
        self.watches.iter().all(|watch| watch.current.load(Ordering::Acquire) == watch.seen)
    }

    pub fn seen(&self) -> u64 {
        self.watches.first().map(|watch| watch.seen).unwrap_or(0)
    }

    pub fn also_seen(&self) -> u64 {
        self.watches.get(1).map(|watch| watch.seen).unwrap_or(0)
    }

    pub fn generation(&self) -> Option<Arc<AtomicU64>> {
        self.watches.first().map(|watch| Arc::clone(&watch.current))
    }

    pub fn also_generation(&self) -> Option<Arc<AtomicU64>> {
        self.watches.get(1).map(|watch| Arc::clone(&watch.current))
    }

    /// Every generation, in the order [`Self::and_fence`] attached them.
    pub fn generations(&self) -> impl Iterator<Item = (u64, Arc<AtomicU64>)> + '_ {
        self.watches.iter().map(|watch| (watch.seen, Arc::clone(&watch.current)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_fence_fails_when_either_generation_moves() {
        let primary = Arc::new(AtomicU64::new(1));
        let extra = Arc::new(AtomicU64::new(4));
        let fence =
            DutyFence::at(1, Arc::clone(&primary)).and_fence(DutyFence::at(4, Arc::clone(&extra)));
        assert!(fence.holds());
        extra.fetch_add(1, Ordering::Release);
        assert!(!fence.holds(), "the second pool's revocation must drop the fence");
        extra.fetch_sub(1, Ordering::Release);
        assert!(fence.holds());
        primary.fetch_add(1, Ordering::Release);
        assert!(!fence.holds(), "the first pool's revocation must drop the fence");
    }

    #[test]
    fn and_fence_keeps_a_generation_already_attached() {
        let primary = Arc::new(AtomicU64::new(1));
        let extra = Arc::new(AtomicU64::new(2));
        let third = Arc::new(AtomicU64::new(3));
        let nested =
            DutyFence::at(2, Arc::clone(&extra)).and_fence(DutyFence::at(3, Arc::clone(&third)));
        let fence = DutyFence::at(1, Arc::clone(&primary)).and_fence(nested);
        assert!(fence.holds());
        third.fetch_add(1, Ordering::Release);
        assert!(!fence.holds(), "combining must keep a generation that was already attached");
    }
}
