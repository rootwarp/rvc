//! Monotonic epoch clock (M-7 / SEC-2b).
//!
//! Anchors epoch math on a monotonic [`Instant`] captured at construction so
//! NTP wall-clock steps cannot compress or skip the doppelganger window.
//! Shared by boot `register` and keymanager import `register_for_import`.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eth_types::{Epoch, SLOTS_PER_EPOCH, SLOT_DURATION_MS};

/// Epoch provider immune to post-start NTP steps.
///
/// ```text
/// now_unix       = start_unix_time + start_instant.elapsed()
/// current_epoch  = (now_unix - genesis_time) * 1000 / SLOT_DURATION_MS / SLOTS_PER_EPOCH
/// ```
///
/// If `genesis_time` is far in the future relative to process start, epoch
/// computation saturates to 0. Callers that must not apply the pre-genesis
/// Safe bypass (API import) should use [`crate::ForwardWindowMachine::register_for_import`]
/// rather than trusting epoch 0 as "safe to sign".
#[derive(Debug, Clone)]
pub struct MonotonicEpochClock {
    genesis_time: u64,
    start_instant: Instant,
    start_unix_time: u64,
}

impl MonotonicEpochClock {
    /// Capture the current wall clock once and freeze the monotonic base.
    pub fn new(genesis_time: u64) -> Self {
        let start_unix_time =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if genesis_time
            > start_unix_time
                .saturating_add(SLOT_DURATION_MS.saturating_mul(SLOTS_PER_EPOCH) / 1000)
        {
            // Genesis more than one epoch in the future → every call yields 0
            // until wall time catches up. Import path must use register_for_import.
            tracing::warn!(
                genesis_time,
                start_unix_time,
                "MonotonicEpochClock: genesis_time is in the future; epoch will stay 0 \
                 until genesis (import path must not treat that as Safe)"
            );
        }
        Self { genesis_time, start_instant: Instant::now(), start_unix_time }
    }

    /// Test/helper constructor with explicit anchors.
    ///
    /// Production paths use [`Self::new`]; tests use this to drive
    /// deterministic epoch values.
    pub fn with_start_time(
        genesis_time: u64,
        start_instant: Instant,
        start_unix_time: u64,
    ) -> Self {
        Self { genesis_time, start_instant, start_unix_time }
    }

    /// Current epoch from the monotonic clock.
    pub fn current_epoch(&self) -> Epoch {
        self.current_slot() / SLOTS_PER_EPOCH
    }

    /// Current slot from the monotonic clock (SEC-2c liveness loop).
    pub fn current_slot(&self) -> u64 {
        let elapsed_secs = self.start_instant.elapsed().as_secs();
        let now_unix = self.start_unix_time.saturating_add(elapsed_secs);
        let secs_since_genesis = now_unix.saturating_sub(self.genesis_time);
        secs_since_genesis.saturating_mul(1000) / SLOT_DURATION_MS
    }

    /// Slot index within the current epoch (`0..SLOTS_PER_EPOCH`).
    pub fn slot_in_epoch(&self) -> u64 {
        self.current_slot() % SLOTS_PER_EPOCH
    }

    pub fn genesis_time(&self) -> u64 {
        self.genesis_time
    }
}
