//! Monotonic epoch clock (M-7 / SEC-2b).
//!
//! Anchors epoch math on a monotonic [`Instant`] captured at construction so
//! NTP wall-clock steps cannot compress or skip the doppelganger window.
//! Shared by boot `register` and keymanager import `register_for_import`.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eth_types::{Epoch, SLOTS_PER_EPOCH};

/// Epoch provider immune to post-start NTP steps.
///
/// ```text
/// now_unix_ms    = start_unix_time_ms + elapsed milliseconds
/// current_slot   = (now_unix_ms - genesis_time * 1000) / slot_duration_ms
/// current_epoch  = current_slot / SLOTS_PER_EPOCH
/// ```
///
/// `slot_duration_ms` is the beacon node's resolved slot length. A zero
/// duration does not yield epoch 0: that epoch is the pre-genesis signing
/// bypass. If the clock is before `genesis_time`, slot math saturates to 0.
/// That is not a counted epoch. [`Self::allow_epoch0_bypass`] stays false
/// until the clock reaches genesis, so boot registration does not mark keys
/// Safe. API import uses [`crate::ForwardWindowMachine::register_for_import`]
/// and never takes the bypass.
#[derive(Debug, Clone)]
pub struct MonotonicEpochClock {
    genesis_time: u64,
    start_instant: Instant,
    /// Unix time at `start_instant`, in milliseconds.
    start_unix_time_ms: u64,
    slot_duration_ms: u64,
}

impl MonotonicEpochClock {
    /// Capture the current wall clock once and freeze the monotonic base.
    ///
    /// `slot_duration_ms` is the value resolved from the beacon node spec.
    pub fn new(genesis_time: u64, slot_duration_ms: u64) -> Self {
        let start_unix_time_ms = u64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
        )
        .unwrap_or(u64::MAX);
        let start_unix_time = start_unix_time_ms / 1000;
        let one_epoch_secs = slot_duration_ms.saturating_mul(SLOTS_PER_EPOCH) / 1000;
        if genesis_time > start_unix_time.saturating_add(one_epoch_secs) {
            // Genesis more than one epoch in the future → every call yields 0
            // until wall time catches up. Import path must use register_for_import.
            tracing::warn!(
                genesis_time,
                start_unix_time,
                slot_duration_ms,
                "MonotonicEpochClock: genesis_time is in the future; epoch will stay 0 \
                 until genesis (import path must not treat that as Safe)"
            );
        }
        Self { genesis_time, start_instant: Instant::now(), start_unix_time_ms, slot_duration_ms }
    }

    /// Test/helper constructor with explicit anchors, in whole seconds.
    ///
    /// Production paths use [`Self::new`]; tests use this to drive
    /// deterministic epoch values. Sub-second anchors use
    /// [`Self::with_start_time_ms`].
    pub fn with_start_time(
        genesis_time: u64,
        start_instant: Instant,
        start_unix_time: u64,
        slot_duration_ms: u64,
    ) -> Self {
        Self::with_start_time_ms(
            genesis_time,
            start_instant,
            start_unix_time.saturating_mul(1000),
            slot_duration_ms,
        )
    }

    /// Test/helper constructor. `start_unix_time_ms` is milliseconds since
    /// the Unix epoch.
    pub fn with_start_time_ms(
        genesis_time: u64,
        start_instant: Instant,
        start_unix_time_ms: u64,
        slot_duration_ms: u64,
    ) -> Self {
        Self { genesis_time, start_instant, start_unix_time_ms, slot_duration_ms }
    }

    /// Beacon-node slot length in milliseconds used by this clock.
    pub fn slot_duration_ms(&self) -> u64 {
        self.slot_duration_ms
    }

    /// `true` when this clock's anchored unix time is still before genesis.
    ///
    /// Slot math then saturates to epoch 0. That epoch has not started, so it
    /// must not count and must not take the epoch-0 Safe bypass.
    pub fn before_genesis(&self) -> bool {
        self.now_unix_ms() < self.genesis_time.saturating_mul(1000)
    }

    /// Epoch-0 Safe bypass for a named network whose clock has reached genesis.
    ///
    /// A custom network stays closed. A clock reading before genesis stays
    /// closed even on a named network: no epoch has been counted yet.
    pub fn allow_epoch0_bypass(named_network: bool, now_unix: u64, genesis_time: u64) -> bool {
        named_network && now_unix >= genesis_time
    }

    fn now_unix_ms(&self) -> u64 {
        let elapsed_ms =
            u64::try_from(self.start_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.start_unix_time_ms.saturating_add(elapsed_ms)
    }

    /// Current epoch from the monotonic clock.
    ///
    /// Before genesis this is 0 only because subtraction saturates. Callers
    /// that register boot keys must consult [`Self::before_genesis`] or
    /// [`Self::allow_epoch0_bypass`] before treating that 0 as the Safe bypass.
    pub fn current_epoch(&self) -> Epoch {
        self.current_slot() / SLOTS_PER_EPOCH
    }

    /// Current slot from the monotonic clock (SEC-2c liveness loop).
    ///
    /// A zero `slot_duration_ms` returns [`u64::MAX`] so the result is not
    /// epoch 0. Epoch 0 would take the pre-genesis signing bypass.
    pub fn current_slot(&self) -> u64 {
        // Out of range (zero or huge) must not become slot 0 / epoch 0.
        if !(eth_types::MIN_SLOT_DURATION_MS..=eth_types::MAX_SLOT_DURATION_MS)
            .contains(&self.slot_duration_ms)
        {
            return u64::MAX;
        }
        let now_ms = self.now_unix_ms();
        let genesis_ms = self.genesis_time.saturating_mul(1000);
        // Before genesis this saturates to 0. That is not slot 0 of epoch 0;
        // `before_genesis` is how boot refuses the Safe bypass.
        let elapsed_ms = now_ms.saturating_sub(genesis_ms);
        elapsed_ms.checked_div(self.slot_duration_ms).unwrap_or(u64::MAX)
    }

    /// Slot index within the current epoch (`0..SLOTS_PER_EPOCH`).
    pub fn slot_in_epoch(&self) -> u64 {
        self.current_slot() % SLOTS_PER_EPOCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn clock_before_genesis_is_not_a_counted_epoch() {
        let genesis = 1_700_000_000u64;
        let clock = MonotonicEpochClock::with_start_time(
            genesis,
            Instant::now(),
            genesis.saturating_sub(10_000),
            12_000,
        );
        assert!(clock.before_genesis());
        assert_eq!(clock.current_epoch(), 0);
        assert_eq!(clock.current_slot(), 0);
        assert!(!MonotonicEpochClock::allow_epoch0_bypass(true, genesis - 1, genesis));
        assert!(!MonotonicEpochClock::allow_epoch0_bypass(false, genesis, genesis));
    }

    #[test]
    fn at_genesis_epoch_zero_may_bypass_on_a_named_network() {
        let genesis = 1_700_000_000u64;
        let clock = MonotonicEpochClock::with_start_time(genesis, Instant::now(), genesis, 12_000);
        assert!(!clock.before_genesis());
        assert_eq!(clock.current_epoch(), 0);
        assert!(MonotonicEpochClock::allow_epoch0_bypass(true, genesis, genesis));
        assert!(!MonotonicEpochClock::allow_epoch0_bypass(false, genesis, genesis));
    }
}
