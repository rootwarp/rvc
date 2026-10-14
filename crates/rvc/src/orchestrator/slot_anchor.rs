//! One wall-clock read per slot, and absolute phase deadlines off that read.
//!
//! Lives in `rvc` rather than `timing`: `timing` is a Base-layer crate and must
//! not take a `tokio` dependency for [`tokio::time::Instant`].

use std::time::Duration;

use eth_types::Slot;
use timing::{due_ms, SlotClock};

/// Absolute phase deadlines for one slot.
///
/// `start` is the true slot start on the tokio clock: the wake instant minus
/// the captured offset into the slot. Every phase deadline is `start` plus a
/// basis-points offset, so a late phase does not push a later one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SlotAnchor {
    slot: Slot,
    start: tokio::time::Instant,
    /// Clamped offset observed at capture. Read via [`Self::offset_at_capture_ms`].
    #[allow(dead_code)]
    captured_into_slot_ms: u64,
    slot_duration_ms: u64,
}

impl SlotAnchor {
    /// Capture `slot` from a single [`SlotClock::ms_into_slot`] read.
    ///
    /// The offset is clamped to two slot durations, and `checked_sub` falls
    /// back to `Instant::now()` when that rewind cannot be represented. An NTP
    /// jump or a stalled loop must not panic.
    pub(crate) fn capture(clock: &dyn SlotClock, slot: Slot) -> Self {
        let slot_duration_ms =
            u64::try_from(clock.slot_duration().as_millis()).unwrap_or(u64::MAX / 2);
        let into = clock.ms_into_slot(slot).min(2 * slot_duration_ms);
        let start = anchored_start(tokio::time::Instant::now(), into);
        Self { slot, start, captured_into_slot_ms: into, slot_duration_ms }
    }

    pub(crate) fn slot(&self) -> Slot {
        self.slot
    }

    pub(crate) fn slot_duration_ms(&self) -> u64 {
        self.slot_duration_ms
    }

    /// Absolute tokio instant for `bps` into this slot. Does not read the clock.
    pub(crate) fn deadline(&self, bps: u64) -> tokio::time::Instant {
        self.start + Duration::from_millis(due_ms(bps, self.slot_duration_ms))
    }

    /// Absolute tokio instant of the end of this slot.
    pub(crate) fn slot_end(&self) -> tokio::time::Instant {
        self.start + Duration::from_millis(self.slot_duration_ms)
    }

    /// Milliseconds since the true slot start.
    pub(crate) fn elapsed_ms(&self) -> u64 {
        u64::try_from(tokio::time::Instant::now().saturating_duration_since(self.start).as_millis())
            .unwrap_or(u64::MAX)
    }

    /// Offset into the slot at [`Self::capture`], after the two-slot clamp.
    #[allow(dead_code)] // Read by the capture tests and by RR1-05's hand-off.
    pub(crate) fn offset_at_capture_ms(&self) -> u64 {
        self.captured_into_slot_ms
    }

    /// `true` when the wake is at or past [`Self::slot_end`].
    #[allow(dead_code)] // Slot-end budget (RR2-02) consumes this.
    pub(crate) fn woke_after_slot_end(&self) -> bool {
        tokio::time::Instant::now() >= self.slot_end()
    }
}

/// True slot start on the tokio clock.
///
/// `checked_sub` falls back to a fresh [`tokio::time::Instant::now`] when `into_ms`
/// reaches past the representable range (NTP jump / stalled loop must not panic).
fn anchored_start(now: tokio::time::Instant, into_ms: u64) -> tokio::time::Instant {
    now.checked_sub(Duration::from_millis(into_ms)).unwrap_or_else(tokio::time::Instant::now)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use timing::{MockSlotClock, SlotClock, TimingError};

    use super::*;

    const GENESIS: u64 = 1_606_824_023;

    /// Counts [`SlotClock::now_since_epoch`] so the anchor path can be shown
    /// to read the wall clock once.
    struct CountingClock {
        inner: MockSlotClock,
        reads: AtomicU64,
    }

    impl CountingClock {
        fn new(inner: MockSlotClock) -> Self {
            Self { inner, reads: AtomicU64::new(0) }
        }

        fn reads(&self) -> u64 {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl SlotClock for CountingClock {
        fn genesis_time(&self) -> u64 {
            self.inner.genesis_time()
        }

        fn slot_duration(&self) -> Duration {
            self.inner.slot_duration()
        }

        fn slots_per_epoch(&self) -> u64 {
            self.inner.slots_per_epoch()
        }

        fn now_since_epoch(&self) -> Duration {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.now_since_epoch()
        }

        fn current_slot(&self) -> Result<Slot, TimingError> {
            self.inner.current_slot()
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn capture_clamps_ms_into_slot_at_two_slot_durations_without_panic() {
        let clock = MockSlotClock::new(GENESIS, Duration::from_secs(12), 32);
        clock.set_slot_with_offset_ms(4, 100_000);
        let before = tokio::time::Instant::now();
        let anchor = SlotAnchor::capture(&clock, 4);
        assert_eq!(anchor.offset_at_capture_ms(), 24_000);
        assert_eq!(anchor.slot(), 4);
        let rewound = before.saturating_duration_since(anchor.start);
        assert_eq!(rewound, Duration::from_millis(24_000));
        assert_eq!(anchor.elapsed_ms(), 24_000);
        assert!(anchor.woke_after_slot_end());
        assert_eq!(anchor.slot_end(), anchor.start + Duration::from_millis(12_000));
    }

    /// `checked_sub` of a duration past the tokio clock's floor returns
    /// `Instant::now()` instead of panicking. Any `u64` millisecond offset still
    /// fits, so the floor is an instant walked to the bottom of the clock.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn capture_checked_sub_underflow_falls_back_to_now() {
        let floor = instant_floor(tokio::time::Instant::now());
        assert!(
            floor.checked_sub(Duration::from_nanos(1)).is_none(),
            "fixture must sit on the instant floor"
        );

        let before = tokio::time::Instant::now();
        let start = anchored_start(floor, 1);
        let after = tokio::time::Instant::now();
        assert!(
            start >= before && start <= after,
            "underflow must fall back to Instant::now(), not the unrepresentable rewind"
        );
        assert!(floor < before);

        // A far capture still completes. The clamp bounds the rewind; the same
        // fallback covers a rewind the clock cannot represent.
        let clock = MockSlotClock::new(0, Duration::from_millis(u64::MAX / 2), 32);
        clock.set_current_time_ms(u64::MAX);
        let anchor = SlotAnchor::capture(&clock, 0);
        assert_eq!(anchor.offset_at_capture_ms(), u64::MAX - 1);
    }

    fn instant_floor(now: tokio::time::Instant) -> tokio::time::Instant {
        let mut base = now;
        let mut step = Duration::from_secs(1 << 62);
        while step != Duration::ZERO {
            if let Some(earlier) = base.checked_sub(step) {
                base = earlier;
            } else {
                step /= 2;
            }
        }
        base
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn capture_reads_the_wall_clock_once_per_slot() {
        let inner = MockSlotClock::new(GENESIS, Duration::from_secs(12), 32);
        inner.set_slot_with_offset_ms(7, 600);
        let clock = CountingClock::new(inner);
        let anchor = SlotAnchor::capture(&clock, 7);
        assert_eq!(clock.reads(), 1, "capture takes one wall-clock read");
        let _ = anchor.deadline(3333);
        let _ = anchor.deadline(6667);
        let _ = anchor.slot_end();
        let _ = anchor.elapsed_ms();
        let _ = anchor.offset_at_capture_ms();
        let _ = anchor.woke_after_slot_end();
        assert_eq!(clock.reads(), 1, "deadlines stay on the captured anchor");
        assert_eq!(anchor.offset_at_capture_ms(), 600);
        assert_eq!(
            anchor.deadline(3333).saturating_duration_since(anchor.start),
            Duration::from_millis(3999)
        );
    }
}
