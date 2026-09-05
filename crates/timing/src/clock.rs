//! Slot clock implementations for Ethereum consensus timing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eth_types::Slot;

use crate::error::TimingError;
use crate::{due_ms, DeadlineBps, SLOTS_PER_EPOCH, SLOT_DURATION_MS};

/// Slot timing source.
///
/// Required methods are the primitives every implementation must supply.
/// All other methods have default bodies derived from those primitives so
/// `SystemSlotClock` and `MockSlotClock` cannot drift on shared slot math.
pub trait SlotClock: Send + Sync {
    fn genesis_time(&self) -> u64;
    fn slot_duration(&self) -> Duration;
    fn slots_per_epoch(&self) -> u64;
    fn current_time_secs(&self) -> u64;
    fn current_slot(&self) -> Result<Slot, TimingError>;

    fn deadlines(&self) -> DeadlineBps {
        DeadlineBps::default()
    }

    fn slot_start_time(&self, slot: Slot) -> u64 {
        self.genesis_time() + (slot * self.slot_duration().as_secs())
    }

    fn slot_end_time(&self, slot: Slot) -> u64 {
        self.slot_start_time(slot + 1)
    }

    fn attestation_time(&self, slot: Slot) -> u64 {
        let slot_start_ms = self.slot_start_time(slot) * 1000;
        let slot_duration_ms = self.slot_duration().as_millis() as u64;
        (slot_start_ms + due_ms(self.deadlines().attestation, slot_duration_ms)) / 1000
    }

    fn time_until_slot(&self, slot: Slot) -> Result<Duration, TimingError> {
        let current_time = self.current_time_secs();
        let slot_start = self.slot_start_time(slot);

        if current_time >= slot_start {
            return Ok(Duration::ZERO);
        }

        Ok(Duration::from_secs(slot_start - current_time))
    }

    fn time_until_attestation(&self, slot: Slot) -> Result<Duration, TimingError> {
        // Basis-points formula in millisecond arithmetic so the deadline is exact
        // for non-standard slot durations (e.g. 6 s testnets where 1/3 = 2.000 s
        // exactly, but a 7 s slot would be truncated from 2.333 s to 2 s under
        // integer-second division — firing up to ~333 ms early). Mainnet is
        // 3333 * 12000 / 10000 = 3999 ms (report §4.3).
        //
        // Sub-second wall-clock precision is intentionally not required: both
        // impls share this body via `current_time_secs`.
        let current_time_ms = self.current_time_secs() * 1000;
        let slot_start_ms = self.slot_start_time(slot) * 1000;
        let slot_duration_ms = self.slot_duration().as_millis() as u64;
        let attestation_time_ms =
            slot_start_ms + due_ms(self.deadlines().attestation, slot_duration_ms);

        if current_time_ms >= attestation_time_ms {
            return Ok(Duration::ZERO);
        }

        Ok(Duration::from_millis(attestation_time_ms - current_time_ms))
    }

    fn slot_to_epoch(&self, slot: Slot) -> u64 {
        slot / self.slots_per_epoch()
    }

    fn epoch_start_slot(&self, epoch: u64) -> Slot {
        epoch * self.slots_per_epoch()
    }
}

pub struct SystemSlotClock {
    genesis_time: u64,
    slot_duration: Duration,
    slots_per_epoch: u64,
    deadlines: DeadlineBps,
}

impl SystemSlotClock {
    pub fn new(
        genesis_time: u64,
        slot_duration: Duration,
        slots_per_epoch: u64,
    ) -> Result<Self, TimingError> {
        if slot_duration.as_secs() < 1 {
            return Err(TimingError::InvalidSlotDuration);
        }
        tracing::debug!(
            genesis_time,
            slot_duration_secs = slot_duration.as_secs(),
            slots_per_epoch,
            "clock created"
        );
        Ok(Self { genesis_time, slot_duration, slots_per_epoch, deadlines: DeadlineBps::default() })
    }

    pub fn with_deadlines(mut self, deadlines: DeadlineBps) -> Self {
        self.deadlines = deadlines;
        self
    }

    pub fn new_mainnet(genesis_time: u64) -> Result<Self, TimingError> {
        Self::new(genesis_time, Duration::from_millis(SLOT_DURATION_MS), SLOTS_PER_EPOCH)
    }

    fn current_unix_time(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards").as_secs()
    }
}

impl SlotClock for SystemSlotClock {
    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    fn deadlines(&self) -> DeadlineBps {
        self.deadlines
    }

    fn current_time_secs(&self) -> u64 {
        self.current_unix_time()
    }

    fn current_slot(&self) -> Result<Slot, TimingError> {
        let current_time = self.current_unix_time();
        if current_time < self.genesis_time {
            return Err(TimingError::BeforeGenesis {
                current_time,
                genesis_time: self.genesis_time,
            });
        }
        let seconds_since_genesis = current_time - self.genesis_time;
        let slot_duration_secs = self.slot_duration.as_secs();
        let slot = seconds_since_genesis / slot_duration_secs;
        let epoch = slot / self.slots_per_epoch;
        let time_into_slot_ms = (seconds_since_genesis % slot_duration_secs) * 1000;
        tracing::trace!(slot, epoch, time_into_slot_ms, "slot transition");
        Ok(slot)
    }
}

pub struct MockSlotClock {
    genesis_time: u64,
    slot_duration: Duration,
    slots_per_epoch: u64,
    current_time: std::sync::atomic::AtomicU64,
    deadlines: DeadlineBps,
}

impl MockSlotClock {
    pub fn new(genesis_time: u64, slot_duration: Duration, slots_per_epoch: u64) -> Self {
        Self {
            genesis_time,
            slot_duration,
            slots_per_epoch,
            current_time: std::sync::atomic::AtomicU64::new(genesis_time),
            deadlines: DeadlineBps::default(),
        }
    }

    pub fn with_deadlines(mut self, deadlines: DeadlineBps) -> Self {
        self.deadlines = deadlines;
        self
    }

    pub fn set_current_time(&self, time: u64) {
        self.current_time.store(time, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn advance_time(&self, seconds: u64) {
        self.current_time.fetch_add(seconds, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_slot(&self, slot: Slot) {
        let slot_start = self.genesis_time + (slot * self.slot_duration.as_secs());
        self.set_current_time(slot_start);
    }

    fn get_current_time(&self) -> u64 {
        self.current_time.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SlotClock for MockSlotClock {
    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    fn deadlines(&self) -> DeadlineBps {
        self.deadlines
    }

    fn current_time_secs(&self) -> u64 {
        self.get_current_time()
    }

    fn current_slot(&self) -> Result<Slot, TimingError> {
        let current_time = self.get_current_time();
        if current_time < self.genesis_time {
            return Err(TimingError::BeforeGenesis {
                current_time,
                genesis_time: self.genesis_time,
            });
        }
        let seconds_since_genesis = current_time - self.genesis_time;
        Ok(seconds_since_genesis / self.slot_duration.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GENESIS_TIME: u64 = 1606824023; // Mainnet genesis

    fn create_mock_clock() -> MockSlotClock {
        MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32)
    }

    #[test]
    fn test_slot_clock_genesis_time() {
        let clock = create_mock_clock();
        assert_eq!(clock.genesis_time(), TEST_GENESIS_TIME);
    }

    #[test]
    fn test_slot_clock_slot_duration() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_duration(), Duration::from_secs(12));
    }

    #[test]
    fn test_current_slot_at_genesis() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        assert_eq!(clock.current_slot().unwrap(), 0);
    }

    #[test]
    fn test_current_slot_after_one_slot() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 12);
        assert_eq!(clock.current_slot().unwrap(), 1);
    }

    #[test]
    fn test_current_slot_mid_slot() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 6);
        assert_eq!(clock.current_slot().unwrap(), 0);
    }

    #[test]
    fn test_current_slot_multiple_slots() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + (100 * 12));
        assert_eq!(clock.current_slot().unwrap(), 100);
    }

    #[test]
    fn test_current_slot_before_genesis() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME - 100);
        let result = clock.current_slot();
        assert!(matches!(result, Err(TimingError::BeforeGenesis { .. })));
    }

    #[test]
    fn test_slot_start_time() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_start_time(0), TEST_GENESIS_TIME);
        assert_eq!(clock.slot_start_time(1), TEST_GENESIS_TIME + 12);
        assert_eq!(clock.slot_start_time(100), TEST_GENESIS_TIME + 1200);
    }

    #[test]
    fn test_slot_end_time() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_end_time(0), TEST_GENESIS_TIME + 12);
        assert_eq!(clock.slot_end_time(1), TEST_GENESIS_TIME + 24);
    }

    #[test]
    fn test_attestation_time() {
        let clock = create_mock_clock();
        // Seconds API floors (slot_start_ms + due_ms) / 1000. For a 12 s slot,
        // due_ms = 3333 * 12000 / 10000 = 3999, so (0 + 3999) / 1000 = genesis + 3
        // and ((12)*1000 + 3999) / 1000 = genesis + 15 (down from +4 / +16).
        assert_eq!(clock.attestation_time(0), TEST_GENESIS_TIME + 3);
        assert_eq!(clock.attestation_time(1), TEST_GENESIS_TIME + 15);
    }

    #[test]
    fn test_time_until_slot_in_future() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        let time_until = clock.time_until_slot(10).unwrap();
        assert_eq!(time_until, Duration::from_secs(120));
    }

    #[test]
    fn test_time_until_slot_already_started() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 100);
        let time_until = clock.time_until_slot(5).unwrap();
        assert_eq!(time_until, Duration::ZERO);
    }

    #[test]
    fn test_time_until_attestation_in_future() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        let time_until = clock.time_until_attestation(0).unwrap();
        // BPS: 3333 * 12000 / 10000 = 3999 ms (down from the legacy 4 s).
        assert_eq!(time_until, Duration::from_millis(3999));
    }

    #[test]
    fn test_time_until_attestation_already_passed() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 10);
        let time_until = clock.time_until_attestation(0).unwrap();
        assert_eq!(time_until, Duration::ZERO);
    }

    #[test]
    fn test_slot_to_epoch() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_to_epoch(0), 0);
        assert_eq!(clock.slot_to_epoch(31), 0);
        assert_eq!(clock.slot_to_epoch(32), 1);
        assert_eq!(clock.slot_to_epoch(64), 2);
        assert_eq!(clock.slot_to_epoch(100), 3);
    }

    #[test]
    fn test_epoch_start_slot() {
        let clock = create_mock_clock();
        assert_eq!(clock.epoch_start_slot(0), 0);
        assert_eq!(clock.epoch_start_slot(1), 32);
        assert_eq!(clock.epoch_start_slot(2), 64);
        assert_eq!(clock.epoch_start_slot(10), 320);
    }

    #[test]
    fn test_mock_clock_set_slot() {
        let clock = create_mock_clock();
        clock.set_slot(50);
        assert_eq!(clock.current_slot().unwrap(), 50);
    }

    #[test]
    fn test_mock_clock_advance_time() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        assert_eq!(clock.current_slot().unwrap(), 0);
        clock.advance_time(12);
        assert_eq!(clock.current_slot().unwrap(), 1);
        clock.advance_time(24);
        assert_eq!(clock.current_slot().unwrap(), 3);
    }

    #[test]
    fn test_system_slot_clock_new_mainnet() {
        let clock = SystemSlotClock::new_mainnet(TEST_GENESIS_TIME).unwrap();
        assert_eq!(clock.genesis_time(), TEST_GENESIS_TIME);
        assert_eq!(clock.slot_duration(), Duration::from_secs(12));
        assert_eq!(clock.slots_per_epoch(), 32);
    }

    #[test]
    fn test_system_slot_clock_zero_duration_returns_error() {
        let result = SystemSlotClock::new(TEST_GENESIS_TIME, Duration::ZERO, 32);
        assert!(matches!(result, Err(TimingError::InvalidSlotDuration)));
    }

    #[test]
    fn test_system_slot_clock_valid_duration_succeeds() {
        let result = SystemSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32);
        assert!(result.is_ok());
    }

    #[test]
    fn test_current_time_secs_returns_mock_time() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 42);
        assert_eq!(clock.current_time_secs(), TEST_GENESIS_TIME + 42);
    }

    #[test]
    fn test_system_slot_clock_sub_second_duration_returns_error() {
        let result = SystemSlotClock::new(TEST_GENESIS_TIME, Duration::from_millis(500), 32);
        assert!(matches!(result, Err(TimingError::InvalidSlotDuration)));
    }

    /// Table-driven: pure derived methods must agree for System and Mock clocks
    /// configured with the same genesis / duration / slots_per_epoch.
    #[test]
    fn test_system_and_mock_clocks_agree_on_all_derived_methods() {
        let system = SystemSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32).unwrap();
        let mock = MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32);

        let slots: &[Slot] = &[0, 1, 31, 32, 100, 320];
        let epochs: &[u64] = &[0, 1, 2, 10];

        for &slot in slots {
            assert_eq!(
                system.slot_start_time(slot),
                mock.slot_start_time(slot),
                "slot_start_time({slot})"
            );
            assert_eq!(
                system.slot_end_time(slot),
                mock.slot_end_time(slot),
                "slot_end_time({slot})"
            );
            assert_eq!(
                system.attestation_time(slot),
                mock.attestation_time(slot),
                "attestation_time({slot})"
            );
            assert_eq!(
                system.slot_to_epoch(slot),
                mock.slot_to_epoch(slot),
                "slot_to_epoch({slot})"
            );
        }

        for &epoch in epochs {
            assert_eq!(
                system.epoch_start_slot(epoch),
                mock.epoch_start_slot(epoch),
                "epoch_start_slot({epoch})"
            );
        }

        // Time-dependent defaults: pin mock to a known "now" and assert both
        // clocks' pure inputs plus mock's time_until_* match the shared formulas.
        // System wall-clock time_until_* cannot be frozen; agreement is proven
        // via the pure methods above + the minimal-impl test below.
        mock.set_current_time(TEST_GENESIS_TIME);
        assert_eq!(mock.time_until_slot(10).unwrap(), Duration::from_secs(120));
        assert_eq!(mock.time_until_attestation(0).unwrap(), Duration::from_millis(3999));

        mock.set_current_time(TEST_GENESIS_TIME + 200);
        assert_eq!(mock.time_until_slot(5).unwrap(), Duration::ZERO);
        assert_eq!(mock.time_until_attestation(0).unwrap(), Duration::ZERO);
    }

    /// A clock that only implements the required primitives must still get
    /// correct derived results from the trait defaults.
    #[test]
    fn test_default_methods_used_when_impl_omits_them() {
        struct MinimalClock {
            genesis: u64,
            slot_secs: u64,
            spe: u64,
            now: u64,
        }

        impl SlotClock for MinimalClock {
            fn genesis_time(&self) -> u64 {
                self.genesis
            }

            fn slot_duration(&self) -> Duration {
                Duration::from_secs(self.slot_secs)
            }

            fn slots_per_epoch(&self) -> u64 {
                self.spe
            }

            fn current_time_secs(&self) -> u64 {
                self.now
            }

            fn current_slot(&self) -> Result<Slot, TimingError> {
                let t = self.now;
                if t < self.genesis {
                    return Err(TimingError::BeforeGenesis {
                        current_time: t,
                        genesis_time: self.genesis,
                    });
                }
                Ok((t - self.genesis) / self.slot_secs)
            }
        }

        let clock = MinimalClock {
            genesis: TEST_GENESIS_TIME,
            slot_secs: 12,
            spe: 32,
            now: TEST_GENESIS_TIME,
        };

        assert_eq!(clock.slot_start_time(0), TEST_GENESIS_TIME);
        assert_eq!(clock.slot_start_time(1), TEST_GENESIS_TIME + 12);
        assert_eq!(clock.slot_end_time(0), TEST_GENESIS_TIME + 12);
        assert_eq!(clock.attestation_time(0), TEST_GENESIS_TIME + 3);
        assert_eq!(clock.time_until_slot(10).unwrap(), Duration::from_secs(120));
        assert_eq!(clock.time_until_attestation(0).unwrap(), Duration::from_millis(3999));
        assert_eq!(clock.slot_to_epoch(32), 1);
        assert_eq!(clock.epoch_start_slot(2), 64);

        // Non-12 s slot: 7 s → due_ms(3333, 7000) = 2333 ms
        let clock7 = MinimalClock {
            genesis: TEST_GENESIS_TIME,
            slot_secs: 7,
            spe: 32,
            now: TEST_GENESIS_TIME,
        };
        assert_eq!(clock7.time_until_attestation(0).unwrap(), Duration::from_millis(2333));
    }

    #[test]
    fn test_deadlines_default_matches_pre_gloas_bps() {
        let mock = create_mock_clock();
        let system = SystemSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32).unwrap();
        assert_eq!(mock.deadlines(), DeadlineBps::default());
        assert_eq!(system.deadlines(), DeadlineBps::default());
        assert_eq!(mock.deadlines().attestation, crate::ATTESTATION_DUE_BPS);
        assert_eq!(mock.deadlines().aggregate, crate::AGGREGATE_DUE_BPS);
    }

    #[test]
    fn test_with_deadlines_2500_bps_12s_is_3000ms() {
        let clock = MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32)
            .with_deadlines(DeadlineBps { attestation: 2500, aggregate: 6667 });
        clock.set_current_time(TEST_GENESIS_TIME);
        assert_eq!(clock.deadlines().attestation, 2500);
        assert_eq!(clock.time_until_attestation(0).unwrap(), Duration::from_millis(3000));
    }

    #[test]
    fn test_with_deadlines_7000ms_slot_3333_bps_is_2333ms() {
        let clock = MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_millis(7000), 32)
            .with_deadlines(DeadlineBps { attestation: 3333, aggregate: 6667 });
        clock.set_current_time(TEST_GENESIS_TIME);
        assert_eq!(clock.time_until_attestation(0).unwrap(), Duration::from_millis(2333));
    }

    #[test]
    fn test_system_slot_clock_with_deadlines() {
        let clock = SystemSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32)
            .unwrap()
            .with_deadlines(DeadlineBps { attestation: 2500, aggregate: 4000 });
        assert_eq!(clock.deadlines(), DeadlineBps { attestation: 2500, aggregate: 4000 });
    }
}
