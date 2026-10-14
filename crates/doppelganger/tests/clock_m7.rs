//! Integration tests for M-7: BN-derived clock anchored on genesis_time.
//!
//! Verifies that [`MonotonicEpochClock`] is immune to NTP wall-clock steps
//! by anchoring epoch computation on a monotonic `Instant` elapsed plus a
//! `start_unix_time` captured once at construction.

use std::time::{Duration, Instant};

use eth_types::{SLOTS_PER_EPOCH, SLOT_DURATION_MS};
use rvc_doppelganger::MonotonicEpochClock;

// Epoch length in seconds: SLOT_DURATION_MS * SLOTS_PER_EPOCH / 1000 = 12_000 * 32 / 1000 = 384
const SECONDS_PER_EPOCH: u64 = SLOT_DURATION_MS * SLOTS_PER_EPOCH / 1000;

/// Slot 0 at genesis; one 12_000 ms slot later is slot 1 (not 12_000 s later).
/// Would fail a naive `secs / SLOT_DURATION_MS` rename of `secs / SECONDS_PER_SLOT`.
#[test]
fn test_slot_zero_at_genesis() {
    let genesis = 1_606_824_023_u64;
    let clock = MonotonicEpochClock::with_start_time(genesis, Instant::now(), genesis);
    assert_eq!(clock.current_slot(), 0);
    assert_eq!(clock.current_epoch(), 0);

    let one_slot_secs = SLOT_DURATION_MS / 1000;
    assert_eq!(one_slot_secs, 12, "mainnet slot is 12 s");
    let one_slot_later =
        MonotonicEpochClock::with_start_time(genesis, Instant::now(), genesis + one_slot_secs);
    assert_eq!(one_slot_later.current_slot(), 1);

    let still_genesis =
        MonotonicEpochClock::with_start_time(genesis, Instant::now(), genesis + one_slot_secs - 1);
    assert_eq!(still_genesis.current_slot(), 0);
}

/// One epoch is 384 s (`SLOT_DURATION_MS * SLOTS_PER_EPOCH` ms), matching the pre-ms tree.
#[test]
fn test_epoch_duration_is_384_seconds() {
    assert_eq!(SECONDS_PER_EPOCH, 384);
    let genesis = 0_u64;
    let clock =
        MonotonicEpochClock::with_start_time(genesis, Instant::now(), genesis + SECONDS_PER_EPOCH);
    assert_eq!(clock.current_epoch(), 1);
    assert_eq!(clock.current_slot(), SLOTS_PER_EPOCH);
}

/// M-7: A wall-clock step (NTP jump) must NOT shift the computed epoch.
#[test]
fn test_wall_clock_jump_does_not_shift_epoch() {
    // Scenario:
    //   genesis_time  = 0
    //   start_unix    = 384 * 5 = 1920  (clock "started" 5 epochs after genesis)
    //   start_instant = Instant::now()  (zero elapsed so far)
    //
    // current_epoch() = (start_unix + elapsed - genesis) / SECONDS_PER_EPOCH
    //                 = (1920 + ~0 - 0) / 384 = 5

    let genesis_time = 0_u64;
    let start_unix_time = SECONDS_PER_EPOCH * 5; // 1920s => epoch 5
    let start_instant = Instant::now();

    let clock = MonotonicEpochClock::with_start_time(genesis_time, start_instant, start_unix_time);

    let epoch = clock.current_epoch();
    assert_eq!(epoch, 5, "epoch should be anchored at 5 epochs past genesis");

    // Simulate a "wall-clock jump" by observing that our formula does NOT use
    // SystemTime::now().  We verify by cross-checking with the manual formula:
    //   expected = (start_unix + elapsed - genesis) / SECONDS_PER_EPOCH
    let elapsed_secs = start_instant.elapsed().as_secs();
    let expected = (start_unix_time + elapsed_secs - genesis_time) / SECONDS_PER_EPOCH;
    assert_eq!(
        clock.current_epoch(),
        expected,
        "epoch must equal the monotonic-elapsed formula, not SystemTime::now()"
    );
}

/// M-7: Two clocks with different genesis_times must produce epochs that differ
/// by exactly `(genesis_time_diff / SECONDS_PER_EPOCH)`.
#[test]
fn test_genesis_time_anchored() {
    let start_instant = Instant::now();
    let start_unix_time = 2_000_000_u64;

    let genesis1 = 1_000_000_u64;
    // genesis2 is 1_000 epochs later: 1_000 * 384 = 384_000 seconds
    let genesis2 = genesis1 + SECONDS_PER_EPOCH * 1_000; // 1_384_000

    let clock1 = MonotonicEpochClock::with_start_time(genesis1, start_instant, start_unix_time);
    let clock2 = MonotonicEpochClock::with_start_time(genesis2, start_instant, start_unix_time);

    let epoch1 = clock1.current_epoch();
    let epoch2 = clock2.current_epoch();

    // clock1: (2_000_000 - 1_000_000) / 384 = 2_604 epochs
    // clock2: (2_000_000 - 1_384_000) / 384 = 1_604 epochs
    // Difference: 1_000 epochs
    assert_eq!(
        epoch1.saturating_sub(epoch2),
        1_000,
        "epoch diff should be genesis_time_diff / SECONDS_PER_EPOCH"
    );
}

/// Sanity-check: epoch advances monotonically as elapsed increases.
#[test]
fn test_epoch_advances_with_elapsed() {
    let genesis_time = 0_u64;
    // Pin start_instant to appear 384 seconds in the past (one epoch elapsed)
    let one_epoch_ago = Instant::now() - Duration::from_secs(SECONDS_PER_EPOCH);
    let start_unix_time = SECONDS_PER_EPOCH; // started 1 epoch after genesis

    let clock = MonotonicEpochClock::with_start_time(genesis_time, one_epoch_ago, start_unix_time);

    // elapsed ≈ 384s, start_unix = 384, genesis = 0
    // now_unix ≈ 384 + 384 = 768, epoch ≈ 768 / 384 = 2
    let epoch = clock.current_epoch();
    assert!(epoch >= 2, "with ~1 epoch elapsed the computed epoch should be ≥ 2, got {epoch}");
}
