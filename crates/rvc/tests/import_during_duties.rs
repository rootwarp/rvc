//! RR2-15: 10 MB interchange import during the N=200 slot loop.
//!
//! Record-only and `#[ignore]`d. `cargo nextest run --workspace` does not run
//! it. The 0-miss gate is RR3-07.
//!
//! ```text
//! cargo nextest run --release -p rvc --test import_during_duties \
//!   --run-ignored ignored-only --no-capture \
//!   -E 'test(import_during_duties_records_deadline_misses)'
//! ```

mod common;

use common::import_during_duties::{
    intervals_overlap, late_reserve_count, poll_reconstructed_interval, run_import_during_duties,
    ImportDuringDutiesOpts, ScheduledImport, UnscheduledImport, ATTESTATION_PUBLISH_BUDGET_MS,
    TEN_MB_HISTORY_ROWS, TEN_MB_JSON_BYTES, TEN_MB_VALIDATORS,
};

/// Unscheduled 10 MB import against the N=200 slot loop.
///
/// Drives [`run_import_during_duties`] with [`UnscheduledImport`]. RR3-07
/// calls that same function with a gate-backed [`common::import_during_duties::ImportAdmission`].
#[tokio::test(flavor = "current_thread")]
#[ignore = "manual RR2-15 import-during-duties scenario; excluded from cargo nextest run --workspace"]
async fn import_during_duties_records_deadline_misses() {
    let opts = ImportDuringDutiesOpts::n200_unscheduled_attestation();
    let record = run_import_during_duties(opts, UnscheduledImport)
        .await
        .expect("import-during-duties scenario");
    let json = record.to_json();
    print!("{json}");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    assert_eq!(record.admission, "unscheduled");
    assert_eq!(record.clock_mode, "wall");
    assert_eq!(record.n, 200);
    assert_eq!(record.payload_bytes, TEN_MB_JSON_BYTES);
    assert_eq!(record.payload_validators, TEN_MB_VALIDATORS);
    assert_eq!(record.history_rows, TEN_MB_HISTORY_ROWS);
    assert!(record.on_disk, "scenario must use the on-disk SlashingDb");
    assert_eq!(record.fire_at, "attestation");
    assert_eq!(record.attestation_deadline_ms, 3999);
    assert_eq!(record.attestation_publish_budget_ms, ATTESTATION_PUBLISH_BUDGET_MS);
    assert_eq!(record.conn_hold_samples, 1, "one import records one conn-hold sample");
    assert!(record.conn_hold_ms > 0.0, "rvc_slashing_import_conn_hold_ms must move");
    assert!(
        record.overlapping_phase.split('+').any(|phase| phase == "attestation"),
        "hold must overlap the attestation phase, got {}",
        record.overlapping_phase
    );
    assert_eq!(record.attestation_items, 200, "the slot loop must publish every validator");
    assert_eq!(record.sha.len(), 40, "sha must be a full git revision");
    assert!(!record.host.is_empty());
    assert!(record.toolchain.contains("rustc"), "toolchain: {}", record.toolchain);
    assert!(record.conn_hold_end_ms >= record.conn_hold_start_ms);
    assert!(!record.overlapping_phase.is_empty());
    assert!(
        record.attestation_deadline_misses <= record.attestation_items,
        "a miss count cannot exceed published items"
    );
}

/// Scheduled 10 MB import against the N=200 slot loop.
///
/// Drives [`run_import_during_duties`] through RR3-02's gate
/// ([`ScheduledImport`]) with RR3-06's proposer duty. The signature of
/// `run_import_during_duties` is the one RR2-15 published.
///
/// ```text
/// cargo nextest run --release -p rvc --test import_during_duties \
///   --run-ignored ignored-only --no-capture \
///   -E 'test(scheduled_import_at_n200_misses_no_deadline_and_no_late_block_reserve)'
/// ```
#[tokio::test(flavor = "current_thread")]
#[ignore = "manual RR3-07 scheduled import-during-duties gate; excluded from cargo nextest run --workspace"]
async fn scheduled_import_at_n200_misses_no_deadline_and_no_late_block_reserve() {
    let opts = ImportDuringDutiesOpts::n200_scheduled_attestation();
    let record = run_import_during_duties(opts, ScheduledImport)
        .await
        .expect("scheduled import-during-duties");
    let json = record.to_json();
    print!("{json}");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    assert_eq!(record.admission, "scheduled");
    assert_eq!(record.clock_mode, "wall");
    assert_eq!(record.n, 200);
    assert!(record.proposer, "RR3-06 proposer duty must be on");
    assert_eq!(
        record.slot,
        40 * 32,
        "Deneb epoch's first slot, so the block body matches the fork"
    );
    assert_eq!(record.payload_bytes, TEN_MB_JSON_BYTES);
    assert_eq!(record.payload_validators, TEN_MB_VALIDATORS);
    assert_eq!(record.history_rows, TEN_MB_HISTORY_ROWS);
    assert!(record.on_disk, "scenario must use the on-disk SlashingDb");
    assert_eq!(record.fire_at, "attestation");
    assert_eq!(record.attestation_deadline_ms, 3999);
    assert_eq!(record.attestation_publish_budget_ms, ATTESTATION_PUBLISH_BUDGET_MS);
    assert_eq!(record.conn_hold_samples, 1, "one import records one conn-hold sample");
    assert!(record.conn_hold_ms > 0.0, "rvc_slashing_import_conn_hold_ms must move");
    assert_eq!(record.attestation_items, 200, "the slot loop must publish every validator");
    assert_eq!(
        record.attestation_deadline_misses, 0,
        "scheduled path must miss no attestation deadline"
    );
    assert_eq!(
        record.block_reserves, 1,
        "the proposer duty must record one block-reserve wait; intervals: {:?}",
        record.block_reserve_intervals
    );
    // PQ-7 (a later block reserve) is not decidable on this cell: the only
    // reserve is the t=0 proposal, and it always returns before the import.
    // `boundary_*` is the cell that can fail.
    assert!(
        record.import_deferred_samples >= 1 && record.import_deferred_ms > 0.0,
        "the gate wait must be observable, got {} samples / {} ms",
        record.import_deferred_samples,
        record.import_deferred_ms
    );
    assert!(
        record.conn_hold_start_ms >= 4_499.0,
        "conn-hold must open at or after the free window (4499 ms), got {}",
        record.conn_hold_start_ms
    );
    assert!(!record.block_phase_overlapped, "hold must not meet the block phase span");
    assert_eq!(record.sha.len(), 40, "sha must be a full git revision");
    assert!(!record.host.is_empty());
    assert!(record.toolchain.contains("rustc"), "toolchain: {}", record.toolchain);
}

/// Unscheduled import late in slot N meets slot N+1's t=0 block reserve.
///
/// ```text
/// cargo nextest run --release -p rvc --test import_during_duties \
///   --run-ignored ignored-only --no-capture \
///   -E 'test(boundary_unscheduled_import_meets_next_slot_block_reserve)'
/// ```
#[tokio::test(flavor = "current_thread")]
#[ignore = "manual RR3-07 boundary cell; excluded from cargo nextest run --workspace"]
async fn boundary_unscheduled_import_meets_next_slot_block_reserve() {
    let opts = ImportDuringDutiesOpts::n200_boundary_attestation();
    let record = run_import_during_duties(opts, UnscheduledImport)
        .await
        .expect("boundary unscheduled import");
    let json = record.to_json();
    print!("{json}");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    assert_eq!(record.admission, "unscheduled");
    assert_eq!(record.fire_after_ms, Some(11_600));
    assert!(record.roll_slot_clock);
    assert_eq!(record.following_slots, 1);
    assert!(
        record.block_reserves >= 2,
        "slot N and slot N+1 must each reserve a block; intervals: {:?}",
        record.block_reserve_intervals
    );
    assert!(
        record.late_block_reserves >= 1,
        "the unscheduled hold must meet a later block reserve; intervals: {:?} hold {}–{}",
        record.block_reserve_intervals,
        record.conn_hold_start_ms,
        record.conn_hold_end_ms
    );
}

/// Scheduled import late in slot N misses slot N+1's t=0 block reserve.
///
/// The gate sees the short remainder before 11_800 ms and waits for slot
/// N+1's free window, which opens after that slot's block reserve.
///
/// ```text
/// cargo nextest run --release -p rvc --test import_during_duties \
///   --run-ignored ignored-only --no-capture \
///   -E 'test(boundary_scheduled_import_misses_next_slot_block_reserve)'
/// ```
#[tokio::test(flavor = "current_thread")]
#[ignore = "manual RR3-07 boundary cell; excluded from cargo nextest run --workspace"]
async fn boundary_scheduled_import_misses_next_slot_block_reserve() {
    let opts = ImportDuringDutiesOpts::n200_boundary_attestation();
    let record =
        run_import_during_duties(opts, ScheduledImport).await.expect("boundary scheduled import");
    let json = record.to_json();
    print!("{json}");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    assert_eq!(record.admission, "scheduled");
    assert_eq!(record.fire_after_ms, Some(11_600));
    assert!(record.roll_slot_clock);
    assert_eq!(record.following_slots, 1);
    assert!(
        record.block_reserves >= 2,
        "slot N and slot N+1 must each reserve a block; intervals: {:?}",
        record.block_reserve_intervals
    );
    assert_eq!(
        record.late_block_reserves, 0,
        "the scheduled hold must miss every block reserve; intervals: {:?} hold {}–{}",
        record.block_reserve_intervals, record.conn_hold_start_ms, record.conn_hold_end_ms
    );
    assert!(
        record.import_deferred_ms > 0.0,
        "the gate must defer the late import, got {} ms",
        record.import_deferred_ms
    );
}

/// Precise endpoints count a reserve that sits inside the hold, including a
/// closed touch at the hold's end.
#[test]
fn precise_intervals_count_a_synthetic_overlap() {
    let hold = (100.0, 200.0);
    let inside = (190.0, 195.0);
    assert!(intervals_overlap(hold.0, hold.1, inside.0, inside.1));
    assert_eq!(late_reserve_count(hold.0, hold.1, &[inside]), 1);
    // hold_end == reserve_start is a closed-interval overlap.
    let touch = (200.0, 205.0);
    assert!(intervals_overlap(hold.0, hold.1, touch.0, touch.1));
    assert_eq!(late_reserve_count(hold.0, hold.1, &[touch]), 1);
}

/// A reserve that starts after the hold, and one that ends before it, are
/// not late.
#[test]
fn precise_intervals_reject_a_non_overlapping_edge() {
    let hold = (100.0, 200.0);
    let after = (201.0, 210.0);
    assert!(!intervals_overlap(hold.0, hold.1, after.0, after.1));
    assert_eq!(late_reserve_count(hold.0, hold.1, &[after]), 0);
    // Same-slot shape: the t=0 reserve is finished before the hold opens.
    let before = (105.52, 111.218);
    let same_slot_hold = (4_536.292, 5_305.907);
    assert!(!intervals_overlap(same_slot_hold.0, same_slot_hold.1, before.0, before.1));
    assert_eq!(late_reserve_count(same_slot_hold.0, same_slot_hold.1, &[before]), 0);
}

/// The old poll detector slides a real overlap off the hold. The precise
/// endpoints still count it.
///
/// True reserve `[190, 195]` (duration 5 ms) meets hold `[100, 200]`. A poll
/// 30 ms after the reserve returns reconstructs `[220, 225]` and misses.
#[test]
fn poll_lagged_reserve_interval_misses_an_overlap_precise_endpoints_catch() {
    let hold = (100.0, 200.0);
    let true_reserve = (190.0, 195.0);
    let duration_ms = true_reserve.1 - true_reserve.0;
    let poll_at_ms = true_reserve.1 + 30.0;
    let polled = poll_reconstructed_interval(poll_at_ms, duration_ms);
    assert_eq!(polled, (220.0, 225.0));
    assert!(
        !intervals_overlap(hold.0, hold.1, polled.0, polled.1),
        "poll reconstruction of [190, 195] at a 30 ms lag must miss [100, 200]"
    );
    assert_eq!(late_reserve_count(hold.0, hold.1, &[polled]), 0);
    assert!(intervals_overlap(hold.0, hold.1, true_reserve.0, true_reserve.1));
    assert_eq!(late_reserve_count(hold.0, hold.1, &[true_reserve]), 1);
}
