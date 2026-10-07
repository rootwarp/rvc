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
    run_import_during_duties, ImportDuringDutiesOpts, UnscheduledImport,
    ATTESTATION_PUBLISH_BUDGET_MS, TEN_MB_HISTORY_ROWS, TEN_MB_JSON_BYTES, TEN_MB_VALIDATORS,
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
