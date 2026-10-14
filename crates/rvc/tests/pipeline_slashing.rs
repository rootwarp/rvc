//! Pipeline-level slashing protection tests (RF1-02).
//!
//! Guards the wiring `DutyOrchestrator → AttestationService → SignerService →
//! SlashingDb`. A double-vote across two `process_slot` calls must be rejected
//! with **no second signature**, and a slashing-DB error must fail closed.
//!
//! The module-level fixture lives in [`common::pipeline_fixture`] and is
//! intentionally reusable — RF1-08 (doppelganger gate / key-import integration)
//! builds on it.

mod common;

use std::collections::HashMap;

use common::pipeline_fixture::{
    double_vote_attestation_map, make_beacon_attestation_data, open_poisoned_slashing_db,
    pipeline_fixture, PipelineFixtureOpts, SLOT_A, SLOT_B,
};

// ── tests ────────────────────────────────────────────────────────────────────

/// RF1-02: two `process_slot` calls with conflicting AttestationData.
/// First signs; second is rejected by slashing protection — asserted via
/// **absence of a second signature** (not logs).
#[tokio::test]
async fn test_pipeline_rejects_double_vote_across_two_process_slot_calls() {
    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: double_vote_attestation_map(),
        duty_slots: vec![SLOT_A, SLOT_B],
        initial_slot: SLOT_A,
        ..Default::default()
    });

    let results_a = fixture.process_slot(SLOT_A).await.expect("slot A process_slot");
    assert_eq!(results_a.len(), 1, "exactly one duty at slot A");
    assert!(
        results_a[0].outcome.is_published(),
        "first attestation must sign successfully; error={:?}",
        results_a[0].outcome
    );
    assert_eq!(
        fixture.submitter.signature_count(),
        1,
        "first process_slot must emit exactly one signature"
    );

    let results_b = fixture.process_slot(SLOT_B).await.expect("slot B process_slot");
    assert_eq!(results_b.len(), 1, "exactly one duty at slot B");
    assert!(
        !results_b[0].outcome.is_published(),
        "conflicting second attestation must be rejected; got success with error={:?}",
        results_b[0].outcome
    );
    let err = common::failed_attestation_message(&results_b[0]);
    assert!(
        err.to_lowercase().contains("sign") || err.to_lowercase().contains("slash"),
        "rejection must surface as a signing/slashing failure, got: {err}"
    );

    // Absence of signature: submitter must still have only the first one.
    assert_eq!(
        fixture.submitter.signature_count(),
        1,
        "second process_slot must not emit a signature (fail-closed double-vote)"
    );
    assert_eq!(fixture.submitter.batch_count(), 1);
}

/// RF1-02: after double-vote rejection the slashing DB holds exactly one
/// attestation row for the pubkey.
#[tokio::test]
async fn test_pipeline_double_vote_leaves_single_db_row() {
    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: double_vote_attestation_map(),
        duty_slots: vec![SLOT_A, SLOT_B],
        initial_slot: SLOT_A,
        ..Default::default()
    });

    let results_a = fixture.process_slot(SLOT_A).await.expect("slot A");
    assert!(results_a[0].outcome.is_published(), "first must succeed: {:?}", results_a[0].outcome);

    let results_b = fixture.process_slot(SLOT_B).await.expect("slot B");
    assert!(!results_b[0].outcome.is_published(), "second must fail: {:?}", results_b[0].outcome);

    let rows = fixture.slashing_db.get_attestations(&fixture.pubkey_hex).expect("get_attestations");
    assert_eq!(
        rows.len(),
        1,
        "after double-vote rejection exactly one attestation row must remain; got {rows:?}"
    );
    assert_eq!(rows[0].target_epoch, SLOT_A / common::pipeline_fixture::SLOTS_PER_EPOCH);
}

/// RF1-02: a slashing-DB error during `process_slot` fails closed — no signature.
#[tokio::test]
async fn test_pipeline_slashing_db_error_is_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.sqlite");
    let poisoned = open_poisoned_slashing_db(&db_path);

    let mut att_map = HashMap::new();
    att_map.insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));

    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: att_map,
        duty_slots: vec![SLOT_A],
        slashing_db: Some(poisoned),
        initial_slot: SLOT_A,
        ..Default::default()
    });

    let results = fixture.process_slot(SLOT_A).await.expect("process_slot returns results");
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].outcome.is_published(),
        "DB error must fail closed (no successful attestation); error={:?}",
        results[0].outcome
    );
    let err = common::failed_attestation_message(&results[0]);
    assert!(
        err.to_lowercase().contains("sign")
            || err.to_lowercase().contains("slash")
            || err.to_lowercase().contains("database")
            || err.to_lowercase().contains("db"),
        "error should indicate signing/DB failure, got: {err}"
    );

    // Absence of signature is the hard assertion.
    assert_eq!(fixture.submitter.signature_count(), 0, "slashing-DB error must emit no signature");
    assert_eq!(fixture.submitter.batch_count(), 0);
}
