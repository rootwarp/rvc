/// Integration tests for the stage/commit ordering API (ISSUE-1.4 / A15).
///
/// These tests verify the RAII guard semantics:
/// - `discard()` rolls back so no row is committed.
/// - `commit()` persists the row; a conflicting re-stage is then rejected.
/// - Bare `drop` without calling `commit()` or `discard()` also rolls back.
/// - Symmetric behaviour for `StagedAttestation`.
/// - The existing `check_and_record_*` API still works on the same DB.
use rvc_slashing::{
    AttestationSlashingViolation, BlockSlashingViolation, SlashingDb, SlashingError,
};

const PUBKEY: &str = "0xdeadbeef01";
const PUBKEY2: &str = "0xdeadbeef02";
const GVR: &[u8; 32] = &[0u8; 32];

// ── StagedBlock tests ─────────────────────────────────────────────────────────

/// Stage a block, call `discard()`, and assert the row is absent in `blocks`.
#[test]
fn test_stage_block_discard_no_row_committed() {
    let db = SlashingDb::open_in_memory().expect("open");
    let staged = db.stage_block(PUBKEY, 42, Some("0xroot_a".into()), GVR).expect("stage");
    staged.discard();

    // The row must NOT appear in the database.
    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert!(blocks.is_empty(), "discard must not commit any row; got: {blocks:?}");
}

/// Issue 2.7: a slashing violation is logged as a DECISION at debug inside the
/// slashing crate (the terminal error is logged once by the terminal caller —
/// signer/gate/DVT error!), and the signing root is never logged.
#[test]
#[tracing_test::traced_test]
// kat_exempt: logging only — asserts the signing root is never logged, not a spec root
fn test_slashing_decision_logged_at_debug_without_root() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.stage_block(PUBKEY, 100, Some("0xroot_alpha_marker".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");
    // A conflicting block at the same slot is a double proposal -> rejected.
    let _ = db
        .stage_block(PUBKEY, 100, Some("0xroot_beta_marker".into()), GVR)
        .expect_err("double proposal must be rejected");

    logs_assert(|lines: &[&str]| {
        let decision = lines
            .iter()
            .find(|l| l.contains("double_block_proposal"))
            .ok_or_else(|| "no slashing-decision line captured".to_string())?;
        if decision.contains("ERROR") {
            return Err(format!(
                "slashing decision must not be ERROR (caller logs the terminal): {decision}"
            ));
        }
        if !decision.contains("DEBUG") {
            return Err(format!("slashing decision must be logged at DEBUG: {decision}"));
        }
        if decision.contains("root_alpha_marker") || decision.contains("root_beta_marker") {
            return Err(format!("the signing root must never be logged: {decision}"));
        }
        Ok(())
    });
}

/// Stage + commit a block; then attempt to stage the same (pubkey, slot) with a
/// different signing root — the second stage must return `DoubleBlockProposal`.
#[test]
fn test_stage_block_commit_then_conflicting_stage_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");

    // First stage + commit.
    db.stage_block(PUBKEY, 100, Some("0xroot_1".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // One row should be in the DB.
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);

    // Second stage with a different root must be rejected immediately.
    let err = db
        .stage_block(PUBKEY, 100, Some("0xroot_2".into()), GVR)
        .expect_err("second stage must fail");

    match err {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(slot, 100);
        }
        other => panic!("expected DoubleBlockProposal, got: {other:?}"),
    }
}

/// Stage a block and drop the guard without calling `commit()` or `discard()`.
/// The row must not appear in the database (drop rolls back).
#[test]
fn test_stage_block_drop_without_commit_rolls_back() {
    let db = SlashingDb::open_in_memory().expect("open");

    {
        let _guard = db.stage_block(PUBKEY, 77, Some("0xroot_drop".into()), GVR).expect("stage");
        // _guard is dropped here without calling commit() or discard()
    }

    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert!(blocks.is_empty(), "bare drop must roll back; got: {blocks:?}");
}

/// Verify that `commit()` actually persists the row.
#[test]
fn test_stage_block_commit_persists_row() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block(PUBKEY, 55, Some("0xroot_persist".into()), GVR)
        .expect("stage")
        .commit()
        .expect("commit");

    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 1, "commit must persist exactly one row");
    assert_eq!(blocks[0].slot, 55);
}

// ── StagedAttestation tests ───────────────────────────────────────────────────

/// Stage an attestation, call `discard()`, and assert the row is absent.
#[test]
fn test_stage_attestation_discard_no_row_committed() {
    let db = SlashingDb::open_in_memory().expect("open");
    let staged =
        db.stage_attestation(PUBKEY, 1, 5, Some("0xatt_root_a".into()), GVR).expect("stage");
    staged.discard();

    let atts = db.get_attestations(PUBKEY).expect("get");
    assert!(atts.is_empty(), "discard must not commit any row; got: {atts:?}");
}

/// Stage + commit an attestation; then attempt a double vote — second stage must return
/// `DoubleVote`.
#[test]
fn test_stage_attestation_commit_then_double_vote_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");

    // First stage + commit.
    db.stage_attestation(PUBKEY, 3, 10, Some("0xatt_root_1".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // Second stage: same target_epoch (double vote) with a different root.
    let err = db
        .stage_attestation(PUBKEY, 3, 10, Some("0xatt_root_2".into()), GVR)
        .expect_err("second stage must fail");

    match err {
        SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
            target_epoch,
        }) => {
            assert_eq!(target_epoch, 10);
        }
        other => panic!("expected DoubleVote, got: {other:?}"),
    }
}

/// Stage an attestation and drop without `commit()` — must roll back.
#[test]
fn test_stage_attestation_drop_without_commit_rolls_back() {
    let db = SlashingDb::open_in_memory().expect("open");

    {
        let _guard =
            db.stage_attestation(PUBKEY, 2, 8, Some("0xatt_root_drop".into()), GVR).expect("stage");
        // dropped without commit
    }

    let atts = db.get_attestations(PUBKEY).expect("get");
    assert!(atts.is_empty(), "bare drop must roll back; got: {atts:?}");
}

/// Stage a surrounding vote; must be rejected at stage time (before commit).
#[test]
fn test_stage_attestation_commit_then_surround_vote_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");

    // Commit a narrow attestation: source=3, target=7.
    db.stage_attestation(PUBKEY, 3, 7, Some("0xnarrow".into()), GVR)
        .expect("narrow stage")
        .commit()
        .expect("narrow commit");

    // Attempt a surrounding attestation: source=1, target=10 surrounds (3,7).
    let err = db
        .stage_attestation(PUBKEY, 1, 10, Some("0xsurrounding".into()), GVR)
        .expect_err("surrounding vote must be rejected at stage");

    match err {
        SlashingError::SlashableAttestation(AttestationSlashingViolation::SurroundingVote {
            ..
        }) => {}
        other => panic!("expected SurroundingVote, got: {other:?}"),
    }
}

// ── Backwards-compatibility test ─────────────────────────────────────────────

/// `check_and_record_block` must still work on the same DB that has staged records.
#[test]
fn test_stage_block_keeps_existing_check_and_record_unchanged() {
    let db = SlashingDb::open_in_memory().expect("open");

    // Use check_and_record for the first block.
    db.check_and_record_block(PUBKEY, 200, Some("0xcheck_root".into()), GVR)
        .expect("check_and_record_block");

    // Stage a different slot — should work fine.
    db.stage_block(PUBKEY, 201, Some("0xstage_root".into()), GVR)
        .expect("stage")
        .commit()
        .expect("commit");

    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 2, "both records must be present");

    // Attempting to check_and_record at slot 200 with a different root must fail.
    let err = db
        .check_and_record_block(PUBKEY, 200, Some("0xdifferent".into()), GVR)
        .expect_err("double proposal must be rejected by check_and_record");
    assert!(
        matches!(
            err,
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { .. })
        ),
        "expected DoubleBlockProposal, got: {err:?}"
    );
}

/// `check_and_record_attestation` must still work on the same DB.
#[test]
fn test_stage_attestation_keeps_existing_check_and_record_unchanged() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.check_and_record_attestation(PUBKEY2, 5, 15, Some("0xatt_check".into()), GVR)
        .expect("check_and_record_attestation");

    // Stage a non-conflicting attestation.
    db.stage_attestation(PUBKEY2, 16, 20, Some("0xatt_stage".into()), GVR)
        .expect("stage")
        .commit()
        .expect("commit");

    let atts = db.get_attestations(PUBKEY2).expect("get");
    assert_eq!(atts.len(), 2);

    // Attempt a double vote via check_and_record — must be rejected.
    let err = db
        .check_and_record_attestation(PUBKEY2, 5, 15, Some("0xatt_conflict".into()), GVR)
        .expect_err("double vote must be rejected");
    assert!(
        matches!(
            err,
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote { .. })
        ),
        "expected DoubleVote, got: {err:?}"
    );
}

// ── v3 pubkey-scoped test ─────────────────────────────────────────────────────

/// After Issue 2.5, `stage_block` takes no CN — the check is purely pubkey+slot scoped.
/// Conflicting blocks for the same (pubkey, slot) are rejected regardless of origin.
#[test]
fn test_stage_block_pubkey_scoped_conflict_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block(PUBKEY, 300, Some("0xroot_alpha".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // Different root for same (pubkey, slot) — must be rejected.
    let result = db.stage_block(PUBKEY, 300, Some("0xroot_beta".into()), GVR);
    assert!(
        matches!(
            result,
            Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot: 300
            }))
        ),
        "conflicting block must be rejected in pubkey-scoped schema: {result:?}"
    );

    // Same root is a re-sign (not a violation).
    db.stage_block(PUBKEY, 300, Some("0xroot_alpha".into()), GVR)
        .expect("same-root re-sign must be allowed")
        .commit()
        .expect("re-sign commit");

    // Only one row (the first commit); the re-sign didn't insert a new row.
    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 1, "re-sign must not produce a duplicate row");
}

// ── Re-sign (idempotent) tests ────────────────────────────────────────────────

/// Staging the same (pubkey, slot, root) twice is an idempotent re-sign.
/// The second stage+commit must succeed and must not produce a duplicate row.
#[test]
fn test_stage_block_resign_is_idempotent() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block(PUBKEY, 400, Some("0xresign_root".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // Same signing root — should be treated as an idempotent re-sign.
    db.stage_block(PUBKEY, 400, Some("0xresign_root".into()), GVR)
        .expect("second stage (re-sign) should succeed")
        .commit()
        .expect("second commit");

    // Still only one row.
    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 1, "re-sign must not create a duplicate row");
}

/// Staging the same (pubkey, target, root) twice is an idempotent re-sign
/// for attestations.
#[test]
fn test_stage_attestation_resign_is_idempotent() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_attestation(PUBKEY, 5, 20, Some("0xresign_att".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    db.stage_attestation(PUBKEY, 5, 20, Some("0xresign_att".into()), GVR)
        .expect("second stage (re-sign)")
        .commit()
        .expect("second commit");

    let atts = db.get_attestations(PUBKEY).expect("get");
    assert_eq!(atts.len(), 1, "re-sign must not create a duplicate attestation row");
}

/// Discarding (or dropping) a re-sign stage must NOT delete the existing
/// committed row.  The transaction was effectively read-only on the resign
/// path, so ROLLBACK is a data no-op.
#[test]
fn test_stage_block_resign_discard_keeps_existing_row() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block(PUBKEY, 500, Some("0xresign_keep".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    let before = db.get_blocks(PUBKEY).expect("get before");
    assert_eq!(before.len(), 1);

    // Same signing root — resign path.  Discard instead of commit.
    db.stage_block(PUBKEY, 500, Some("0xresign_keep".into()), GVR).expect("resign stage").discard();

    let after = db.get_blocks(PUBKEY).expect("get after");
    assert_eq!(after.len(), 1, "resign+discard must not delete the existing row");
    assert_eq!(after[0].slot, 500);
    assert_eq!(after[0].signing_root.as_deref(), Some("0xresign_keep"));

    // Bare drop (no explicit commit/discard) on a resign must also be safe.
    {
        let _staged =
            db.stage_block(PUBKEY, 500, Some("0xresign_keep".into()), GVR).expect("resign stage 2");
        // _staged is dropped here without commit/discard.
    }

    let final_rows = db.get_blocks(PUBKEY).expect("get final");
    assert_eq!(final_rows.len(), 1, "resign+drop must not delete the existing row");
}

/// Same property for attestations: a duplicate stage that is discarded must
/// leave the previously committed attestation row intact.
#[test]
fn test_stage_attestation_duplicate_discard_keeps_existing_row() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_attestation(PUBKEY, 7, 30, Some("0xdup_keep".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    let before = db.get_attestations(PUBKEY).expect("get before");
    assert_eq!(before.len(), 1);

    db.stage_attestation(PUBKEY, 7, 30, Some("0xdup_keep".into()), GVR)
        .expect("duplicate stage")
        .discard();

    let after = db.get_attestations(PUBKEY).expect("get after");
    assert_eq!(after.len(), 1, "duplicate+discard must not delete the existing attestation");
    assert_eq!(after[0].source_epoch, 7);
    assert_eq!(after[0].target_epoch, 30);
}

// ── Watermark equality (RF1-01 / EIP-3076 SEC-9 / M-1) ───────────────────────
//
// Block-slot and attestation-target watermarks are strictly increasing: a
// candidate equal to the watermark must be rejected. Source-epoch equality
// remains allowed (only source < watermark is blocked).

/// RF1-01: stage_block at the block watermark must be rejected.
#[test]
fn test_stage_block_at_block_watermark_is_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_block_watermark(PUBKEY, 1000).expect("set watermark");

    let err = db
        .stage_block(PUBKEY, 1000, Some("0xwm_eq".into()), GVR)
        .expect_err("slot equal to block watermark must be rejected");

    match err {
        // RF2-12: error names the pubkey and offending values.
        SlashingError::BelowBlockWatermark { pubkey: ref err_pk, slot, watermark_slot } => {
            assert!(err_pk.contains("deadbeef01"), "pubkey in error: {err_pk}");
            assert_eq!(slot, 1000);
            assert_eq!(watermark_slot, 1000);
        }
        other => panic!("expected BelowBlockWatermark, got: {other:?}"),
    }
}

/// RF1-01: stage_block strictly below the block watermark must be rejected.
/// Guards a future `<=` → `==` typo that would re-open fail-open for below-wm duties.
#[test]
fn test_stage_block_strictly_below_block_watermark_is_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_block_watermark(PUBKEY, 1000).expect("set watermark");

    let err = db
        .stage_block(PUBKEY, 999, Some("0xwm_below".into()), GVR)
        .expect_err("slot strictly below block watermark must be rejected");

    match err {
        // RF2-12: error names the pubkey and offending values.
        // (pubkey is asserted in the equality test; field presence is required here.)
        SlashingError::BelowBlockWatermark { slot, watermark_slot, .. } => {
            assert_eq!(slot, 999);
            assert_eq!(watermark_slot, 1000);
        }
        other => panic!("expected BelowBlockWatermark, got: {other:?}"),
    }
}

/// RF1-01: stage_attestation at the target watermark must be rejected.
#[test]
fn test_stage_attestation_at_target_watermark_is_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_attestation_watermark(PUBKEY, 100, 200).expect("set watermark");

    let err = db
        .stage_attestation(PUBKEY, 100, 200, Some("0xatt_wm_eq".into()), GVR)
        .expect_err("target equal to att-target watermark must be rejected");

    match err {
        SlashingError::BelowAttestationWatermark {
            pubkey: ref err_pk,
            target_epoch,
            watermark_target,
        } => {
            assert!(err_pk.contains("deadbeef01"), "pubkey in error: {err_pk}");
            assert_eq!(target_epoch, 200);
            assert_eq!(watermark_target, 200);
        }
        other => panic!("expected BelowAttestationWatermark, got: {other:?}"),
    }
}

/// RF1-01: stage_attestation with target strictly below the target watermark must be rejected.
/// Guards a future `<=` → `==` typo (same regression class as block strictly-below).
#[test]
fn test_stage_attestation_strictly_below_target_watermark_is_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_attestation_watermark(PUBKEY, 100, 200).expect("set watermark");

    // source == 100 (allowed at source wm); target 199 < 200.
    let err = db
        .stage_attestation(PUBKEY, 100, 199, Some("0xatt_wm_below".into()), GVR)
        .expect_err("target strictly below att-target watermark must be rejected");

    match err {
        SlashingError::BelowAttestationWatermark { target_epoch, watermark_target, .. } => {
            assert_eq!(target_epoch, 199);
            assert_eq!(watermark_target, 200);
        }
        other => panic!("expected BelowAttestationWatermark, got: {other:?}"),
    }
}

/// RF1-01: stage_block strictly above the block watermark still succeeds.
#[test]
fn test_stage_block_above_block_watermark_succeeds() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_block_watermark(PUBKEY, 1000).expect("set watermark");

    db.stage_block(PUBKEY, 1001, Some("0xwm_above".into()), GVR)
        .expect("slot above watermark must stage")
        .commit()
        .expect("commit");

    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].slot, 1001);
}

/// RF1-01: source equal to source watermark with target above target watermark
/// is accepted (guards against over-applying <= to the source comparison).
#[test]
fn test_stage_attestation_at_source_watermark_succeeds() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_attestation_watermark(PUBKEY, 100, 200).expect("set watermark");

    // source == 100 (equal to source watermark — allowed); target 201 > 200.
    db.stage_attestation(PUBKEY, 100, 201, Some("0xsrc_eq_ok".into()), GVR)
        .expect("source equality with target above watermark must succeed")
        .commit()
        .expect("commit");

    let atts = db.get_attestations(PUBKEY).expect("get");
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0].source_epoch, 100);
    assert_eq!(atts[0].target_epoch, 201);
}

/// RF2-09: source strictly below the source watermark is rejected even when target
/// is above the target watermark. (Check-only: stage fails before a guard is handed out.)
#[test]
fn test_stage_attestation_below_source_watermark_is_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_attestation_watermark(PUBKEY, 20, 20).expect("set watermark");

    // source=1 < source watermark=20; target=31 > target watermark=20.
    let err = db
        .stage_attestation(PUBKEY, 1, 31, Some("0xsrc_below".into()), GVR)
        .expect_err("source strictly below att-source watermark must be rejected");

    match err {
        // Check-only path: stage returns the watermark error; no commit needed.
        // RF2-12: error names the pubkey and offending values.
        SlashingError::BelowAttestationSourceWatermark {
            pubkey: ref err_pk,
            source_epoch,
            watermark_source,
        } => {
            assert!(err_pk.contains("deadbeef01"), "pubkey in error: {err_pk}");
            assert_eq!(source_epoch, 1);
            assert_eq!(watermark_source, 20);
        }
        other => panic!("expected BelowAttestationSourceWatermark, got: {other:?}"),
    }

    // At source watermark with target above is fine (mirrors the deleted unit test).
    db.stage_attestation(PUBKEY, 20, 31, Some("0xsrc_at_ok".into()), GVR)
        .expect("source at watermark with target above must succeed")
        .discard();
}

/// RF1-01: a watermark rejection must leave no committed row.
#[test]
fn test_stage_below_watermark_commits_no_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.set_block_watermark(PUBKEY, 1000).expect("set block watermark");
    db.set_attestation_watermark(PUBKEY, 100, 200).expect("set att watermark");

    let _ = db
        .stage_block(PUBKEY, 1000, Some("0xno_commit_block".into()), GVR)
        .expect_err("block at watermark");
    assert!(
        db.get_blocks(PUBKEY).expect("get blocks").is_empty(),
        "rejected stage_block must leave no block row"
    );

    let _ = db
        .stage_attestation(PUBKEY, 100, 200, Some("0xno_commit_att".into()), GVR)
        .expect_err("att at target watermark");
    assert!(
        db.get_attestations(PUBKEY).expect("get atts").is_empty(),
        "rejected stage_attestation must leave no attestation row"
    );
}

/// RF1-01: stage_* and check_and_record_* must agree on watermark-equality verdicts.
#[test]
fn test_stage_and_check_and_record_agree_on_watermark_equality() {
    // Block: equality rejected on both paths.
    {
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_block_watermark(PUBKEY, 1000).expect("set");

        let stage_err = db
            .stage_block(PUBKEY, 1000, Some("0xparity_b".into()), GVR)
            .expect_err("stage must err at equality");
        let check_err = db
            .check_and_record_block(PUBKEY, 1000, Some("0xparity_b".into()), GVR)
            .expect_err("check_and_record must err at equality");

        assert!(
            matches!(
                stage_err,
                SlashingError::BelowBlockWatermark { slot: 1000, watermark_slot: 1000, .. }
            ),
            "stage: {stage_err:?}"
        );
        assert!(
            matches!(
                check_err,
                SlashingError::BelowBlockWatermark { slot: 1000, watermark_slot: 1000, .. }
            ),
            "check_and_record: {check_err:?}"
        );
    }

    // Attestation target: equality rejected on both paths.
    {
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_attestation_watermark(PUBKEY, 100, 200).expect("set");

        let stage_err = db
            .stage_attestation(PUBKEY, 100, 200, Some("0xparity_a".into()), GVR)
            .expect_err("stage must err at target equality");
        let check_err = db
            .check_and_record_attestation(PUBKEY, 100, 200, Some("0xparity_a".into()), GVR)
            .expect_err("check_and_record must err at target equality");

        assert!(
            matches!(
                stage_err,
                SlashingError::BelowAttestationWatermark {
                    target_epoch: 200,
                    watermark_target: 200,
                    ..
                }
            ),
            "stage: {stage_err:?}"
        );
        assert!(
            matches!(
                check_err,
                SlashingError::BelowAttestationWatermark {
                    target_epoch: 200,
                    watermark_target: 200,
                    ..
                }
            ),
            "check_and_record: {check_err:?}"
        );
    }
}
