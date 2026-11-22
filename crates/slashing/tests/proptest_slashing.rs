//! Property-based tests for slashing protection invariants.
//!
//! Uses proptest to verify that the slashing DB enforces EIP-3076
//! constraints under random input sequences.
//!
//! All properties drive the production `stage_* → commit()/discard()` path
//! (RF1-05). Helpers always resolve the staged guard before returning so a
//! property that stages repeatedly cannot deadlock on the connection mutex.

mod common;

use common::{stage_and_commit_attestation, stage_and_commit_block};
use proptest::prelude::*;
use rvc_slashing::{AttestationSlashingViolation, SlashingDb, SlashingError};

/// Zero GVR for signing-path checks (matches the historical harness).
const SIGN_GVR: &[u8; 32] = &[0u8; 32];

/// Configuration for proptest: 256 cases per property for CI friendliness.
const PROPTEST_CASES: u32 = 256;

fn config() -> ProptestConfig {
    ProptestConfig { cases: PROPTEST_CASES, ..ProptestConfig::default() }
}

fn hex_root(n: u8) -> String {
    format!("0x{}", hex::encode([n; 32]))
}

fn pubkey(n: u8) -> String {
    format!("0x{}", hex::encode([n; 48]))
}

/// Strategy that produces either None or Some(hex_root) to cover the EIP-3076
/// "unknown signing root" code path.
fn signing_root_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), (1u8..255).prop_map(|b| Some(hex_root(b))),]
}

/// Watermark W paired with candidate T, biased so equality is hit often.
///
/// Uniform independent draws of `(W, T)` over a large range almost never
/// sample `T == W` (the RF1-01 boundary). Force roughly equal weight on:
/// - `T == W` (equality blocked)
/// - `T < W`  (strictly below blocked)
/// - `T > W`  (strictly above accepted)
///
/// `W` is drawn from `1..10_000` so a strict-below candidate always exists.
fn watermark_and_candidate_strategy() -> impl Strategy<Value = (u64, u64)> {
    (1u64..10_000).prop_flat_map(|w| {
        prop_oneof![
            Just((w, w)),     // equal
            Just((w, w - 1)), // strictly below
            Just((w, w + 1)), // strictly above
        ]
    })
}

// =========================================================================
// Property 1: No double proposals
// Same (validator, slot) with different signing roots → exactly one success
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_no_double_proposals(
        slot in 0u64..100_000,
        root_a in signing_root_strategy(),
        root_b in signing_root_strategy(),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        if root_a == root_b {
            // Same signing root — both should succeed (idempotent re-signing)
            prop_assert!(stage_and_commit_block(&db, &pk, slot, root_a.clone(), SIGN_GVR).is_ok());
            prop_assert!(stage_and_commit_block(&db, &pk, slot, root_b, SIGN_GVR).is_ok());
        } else {
            // Different signing roots — exactly one should succeed
            // (guard from first call is committed before the second stage)
            let r1 = stage_and_commit_block(&db, &pk, slot, root_a, SIGN_GVR);
            let r2 = stage_and_commit_block(&db, &pk, slot, root_b, SIGN_GVR);
            prop_assert!(r1.is_ok());
            prop_assert!(r2.is_err());
        }
    }
}

// =========================================================================
// Property 2: No double votes
// Same (validator, target_epoch) with different signing roots → exactly one success
// =========================================================================

proptest! {
    #![proptest_config(config())]

    // Targets stay above both sources: source > target is refused before
    // the double-vote rule runs (W4-S2).
    #[test]
    fn proptest_no_double_votes(
        source_a in 0u64..50_000,
        source_b in 0u64..50_000,
        target in 50_000u64..100_000,
        root_a in signing_root_strategy(),
        root_b in signing_root_strategy(),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        // First attestation should always succeed
        let r1 = stage_and_commit_attestation(
            &db, &pk, source_a, target, root_a.clone(), SIGN_GVR,
        );
        prop_assert!(r1.is_ok());

        if root_a == root_b {
            // Same signing root — idempotent, should succeed
            let r2 = stage_and_commit_attestation(
                &db, &pk, source_b, target, root_b, SIGN_GVR,
            );
            prop_assert!(r2.is_ok());

            // Verify only 1 record exists and original source is preserved
            let atts = db.get_attestations(&pk).unwrap();
            prop_assert_eq!(atts.len(), 1, "re-sign should not create duplicate record");
            prop_assert_eq!(atts[0].source_epoch, source_a, "re-sign must not overwrite source epoch");
        } else {
            // Different signing roots — must be rejected (double vote)
            let r2 = stage_and_commit_attestation(
                &db, &pk, source_b, target, root_b, SIGN_GVR,
            );
            prop_assert!(r2.is_err());
        }
    }
}

// =========================================================================
// Property 3: No surround votes
// Accepted attestations never form surround pairs
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_no_surround_votes(
        attestations in prop::collection::vec(
            (0u64..1000, 1u64..1000),
            1..20
        ),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        // Submit attestations with unique roots per index to avoid collisions.
        // Each stage_and_commit resolves the guard before the next iteration.
        for (i, (source, target_offset)) in attestations.iter().enumerate() {
            let target = source + target_offset; // Ensure target > source
            let root = Some(hex_root((i as u8).wrapping_add(1)));
            let _ = stage_and_commit_attestation(
                &db, &pk, *source, target, root, SIGN_GVR,
            );
        }

        // Query the ACTUAL DB records for the surround invariant check
        let accepted = db.get_attestations(&pk).unwrap();

        // Verify no surround pairs exist among accepted attestations
        for i in 0..accepted.len() {
            for j in 0..accepted.len() {
                if i == j {
                    continue;
                }
                let (s_i, t_i) = (accepted[i].source_epoch, accepted[i].target_epoch);
                let (s_j, t_j) = (accepted[j].source_epoch, accepted[j].target_epoch);
                // i surrounds j: s_i < s_j AND t_i > t_j
                prop_assert!(
                    !(s_i < s_j && t_i > t_j),
                    "surround detected: ({}, {}) surrounds ({}, {})",
                    s_i, t_i, s_j, t_j,
                );
            }
        }
    }
}

// =========================================================================
// Property 4: Monotonicity
// After operations, min slot/epoch watermarks never decrease
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_block_slot_monotonicity(
        slots in prop::collection::vec(0u64..100_000, 1..30),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        let mut max_slot: Option<u64> = None;

        for (i, &slot) in slots.iter().enumerate() {
            let root = Some(hex_root(i as u8 + 1));
            let _ = stage_and_commit_block(&db, &pk, slot, root, SIGN_GVR);

            let current_max = db.last_signed_block_slot(&pk).unwrap();
            if let Some(prev) = max_slot {
                // Max slot must never decrease
                prop_assert!(
                    current_max.unwrap_or(0) >= prev,
                    "block slot watermark decreased: {} -> {:?}",
                    prev, current_max,
                );
            }
            if let Some(cm) = current_max {
                max_slot = Some(cm);
            }
        }
    }

    #[test]
    fn proptest_attestation_epoch_monotonicity(
        attestations in prop::collection::vec(
            (0u64..1000, 1u64..1000),
            1..30
        ),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        let mut max_target: Option<u64> = None;

        for (i, (source, target_offset)) in attestations.iter().enumerate() {
            let target = source + target_offset;
            let root = Some(hex_root(i as u8 + 1));
            let _ = stage_and_commit_attestation(
                &db, &pk, *source, target, root, SIGN_GVR,
            );

            let current_max = db.last_signed_attestation_epoch(&pk).unwrap();
            if let Some(prev) = max_target {
                // Max target epoch must never decrease
                prop_assert!(
                    current_max.unwrap_or(0) >= prev,
                    "attestation epoch watermark decreased: {} -> {:?}",
                    prev, current_max,
                );
            }
            if let Some(cm) = current_max {
                max_target = Some(cm);
            }
        }
    }
}

// =========================================================================
// Property 5: Independence
// Validator A's operations never affect validator B's outcomes
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_validator_independence_blocks(
        slot in 0u64..100_000,
        root in signing_root_strategy(),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk_a = pubkey(1);
        let pk_b = pubkey(2);

        // Validator A records a block
        stage_and_commit_block(&db, &pk_a, slot, root.clone(), SIGN_GVR).unwrap();

        // Validator B should still be able to propose at the same slot
        let result = stage_and_commit_block(&db, &pk_b, slot, root, SIGN_GVR);
        prop_assert!(result.is_ok(), "validator B blocked by validator A's block at slot {}", slot);
    }

    #[test]
    fn proptest_validator_independence_attestations(
        source in 0u64..50_000,
        target in 50_001u64..100_000,
        root in signing_root_strategy(),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk_a = pubkey(1);
        let pk_b = pubkey(2);

        // Validator A records an attestation
        stage_and_commit_attestation(
            &db, &pk_a, source, target, root.clone(), SIGN_GVR,
        )
        .unwrap();

        // Validator B should still be able to attest with the same epochs
        let result = stage_and_commit_attestation(
            &db, &pk_b, source, target, root, SIGN_GVR,
        );
        prop_assert!(
            result.is_ok(),
            "validator B blocked by validator A's attestation ({}, {})",
            source, target,
        );
    }
}

// =========================================================================
// Property 6: Re-signing safety
// Same message (same signing root) always succeeds
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_resign_block_always_succeeds(
        slot in 0u64..100_000,
        root in signing_root_strategy(),
        repeat_count in 2u8..10,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        for _ in 0..repeat_count {
            // Each call commits before the next stage (no overlapping guards)
            let result = stage_and_commit_block(&db, &pk, slot, root.clone(), SIGN_GVR);
            prop_assert!(result.is_ok(), "re-signing block at slot {} with same root failed", slot);
        }

        // Should still only have one record
        let blocks = db.get_blocks(&pk).unwrap();
        prop_assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn proptest_resign_attestation_always_succeeds(
        source in 0u64..50_000,
        target in 50_001u64..100_000,
        root in signing_root_strategy(),
        repeat_count in 2u8..10,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        for _ in 0..repeat_count {
            let result = stage_and_commit_attestation(
                &db, &pk, source, target, root.clone(), SIGN_GVR,
            );
            prop_assert!(
                result.is_ok(),
                "re-signing attestation ({}, {}) with same root failed",
                source, target,
            );
        }

        // Should still only have one record
        let attestations = db.get_attestations(&pk).unwrap();
        prop_assert_eq!(attestations.len(), 1);
    }
}

// =========================================================================
// Property 7: Watermark blocks at-or-below (RF1-01 / RF1-05)
// stage_* accepts a candidate T iff T > W for block slot and att target
// =========================================================================

proptest! {
    #![proptest_config(config())]

    /// For watermark W and candidate T (biased: ~1/3 equal / below / above),
    /// the production stage path accepts block slot and attestation target
    /// **iff** `T > W` (EIP-3076 equality blocking; pins RF1-01 under random
    /// input). Reject path asserts the watermark error variants.
    #[test]
    fn proptest_watermark_blocks_at_or_below(
        (w, t) in watermark_and_candidate_strategy(),
    ) {
        let pk = pubkey(1);
        let root = Some(hex_root(1));

        // --- Block slot watermark ---
        {
            let db = SlashingDb::open_in_memory().unwrap();
            db.set_block_watermark(&pk, w).unwrap();

            // Guard resolved before any subsequent stage (fresh DB here, but
            // the helper still commits/errs without holding the mutex).
            let result = stage_and_commit_block(&db, &pk, t, root.clone(), SIGN_GVR);
            if t > w {
                prop_assert!(
                    result.is_ok(),
                    "block slot T={t} > W={w} must be accepted, got {result:?}",
                );
            } else {
                prop_assert!(
                    matches!(
                        result,
                        Err(SlashingError::BelowBlockWatermark {
                            slot,
                            watermark_slot,
                            ..
                        }) if slot == t && watermark_slot == w
                    ),
                    "block slot T={t} <= W={w} must be BelowBlockWatermark, got {result:?}",
                );
            }
        }

        // --- Attestation target watermark ---
        // Source watermark set to 0 so source-epoch comparison cannot reject
        // independently of the target rule under test (source uses `<`, so
        // source == 0 is allowed).
        {
            let db = SlashingDb::open_in_memory().unwrap();
            db.set_attestation_watermark(&pk, 0, w).unwrap();

            let result = stage_and_commit_attestation(
                &db, &pk, 0, t, root, SIGN_GVR,
            );
            if t > w {
                prop_assert!(
                    result.is_ok(),
                    "att target T={t} > W={w} must be accepted, got {result:?}",
                );
            } else {
                prop_assert!(
                    matches!(
                        result,
                        Err(SlashingError::BelowAttestationWatermark {
                            target_epoch,
                            watermark_target,
                            ..
                        }) if target_epoch == t && watermark_target == w
                    ),
                    "att target T={t} <= W={w} must be BelowAttestationWatermark, got {result:?}",
                );
            }
        }
    }
}

fn near_i64_max() -> impl Strategy<Value = u64> {
    (i64::MAX as u64 - 64)..=(i64::MAX as u64 + 64)
}

fn no_surround(rows: &[(u64, u64)]) {
    for (s_i, t_i) in rows {
        for (s_j, t_j) in rows {
            assert!(
                !(*s_i < *s_j && *t_i > *t_j),
                "surround detected: ({s_i}, {t_i}) surrounds ({s_j}, {t_j})"
            );
        }
    }
}

// Values within 64 of `i64::MAX` keep no-double and no-surround.
// Values above `i64::MAX` are refused and write no row. An in-range source
// above its target is refused and writes no row (W4-S2).
proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_near_i64_max_keeps_no_double_no_surround_and_refuses_above(
        slot in near_i64_max(),
        source in near_i64_max(),
        target in near_i64_max(),
        root_a in signing_root_strategy(),
        root_b in signing_root_strategy(),
    ) {
        let limit = i64::MAX as u64;
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        if slot > limit {
            let err = db.reserve_block(&pk, slot, root_a.clone(), SIGN_GVR).unwrap_err();
            prop_assert!(
                matches!(err, SlashingError::OutOfRange { field: "slot", value } if value == slot),
                "slot {slot} must be OutOfRange, got {err:?}"
            );
            prop_assert!(db.get_blocks(&pk).unwrap().is_empty(), "refused slot must write no row");
        } else {
            let first = db.reserve_block(&pk, slot, root_a.clone(), SIGN_GVR);
            prop_assert!(
                first.is_ok(),
                "in-range slot {slot} must be accepted: {:?}",
                first.as_ref().err()
            );
            let blocks = db.get_blocks(&pk).unwrap();
            prop_assert_eq!(blocks.len(), 1);
            prop_assert_eq!(blocks[0].slot, slot);
            let second = db.reserve_block(&pk, slot, root_b.clone(), SIGN_GVR);
            if root_a == root_b {
                prop_assert!(second.is_ok(), "same root must re-sign: {:?}", second.as_ref().err());
            } else {
                prop_assert!(second.is_err(), "different root at slot {slot} must be refused");
            }
            prop_assert_eq!(db.get_blocks(&pk).unwrap().len(), 1, "no double proposal row");
        }

        let db = SlashingDb::open_in_memory().unwrap();
        if source > limit {
            let err = db
                .reserve_attestation(&pk, source, target, root_a.clone(), SIGN_GVR)
                .unwrap_err();
            prop_assert!(
                matches!(
                    err,
                    SlashingError::OutOfRange { field: "source_epoch", value } if value == source
                ),
                "source {source} must be OutOfRange before target, got {err:?}"
            );
            prop_assert!(db.get_attestations(&pk).unwrap().is_empty());
        } else if target > limit {
            let err = db
                .reserve_attestation(&pk, source, target, root_a.clone(), SIGN_GVR)
                .unwrap_err();
            prop_assert!(
                matches!(
                    err,
                    SlashingError::OutOfRange { field: "target_epoch", value } if value == target
                ),
                "target {target} must be OutOfRange, got {err:?}"
            );
            prop_assert!(db.get_attestations(&pk).unwrap().is_empty());
        } else if source > target {
            let err = db
                .reserve_attestation(&pk, source, target, root_a.clone(), SIGN_GVR)
                .unwrap_err();
            prop_assert!(
                matches!(
                    err,
                    SlashingError::SlashableAttestation(
                        AttestationSlashingViolation::SourceExceedsTarget {
                            source_epoch,
                            target_epoch,
                        }
                    ) if source_epoch == source && target_epoch == target
                ),
                "({source}, {target}) must be SourceExceedsTarget, got {err:?}"
            );
            prop_assert!(db.get_attestations(&pk).unwrap().is_empty());
        } else {
            let first = db.reserve_attestation(&pk, source, target, root_a.clone(), SIGN_GVR);
            prop_assert!(
                first.is_ok(),
                "in-range ({source}, {target}) must be accepted: {:?}",
                first.as_ref().err()
            );
            let rows = db.get_attestations(&pk).unwrap();
            prop_assert_eq!(rows.len(), 1);
            prop_assert_eq!(rows[0].source_epoch, source);
            prop_assert_eq!(rows[0].target_epoch, target);

            let second = db.reserve_attestation(&pk, source, target, root_b.clone(), SIGN_GVR);
            if root_a == root_b {
                prop_assert!(second.is_ok(), "same root must re-sign: {:?}", second.as_ref().err());
            } else {
                prop_assert!(second.is_err(), "different root at target {target} must be refused");
            }
            prop_assert_eq!(db.get_attestations(&pk).unwrap().len(), 1, "no double vote row");

            if source > 0 {
                let surround_target = target.saturating_add(1);
                let before = db.get_attestations(&pk).unwrap().len();
                let surround = db.reserve_attestation(
                    &pk,
                    source - 1,
                    surround_target,
                    Some(hex_root(0)),
                    SIGN_GVR,
                );
                if surround_target > limit {
                    prop_assert!(
                        matches!(
                            surround,
                            Err(SlashingError::OutOfRange { field: "target_epoch", .. })
                        ),
                        "surround target above i64::MAX must be refused, got {surround:?}"
                    );
                } else {
                    prop_assert!(
                        surround.is_err(),
                        "({} , {surround_target}) must not surround ({source}, {target})",
                        source - 1
                    );
                    prop_assert!(
                        !matches!(surround, Err(SlashingError::OutOfRange { .. })),
                        "in-range surround must be a rule refusal, got {surround:?}"
                    );
                }
                prop_assert_eq!(db.get_attestations(&pk).unwrap().len(), before);
            }

            // A second target below the stored minimum is `TargetEpochBelowMinimum`,
            // so the extra in-range row takes the next target above the row already
            // stored, sourced at the stored target (neither surrounds the other).
            if target < limit {
                let extra = db.reserve_attestation(
                    &pk,
                    target,
                    target + 1,
                    Some("0xnear-extra".into()),
                    SIGN_GVR,
                );
                prop_assert!(
                    extra.is_ok(),
                    "non-surrounding ({target}, {}) must be accepted: {:?}",
                    target + 1,
                    extra.as_ref().err()
                );
            }
            let stored: Vec<(u64, u64)> = db
                .get_attestations(&pk)
                .unwrap()
                .into_iter()
                .map(|row| (row.source_epoch, row.target_epoch))
                .collect();
            prop_assert!(!stored.is_empty(), "an in-range attestation must be stored");
            no_surround(&stored);
        }
    }
}
