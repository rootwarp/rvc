//! Targeted SQL implementations of the EIP-3076 history query traits.
//!
//! RF4-18: replace the full-history `SELECT … WHERE pubkey = ?` materialization
//! with one indexed query per rule question (`EXISTS`/`MIN`/point lookup).
//! Production [`stage_block`](crate::SlashingDb::stage_block) /
//! [`stage_attestation`](crate::SlashingDb::stage_attestation) use these impls.
//! The Vec-backed full-scan oracles stay under `cfg(test)` in [`crate::rules`]
//! for the old-vs-new equivalence proptest.

use eth_types::{Epoch, Slot};
use rusqlite::{Connection, OptionalExtension};

use crate::db::to_sql_i64;
use crate::error::SlashingError;
use crate::rules::{AttestationHistory, BlockHistory, ExistingAtt};

/// Non-unique indexes that make per-sign history queries index-only (no table scan).
///
/// Safe to call on every open: `CREATE INDEX IF NOT EXISTS`. Complements the v3
/// unique indexes `(pubkey, gvr, target/slot)` which cannot serve queries that
/// omit `genesis_validators_root` (gvr sits in the middle of the key).
pub(crate) fn ensure_history_indexes(conn: &Connection) -> Result<(), SlashingError> {
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_attestations_pubkey_target
            ON attestations(pubkey, target_epoch);
        CREATE INDEX IF NOT EXISTS idx_attestations_pubkey_source_target
            ON attestations(pubkey, source_epoch, target_epoch);
        CREATE INDEX IF NOT EXISTS idx_blocks_pubkey_slot
            ON blocks(pubkey, slot);
        ",
    )?;
    Ok(())
}

// ── Attestation history ───────────────────────────────────────────────────────

/// Answers each [`AttestationHistory`] question with a single indexed query.
pub(crate) struct TargetedSqlAttestationHistory<'a> {
    conn: &'a Connection,
    pubkey: &'a str,
}

impl<'a> TargetedSqlAttestationHistory<'a> {
    pub(crate) fn new(conn: &'a Connection, pubkey: &'a str) -> Self {
        Self { conn, pubkey }
    }
}

/// Production SQL for [`AttestationHistory::surrounding_exists`].
///
/// Shared with the work-bound unit test so counters measure this statement, not
/// a private copy. Do **not** add `ORDER BY` — that materializes the match set
/// into a TEMP B-TREE and defeats early `LIMIT 1` exit.
pub(crate) const SURROUNDING_EXISTS_SQL: &str = "SELECT source_epoch, target_epoch \
     FROM attestations \
     WHERE pubkey = ?1 AND source_epoch > ?2 AND target_epoch < ?3 \
     LIMIT 1";

impl AttestationHistory for TargetedSqlAttestationHistory<'_> {
    fn conflicting_at_target(&self, target: Epoch) -> Result<Option<ExistingAtt>, SlashingError> {
        // At most one row per (pubkey, gvr, target) under the v3 unique index.
        // No ORDER BY: a point lookup must not force a TEMP B-TREE.
        let target = to_sql_i64(target, "target_epoch")?;
        let row = self
            .conn
            .query_row(
                "SELECT source_epoch, target_epoch, signing_root \
                 FROM attestations \
                 WHERE pubkey = ?1 AND target_epoch = ?2 \
                 LIMIT 1",
                (self.pubkey, target),
                |row| {
                    Ok(ExistingAtt {
                        source_epoch: row.get::<_, i64>(0)? as Epoch,
                        target_epoch: row.get::<_, i64>(1)? as Epoch,
                        signing_root: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    fn surrounding_exists(
        &self,
        source: Epoch,
        target: Epoch,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError> {
        // Candidate surrounds existing: source < existing.source && target > existing.target
        // ⇔ existing.source > source && existing.target < target.
        //
        // EXISTS-style: any matching witness is enough for the violation payload.
        let source = to_sql_i64(source, "source_epoch")?;
        let target = to_sql_i64(target, "target_epoch")?;
        let row = self
            .conn
            .query_row(SURROUNDING_EXISTS_SQL, (self.pubkey, source, target), |row| {
                Ok((row.get::<_, i64>(0)? as Epoch, row.get::<_, i64>(1)? as Epoch))
            })
            .optional()?;
        Ok(row)
    }

    fn surrounded_exists(
        &self,
        source: Epoch,
        target: Epoch,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError> {
        // Candidate is surrounded: existing.source < source && existing.target > target.
        // Same EXISTS-style rule as surrounding_exists — no ORDER BY.
        let source = to_sql_i64(source, "source_epoch")?;
        let target = to_sql_i64(target, "target_epoch")?;
        let row = self
            .conn
            .query_row(
                "SELECT source_epoch, target_epoch \
                 FROM attestations \
                 WHERE pubkey = ?1 AND source_epoch < ?2 AND target_epoch > ?3 \
                 LIMIT 1",
                (self.pubkey, source, target),
                |row| Ok((row.get::<_, i64>(0)? as Epoch, row.get::<_, i64>(1)? as Epoch)),
            )
            .optional()?;
        Ok(row)
    }

    fn min_target(&self) -> Result<Option<Epoch>, SlashingError> {
        let min: Option<i64> = self
            .conn
            .query_row(
                "SELECT MIN(target_epoch) FROM attestations WHERE pubkey = ?1",
                (self.pubkey,),
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(min.map(|v| v as Epoch))
    }
}

// ── Block history ─────────────────────────────────────────────────────────────

/// Answers each [`BlockHistory`] question with a point lookup / `MIN(slot)`.
pub(crate) struct TargetedSqlBlockHistory<'a> {
    conn: &'a Connection,
    pubkey: &'a str,
}

impl<'a> TargetedSqlBlockHistory<'a> {
    pub(crate) fn new(conn: &'a Connection, pubkey: &'a str) -> Self {
        Self { conn, pubkey }
    }
}

impl BlockHistory for TargetedSqlBlockHistory<'_> {
    fn signing_root_at_slot(&self, slot: Slot) -> Result<Option<Option<String>>, SlashingError> {
        // Outer Option = row presence; inner = stored signing_root (NULL → None).
        // `optional()` maps QueryReturnedNoRows → None without collapsing a NULL root.
        let existing: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT signing_root FROM blocks \
                 WHERE pubkey = ?1 AND slot = ?2 \
                 LIMIT 1",
                (self.pubkey, to_sql_i64(slot, "slot")?),
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        Ok(existing)
    }

    fn min_slot(&self) -> Result<Option<Slot>, SlashingError> {
        let min: Option<i64> = self
            .conn
            .query_row("SELECT MIN(slot) FROM blocks WHERE pubkey = ?1", (self.pubkey,), |row| {
                row.get(0)
            })
            .optional()?
            .flatten();
        Ok(min.map(|v| v as Slot))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{AttestationSlashingViolation, BlockSlashingViolation, SlashingError};
    use crate::rules::{
        check_attestation, check_block, AttestationCandidate, AttestationVerdict,
        AttestationWatermarks, BlockCandidate, BlockVerdict, BlockWatermarks,
        FullScanAttestationHistory, FullScanBlockHistory,
    };
    use crate::SlashingDb;
    use proptest::prelude::*;
    use rusqlite::StatementStatus;

    const PK: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// Noise validators: overlapping epochs/slots must not bleed into subject checks.
    const PK_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PK_C: &str = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const GVR: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

    fn seed_attestation(
        conn: &Connection,
        pubkey: &str,
        source: Epoch,
        target: Epoch,
        root: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO attestations \
             (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root) \
             VALUES ('local-vc', ?1, ?2, ?3, ?4, ?5)",
            (
                pubkey,
                i64::try_from(source).expect("test source fits i64"),
                i64::try_from(target).expect("test target fits i64"),
                root,
                GVR,
            ),
        )
        .expect("insert attestation");
    }

    fn seed_block(conn: &Connection, pubkey: &str, slot: Slot, root: Option<&str>) {
        conn.execute(
            "INSERT INTO blocks \
             (client_cn, pubkey, slot, signing_root, genesis_validators_root) \
             VALUES ('local-vc', ?1, ?2, ?3, ?4)",
            (pubkey, i64::try_from(slot).expect("test slot fits i64"), root, GVR),
        )
        .expect("insert block");
    }

    /// Insert overlapping history for noise pubkeys so a missing `WHERE pubkey = ?`
    /// would change the subject oracle and fail the equivalence proptest.
    fn seed_noise_attestation_history(conn: &Connection) {
        for (pk, base) in [(PK_B, 0u64), (PK_C, 50u64)] {
            for i in 0..30 {
                let source = base + i;
                let target = source + 5;
                seed_attestation(conn, pk, source, target, Some("0xnoise"));
            }
        }
    }

    fn seed_noise_block_history(conn: &Connection) {
        for (pk, base) in [(PK_B, 0u64), (PK_C, 100u64)] {
            for i in 0..30 {
                seed_block(conn, pk, base + i, Some("0xnoise"));
            }
        }
    }

    fn load_full_scan_att(conn: &Connection, pubkey: &str) -> FullScanAttestationHistory {
        let mut stmt = conn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root \
                 FROM attestations WHERE pubkey = ?1 ORDER BY id ASC",
            )
            .unwrap();
        let rows = stmt
            .query_map((pubkey,), |row| {
                Ok(ExistingAtt {
                    source_epoch: row.get::<_, i64>(0)? as Epoch,
                    target_epoch: row.get::<_, i64>(1)? as Epoch,
                    signing_root: row.get(2)?,
                })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        FullScanAttestationHistory::new(rows)
    }

    fn load_full_scan_block(conn: &Connection, pubkey: &str) -> FullScanBlockHistory {
        let mut stmt = conn
            .prepare("SELECT slot, signing_root FROM blocks WHERE pubkey = ?1 ORDER BY id ASC")
            .unwrap();
        let rows = stmt
            .query_map((pubkey,), |row| {
                Ok((row.get::<_, i64>(0)? as Slot, row.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        FullScanBlockHistory::new(rows)
    }

    /// Normalize a check result for equivalence.
    ///
    /// Surround/surrounded witnesses may differ between FullScan (first-by-id) and
    /// TargetedSql (any match, no ORDER BY). Only the violation *kind* and candidate
    /// epochs are compared for those arms.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum AttOutcome {
        Ok(AttestationVerdict),
        DoubleVote { target_epoch: Epoch },
        Surrounding { new_source: Epoch, new_target: Epoch },
        Surrounded { new_source: Epoch, new_target: Epoch },
        TargetBelowMin { target_epoch: Epoch, min_target: Epoch },
        BelowSourceWm { source_epoch: Epoch, watermark_source: Epoch },
        BelowTargetWm { target_epoch: Epoch, watermark_target: Epoch },
        Other(String),
    }

    fn att_outcome(r: Result<AttestationVerdict, SlashingError>) -> AttOutcome {
        match r {
            Ok(v) => AttOutcome::Ok(v),
            Err(SlashingError::SlashableAttestation(v)) => match v {
                AttestationSlashingViolation::DoubleVote { target_epoch } => {
                    AttOutcome::DoubleVote { target_epoch }
                }
                AttestationSlashingViolation::SurroundingVote {
                    new_source, new_target, ..
                } => AttOutcome::Surrounding { new_source, new_target },
                AttestationSlashingViolation::SurroundedVote { new_source, new_target, .. } => {
                    AttOutcome::Surrounded { new_source, new_target }
                }
                AttestationSlashingViolation::TargetEpochBelowMinimum {
                    target_epoch,
                    min_target,
                } => AttOutcome::TargetBelowMin { target_epoch, min_target },
                other @ AttestationSlashingViolation::SourceExceedsTarget { .. } => {
                    AttOutcome::Other(other.to_string())
                }
            },
            Err(SlashingError::BelowAttestationSourceWatermark {
                source_epoch,
                watermark_source,
                ..
            }) => AttOutcome::BelowSourceWm { source_epoch, watermark_source },
            Err(SlashingError::BelowAttestationWatermark {
                target_epoch,
                watermark_target,
                ..
            }) => AttOutcome::BelowTargetWm { target_epoch, watermark_target },
            Err(e) => AttOutcome::Other(e.to_string()),
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum BlockOutcome {
        Ok(BlockVerdict),
        DoubleProposal { slot: Slot },
        SlotBelowMin { slot: Slot, min_slot: Slot },
        BelowWm { slot: Slot, watermark_slot: Slot },
        Other(String),
    }

    fn block_outcome(r: Result<BlockVerdict, SlashingError>) -> BlockOutcome {
        match r {
            Ok(v) => BlockOutcome::Ok(v),
            Err(SlashingError::SlashableBlock(v)) => match v {
                BlockSlashingViolation::DoubleBlockProposal { slot } => {
                    BlockOutcome::DoubleProposal { slot }
                }
                BlockSlashingViolation::SlotBelowMinimum { slot, min_slot } => {
                    BlockOutcome::SlotBelowMin { slot, min_slot }
                }
            },
            Err(SlashingError::BelowBlockWatermark { slot, watermark_slot, .. }) => {
                BlockOutcome::BelowWm { slot, watermark_slot }
            }
            Err(e) => BlockOutcome::Other(e.to_string()),
        }
    }

    // Phase-gate equivalence: FullScan and TargetedSql agree on random histories.
    // ≥ 10k cases (plan risk note). Cases are cheap (in-memory SQLite + pure checks).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn proptest_full_scan_and_targeted_sql_agree_on_random_histories(
            history in prop::collection::vec(
                (0u64..200u64, 1u64..50u64, 0u8..5u8),
                0..40
            ),
            cand_source in 0u64..250u64,
            cand_target_offset in 1u64..60u64,
            cand_root_byte in 0u8..5u8,
            wm_source in prop::option::of(0u64..100u64),
            wm_target in prop::option::of(0u64..200u64),
            strict in proptest::bool::ANY,
        ) {
            let db = SlashingDb::open_in_memory().unwrap();
            let conn = db.conn.lock();

            // Foreign validators with overlapping epochs — missing pubkey filter fails here.
            seed_noise_attestation_history(&conn);

            // Dedup by target_epoch (unique index); keep first insert order.
            let mut seen_targets = std::collections::HashSet::new();
            for (source, target_off, root_b) in &history {
                let target = source + target_off;
                if !seen_targets.insert(target) {
                    continue;
                }
                let root = if *root_b == 0 {
                    None
                } else {
                    Some(format!("0x{:02x}", root_b))
                };
                seed_attestation(
                    &conn,
                    PK,
                    *source,
                    target,
                    root.as_deref(),
                );
            }

            // FullScan loads only the subject pubkey; TargetedSql must filter the same way.
            let full = load_full_scan_att(&conn, PK);
            let targeted = TargetedSqlAttestationHistory::new(&conn, PK);
            let watermarks = AttestationWatermarks {
                source: wm_source,
                target: wm_target,
            };
            let cand_target = cand_source + cand_target_offset;
            let cand_root = if cand_root_byte == 0 {
                None
            } else {
                Some(format!("0x{:02x}", cand_root_byte))
            };
            let candidate = AttestationCandidate {
                source_epoch: cand_source,
                target_epoch: cand_target,
                signing_root: cand_root,
            };

            let full_r = check_attestation(PK, &full, &watermarks, &candidate, strict);
            let targeted_r = check_attestation(PK, &targeted, &watermarks, &candidate, strict);
            prop_assert_eq!(
                att_outcome(full_r),
                att_outcome(targeted_r),
                "full-scan and targeted SQL must agree (multi-pubkey DB)"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        #[test]
        fn proptest_full_scan_and_targeted_sql_agree_on_block_histories(
            history in prop::collection::vec((0u64..500u64, 0u8..5u8), 0..30),
            cand_slot in 0u64..600u64,
            cand_root_byte in 0u8..5u8,
            wm_block in prop::option::of(0u64..400u64),
            strict in proptest::bool::ANY,
        ) {
            let db = SlashingDb::open_in_memory().unwrap();
            let conn = db.conn.lock();

            seed_noise_block_history(&conn);

            let mut seen_slots = std::collections::HashSet::new();
            for (slot, root_b) in &history {
                if !seen_slots.insert(*slot) {
                    continue;
                }
                let root = if *root_b == 0 {
                    None
                } else {
                    Some(format!("0x{:02x}", root_b))
                };
                seed_block(&conn, PK, *slot, root.as_deref());
            }

            let full = load_full_scan_block(&conn, PK);
            let targeted = TargetedSqlBlockHistory::new(&conn, PK);
            let watermarks = BlockWatermarks { block: wm_block };
            let cand_root = if cand_root_byte == 0 {
                None
            } else {
                Some(format!("0x{:02x}", cand_root_byte))
            };
            let candidate = BlockCandidate {
                slot: cand_slot,
                signing_root: cand_root,
            };

            let full_r = check_block(PK, &full, &watermarks, &candidate, strict);
            let targeted_r = check_block(PK, &targeted, &watermarks, &candidate, strict);
            prop_assert_eq!(
                block_outcome(full_r),
                block_outcome(targeted_r),
                "block full-scan and targeted SQL must agree (multi-pubkey DB)"
            );
        }
    }

    /// Deterministic surround cases: targeted matches full-scan on known corpus.
    #[test]
    fn test_targeted_surround_detection_matches_full_scan_on_conformance_corpus() {
        struct Case {
            existing: (Epoch, Epoch, Option<&'static str>),
            candidate: (Epoch, Epoch, Option<&'static str>),
            label: &'static str,
        }
        let cases = [
            // surrounding: new (1,10) surrounds existing (3,7)
            Case {
                existing: (3, 7, Some("0xnarrow")),
                candidate: (1, 10, Some("0xwide")),
                label: "surrounding",
            },
            // surrounded: new (5,7) surrounded by existing (3,10)
            Case {
                existing: (3, 10, Some("0xwide")),
                candidate: (5, 7, Some("0xnarrow")),
                label: "surrounded",
            },
            // double vote
            Case {
                existing: (1, 10, Some("0xa")),
                candidate: (2, 10, Some("0xb")),
                label: "double_vote",
            },
            // accept non-conflicting
            Case { existing: (1, 5, Some("0xa")), candidate: (5, 8, Some("0xb")), label: "accept" },
            // resign
            Case {
                existing: (1, 5, Some("0xsame")),
                candidate: (1, 5, Some("0xsame")),
                label: "resign",
            },
        ];

        for case in &cases {
            let db = SlashingDb::open_in_memory().unwrap();
            let conn = db.conn.lock();
            seed_noise_attestation_history(&conn);
            seed_attestation(&conn, PK, case.existing.0, case.existing.1, case.existing.2);

            let full = load_full_scan_att(&conn, PK);
            let targeted = TargetedSqlAttestationHistory::new(&conn, PK);
            let cand = AttestationCandidate {
                source_epoch: case.candidate.0,
                target_epoch: case.candidate.1,
                signing_root: case.candidate.2.map(str::to_string),
            };
            let wm = AttestationWatermarks::default();
            let fo = att_outcome(check_attestation(PK, &full, &wm, &cand, false));
            let to = att_outcome(check_attestation(PK, &targeted, &wm, &cand, false));
            assert_eq!(fo, to, "mismatch on corpus case {}", case.label);
        }
    }

    /// Explicit isolation: foreign pubkey history must not affect subject checks.
    #[test]
    fn test_targeted_sql_isolates_by_pubkey() {
        let db = SlashingDb::open_in_memory().unwrap();
        let conn = db.conn.lock();
        // Noise: wide surrounding attestation on other keys.
        seed_attestation(&conn, PK_B, 0, 1000, Some("0xb"));
        seed_attestation(&conn, PK_C, 1, 999, Some("0xc"));
        // Subject has a narrow att only.
        seed_attestation(&conn, PK, 10, 20, Some("0xa"));

        let history = TargetedSqlAttestationHistory::new(&conn, PK);
        // Would be surrounded by PK_B/PK_C if pubkey filter were missing.
        let candidate = AttestationCandidate {
            source_epoch: 50,
            target_epoch: 60,
            signing_root: Some("0xnew".into()),
        };
        let v =
            check_attestation(PK, &history, &AttestationWatermarks::default(), &candidate, false)
                .expect("foreign history must not surround subject");
        assert_eq!(v, AttestationVerdict::Stage);
    }

    fn explain_plan(
        conn: &Connection,
        sql: &str,
        params: &[&dyn rusqlite::types::ToSql],
    ) -> String {
        let explain_sql = format!("EXPLAIN QUERY PLAN {sql}");
        let mut stmt = conn.prepare(&explain_sql).unwrap();
        let rows = stmt
            .query_map(params, |row| {
                // detail is column 3 in EXPLAIN QUERY PLAN
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows.join(" | ")
    }

    fn assert_no_table_scan(plan: &str, query_label: &str) {
        // SQLite may say "SCAN <table>" for a full table walk. Index use is
        // "SEARCH … USING INDEX/COVERING INDEX" (or "USING INTEGER PRIMARY KEY").
        let upper = plan.to_uppercase();
        assert!(
            !upper.contains("SCAN TABLE ATTESTATIONS")
                && !upper.contains("SCAN ATTESTATIONS")
                && !upper.contains("SCAN TABLE BLOCKS")
                && !upper.contains("SCAN BLOCKS"),
            "{query_label} must use an index, plan was: {plan}"
        );
        assert!(
            upper.contains("USING INDEX")
                || upper.contains("USING COVERING INDEX")
                || upper.contains("USING INTEGER PRIMARY KEY"),
            "{query_label} expected INDEX in plan, got: {plan}"
        );
        assert!(
            !upper.contains("TEMP B-TREE"),
            "{query_label} must not force TEMP B-TREE (ORDER BY materialization), plan was: {plan}"
        );
    }

    #[test]
    fn test_targeted_double_vote_lookup_uses_unique_index() {
        let db = SlashingDb::open_in_memory().unwrap();
        let conn = db.conn.lock();
        // Seed enough rows so a bad plan would matter.
        for i in 0..100 {
            seed_attestation(&conn, PK, i, i + 1, Some("0x01"));
        }
        seed_block(&conn, PK, 42, Some("0xblock"));

        let plan = explain_plan(
            &conn,
            "SELECT source_epoch, target_epoch, signing_root \
             FROM attestations WHERE pubkey = ?1 AND target_epoch = ?2 \
             LIMIT 1",
            &[&PK as &dyn rusqlite::types::ToSql, &50i64],
        );
        assert_no_table_scan(&plan, "conflicting_at_target");
        assert!(
            plan.contains("idx_attestations_pubkey_target")
                || plan.contains("idx_attestations_pubkey_gvr_target")
                || plan.contains("idx_attestations_pubkey_source_target"),
            "double-vote plan should hit a pubkey/target index: {plan}"
        );

        // Wide surround: many rows match source_epoch > 1 AND target_epoch < 100.
        // Without ORDER BY the plan must still use the index and not TEMP B-TREE.
        let surround_plan = explain_plan(
            &conn,
            SURROUNDING_EXISTS_SQL,
            &[&PK as &dyn rusqlite::types::ToSql, &1i64, &100i64],
        );
        assert_no_table_scan(&surround_plan, "surrounding_exists");

        let surrounded_plan = explain_plan(
            &conn,
            "SELECT source_epoch, target_epoch FROM attestations \
             WHERE pubkey = ?1 AND source_epoch < ?2 AND target_epoch > ?3 \
             LIMIT 1",
            &[&PK as &dyn rusqlite::types::ToSql, &50i64, &10i64],
        );
        assert_no_table_scan(&surrounded_plan, "surrounded_exists");

        let min_plan = explain_plan(
            &conn,
            "SELECT MIN(target_epoch) FROM attestations WHERE pubkey = ?1",
            &[&PK as &dyn rusqlite::types::ToSql],
        );
        assert_no_table_scan(&min_plan, "min_target");

        let block_plan = explain_plan(
            &conn,
            "SELECT signing_root FROM blocks WHERE pubkey = ?1 AND slot = ?2 \
             LIMIT 1",
            &[&PK as &dyn rusqlite::types::ToSql, &42i64],
        );
        assert_no_table_scan(&block_plan, "signing_root_at_slot");

        let min_slot_plan = explain_plan(
            &conn,
            "SELECT MIN(slot) FROM blocks WHERE pubkey = ?1",
            &[&PK as &dyn rusqlite::types::ToSql],
        );
        assert_no_table_scan(&min_slot_plan, "min_slot");
    }

    /// Production [`SURROUNDING_EXISTS_SQL`] stays an index `LIMIT 1` lookup:
    /// no sort, no full scan, and VM/filter work does not grow with history size.
    ///
    /// The sole matching row is inserted after a long non-matching prefix so a
    /// table scan from the start would pay O(N). Wall-clock ratios flake under
    /// llvm-cov; these statement counters are deterministic.
    #[test]
    fn test_surrounding_exists_sql_is_index_limit_without_sort_or_fullscan() {
        #[derive(Debug, Clone, Copy)]
        struct SurroundWork {
            surrounding_vm: i32,
            surrounding_filter: i32,
            sort: i32,
            fullscan: i32,
            query_runs: i32,
        }

        /// `non_matching` rows with `source = 0` (not a surround witness for
        /// candidate `source = 0`), then one late match (`source = 1`).
        fn surround_work(non_matching: usize) -> SurroundWork {
            let db = SlashingDb::open_in_memory().unwrap();
            {
                let conn = db.conn.lock();
                for i in 0..non_matching {
                    // source == 0 ⇒ not `(source > 0 AND target < cand_target)`.
                    seed_attestation(&conn, PK, 0, (i as u64) + 1, Some("0x01"));
                }
                let match_target = (non_matching as u64) + 1;
                seed_attestation(&conn, PK, 1, match_target, Some("0x02"));
            }

            let conn = db.conn.lock();
            let cand_source = 0i64;
            let cand_target = i64::try_from(non_matching).expect("non_matching fits i64") + 10;
            let mut surrounding = conn.prepare(SURROUNDING_EXISTS_SQL).unwrap();
            let hit = surrounding
                .query_row((PK, cand_source, cand_target), |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                })
                .optional()
                .unwrap();
            assert_eq!(
                hit,
                Some((1, i64::try_from(non_matching).expect("non_matching fits i64") + 1)),
                "late witness must be found"
            );

            let surrounding_vm = surrounding.get_status(StatementStatus::VmStep);
            let surrounding_filter = surrounding.get_status(StatementStatus::FilterHit)
                + surrounding.get_status(StatementStatus::FilterMiss);
            let sort = surrounding.get_status(StatementStatus::Sort);
            let fullscan = surrounding.get_status(StatementStatus::FullscanStep);
            let surrounding_runs = surrounding.get_status(StatementStatus::Run);

            let history = TargetedSqlAttestationHistory::new(&conn, PK);
            let candidate = AttestationCandidate {
                source_epoch: 0,
                target_epoch: (non_matching as u64) + 10,
                signing_root: Some("0xaa".into()),
            };
            let outcome = check_attestation(
                PK,
                &history,
                &AttestationWatermarks::default(),
                &candidate,
                false,
            );
            assert!(
                matches!(
                    outcome,
                    Err(SlashingError::SlashableAttestation(
                        AttestationSlashingViolation::SurroundingVote { .. }
                    ))
                ),
                "candidate must be a surrounding vote via production history, got {outcome:?}"
            );

            SurroundWork {
                surrounding_vm,
                surrounding_filter,
                sort,
                fullscan,
                query_runs: surrounding_runs,
            }
        }

        let small = surround_work(10);
        let large = surround_work(10_000);

        assert_eq!(small.sort, 0, "production SQL must not SORT (small={small:?})");
        assert_eq!(large.sort, 0, "production SQL must not SORT (large={large:?})");
        assert_eq!(small.fullscan, 0, "production SQL must not FULLSCAN (small={small:?})");
        assert_eq!(large.fullscan, 0, "production SQL must not FULLSCAN (large={large:?})");

        assert_eq!(
            small.query_runs, large.query_runs,
            "surrounding_exists is one statement run; runs must not grow with N \
             (small={small:?}, large={large:?})"
        );
        assert_eq!(small.query_runs, 1, "exactly one LIMIT 1 run per surround question");

        // O(N) full-scan / TEMP B-TREE materialization would grow roughly with N
        // (~1000× from 10 → 10k). LIMIT 1 + index keeps VM/filter work near-constant.
        let vm_factor = (large.surrounding_vm.max(1) as u64)
            .checked_div(small.surrounding_vm.max(1) as u64)
            .unwrap_or(0);
        let filter_factor = (large.surrounding_filter.max(1) as u64)
            .checked_div(small.surrounding_filter.max(1) as u64)
            .unwrap_or(0);
        assert!(
            vm_factor < 50 && filter_factor < 50,
            "production surrounding_exists work not bounded: small={small:?}, large={large:?} \
             (vm_factor={vm_factor}, filter_factor={filter_factor})"
        );
    }

    /// A value wrapped by the old `as i64` bind is not migrated.
    ///
    /// A wrapped target reads back at 2^63 and a later ordinary surround is refused.
    /// A wrapped slot row refuses a later ordinary slot (`min_slot` reads back at 2^63).
    /// A wrapped block watermark does the same via the unsigned floor.
    /// A source-only wrapped row `(i64::MIN, 101)` does not block `(99, 102)`.
    #[test]
    fn legacy_wrapped_target_and_slot_refuse_later_signs_source_only_wrap_does_not() {
        let gvr = [0u8; 32];
        let gvr_hex = SlashingDb::root_to_hex(&gvr);
        let stored = crate::db::normalize_pubkey(PK).expect("pubkey");
        let pk = stored.as_ref();

        {
            let db = SlashingDb::open_in_memory().expect("open");
            {
                let conn = db.conn.lock();
                conn.execute(
                    "INSERT INTO attestations \
                     (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root) \
                     VALUES ('local-vc', ?1, ?2, ?3, '0xleg', ?4)",
                    (pk, 100i64, i64::MIN, gvr_hex.as_str()),
                )
                .expect("seed wrapped target");
            }
            let err = db
                .reserve_attestation(PK, 99, 101, Some("0xnext".into()), &gvr)
                .expect_err("wrapped target must refuse (99, 101)");
            assert!(
                matches!(
                    err,
                    SlashingError::SlashableAttestation(
                        AttestationSlashingViolation::SurroundingVote {
                            new_source: 99,
                            new_target: 101,
                            existing_source: 100,
                            existing_target,
                        }
                    ) if existing_target == 1 << 63
                ),
                "wrapped target stays a surround refusal, got {err:?}"
            );
            assert_eq!(db.get_attestations(PK).expect("rows").len(), 1);
        }

        {
            let db = SlashingDb::open_in_memory().expect("open");
            {
                let conn = db.conn.lock();
                conn.execute(
                    "INSERT INTO blocks \
                     (client_cn, pubkey, slot, signing_root, genesis_validators_root) \
                     VALUES ('local-vc', ?1, ?2, '0xleg', ?3)",
                    (pk, i64::MIN, gvr_hex.as_str()),
                )
                .expect("seed wrapped slot");
            }
            let err = db
                .reserve_block(PK, 100, Some("0xnext".into()), &gvr)
                .expect_err("wrapped slot must refuse an ordinary slot");
            assert!(
                matches!(
                    err,
                    SlashingError::SlashableBlock(BlockSlashingViolation::SlotBelowMinimum {
                        slot: 100,
                        min_slot,
                    }) if min_slot == 1 << 63
                ),
                "wrapped slot stays a refusal, got {err:?}"
            );
            assert!(db.get_blocks(PK).expect("rows").iter().all(|block| block.slot != 100));
        }

        {
            let db = SlashingDb::open_in_memory().expect("open");
            {
                let conn = db.conn.lock();
                conn.execute(
                    "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, 'block', ?2)",
                    (pk, i64::MIN),
                )
                .expect("seed wrapped block watermark");
            }
            let err = db
                .reserve_block(PK, 100, Some("0xnext".into()), &gvr)
                .expect_err("wrapped block watermark must refuse an ordinary slot");
            assert!(
                matches!(
                    err,
                    SlashingError::BelowBlockWatermark { slot: 100, watermark_slot, .. }
                        if watermark_slot == 1 << 63
                ),
                "wrapped block watermark stays a refusal, got {err:?}"
            );
            assert!(db.get_blocks(PK).expect("rows").is_empty());
        }

        {
            let db = SlashingDb::open_in_memory().expect("open");
            {
                let conn = db.conn.lock();
                conn.execute(
                    "INSERT INTO attestations \
                     (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root) \
                     VALUES ('local-vc', ?1, ?2, ?3, '0xleg', ?4)",
                    (pk, i64::MIN, 101i64, gvr_hex.as_str()),
                )
                .expect("seed source-only wrap");
            }
            let reserved = db
                .reserve_attestation(PK, 99, 102, Some("0xnext".into()), &gvr)
                .expect("source-only wrap must not block (99, 102)");
            assert!(reserved.inserted);
            let rows = db.get_attestations(PK).expect("rows");
            assert!(
                rows.iter().any(|row| row.source_epoch == 99 && row.target_epoch == 102),
                "got {rows:?}"
            );
        }
    }
}
