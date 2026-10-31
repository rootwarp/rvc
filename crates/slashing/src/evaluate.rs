//! The one EIP-3076 decision per sign, shared by `stage_*` and group commit.
//!
//! Each helper derives the fork-aware strict flag, reads the watermarks and
//! the targeted history on the caller's connection, and runs the pure rule
//! check. The caller owns the transaction: `stage_*` rolls back on `Err`,
//! group commit rejects the member or aborts the batch.

use rusqlite::Connection;

use crate::db::watermarks::{read_watermark, WatermarkKind};
use crate::error::{AttestationSlashingViolation, SlashingError};
use crate::history::{TargetedSqlAttestationHistory, TargetedSqlBlockHistory};
use crate::rules::{
    check_attestation, check_block, AttestationCandidate, AttestationVerdict,
    AttestationWatermarks, BlockCandidate, BlockVerdict, BlockWatermarks,
};
use crate::SlashingDb;
use eth_types::{Epoch, Slot, SLOTS_PER_EPOCH};

/// Block proposal check. Strict from the slot's epoch.
pub(crate) fn evaluate_block(
    db: &SlashingDb,
    conn: &Connection,
    pubkey: &str,
    slot: Slot,
    signing_root: Option<String>,
) -> Result<BlockVerdict, SlashingError> {
    let strict = db.fork_aware_strict(slot / SLOTS_PER_EPOCH);
    let watermarks = BlockWatermarks { block: read_watermark(conn, pubkey, WatermarkKind::Block)? };
    let history = TargetedSqlBlockHistory::new(conn, pubkey);
    let candidate = BlockCandidate { slot, signing_root };
    check_block(pubkey, &history, &watermarks, &candidate, strict)
}

/// Attestation check. Strict from the target epoch.
///
/// A source above its target is refused before any history read (Lighthouse
/// `SourceExceedsTarget`); the signer-server paths have no caller-side filter.
pub(crate) fn evaluate_attestation(
    db: &SlashingDb,
    conn: &Connection,
    pubkey: &str,
    source_epoch: Epoch,
    target_epoch: Epoch,
    signing_root: Option<String>,
) -> Result<AttestationVerdict, SlashingError> {
    if source_epoch > target_epoch {
        return Err(AttestationSlashingViolation::SourceExceedsTarget {
            source_epoch,
            target_epoch,
        }
        .into());
    }
    let strict = db.fork_aware_strict(target_epoch);
    let watermarks = AttestationWatermarks {
        source: read_watermark(conn, pubkey, WatermarkKind::AttestationSource)?,
        target: read_watermark(conn, pubkey, WatermarkKind::AttestationTarget)?,
    };
    let history = TargetedSqlAttestationHistory::new(conn, pubkey);
    let candidate = AttestationCandidate { source_epoch, target_epoch, signing_root };
    check_attestation(pubkey, &history, &watermarks, &candidate, strict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::normalize_pubkey;
    use crate::error::BlockSlashingViolation;
    use eth_types::Root;

    const PK: &str = "0xfeed01";
    const GVR: Root = [0u8; 32];
    /// Gloas fork epoch E. NULL == NULL is a re-sign below E and a double
    /// sign at or above it (FU-33).
    const FORK: Epoch = 10;

    fn fresh_db() -> (SlashingDb, String) {
        let db = SlashingDb::open_in_memory().expect("open");
        let pubkey = normalize_pubkey(PK).expect("pubkey").to_string();
        (db, pubkey)
    }

    fn block(db: &SlashingDb, pubkey: &str, slot: Slot) -> Result<BlockVerdict, SlashingError> {
        let conn = db.conn.lock();
        evaluate_block(db, &conn, pubkey, slot, None)
    }

    fn attestation(
        db: &SlashingDb,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
    ) -> Result<AttestationVerdict, SlashingError> {
        let conn = db.conn.lock();
        evaluate_attestation(db, &conn, pubkey, source_epoch, target_epoch, None)
    }

    fn assert_double_proposal(result: Result<BlockVerdict, SlashingError>, slot: Slot) {
        match result {
            Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot: got,
            })) => assert_eq!(got, slot),
            other => panic!("slot {slot}: expected DoubleBlockProposal, got {other:?}"),
        }
    }

    fn assert_double_vote(result: Result<AttestationVerdict, SlashingError>, target: Epoch) {
        match result {
            Err(SlashingError::SlashableAttestation(
                AttestationSlashingViolation::DoubleVote { target_epoch },
            )) => assert_eq!(target_epoch, target),
            other => panic!("target {target}: expected DoubleVote, got {other:?}"),
        }
    }

    #[test]
    fn block_strict_flag_uses_the_slot_epoch_across_the_fork() {
        let last_lenient = FORK * SLOTS_PER_EPOCH - 1;
        let first_strict = FORK * SLOTS_PER_EPOCH;
        let (db, pubkey) = fresh_db();
        for slot in [last_lenient, first_strict] {
            db.seed_block(PK, slot, None, &GVR).expect("seed NULL-root block");
        }

        assert_eq!(block(&db, &pubkey, last_lenient).expect("lenient"), BlockVerdict::Resign);
        assert_eq!(block(&db, &pubkey, first_strict).expect("lenient"), BlockVerdict::Resign);

        db.set_gloas_fork_epoch(FORK);
        assert_eq!(
            block(&db, &pubkey, last_lenient).expect("epoch E-1 stays lenient"),
            BlockVerdict::Resign
        );
        assert_double_proposal(block(&db, &pubkey, first_strict), first_strict);

        db.set_gloas_fork_epoch(u64::MAX);
        db.set_strict_semantics(true);
        assert_double_proposal(block(&db, &pubkey, last_lenient), last_lenient);
    }

    #[test]
    fn attestation_strict_flag_uses_the_target_epoch_across_the_fork() {
        let (db, pubkey) = fresh_db();
        // Both sources sit below E, so only the target epoch can cross it.
        db.seed_attestation(PK, FORK - 2, FORK - 1, None, &GVR).expect("seed (E-2, E-1)");
        db.seed_attestation(PK, FORK - 1, FORK, None, &GVR).expect("seed (E-1, E)");

        assert_eq!(
            attestation(&db, &pubkey, FORK - 1, FORK).expect("lenient"),
            AttestationVerdict::Duplicate
        );

        db.set_gloas_fork_epoch(FORK);
        assert_eq!(
            attestation(&db, &pubkey, FORK - 2, FORK - 1).expect("target E-1 stays lenient"),
            AttestationVerdict::Duplicate
        );
        assert_double_vote(attestation(&db, &pubkey, FORK - 1, FORK), FORK);

        db.set_gloas_fork_epoch(u64::MAX);
        db.set_strict_semantics(true);
        assert_double_vote(attestation(&db, &pubkey, FORK - 2, FORK - 1), FORK - 1);
    }
}
