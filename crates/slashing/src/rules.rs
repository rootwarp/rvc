//! Pure EIP-3076 rule checks behind a history-query seam.
//!
//! Rule evaluation is deliberately free of `rusqlite`. Production
//! [`stage_block`](crate::SlashingDb::stage_block) /
//! [`stage_attestation`](crate::SlashingDb::stage_attestation) build a
//! targeted SQL history impl (see `history` module) and translate the verdict.
//! The Vec-backed full-scan history types remain under
//! `cfg(any(test, feature = "test-utils"))` as the old-vs-new equivalence
//! oracle.

use eth_types::{Epoch, Slot};
use observability::logging::TruncatedPubkey;

use crate::error::{AttestationSlashingViolation, BlockSlashingViolation, SlashingError};

// ── History query traits ──────────────────────────────────────────────────────

/// Existing attestation row material needed by the pure rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExistingAtt {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Option<String>,
}

/// Query surface for attestation history (RF4-16 seam; RF4-18 swaps impls).
///
/// Methods answer one rule question each. Return types that carry a witness
/// (e.g. surrounding source/target) preserve the existing error payloads.
pub(crate) trait AttestationHistory {
    /// Row at `target` if any (double-vote / resign detection).
    fn conflicting_at_target(&self, target: Epoch) -> Result<Option<ExistingAtt>, SlashingError>;

    /// Witness `(existing_source, existing_target)` if the candidate
    /// `(source, target)` surrounds some existing attestation.
    fn surrounding_exists(
        &self,
        source: Epoch,
        target: Epoch,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError>;

    /// Witness if the candidate is surrounded by some existing attestation.
    fn surrounded_exists(
        &self,
        source: Epoch,
        target: Epoch,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError>;

    /// Minimum target epoch in history, if any.
    fn min_target(&self) -> Result<Option<Epoch>, SlashingError>;
}

/// Query surface for block history.
pub(crate) trait BlockHistory {
    /// `None` if no row at `slot`; `Some(None)` if row exists with NULL root;
    /// `Some(Some(root))` if a signing root is stored.
    fn signing_root_at_slot(&self, slot: Slot) -> Result<Option<Option<String>>, SlashingError>;

    fn min_slot(&self) -> Result<Option<Slot>, SlashingError>;
}

// ── Candidates / watermarks / verdicts ────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct BlockCandidate {
    pub slot: Slot,
    pub signing_root: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AttestationCandidate {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BlockWatermarks {
    /// Highest permitted exclusive floor: `slot <= block` is rejected.
    pub block: Option<Slot>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AttestationWatermarks {
    /// Source floor: `source < source_wm` is rejected (strict less-than).
    pub source: Option<Epoch>,
    /// Target floor: `target <= target_wm` is rejected (A1 / SEC-9 equality).
    pub target: Option<Epoch>,
}

/// Successful block check outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockVerdict {
    /// New row; `commit()` will INSERT.
    Stage,
    /// Same signing root already present; `commit()` skips INSERT.
    Resign,
}

/// Successful attestation check outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestationVerdict {
    /// New row; `commit()` will INSERT.
    Stage,
    /// Idempotent re-sign; `commit()` skips INSERT.
    Duplicate,
}

// ── Full-scan history (Vec-backed oracle; production uses TargetedSql in history.rs) ─
//
// Kept under `cfg(any(test, feature = "test-utils"))` as the RF4-18 old-vs-new
// equivalence oracle and the ARCH-5h history-validity oracle. Production
// stage/reserve paths never construct these.

/// Full-history attestation scan — equivalence oracle for RF4-18 / ARCH-5h.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone)]
pub(crate) struct FullScanAttestationHistory {
    rows: Vec<ExistingAtt>,
}

#[cfg(any(test, feature = "test-utils"))]
impl FullScanAttestationHistory {
    pub(crate) fn new(rows: Vec<ExistingAtt>) -> Self {
        Self { rows }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl AttestationHistory for FullScanAttestationHistory {
    fn conflicting_at_target(&self, target: Epoch) -> Result<Option<ExistingAtt>, SlashingError> {
        Ok(self.rows.iter().find(|r| r.target_epoch == target).cloned())
    }

    fn surrounding_exists(
        &self,
        source: Epoch,
        target: Epoch,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError> {
        for r in &self.rows {
            if source < r.source_epoch && target > r.target_epoch {
                return Ok(Some((r.source_epoch, r.target_epoch)));
            }
        }
        Ok(None)
    }

    fn surrounded_exists(
        &self,
        source: Epoch,
        target: Epoch,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError> {
        for r in &self.rows {
            if r.source_epoch < source && r.target_epoch > target {
                return Ok(Some((r.source_epoch, r.target_epoch)));
            }
        }
        Ok(None)
    }

    fn min_target(&self) -> Result<Option<Epoch>, SlashingError> {
        Ok(self.rows.iter().map(|r| r.target_epoch).min())
    }
}

/// Full-history block scan — equivalence oracle for RF4-18 / ARCH-5h.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone)]
pub(crate) struct FullScanBlockHistory {
    /// `(slot, signing_root)` rows for one pubkey.
    rows: Vec<(Slot, Option<String>)>,
}

#[cfg(any(test, feature = "test-utils"))]
impl FullScanBlockHistory {
    /// Construct from an arbitrary row list (unit tests and full-table loads).
    pub(crate) fn new(rows: Vec<(Slot, Option<String>)>) -> Self {
        Self { rows }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl BlockHistory for FullScanBlockHistory {
    fn signing_root_at_slot(&self, slot: Slot) -> Result<Option<Option<String>>, SlashingError> {
        Ok(self.rows.iter().find(|(s, _)| *s == slot).map(|(_, r)| r.clone()))
    }

    fn min_slot(&self) -> Result<Option<Slot>, SlashingError> {
        Ok(self.rows.iter().map(|(s, _)| *s).min())
    }
}

// ── Pure checks ───────────────────────────────────────────────────────────────

/// EIP-3076 block safety check (double proposal, slot-below-minimum, watermark).
///
/// `pubkey` is used only for error payloads and debug logs.
pub(crate) fn check_block(
    pubkey: &str,
    history: &impl BlockHistory,
    watermarks: &BlockWatermarks,
    candidate: &BlockCandidate,
    strict: bool,
) -> Result<BlockVerdict, SlashingError> {
    if let Some(wm) = watermarks.block {
        // SEC-9 / M-1: equality is also blocked (strictly increasing block watermark).
        if candidate.slot <= wm {
            return Err(SlashingError::BelowBlockWatermark {
                pubkey: pubkey.to_string(),
                slot: candidate.slot,
                watermark_slot: wm,
            });
        }
    }

    let existing = history.signing_root_at_slot(candidate.slot)?;
    if let Some(existing_root) = existing {
        let is_resign = match (&existing_root, &candidate.signing_root) {
            (Some(er), Some(nr)) if er == nr => true,
            (None, None) if !strict => true,
            _ => false,
        };
        if !is_resign {
            tracing::debug!(
                pubkey = %TruncatedPubkey::new(pubkey),
                slot = candidate.slot,
                rejection_reason = "double_block_proposal",
                "stage_block slashing check blocked"
            );
            return Err(BlockSlashingViolation::DoubleBlockProposal { slot: candidate.slot }.into());
        }
        return Ok(BlockVerdict::Resign);
    }

    let min_slot = history.min_slot()?;
    if let Some(min) = min_slot {
        if candidate.slot < min {
            return Err(BlockSlashingViolation::SlotBelowMinimum {
                slot: candidate.slot,
                min_slot: min,
            }
            .into());
        }
    }

    Ok(BlockVerdict::Stage)
}

/// EIP-3076 attestation safety check (double vote, surround, surrounded,
/// target-below-minimum, watermark floors).
pub(crate) fn check_attestation(
    pubkey: &str,
    history: &impl AttestationHistory,
    watermarks: &AttestationWatermarks,
    candidate: &AttestationCandidate,
    strict: bool,
) -> Result<AttestationVerdict, SlashingError> {
    if let Some(ws) = watermarks.source {
        if candidate.source_epoch < ws {
            return Err(SlashingError::BelowAttestationSourceWatermark {
                pubkey: pubkey.to_string(),
                source_epoch: candidate.source_epoch,
                watermark_source: ws,
            });
        }
    }

    if let Some(wt) = watermarks.target {
        // SEC-9 / M-1: equality is also blocked (strictly increasing target watermark).
        if candidate.target_epoch <= wt {
            return Err(SlashingError::BelowAttestationWatermark {
                pubkey: pubkey.to_string(),
                target_epoch: candidate.target_epoch,
                watermark_target: wt,
            });
        }
    }

    let mut is_duplicate = false;

    if let Some(existing) = history.conflicting_at_target(candidate.target_epoch)? {
        match (&existing.signing_root, &candidate.signing_root) {
            (Some(er), Some(nr)) if er == nr => {
                if candidate.source_epoch != existing.source_epoch {
                    tracing::warn!(
                        pubkey = %TruncatedPubkey::new(pubkey),
                        target_epoch = candidate.target_epoch,
                        existing_source = existing.source_epoch,
                        new_source = candidate.source_epoch,
                        "stage_attestation: same signing root but different source epoch"
                    );
                }
                is_duplicate = true;
            }
            (None, None) if !strict => {
                is_duplicate = true;
            }
            _ => {
                tracing::debug!(
                    pubkey = %TruncatedPubkey::new(pubkey),
                    source_epoch = candidate.source_epoch,
                    target_epoch = candidate.target_epoch,
                    rejection_reason = "double_vote",
                    "stage_attestation slashing check blocked"
                );
                return Err(AttestationSlashingViolation::DoubleVote {
                    target_epoch: candidate.target_epoch,
                }
                .into());
            }
        }
    }

    if let Some((existing_source, existing_target)) =
        history.surrounding_exists(candidate.source_epoch, candidate.target_epoch)?
    {
        tracing::debug!(
            pubkey = %TruncatedPubkey::new(pubkey),
            source_epoch = candidate.source_epoch,
            target_epoch = candidate.target_epoch,
            rejection_reason = "surrounding_vote",
            "stage_attestation slashing check blocked"
        );
        return Err(AttestationSlashingViolation::SurroundingVote {
            new_source: candidate.source_epoch,
            new_target: candidate.target_epoch,
            existing_source,
            existing_target,
        }
        .into());
    }

    if let Some((existing_source, existing_target)) =
        history.surrounded_exists(candidate.source_epoch, candidate.target_epoch)?
    {
        tracing::debug!(
            pubkey = %TruncatedPubkey::new(pubkey),
            source_epoch = candidate.source_epoch,
            target_epoch = candidate.target_epoch,
            rejection_reason = "surrounded_vote",
            "stage_attestation slashing check blocked"
        );
        return Err(AttestationSlashingViolation::SurroundedVote {
            new_source: candidate.source_epoch,
            new_target: candidate.target_epoch,
            existing_source,
            existing_target,
        }
        .into());
    }

    if !is_duplicate {
        if let Some(min) = history.min_target()? {
            if candidate.target_epoch < min {
                return Err(AttestationSlashingViolation::TargetEpochBelowMinimum {
                    target_epoch: candidate.target_epoch,
                    min_target: min,
                }
                .into());
            }
        }
    }

    if is_duplicate {
        Ok(AttestationVerdict::Duplicate)
    } else {
        Ok(AttestationVerdict::Stage)
    }
}

// ── ARCH-5h test-utils oracle ─────────────────────────────────────────────────

/// First EIP-3076 slashing pair in a committed history, via production
/// [`check_block`] / [`check_attestation`].
///
/// Min-slot / min-target / watermark floors are **not** violations here —
/// those are liveness constraints (a valid history may contain an older row
/// next to a newer one). The slashing pairs are: two distinct signing roots
/// at the same `(pubkey, slot)` or `(pubkey, target)`; a surrounding or
/// surrounded attestation pair.
///
/// Gated to tests / `test-utils` so integration tests (ARCH-5h) can use the
/// production rule engine as the oracle without a second checker that can
/// drift.
#[cfg(any(test, feature = "test-utils"))]
pub fn first_eip3076_history_violation(
    pubkey: &str,
    blocks: &[crate::types::SignedBlock],
    attestations: &[crate::types::SignedAttestation],
) -> Option<String> {
    use crate::error::{AttestationSlashingViolation, BlockSlashingViolation};

    for (i, block) in blocks.iter().enumerate() {
        let others: Vec<(Slot, Option<String>)> = blocks
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, b)| (b.slot, b.signing_root.as_ref().map(|r| r.as_hex().to_string())))
            .collect();
        let history = FullScanBlockHistory::new(others);
        let candidate = BlockCandidate {
            slot: block.slot,
            signing_root: block.signing_root.as_ref().map(|r| r.as_hex().to_string()),
        };
        match check_block(pubkey, &history, &BlockWatermarks::default(), &candidate, false) {
            Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot,
            })) => {
                return Some(format!(
                    "double block proposal at slot {slot} (pubkey={pubkey}, root={:?})",
                    block.signing_root
                ));
            }
            Err(SlashingError::SlashableBlock(BlockSlashingViolation::SlotBelowMinimum {
                ..
            })) => {}
            Err(other) => return Some(format!("unexpected block check error: {other}")),
            Ok(_) => {}
        }
    }

    for (i, att) in attestations.iter().enumerate() {
        let others: Vec<ExistingAtt> = attestations
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| ExistingAtt {
                source_epoch: a.source_epoch,
                target_epoch: a.target_epoch,
                signing_root: a.signing_root.as_ref().map(|r| r.as_hex().to_string()),
            })
            .collect();
        let history = FullScanAttestationHistory::new(others);
        let candidate = AttestationCandidate {
            source_epoch: att.source_epoch,
            target_epoch: att.target_epoch,
            signing_root: att.signing_root.as_ref().map(|r| r.as_hex().to_string()),
        };
        match check_attestation(
            pubkey,
            &history,
            &AttestationWatermarks::default(),
            &candidate,
            false,
        ) {
            Err(SlashingError::SlashableAttestation(
                AttestationSlashingViolation::TargetEpochBelowMinimum { .. },
            )) => {}
            Err(SlashingError::SlashableAttestation(v)) => {
                return Some(format!("attestation violation: {v} (pubkey={pubkey})"));
            }
            Err(other) => return Some(format!("unexpected attestation check error: {other}")),
            Ok(_) => {}
        }
    }

    None
}

/// Whether production [`check_block`] would accept `slot`/`signing_root`
/// against `history` (no watermarks). `true` for Stage or Resign.
#[cfg(any(test, feature = "test-utils"))]
pub fn eip3076_allows_block(
    pubkey: &str,
    history: &[crate::types::SignedBlock],
    slot: Slot,
    signing_root: Option<String>,
    strict: bool,
) -> bool {
    let rows: Vec<(Slot, Option<String>)> = history
        .iter()
        .map(|b| (b.slot, b.signing_root.as_ref().map(|r| r.as_hex().to_string())))
        .collect();
    let hist = FullScanBlockHistory::new(rows);
    let candidate = BlockCandidate { slot, signing_root };
    check_block(pubkey, &hist, &BlockWatermarks::default(), &candidate, strict).is_ok()
}

/// Whether production [`check_attestation`] would accept the candidate
/// against `history` (no watermarks). `true` for Stage or Duplicate.
#[cfg(any(test, feature = "test-utils"))]
pub fn eip3076_allows_attestation(
    pubkey: &str,
    history: &[crate::types::SignedAttestation],
    source_epoch: Epoch,
    target_epoch: Epoch,
    signing_root: Option<String>,
    strict: bool,
) -> bool {
    let rows: Vec<ExistingAtt> = history
        .iter()
        .map(|a| ExistingAtt {
            source_epoch: a.source_epoch,
            target_epoch: a.target_epoch,
            signing_root: a.signing_root.as_ref().map(|r| r.as_hex().to_string()),
        })
        .collect();
    let hist = FullScanAttestationHistory::new(rows);
    let candidate = AttestationCandidate { source_epoch, target_epoch, signing_root };
    check_attestation(pubkey, &hist, &AttestationWatermarks::default(), &candidate, strict).is_ok()
}

// ── Unit tests (pure; no SQLite) ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn att(source: Epoch, target: Epoch, root: Option<&str>) -> ExistingAtt {
        ExistingAtt {
            source_epoch: source,
            target_epoch: target,
            signing_root: root.map(str::to_string),
        }
    }

    fn cand_att(source: Epoch, target: Epoch, root: Option<&str>) -> AttestationCandidate {
        AttestationCandidate {
            source_epoch: source,
            target_epoch: target,
            signing_root: root.map(str::to_string),
        }
    }

    fn cand_block(slot: Slot, root: Option<&str>) -> BlockCandidate {
        BlockCandidate { slot, signing_root: root.map(str::to_string) }
    }

    /// RED-first pure-trait test: double vote detected with no database.
    #[test]
    fn test_check_attestation_is_pure_over_history_trait() {
        let history = FullScanAttestationHistory::new(vec![att(1, 5, Some("0xaaa"))]);
        let watermarks = AttestationWatermarks::default();
        let candidate = cand_att(2, 5, Some("0xbbb"));

        let err = check_attestation("0xpk", &history, &watermarks, &candidate, false)
            .expect_err("different root at same target must double-vote");
        assert!(
            matches!(
                err,
                SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                    target_epoch: 5
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn test_check_attestation_double_vote_surround_surrounded_matrix() {
        // Double vote
        {
            let h = FullScanAttestationHistory::new(vec![att(1, 10, Some("0x1"))]);
            let e = check_attestation(
                "0xpk",
                &h,
                &AttestationWatermarks::default(),
                &cand_att(1, 10, Some("0x2")),
                false,
            )
            .unwrap_err();
            assert!(matches!(
                e,
                SlashingError::SlashableAttestation(
                    AttestationSlashingViolation::DoubleVote { .. }
                )
            ));
        }
        // Surrounding: new (1,10) surrounds existing (3,7)
        {
            let h = FullScanAttestationHistory::new(vec![att(3, 7, Some("0xnarrow"))]);
            let e = check_attestation(
                "0xpk",
                &h,
                &AttestationWatermarks::default(),
                &cand_att(1, 10, Some("0xsurrounding")),
                false,
            )
            .unwrap_err();
            assert!(matches!(
                e,
                SlashingError::SlashableAttestation(
                    AttestationSlashingViolation::SurroundingVote { .. }
                )
            ));
        }
        // Surrounded: new (5,7) surrounded by existing (3,10)
        {
            let h = FullScanAttestationHistory::new(vec![att(3, 10, Some("0xwide"))]);
            let e = check_attestation(
                "0xpk",
                &h,
                &AttestationWatermarks::default(),
                &cand_att(5, 7, Some("0xnarrow")),
                false,
            )
            .unwrap_err();
            assert!(matches!(
                e,
                SlashingError::SlashableAttestation(
                    AttestationSlashingViolation::SurroundedVote { .. }
                )
            ));
        }
        // Accept non-conflicting
        {
            let h = FullScanAttestationHistory::new(vec![att(1, 5, Some("0xa"))]);
            let v = check_attestation(
                "0xpk",
                &h,
                &AttestationWatermarks::default(),
                &cand_att(5, 8, Some("0xb")),
                false,
            )
            .unwrap();
            assert_eq!(v, AttestationVerdict::Stage);
        }
        // Resign / duplicate
        {
            let h = FullScanAttestationHistory::new(vec![att(1, 5, Some("0xsame"))]);
            let v = check_attestation(
                "0xpk",
                &h,
                &AttestationWatermarks::default(),
                &cand_att(1, 5, Some("0xsame")),
                false,
            )
            .unwrap();
            assert_eq!(v, AttestationVerdict::Duplicate);
        }
    }

    #[test]
    fn test_check_block_double_proposal_and_resign() {
        let history = FullScanBlockHistory::new(vec![(100, Some("0xroot_a".into()))]);
        let wm = BlockWatermarks::default();

        let resign =
            check_block("0xpk", &history, &wm, &cand_block(100, Some("0xroot_a")), false).unwrap();
        assert_eq!(resign, BlockVerdict::Resign);

        let dbl = check_block("0xpk", &history, &wm, &cand_block(100, Some("0xroot_b")), false)
            .unwrap_err();
        assert!(matches!(
            dbl,
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot: 100
            })
        ));

        let stage =
            check_block("0xpk", &history, &wm, &cand_block(101, Some("0xnew")), false).unwrap();
        assert_eq!(stage, BlockVerdict::Stage);

        // Slot below minimum
        let below =
            check_block("0xpk", &history, &wm, &cand_block(50, Some("0xold")), false).unwrap_err();
        assert!(matches!(
            below,
            SlashingError::SlashableBlock(BlockSlashingViolation::SlotBelowMinimum { .. })
        ));
    }

    #[test]
    fn test_check_attestation_watermark_equality_blocks() {
        // A1 / SEC-9: target equality is blocked.
        let history = FullScanAttestationHistory::new(vec![]);
        let watermarks = AttestationWatermarks { source: None, target: Some(10) };

        let err =
            check_attestation("0xpk", &history, &watermarks, &cand_att(5, 10, Some("0xeq")), false)
                .unwrap_err();
        assert!(
            matches!(
                err,
                SlashingError::BelowAttestationWatermark {
                    target_epoch: 10,
                    watermark_target: 10,
                    ..
                }
            ),
            "target equality must block: {err:?}"
        );

        // Strictly above target watermark is allowed (empty history).
        let ok = check_attestation(
            "0xpk",
            &history,
            &watermarks,
            &cand_att(5, 11, Some("0xabove")),
            false,
        )
        .unwrap();
        assert_eq!(ok, AttestationVerdict::Stage);

        // Block watermark equality
        let bhist = FullScanBlockHistory::new(vec![]);
        let bwm = BlockWatermarks { block: Some(50) };
        let berr =
            check_block("0xpk", &bhist, &bwm, &cand_block(50, Some("0xeq")), false).unwrap_err();
        assert!(matches!(
            berr,
            SlashingError::BelowBlockWatermark { slot: 50, watermark_slot: 50, .. }
        ));
    }

    #[test]
    fn test_strict_semantics_none_none_attestation_and_block() {
        // Lenient: None==None is resign/duplicate
        let ah = FullScanAttestationHistory::new(vec![att(1, 5, None)]);
        assert_eq!(
            check_attestation(
                "0xpk",
                &ah,
                &AttestationWatermarks::default(),
                &cand_att(1, 5, None),
                false
            )
            .unwrap(),
            AttestationVerdict::Duplicate
        );
        // Strict: None==None is double vote
        assert!(matches!(
            check_attestation(
                "0xpk",
                &ah,
                &AttestationWatermarks::default(),
                &cand_att(1, 5, None),
                true
            )
            .unwrap_err(),
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote { .. })
        ));

        let bh = FullScanBlockHistory::new(vec![(10, None)]);
        assert_eq!(
            check_block("0xpk", &bh, &BlockWatermarks::default(), &cand_block(10, None), false)
                .unwrap(),
            BlockVerdict::Resign
        );
        assert!(matches!(
            check_block("0xpk", &bh, &BlockWatermarks::default(), &cand_block(10, None), true)
                .unwrap_err(),
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { .. })
        ));
    }
}
