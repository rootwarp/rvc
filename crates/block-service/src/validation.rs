use eth_types::Root;

use crate::types::{BlockSelectionMode, CandidateShape};
use crate::BlockServiceError;

/// Reject a produced shape that the selection mode must not sign.
///
/// Builder-only accepts a pre-Gloas blinded block and a Gloas external bid.
/// Execution-only accepts a pre-Gloas unblinded block and a Gloas self-build
/// (`builder_index == BUILDER_INDEX_SELF_BUILD`). Max-profit and builder-always
/// accept every shape. A rejection is not signed; the caller skips that candidate.
pub(crate) fn check_mode_shape(
    mode: BlockSelectionMode,
    shape: CandidateShape,
) -> Result<(), BlockServiceError> {
    let builder_shape = matches!(shape, CandidateShape::Blinded | CandidateShape::BuilderWin);
    let allowed = match mode {
        BlockSelectionMode::MaxProfit | BlockSelectionMode::BuilderAlways => true,
        BlockSelectionMode::BuilderOnly => builder_shape,
        BlockSelectionMode::ExecutionOnly => !builder_shape,
    };
    if allowed {
        Ok(())
    } else {
        Err(BlockServiceError::ModeShapeMismatch { mode, shape })
    }
}

/// Roots a block proposed at slot N may use as `parent_root`.
///
/// `root` is the first header found walking back from N-1. `parent` is that
/// header's own parent when the header sits at N-1, so a single-slot proposer
/// re-org is still signed. A header below N-1 sets `parent` to `None`.
/// `closed` rejects every parent: the header slot disagreed with the requested
/// id, or the head fallback was at slot N or later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedParents {
    pub root: Root,
    pub parent: Option<Root>,
    pub closed: bool,
}

impl ExpectedParents {
    /// Header root, plus the re-org parent when the header is at N-1.
    pub fn open(root: Root, parent: Option<Root>) -> Self {
        Self { root, parent, closed: false }
    }

    /// No parent is acceptable. `root` is unused.
    pub fn closed() -> Self {
        Self { root: [0u8; 32], parent: None, closed: true }
    }

    /// `true` when `got` is [`Self::root`] or the optional re-org parent.
    ///
    /// A closed set accepts nothing, including the zero root.
    pub fn accepts(&self, got: Root) -> bool {
        if self.closed {
            return false;
        }
        got == self.root || self.parent.is_some_and(|parent| got == parent)
    }
}

/// Validates a beacon block returned by the BN against the proposer duty.
///
/// Slot equality is checked once in `check_response_block`, before this runs.
/// Proposer index and parent root are the same for a full block and a blinded
/// block, so both SSZ and JSON arms call [`Self::validate`].
pub(crate) struct BlockResponseValidator {
    pub expected_proposer_index: u64,
    pub expected_parents: Option<ExpectedParents>,
}

impl BlockResponseValidator {
    /// Validate proposer index, then parent root.
    ///
    /// Order (do not reorder without updating the reachability tests):
    /// 1. proposer_index equality
    /// 2. parent root membership in [`ExpectedParents`], when that set is `Some`
    pub fn validate(
        &self,
        proposer_index: u64,
        parent_root: Root,
    ) -> Result<(), BlockServiceError> {
        self.check_proposer_index(proposer_index)?;
        self.check_parent(parent_root)?;
        Ok(())
    }

    fn check_proposer_index(&self, got: u64) -> Result<(), BlockServiceError> {
        if got != self.expected_proposer_index {
            return Err(BlockServiceError::ProposerIndexMismatch {
                expected: self.expected_proposer_index,
                got,
            });
        }
        Ok(())
    }

    fn check_parent(&self, got: Root) -> Result<(), BlockServiceError> {
        let Some(expected) = self.expected_parents else {
            return Ok(());
        };
        if expected.accepts(got) {
            return Ok(());
        }
        Err(BlockServiceError::ParentRootMismatch {
            expected: expected.root,
            reorg_parent: expected.parent,
            got,
            closed: expected.closed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parents(root: Root) -> Option<ExpectedParents> {
        Some(ExpectedParents { root, parent: None, closed: false })
    }

    fn validator(
        expected_proposer_index: u64,
        expected_parents: Option<ExpectedParents>,
    ) -> BlockResponseValidator {
        BlockResponseValidator { expected_proposer_index, expected_parents }
    }

    /// Reachability: ProposerIndexMismatch.
    #[test]
    fn test_proposer_index_mismatch_rejected() {
        let v = validator(42, None);
        let result = v.validate(43, [0u8; 32]);
        assert!(matches!(
            result,
            Err(BlockServiceError::ProposerIndexMismatch { expected: 42, got: 43 })
        ));
    }

    /// A third ancestor is rejected. The reported expected root is the header root.
    #[test]
    fn test_wrong_ancestor_parent_rejected() {
        let header: Root = [0x11; 32];
        let reorg: Root = [0x22; 32];
        let wrong: Root = [0x33; 32];
        let v = validator(
            42,
            Some(ExpectedParents { root: header, parent: Some(reorg), closed: false }),
        );
        let result = v.validate(42, wrong);
        assert!(matches!(
            result,
            Err(BlockServiceError::ParentRootMismatch { expected, got, .. })
            if expected == header && got == wrong
        ));
    }

    /// The header root is accepted.
    #[test]
    fn test_previous_slot_parent_accepted() {
        let header: Root = [0x11; 32];
        let v = validator(42, parents(header));
        assert!(v.validate(42, header).is_ok());
    }

    /// The parent of an N-1 header is accepted, and a different root is not.
    #[test]
    fn test_reorg_parent_accepted_and_other_parent_rejected() {
        let header: Root = [0x11; 32];
        let reorg: Root = [0x22; 32];
        let v = validator(
            42,
            Some(ExpectedParents { root: header, parent: Some(reorg), closed: false }),
        );
        assert!(v.validate(42, header).is_ok());
        assert!(v.validate(42, reorg).is_ok());
        assert!(matches!(
            v.validate(42, [0x33; 32]),
            Err(BlockServiceError::ParentRootMismatch { .. })
        ));
    }

    /// Reachability: ParentRootMismatch when only the header root is allowed.
    #[test]
    fn test_parent_mismatch_rejected() {
        let expected_root: Root = [1u8; 32];
        let actual_root: Root = [2u8; 32];
        let v = validator(42, parents(expected_root));
        let result = v.validate(42, actual_root);
        assert!(matches!(
            result,
            Err(BlockServiceError::ParentRootMismatch { expected, got, .. })
            if expected == expected_root && got == actual_root
        ));
    }

    /// Positive: proposer index matches and no parent set is configured.
    #[test]
    fn test_proposer_index_match_accepted() {
        let v = validator(42, None);
        assert!(v.validate(42, [0u8; 32]).is_ok());
    }

    /// No parent set means any parent is accepted.
    #[test]
    fn test_parent_none_skips_check() {
        let v = validator(42, None);
        assert!(v.validate(42, [0xff; 32]).is_ok());
    }

    /// The error names both the header root and the re-org parent.
    #[test]
    fn test_parent_mismatch_names_the_reorg_parent() {
        let header: Root = [0x11; 32];
        let reorg: Root = [0x22; 32];
        let wrong: Root = [0x33; 32];
        let v = validator(42, Some(ExpectedParents::open(header, Some(reorg))));
        let err = v.validate(42, wrong).expect_err("third ancestor");
        let text = err.to_string();
        match err {
            BlockServiceError::ParentRootMismatch { expected, reorg_parent, got, closed } => {
                assert_eq!(expected, header);
                assert_eq!(reorg_parent, Some(reorg));
                assert_eq!(got, wrong);
                assert!(!closed);
            }
            other => panic!("expected ParentRootMismatch, got {other:?}"),
        }
        assert!(text.contains(&hex::encode(header)), "{text}");
        assert!(text.contains(&hex::encode(reorg)), "{text}");
        assert!(text.contains(&hex::encode(wrong)), "{text}");
    }

    /// A closed set rejects every parent, including the zero root.
    #[test]
    fn test_closed_parent_set_rejects_every_parent() {
        let v = validator(42, Some(ExpectedParents::closed()));
        let err = v.validate(42, [0u8; 32]).expect_err("closed");
        let text = err.to_string();
        assert!(text.contains("no parent accepted"), "{text}");
        assert!(matches!(err, BlockServiceError::ParentRootMismatch { closed: true, .. }));
        assert!(v.validate(42, [0xff; 32]).is_err());
    }

    /// Spec table for `check_mode_shape`. The rows are the allowed pairs;
    /// they are not derived by calling the function under test.
    #[test]
    fn test_check_mode_shape_matrix() {
        use BlockSelectionMode::{BuilderAlways, BuilderOnly, ExecutionOnly, MaxProfit};
        use CandidateShape::{Blinded, BuilderWin, SelfBuild, Unblinded};

        // (mode, shape, allowed). 4 modes × 4 shapes.
        let cases = [
            (BuilderOnly, Unblinded, false),
            (BuilderOnly, Blinded, true),
            (BuilderOnly, SelfBuild, false),
            (BuilderOnly, BuilderWin, true),
            (ExecutionOnly, Unblinded, true),
            (ExecutionOnly, Blinded, false),
            (ExecutionOnly, SelfBuild, true),
            (ExecutionOnly, BuilderWin, false),
            (MaxProfit, Unblinded, true),
            (MaxProfit, Blinded, true),
            (MaxProfit, SelfBuild, true),
            (MaxProfit, BuilderWin, true),
            (BuilderAlways, Unblinded, true),
            (BuilderAlways, Blinded, true),
            (BuilderAlways, SelfBuild, true),
            (BuilderAlways, BuilderWin, true),
        ];
        assert_eq!(cases.len(), 16);

        for (mode, shape, allowed) in cases {
            let result = check_mode_shape(mode, shape);
            if allowed {
                assert!(result.is_ok(), "{mode} must accept {shape}");
                continue;
            }
            match result {
                Err(BlockServiceError::ModeShapeMismatch { mode: got_mode, shape: got_shape }) => {
                    assert_eq!(got_mode, mode);
                    assert_eq!(got_shape, shape);
                }
                other => panic!("{mode} {shape}: {other:?}"),
            }
            let text = check_mode_shape(mode, shape).expect_err("rejected pair").to_string();
            assert_eq!(text, format!("mode {mode} rejects shape {shape}"));
        }
    }

    /// A header below N-1 does not accept that header's parent.
    #[test]
    fn test_header_parent_rejected_when_absent_from_the_set() {
        let header: Root = [0x11; 32];
        let header_parent: Root = [0x22; 32];
        let v = validator(42, parents(header));
        assert!(v.validate(42, header).is_ok());
        assert!(matches!(
            v.validate(42, header_parent),
            Err(BlockServiceError::ParentRootMismatch { expected, got, .. })
            if expected == header && got == header_parent
        ));
    }
}
