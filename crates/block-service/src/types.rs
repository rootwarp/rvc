pub use validator_store::BlockSelectionMode;

/// Shape of one produced block, checked against [`BlockSelectionMode`] before signing.
///
/// Pre-Gloas shapes follow the blinded flag. Gloas shapes follow the bid
/// `builder_index`: `BUILDER_INDEX_SELF_BUILD` (`u64::MAX`) is a self-build, and
/// every other index is an external bid. The produce container does not decide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateShape {
    /// Pre-Gloas local execution block.
    Unblinded,
    /// Pre-Gloas builder block.
    Blinded,
    /// Gloas self-build bid (`builder_index == BUILDER_INDEX_SELF_BUILD`).
    SelfBuild,
    /// Gloas external bid.
    BuilderWin,
}

impl std::fmt::Display for CandidateShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unblinded => "unblinded",
            Self::Blinded => "blinded",
            Self::SelfBuild => "self-build",
            Self::BuilderWin => "external-bid",
        })
    }
}
