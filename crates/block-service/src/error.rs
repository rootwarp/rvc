use beacon::BeaconError;
use eth_types::Root;

use crate::types::{BlockSelectionMode, CandidateShape};

#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockServiceError {
    #[error("signer error: {0}")]
    Signer(String),

    #[error("beacon error: {0}")]
    Beacon(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("slot mismatch: requested {requested}, got {got}")]
    SlotMismatch { requested: u64, got: u64 },

    #[error("builder-only mode: {0}")]
    BuilderOnly(String),

    /// Produced shape contradicts the validator's selection mode.
    ///
    /// Raised before `sign_block_header`. Builder-only proposals surface this
    /// as [`Self::BuilderOnly`] so the coordinator's builder-miss handling is
    /// unchanged. The message names `mode` and `shape`.
    #[error("mode {mode} rejects shape {shape}")]
    ModeShapeMismatch { mode: BlockSelectionMode, shape: CandidateShape },

    /// Returned when `produce_block_v3` fails **and** the request used a
    /// non-zero `builder_boost_factor` (i.e. the builder relay was attempted).
    /// Coordinator pattern-matches this variant to call `record_miss()` on the
    /// circuit breaker so that transient BN errors on the *non-builder* path
    /// (boost = 0) do **not** trip the breaker (H-3 fix).
    #[error("builder failure: {0}")]
    BuilderFailure(String),

    #[error("proposer_index mismatch: expected {expected}, got {got}")]
    ProposerIndexMismatch { expected: u64, got: u64 },

    #[error("{}", parent_mismatch_message(expected, reorg_parent, got, closed))]
    ParentRootMismatch { expected: Root, reorg_parent: Option<Root>, got: Root, closed: bool },

    /// SSZ format selection has no named arm for this consensus version.
    #[error("unrecognised consensus version for SSZ block format: {0}")]
    UnknownSszConsensusVersion(String),

    /// Blinded proposal path is pre-Gloas only; Gloas drops the duty unsigned.
    #[error("blinded block production is not supported at Gloas (slot {slot})")]
    BlindedNotSupportedAtGloas { slot: u64 },

    /// `Eth-Consensus-Version` disagreed with the slot-resolved fork. Duty dropped unsigned.
    #[error("Eth-Consensus-Version {got} does not match slot fork {expected}")]
    ConsensusVersionMismatch { expected: String, got: String },

    /// Gloas body merkleization failed. Duty dropped unsigned — never an Electra fallback.
    #[error(transparent)]
    Gloas(#[from] rvc_gloas::GloasError),

    /// Envelope sign/publish failed after the block was already published.
    #[error("self-build envelope failed after block publish: {0}")]
    EnvelopeAfterPublish(String),

    /// This client does not implement the named operation.
    ///
    /// `publish_block_contents` returns this by default so a test double fails
    /// closed instead of dropping sidecars. Override that method on any client
    /// used for a live JSON publish path.
    #[error("{0} is unsupported; override it on any client used for a live JSON publish path")]
    Unsupported(&'static str),
}

fn parent_mismatch_message(
    expected: &Root,
    reorg_parent: &Option<Root>,
    got: &Root,
    closed: &bool,
) -> String {
    let got = hex::encode(got);
    if *closed {
        return format!("parent_root mismatch: no parent accepted, got 0x{got}");
    }
    let expected = hex::encode(expected);
    match reorg_parent {
        Some(reorg) => format!(
            "parent_root mismatch: expected 0x{expected} or 0x{}, got 0x{got}",
            hex::encode(reorg)
        ),
        None => format!("parent_root mismatch: expected 0x{expected}, got 0x{got}"),
    }
}

impl From<BeaconError> for BlockServiceError {
    fn from(err: BeaconError) -> Self {
        match err {
            BeaconError::ParseError(msg) => Self::Parse(msg),
            other => Self::Beacon(other.to_string()),
        }
    }
}
