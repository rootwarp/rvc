use beacon::BeaconError;
use eth_types::Root;

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

    /// Returned when `produce_block_v3` fails **and** the request used a
    /// non-zero `builder_boost_factor` (i.e. the builder relay was attempted).
    /// Coordinator pattern-matches this variant to call `record_miss()` on the
    /// circuit breaker so that transient BN errors on the *non-builder* path
    /// (boost = 0) do **not** trip the breaker (H-3 fix).
    #[error("builder failure: {0}")]
    BuilderFailure(String),

    #[error("proposer_index mismatch: expected {expected}, got {got}")]
    ProposerIndexMismatch { expected: u64, got: u64 },

    #[error(
        "parent_root mismatch: expected 0x{}, got 0x{}",
        hex::encode(expected),
        hex::encode(got)
    )]
    ParentRootMismatch { expected: Root, got: Root },

    /// SSZ format selection has no named arm for this consensus version.
    #[error("unrecognised consensus version for SSZ block format: {0}")]
    UnknownSszConsensusVersion(String),

    /// Blinded proposal path is pre-Gloas only; Gloas drops the duty unsigned.
    #[error("blinded block production is not supported at Gloas (slot {slot})")]
    BlindedNotSupportedAtGloas { slot: u64 },
}

impl From<BeaconError> for BlockServiceError {
    fn from(err: BeaconError) -> Self {
        match err {
            BeaconError::ParseError(msg) => Self::Parse(msg),
            other => Self::Beacon(other.to_string()),
        }
    }
}
