//! Trait abstractions for doppelganger detection dependencies.

use async_trait::async_trait;
use eth_types::Epoch;

use crate::DoppelgangerError;

/// Liveness data for a single validator at a given epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorLivenessData {
    /// The validator identifier used as the state-map key in
    /// [`crate::ForwardWindowMachine`].
    ///
    /// # Pubkey-hex key contract (SEC-001)
    ///
    /// This field MUST contain the lowercase `hex::encode(pubkey.to_bytes())`
    /// for the validator — the same encoding produced by
    /// `ForwardWindowMachine::register`.  It is NOT the beacon node's numeric
    /// validator index.
    ///
    /// Beacon nodes return numeric indices in liveness responses.  The
    /// orchestrator/adapter layer is responsible for translating each numeric
    /// index → pubkey-hex BEFORE constructing `ValidatorLivenessData` and
    /// passing the slice to `observe_liveness`.  Any index that cannot be
    /// translated (unknown pubkey) MUST be omitted, which causes
    /// `observe_liveness` to treat the corresponding validator as missing
    /// (fail-closed).  The production wiring and translation land in
    /// Issue 2.10.
    pub index: String,
    /// Whether the validator was observed as live (attesting or proposing)
    /// during the queried epoch.
    pub is_live: bool,
}

/// Abstraction for querying validator liveness from a beacon node.
///
/// # Completeness contract (D-2, Issue 2.7)
///
/// A response from `check_liveness` MUST include an entry for every validator
/// index that was requested.  A missing entry is treated as **inconclusive**
/// (fail-closed): `ForwardWindowMachine::observe_liveness` will not record
/// that epoch as observed for the absent validator, preventing a `Safe`
/// transition until a complete response is received.
///
/// Implementors must NOT silently drop entries for validators whose liveness
/// could not be determined.  If the beacon node returns a partial response,
/// the implementor should return `Err(DoppelgangerError::IncompleteLiveness)`
/// rather than an incomplete `Vec`.
///
/// # Pubkey-hex key contract (SEC-001)
///
/// The `index` field of each returned `ValidatorLivenessData` MUST be the
/// lowercase `hex::encode(pubkey.to_bytes())` for the corresponding validator
/// (see [`ValidatorLivenessData::index`]).  Implementations that receive
/// numeric validator indices from the beacon node MUST perform the
/// numeric → pubkey-hex translation before returning.  An untranslatable
/// numeric index MUST be treated as a missing entry (fail-closed).  The
/// production translation adapter lands in Issue 2.10.
#[async_trait]
pub trait LivenessChecker: Send + Sync {
    async fn check_liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[String],
    ) -> Result<Vec<ValidatorLivenessData>, DoppelgangerError>;
}
