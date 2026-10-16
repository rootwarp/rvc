//! Liveness samples consumed by the forward-window doppelganger machine.

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
    /// `observe_liveness` to report that validator as unobserved
    /// (fail-closed).  The production wiring and translation land in
    /// Issue 2.10.
    pub index: String,
    /// Whether the validator was observed as live (attesting or proposing)
    /// during the queried epoch.
    pub is_live: bool,
}
