//! Which produced shapes a duty may rank or sign.
//!
//! bn-manager and block-service both depend on this crate, so the constraint
//! lives here. A prepare check can take the same value.

/// Gloas self-build bid index.
///
/// This is the consensus-spec `BUILDER_INDEX_SELF_BUILD` (`uint64::MAX`).
/// Every other builder index is an external bid.
pub const GLOAS_SELF_BUILD_BUILDER_INDEX: u64 = u64::MAX;

/// Shapes a duty will rank or sign.
///
/// [`Self::Any`] is the unconstrained value. Production sets the variant from
/// the selection mode. A forgotten constraint must not be implied by a
/// missing field: callers set it on the duty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShapeConstraint {
    /// A local block and a builder block are both acceptable.
    #[default]
    Any,
    /// Pre-Gloas blinded block, or a Gloas external bid.
    BlindedOnly,
    /// Pre-Gloas full block, or a Gloas self-build.
    LocalOnly,
}

impl ShapeConstraint {
    /// `true` when a pre-Gloas candidate with this blinded flag may be ranked.
    ///
    /// The flag is `Eth-Execution-Payload-Blinded`. The fork does not change
    /// the rule: phase0 through fulu use the same flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use beacon::ShapeConstraint;
    ///
    /// assert!(ShapeConstraint::LocalOnly.allows_blinded_flag(false));
    /// assert!(!ShapeConstraint::BlindedOnly.allows_blinded_flag(false));
    /// ```
    pub fn allows_blinded_flag(self, is_blinded: bool) -> bool {
        match self {
            Self::Any => true,
            Self::BlindedOnly => is_blinded,
            Self::LocalOnly => !is_blinded,
        }
    }

    /// `true` when a Gloas bid with this `builder_index` may be ranked.
    ///
    /// [`GLOAS_SELF_BUILD_BUILDER_INDEX`] is a self-build. Every other index
    /// is an external bid.
    ///
    /// # Examples
    ///
    /// ```
    /// use beacon::{ShapeConstraint, GLOAS_SELF_BUILD_BUILDER_INDEX};
    ///
    /// assert!(ShapeConstraint::LocalOnly.allows_builder_index(GLOAS_SELF_BUILD_BUILDER_INDEX));
    /// assert!(!ShapeConstraint::LocalOnly.allows_builder_index(0));
    /// ```
    pub fn allows_builder_index(self, builder_index: u64) -> bool {
        let external = builder_index != GLOAS_SELF_BUILD_BUILDER_INDEX;
        match self {
            Self::Any => true,
            Self::BlindedOnly => external,
            Self::LocalOnly => !external,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blinded_flag_is_the_same_rule_on_every_pre_gloas_fork() {
        // The constraint does not take a fork. phase0 through fulu share the flag.
        let _forks = ["phase0", "altair", "bellatrix", "capella", "deneb", "electra", "fulu"];
        for blinded in [false, true] {
            assert!(ShapeConstraint::Any.allows_blinded_flag(blinded));
            assert_eq!(ShapeConstraint::BlindedOnly.allows_blinded_flag(blinded), blinded);
            assert_eq!(ShapeConstraint::LocalOnly.allows_blinded_flag(blinded), !blinded);
        }
    }

    #[test]
    fn gloas_self_build_is_only_the_max_index() {
        assert_eq!(GLOAS_SELF_BUILD_BUILDER_INDEX, u64::MAX);
        assert!(ShapeConstraint::LocalOnly.allows_builder_index(u64::MAX));
        assert!(!ShapeConstraint::LocalOnly.allows_builder_index(u64::MAX - 1));
        assert!(!ShapeConstraint::BlindedOnly.allows_builder_index(u64::MAX));
        assert!(ShapeConstraint::BlindedOnly.allows_builder_index(0));
        assert!(ShapeConstraint::BlindedOnly.allows_builder_index(1));
        assert!(ShapeConstraint::Any.allows_builder_index(0));
        assert!(ShapeConstraint::Any.allows_builder_index(u64::MAX));
    }
}
