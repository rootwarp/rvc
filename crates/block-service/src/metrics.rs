//! Block-proposal Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{define_int_counter_vec, IntCounterVec};

/// `outcome` label values for [`RVC_PROPOSALS_TOTAL`].
pub mod proposal_outcome {
    /// Self-build envelope finished after the injected payload deadline.
    pub const ENVELOPE_LATE: &str = "envelope_late";
}

/// Proposal outcomes. `envelope_late` counts self-build payload overruns.
pub static RVC_PROPOSALS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_proposals_total",
        "Block proposal outcomes (self-build envelope deadline overruns use outcome=envelope_late)",
        &["outcome"],
    )
});

/// Pre-Gloas SSZ proposals published as `SignedBlockContents`.
///
/// Label `fork` is the consensus version (`deneb`, `electra`, `fulu`). One
/// increment per published proposal. Blinded blocks and Gloas do not increment.
pub static RVC_BLOB_SIDECARS_PUBLISHED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_blob_sidecars_published_total",
        "Pre-Gloas SSZ block proposals published as SignedBlockContents with sidecars",
        &["fork"],
    )
});

/// Force-register the family (and the `envelope_late` child) so scrapes see it before an overrun.
pub fn init() {
    LazyLock::force(&RVC_PROPOSALS_TOTAL);
    let _ = RVC_PROPOSALS_TOTAL.with_label_values(&[proposal_outcome::ENVELOPE_LATE]);
    LazyLock::force(&RVC_BLOB_SIDECARS_PUBLISHED_TOTAL);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }
}
