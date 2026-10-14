//! Block-proposal Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{define_int_counter_vec, IntCounterVec};

/// `outcome` label values for [`RVC_PROPOSALS_TOTAL`].
pub mod proposal_outcome {
    /// Self-build envelope finished after the injected payload deadline.
    pub const ENVELOPE_LATE: &str = "envelope_late";
    /// Propose+publish completed without error.
    pub const SUCCESS: &str = "success";
    /// Propose+publish returned an error or the outer timeout fired.
    pub const FAILED: &str = "failed";
    /// Children force-registered at process init so scrapes see them at zero.
    pub const ALL: &[&str] = &[ENVELOPE_LATE, SUCCESS, FAILED];
}

/// Proposal outcomes (`success`, `failed`, and self-build `envelope_late`).
pub static RVC_PROPOSALS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_proposals_total",
        "Block proposal outcomes by result (success, failed, envelope_late)",
        &["outcome"],
    )
});

/// Pre-Gloas proposals published as `SignedBlockContents`.
///
/// Label `fork` is the consensus version (`deneb`, `electra`, `fulu`). One
/// increment per successful JSON or SSZ publish. Blinded blocks and Gloas do not increment.
pub static RVC_BLOB_SIDECARS_PUBLISHED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_blob_sidecars_published_total",
        "Pre-Gloas block proposals published as SignedBlockContents with kzg_proofs and blobs",
        &["fork"],
    )
});

/// Force-register the family and labeled children so scrapes see them before any attempt.
pub fn init() {
    LazyLock::force(&RVC_PROPOSALS_TOTAL);
    for outcome in proposal_outcome::ALL {
        let _ = RVC_PROPOSALS_TOTAL.with_label_values(&[*outcome]);
    }
    LazyLock::force(&RVC_BLOB_SIDECARS_PUBLISHED_TOTAL);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }

    #[test]
    fn init_registers_success_failed_and_envelope_late_children() {
        super::init();
        let gathered = metrics::REGISTRY.gather();
        let family = gathered
            .iter()
            .find(|m| m.name() == "rvc_proposals_total")
            .expect("rvc_proposals_total must be gatherable after init");
        let outcomes: BTreeSet<&str> = family
            .get_metric()
            .iter()
            .filter_map(|metric| {
                metric
                    .get_label()
                    .iter()
                    .find(|label| label.name() == "outcome")
                    .map(|label| label.value())
            })
            .collect();
        assert!(
            outcomes.contains(super::proposal_outcome::SUCCESS),
            "success child must be force-registered at init, got {outcomes:?}"
        );
        assert!(
            outcomes.contains(super::proposal_outcome::FAILED),
            "failed child must be force-registered at init, got {outcomes:?}"
        );
        assert!(
            outcomes.contains(super::proposal_outcome::ENVELOPE_LATE),
            "envelope_late child must be force-registered at init, got {outcomes:?}"
        );
    }
}
