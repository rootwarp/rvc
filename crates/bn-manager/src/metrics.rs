//! Beacon-node-manager Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{
    define_gauge_vec, define_histogram_vec, define_int_counter_vec, define_int_gauge_vec, GaugeVec,
    HistogramVec, IntCounterVec, IntGaugeVec,
};

/// Counter for attestation operations.
/// Labels: status (success, failed, skipped)
pub static RVC_ATTESTATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_attestations_total",
        "Total number of attestation operations",
        &["status"],
    )
});

/// Gauge for proposer BN pool health score.
/// Labels: endpoint
pub static RVC_PROPOSER_BN_HEALTH_SCORE: LazyLock<GaugeVec> = LazyLock::new(|| {
    define_gauge_vec(
        "rvc_proposer_bn_health_score",
        "Health score of proposer beacon nodes",
        &["endpoint"],
        &[("pool", "proposer")],
    )
});

/// Histogram for proposer BN latency in milliseconds.
/// Labels: endpoint
pub static RVC_PROPOSER_BN_LATENCY_MS: LazyLock<HistogramVec> = LazyLock::new(|| {
    define_histogram_vec(
        "rvc_proposer_bn_latency_ms",
        "Latency of proposer beacon node requests in milliseconds",
        &["endpoint"],
        &[5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0],
        &[("pool", "proposer")],
    )
});

/// Per-BN per-capability serving state (1=capable, 0=incapable).
///
/// Labels: endpoint, capability. Owned by issue 6.7; issue 8.3 consumes this
/// family and must not re-declare it.
pub static RVC_BN_CAPABILITY_STATE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    define_int_gauge_vec(
        "rvc_bn_capability_state",
        "Whether a beacon node can serve a capability (1=capable, 0=incapable)",
        &["endpoint", "capability"],
    )
});

pub fn init() {
    LazyLock::force(&RVC_ATTESTATIONS_TOTAL);
    LazyLock::force(&RVC_PROPOSER_BN_HEALTH_SCORE);
    LazyLock::force(&RVC_PROPOSER_BN_LATENCY_MS);
    LazyLock::force(&RVC_BN_CAPABILITY_STATE);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }
}
