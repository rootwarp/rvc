//! Beacon-node-manager Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{
    define_gauge_vec, define_histogram_vec, define_int_counter_vec, define_int_gauge_vec, GaugeVec,
    HistogramVec, IntCounterVec, IntGaugeVec,
};
use url::Url;

/// `scheme://host:port` with userinfo and path stripped — dashboards key on host,
/// not credentials or request path (issue 8.3 label hygiene).
///
/// Shared by `rvc_bn_capability_state` and `rvc_bn_health_tier`.
pub(crate) fn endpoint_label(endpoint: &str) -> String {
    match Url::parse(endpoint) {
        Ok(mut parsed) if parsed.scheme() == "http" || parsed.scheme() == "https" => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_path("");
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string().trim_end_matches('/').to_string()
        }
        // Unparseable (or non-http) input must not become a label — userinfo
        // can sit in a raw string that `Url::parse` rejects.
        _ => "unknown".to_string(),
    }
}

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

/// Op names whose successful BN attempts feed [`RVC_PROPOSER_BN_LATENCY_MS`].
///
/// Limited to block-production produce/publish RPCs (DSR-2.3 / FR-P1-5).
pub(crate) fn is_proposer_block_production_op(op_name: &str) -> bool {
    matches!(
        op_name,
        "produce_block_v3"
            | "produce_block_v4"
            | "publish_block"
            | "publish_block_contents"
            | "publish_blinded_block"
            | "publish_block_ssz"
            | "publish_execution_payload_envelope"
    )
}

/// Record elapsed duration for a successful proposer BN RPC used in block production.
pub(crate) fn observe_proposer_bn_latency(endpoint: &str, latency: std::time::Duration) {
    let endpoint_label = endpoint_label(endpoint);
    let ms = latency.as_secs_f64() * 1000.0;
    RVC_PROPOSER_BN_LATENCY_MS.with_label_values(&[endpoint_label.as_str()]).observe(ms);
}

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
pub(crate) fn gather_capability_state_series() -> Vec<(String, String)> {
    let gathered = metrics::REGISTRY.gather();
    let Some(mf) = gathered.iter().find(|m| m.name() == "rvc_bn_capability_state") else {
        return Vec::new();
    };
    mf.get_metric()
        .iter()
        .filter_map(|metric| {
            let mut endpoint = None;
            let mut capability = None;
            for label in metric.get_label() {
                match label.name() {
                    "endpoint" => endpoint = Some(label.value().to_string()),
                    "capability" => capability = Some(label.value().to_string()),
                    _ => {}
                }
            }
            Some((endpoint?, capability?))
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn gather_health_tier_series() -> Vec<(String, i64)> {
    let gathered = metrics::REGISTRY.gather();
    let Some(mf) = gathered.iter().find(|m| m.name() == "rvc_bn_health_tier") else {
        return Vec::new();
    };
    mf.get_metric()
        .iter()
        .filter_map(|metric| {
            let endpoint = metric.get_label().iter().find_map(|label| {
                (label.name() == "endpoint").then(|| label.value().to_string())
            })?;
            Some((endpoint, metric.get_gauge().get_value() as i64))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        endpoint_label, is_proposer_block_production_op, observe_proposer_bn_latency,
        RVC_PROPOSER_BN_LATENCY_MS,
    };
    use std::time::Duration;

    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }

    #[test]
    fn test_endpoint_label_strips_userinfo_and_path() {
        assert_eq!(endpoint_label("http://127.0.0.1:5052"), "http://127.0.0.1:5052");
        assert_eq!(
            endpoint_label("http://user:secret@bn.example:5052/eth/v4"),
            "http://bn.example:5052"
        );
        assert_eq!(endpoint_label("not a url"), "unknown");
        assert_eq!(
            endpoint_label("user:secret@host"),
            "unknown",
            "parse failure (or non-http scheme) must not emit userinfo"
        );
    }

    #[test]
    fn test_is_proposer_block_production_op_covers_produce_and_publish() {
        assert!(is_proposer_block_production_op("produce_block_v3"));
        assert!(is_proposer_block_production_op("produce_block_v4"));
        assert!(is_proposer_block_production_op("publish_block"));
        assert!(is_proposer_block_production_op("publish_block_ssz"));
        assert!(!is_proposer_block_production_op("get_genesis"));
        assert!(!is_proposer_block_production_op("submit_attestation"));
        assert!(!is_proposer_block_production_op("get_proposer_duties"));
    }

    #[test]
    fn test_observe_proposer_bn_latency_increments_histogram_count() {
        let endpoint = "http://127.0.0.1:18552";
        let label = endpoint_label(endpoint);
        let before =
            RVC_PROPOSER_BN_LATENCY_MS.with_label_values(&[label.as_str()]).get_sample_count();

        observe_proposer_bn_latency(endpoint, Duration::from_millis(12));

        let after =
            RVC_PROPOSER_BN_LATENCY_MS.with_label_values(&[label.as_str()]).get_sample_count();
        assert!(
            after > before,
            "observe must bump histogram count; before={before}, after={after}"
        );
    }
}
