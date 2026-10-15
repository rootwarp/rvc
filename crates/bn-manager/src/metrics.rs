//! Beacon-node-manager Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{
    define_gauge_vec, define_histogram_vec, define_int_counter, define_int_counter_vec,
    define_int_gauge_vec, GaugeVec, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec,
};
use url::Url;

/// `scheme://host:port` with userinfo and path stripped — dashboards key on host,
/// not credentials or request path (issue 8.3 label hygiene).
///
/// Shared by `rvc_bn_capability_state`, `rvc_bn_health_tier`, and
/// `RejectedByBeaconNode.bn` (issue #598).
pub fn endpoint_label(endpoint: &str) -> String {
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

/// Counter for attestation submit outcomes in the beacon-node propagator.
///
/// Labels: `status` (`success`, `failed`, `skipped`).
///
/// **Scope of `{status="failed"}`:** increments from this crate cover beacon-node
/// submit responses only (per-index entries in a partial-failure list, or a
/// complete submit failure). Orchestrator-side terminal failures that never
/// reach a submit response — sign errors, attestation-data fetch errors,
/// submit timeouts, and propagate transport errors — appear in slot accounting
/// (`AttestationOutcome::Failed`, slot summary logs) but do **not** increment
/// this series here. The signer crate may also increment the same Prometheus
/// name for slashing-blocked attestation signs; that path is separate from
/// submit accounting (issue #598 / Security S4).
pub static RVC_ATTESTATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_attestations_total",
        "Attestation submit outcomes (success/failed cover BN submit responses; \
         orchestrator sign/fetch/timeout failures are not counted here)",
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

/// Health samples not applied because a success was skipped while the
/// health-sample cap was full, or because the recorder queue did not accept
/// the sample.
///
/// The publish itself still runs. A full pool still records an error or a
/// timeout when the queue has room. A full queue drops the sample, including
/// an error or a timeout, and does not block the attempt. The cap limits
/// health recording, not sends.
pub static RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL: LazyLock<IntCounter> = LazyLock::new(
    || {
        define_int_counter(
        "rvc_bn_broadcast_drain_health_skipped_total",
        "Broadcast health samples not recorded because the health-sample cap skipped a success, or because the recorder queue was full. When the queue is full, an error or a timeout sample can be dropped, and that drop is counted. The enqueue does not block the publish. A full pool still records an error or a timeout when the queue has room. The publish still runs",
    )
    },
);

/// In-flight overflow publishes, one series per redacted beacon endpoint.
///
/// The 16-permit health-sample cap limits health recording, not sends. A
/// publish past that cap still runs. The gauge drops when that HTTP call
/// finishes, before the health sample is queued. The `endpoint` label is
/// [`endpoint_label`] (`scheme://host:port`, userinfo and path stripped) so
/// a slow beacon node's backlog is visible. Each publish ends at that
/// attempt's budget, or at the beacon client's HTTP timeout when no budget
/// is set.
pub static RVC_BN_BROADCAST_OVERFLOW_DRAINS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    define_int_gauge_vec(
        "rvc_bn_broadcast_overflow_drains",
        "In-flight broadcast publishes past the health-sample cap, by redacted endpoint. The gauge drops when the HTTP call finishes, or when that attempt is cancelled or panics. The cap limits health recording, not sends. Each publish ends at the attempt budget, or at the HTTP client timeout when no budget is set",
        &["endpoint"],
    )
});

pub fn init() {
    LazyLock::force(&RVC_ATTESTATIONS_TOTAL);
    LazyLock::force(&RVC_PROPOSER_BN_HEALTH_SCORE);
    LazyLock::force(&RVC_PROPOSER_BN_LATENCY_MS);
    LazyLock::force(&RVC_BN_CAPABILITY_STATE);
    LazyLock::force(&RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL);
    LazyLock::force(&RVC_BN_BROADCAST_OVERFLOW_DRAINS);
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
