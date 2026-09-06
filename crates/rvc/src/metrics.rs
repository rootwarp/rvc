//! Orchestrator Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{
    define_gauge, define_histogram_vec, define_int_counter, define_int_counter_vec,
    define_int_gauge_vec, Gauge, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec,
};

pub use bn_manager::metrics::RVC_ATTESTATIONS_TOTAL;
pub use duty_tracker::metrics::RVC_DUTIES_FETCHED_TOTAL;
pub use metrics::definitions::{
    attestation_status, attestation_trigger_source, orchestrator_result,
    payload_attestation_skip_reason, pre_proposal_cold_fetch, slot_context_parent_fallback,
    slot_phase_cache, sync_committee_skip_phase, sync_committee_skip_reason, task_exit_outcome,
};

/// Counter for slots processed by the orchestrator.
pub static RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_orchestrator_slots_processed_total",
        "Total number of slots processed by the orchestrator",
        &["result"],
    )
});

/// Counter for missed slots.
pub static RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_orchestrator_missed_slots_total",
        "Total number of missed attestation slots",
        &[],
    )
});

/// Gauge for currently active attestation tasks.
pub static RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS: LazyLock<Gauge> = LazyLock::new(|| {
    define_gauge(
        "rvc_orchestrator_active_attestations",
        "Number of currently active attestation tasks",
    )
});

/// Counter for aggregation operations.
/// Labels: status (success, failed, skipped)
pub static RVC_AGGREGATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_aggregations_total",
        "Total number of attestation aggregation operations",
        &["status"],
    )
});

/// Histogram for slot processing duration in seconds.
pub static RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| {
        define_histogram_vec(
            "rvc_orchestrator_slot_processing_duration_seconds",
            "Duration of slot processing operations in seconds",
            &[],
            &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 12.0],
            &[],
        )
    });

/// Counter for duty reorg detections.
/// Labels: duty_type (attester, proposer, ptc)
pub static RVC_DUTY_REORG_DETECTED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_duty_reorg_detected_total",
        "Total number of duty reorg detections",
        &["duty_type"],
    )
});

/// Counter for proposer config URL refresh successes.
pub static RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    define_int_counter(
        "rvc_proposer_config_refresh_success_total",
        "Total number of successful proposer config URL refreshes",
    )
});

/// Counter for proposer config URL refresh failures.
pub static RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    define_int_counter(
        "rvc_proposer_config_refresh_failures_total",
        "Total number of failed proposer config URL refreshes",
    )
});

/// Cold-cache pre-proposal proposer-duty fetches (ARCH-3j / C6).
pub static RVC_PRE_PROPOSAL_COLD_FETCH_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_pre_proposal_cold_fetch_total",
        "Total pre-proposal cold-cache proposer-duty fetches by outcome",
        &["outcome"],
    )
});

/// Duration of a cold-cache pre-proposal proposer-duty fetch (ARCH-3j).
pub static RVC_PRE_PROPOSAL_COLD_FETCH_DURATION_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| {
        define_histogram_vec(
            "rvc_pre_proposal_cold_fetch_duration_seconds",
            "Duration of pre-proposal cold-cache proposer-duty fetches in seconds",
            &["outcome"],
            &[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0],
            &[],
        )
    });

/// How phase-2 attestation wait returned (ARCH-3m).
pub static RVC_ATTESTATION_TRIGGER_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_attestation_trigger_total",
        "Attestation phase-2 waits completed by source (timer or head event)",
        &["source"],
    )
});

/// Sync committee duties skipped because phase-2 `head_root` is missing (ARCH-3e).
pub static RVC_SYNC_COMMITTEE_SKIPPED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_sync_committee_skipped_total",
        "Total number of sync committee duties skipped",
        &["phase", "reason"],
    )
});

/// Payload attestation duties skipped (HTTP 204 / no data).
pub static RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_payload_attestation_skipped_total",
        "Total number of payload attestation duties skipped",
        &["reason"],
    )
});

/// `sign_type` label values for [`RVC_SIGNER_CAPABILITY`].
pub mod signer_sign_type {
    pub const PAYLOAD_ATTESTATION: &str = "PAYLOAD_ATTESTATION";
    pub const PROPOSER_PREFERENCES: &str = "PROPOSER_PREFERENCES";
    pub const BUILDER_REQUEST_AUTH: &str = "BUILDER_REQUEST_AUTH";
    pub const ALL: &[&str] = &[PAYLOAD_ATTESTATION, PROPOSER_PREFERENCES, BUILDER_REQUEST_AUTH];
}

/// Remote-signer Gloas sign-type support (1=supported, 0=unsupported or unknown).
///
/// Probe failures are recorded as 0; they must never be reported as supported.
pub static RVC_SIGNER_CAPABILITY: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    define_int_gauge_vec(
        "rvc_signer_capability",
        "Whether the configured remote signer supports a Gloas sign type (1=supported, 0=unsupported or unknown)",
        &["sign_type"],
    )
});

/// Force-register orchestrator families and the other owners rvc composes.
pub fn init() {
    metrics::definitions::init_metrics();
    slashing::metrics::init();
    signer::metrics::init();
    duty_tracker::metrics::init();
    bn_manager::metrics::init();
    LazyLock::force(&RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL);
    LazyLock::force(&RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL);
    LazyLock::force(&RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS);
    LazyLock::force(&RVC_AGGREGATIONS_TOTAL);
    LazyLock::force(&RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS);
    LazyLock::force(&RVC_DUTY_REORG_DETECTED_TOTAL);
    LazyLock::force(&RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL);
    LazyLock::force(&RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL);
    LazyLock::force(&RVC_PRE_PROPOSAL_COLD_FETCH_TOTAL);
    LazyLock::force(&RVC_PRE_PROPOSAL_COLD_FETCH_DURATION_SECONDS);
    LazyLock::force(&RVC_ATTESTATION_TRIGGER_TOTAL);
    LazyLock::force(&RVC_SYNC_COMMITTEE_SKIPPED_TOTAL);
    LazyLock::force(&RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL);
    LazyLock::force(&RVC_SIGNER_CAPABILITY);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }
}
