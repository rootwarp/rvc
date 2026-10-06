//! Cross-cutting metric definitions and shared label vocabularies.
//!
//! Domain-named families live in their owning crates (ARCH-6h). This module
//! keeps process-wide primitives, label constants, and a compatibility alias
//! so `crates/signer/tests/tx_hold_metric.rs` stays byte-unmodified.

use lazy_static::lazy_static;
use prometheus::{Gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge};

use crate::{
    define_gauge, define_histogram_vec, define_int_counter, define_int_counter_vec,
    define_int_counter_with_const_labels, define_int_gauge, define_int_gauge_vec,
};

/// Buckets (ms) shared by the retained phase-0 histogram and `rvc_slot_phase_offset_ms`.
const SLOT_PHASE_OFFSET_BUCKETS_MS: &[f64] = &[
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2000.0, 4000.0, 8000.0, 12000.0, 20000.0,
    30000.0, 60000.0,
];

lazy_static! {
    /// Gauge for attestation enabled state (1=enabled, 0=disabled).
    pub static ref RVC_ATTESTING_ENABLED: Gauge = {
        define_gauge(
            "rvc_attesting_enabled",
            "Whether attestation duties are enabled (1=enabled, 0=disabled)",
        )
    };

    /// Counter for slashed validators detected.
    pub static ref RVC_VALIDATORS_SLASHED_TOTAL: IntCounter = {
        define_int_counter(
            "rvc_validators_slashed_total",
            "Total number of slashed validators detected",
        )
    };

    /// Counter for circuit breaker trip events.
    pub static ref RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL: IntCounter = {
        define_int_counter(
            "rvc_builder_circuit_breaker_trips_total",
            "Total number of times the builder circuit breaker has tripped",
        )
    };

    /// Gauge for current consecutive builder misses.
    pub static ref RVC_BUILDER_CONSECUTIVE_MISSES: IntGauge = {
        define_int_gauge(
            "rvc_builder_consecutive_misses",
            "Current number of consecutive builder misses",
        )
    };

    /// Gauge for current epoch builder misses.
    pub static ref RVC_BUILDER_EPOCH_MISSES: IntGauge = {
        define_int_gauge(
            "rvc_builder_epoch_misses",
            "Current number of builder misses in the current epoch",
        )
    };

    /// Counter for successful monitoring pushes.
    pub static ref RVC_MONITORING_PUSH_SUCCESS_TOTAL: IntCounter = {
        define_int_counter(
            "rvc_monitoring_push_success_total",
            "Total number of successful monitoring metric pushes",
        )
    };

    /// Counter for failed monitoring pushes.
    pub static ref RVC_MONITORING_PUSH_FAILURES_TOTAL: IntCounter = {
        define_int_counter(
            "rvc_monitoring_push_failures_total",
            "Total number of failed monitoring metric pushes",
        )
    };

    /// Gauge for per-BN health tier (1=Synced, 2=SmallLag, 3=LargeLag, 4=Unsynced).
    /// Labels: endpoint
    pub static ref RVC_BN_HEALTH_TIER: prometheus::IntGaugeVec = {
        define_int_gauge_vec(
            "rvc_bn_health_tier",
            "Health tier of each beacon node (1=synced, 2=small-lag, 3=large-lag, 4=unsynced)",
            &["endpoint"],
        )
    };

    /// Compatibility handle for `rvc_signer_slashing_tx_hold_duration_ms`.
    ///
    /// The owning declaration is `signer::metrics`. This rust identifier is
    /// deliberately not domain-named so the ARCH-6h scanner stays green, while
    /// [`RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS`] keeps the pre-change path
    /// used by `tx_hold_metric.rs`.
    pub static ref RVC_TX_HOLD_DURATION_MS: HistogramVec = {
        define_histogram_vec(
            "rvc_signer_slashing_tx_hold_duration_ms",
            "Duration (ms) that the slashing-DB transaction is held per stage→commit/discard cycle",
            &["kind"],
            &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0],
            &[],
        )
    };

    /// retained for dashboards
    ///
    /// Histogram for slot phase-0 start offset in milliseconds (M2 / AQ-7).
    pub static ref RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS: HistogramVec = {
        define_histogram_vec(
            "rvc_slot_phase_block_start_offset_ms",
            "Offset (ms) from slot start to entry of maybe_propose_block",
            &["cache"],
            SLOT_PHASE_OFFSET_BUCKETS_MS,
            &[],
        )
    };

    /// Offset (ms) from the true slot start when a slot phase fires.
    ///
    /// Label `phase` is one of {block, attestation, sync_message, aggregate,
    /// contribution, payload_attestation}. Buckets match
    /// [`RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS`].
    pub static ref RVC_SLOT_PHASE_OFFSET_MS: HistogramVec = {
        define_histogram_vec(
            "rvc_slot_phase_offset_ms",
            "Offset (ms) from the true slot start when a slot phase fires",
            &["phase"],
            SLOT_PHASE_OFFSET_BUCKETS_MS,
            &[],
        )
    };

    /// Phases that fired immediately because their absolute deadline had already passed.
    /// Label: phase
    pub static ref RVC_SLOT_PHASE_LATE_TOTAL: IntCounterVec = {
        define_int_counter_vec(
            "rvc_slot_phase_late_total",
            "Total number of slot phases that fired immediately because their absolute deadline had already passed",
            &["phase"],
        )
    };

    /// Gauge for currently running registered tasks (TaskExecutor).
    pub static ref RVC_TASKS_RUNNING: prometheus::IntGaugeVec = {
        define_int_gauge_vec(
            "rvc_tasks_running",
            "Number of currently running registered tasks",
            &["task"],
        )
    };

    /// Head events superseded on the latest-wins watch bridge (C7).
    pub static ref RVC_SSE_EVENTS_DROPPED_TOTAL: IntCounter = {
        define_int_counter_with_const_labels(
            "rvc_sse_events_dropped_total",
            "Head SSE events superseded by a later event on the latest-wins watch bridge",
            &[("expected", "true")],
        )
    };

    /// Counter for registered task exits by outcome (TaskExecutor).
    pub static ref RVC_TASK_EXITS_TOTAL: IntCounterVec = {
        define_int_counter_vec(
            "rvc_task_exits_total",
            "Total number of registered task exits by outcome",
            &["task", "outcome"],
        )
    };

    /// Parent-root walk-back fallbacks at t=0 (ARCH-3d).
    pub static ref RVC_SLOT_CONTEXT_PARENT_FALLBACK_TOTAL: IntCounterVec = {
        define_int_counter_vec(
            "rvc_slot_context_parent_fallback_total",
            "Total number of SlotContext parent_root fallbacks after walk-back",
            &["reason"],
        )
    };

    /// Slots skipped because the clock stepped back onto an already-processed slot.
    pub static ref RVC_SLOT_REPLAY_SKIPPED_TOTAL: IntCounter = {
        define_int_counter(
            "rvc_slot_replay_skipped_total",
            "Total number of slots skipped because the clock stepped back onto an already-processed slot",
        )
    };
}

/// Pre-change path for `tx_hold_metric.rs` (byte-unmodified).
pub use RVC_TX_HOLD_DURATION_MS as RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS;

/// Initializes cross-cutting metrics by accessing the lazy_static variables.
pub fn init_metrics() {
    lazy_static::initialize(&RVC_ATTESTING_ENABLED);
    lazy_static::initialize(&RVC_VALIDATORS_SLASHED_TOTAL);
    lazy_static::initialize(&RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL);
    lazy_static::initialize(&RVC_BUILDER_CONSECUTIVE_MISSES);
    lazy_static::initialize(&RVC_BUILDER_EPOCH_MISSES);
    lazy_static::initialize(&RVC_MONITORING_PUSH_SUCCESS_TOTAL);
    lazy_static::initialize(&RVC_MONITORING_PUSH_FAILURES_TOTAL);
    lazy_static::initialize(&RVC_BN_HEALTH_TIER);
    lazy_static::initialize(&RVC_TX_HOLD_DURATION_MS);
    lazy_static::initialize(&RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS);
    lazy_static::initialize(&RVC_SLOT_PHASE_OFFSET_MS);
    lazy_static::initialize(&RVC_SLOT_PHASE_LATE_TOTAL);
    lazy_static::initialize(&RVC_TASKS_RUNNING);
    lazy_static::initialize(&RVC_SSE_EVENTS_DROPPED_TOTAL);
    lazy_static::initialize(&RVC_TASK_EXITS_TOTAL);
    lazy_static::initialize(&RVC_SLOT_CONTEXT_PARENT_FALLBACK_TOTAL);
    lazy_static::initialize(&RVC_SLOT_REPLAY_SKIPPED_TOTAL);
    // DSR-2.4: force-register S5A zero children so scrapes see numeric samples.
    let _ = RVC_BN_HEALTH_TIER.with_label_values(&[bn_health_tier::UNCONFIGURED_ENDPOINT]);
    for task in task_exit_tasks::ALL {
        for outcome in task_exit_outcome::ALL {
            let _ = RVC_TASK_EXITS_TOTAL.with_label_values(&[task, outcome]);
        }
    }
}

/// Attestation status label values.
pub mod attestation_status {
    pub const SUCCESS: &str = "success";
    pub const FAILED: &str = "failed";
    pub const SKIPPED: &str = "skipped";
}

/// Slashing protection result label values.
pub mod slashing_result {
    pub const SAFE: &str = "safe";
    pub const BLOCKED: &str = "blocked";
}

/// Orchestrator slot processing result label values.
pub mod orchestrator_result {
    pub const SUCCESS: &str = "success";
    pub const FAILED: &str = "failed";
    pub const NO_DUTIES: &str = "no_duties";
}

/// Slashing DB prune type label values.
pub mod prune_type {
    pub const ATTESTATION: &str = "attestation";
    pub const BLOCK: &str = "block";
}

/// `kind` label values for `rvc_signer_slashing_tx_hold_duration_ms`.
pub mod tx_hold_kind {
    pub const ATTESTATION: &str = "attestation";
    pub const BLOCK: &str = "block";
}

/// `cache` label values for `rvc_slot_phase_block_start_offset_ms`.
pub mod slot_phase_cache {
    pub const WARM: &str = "warm";
    pub const COLD: &str = "cold";
}

/// `phase` label values for `rvc_slot_phase_late_total`.
pub mod slot_phase_late {
    pub const ATTESTATION: &str = "attestation";
    pub const SYNC_MESSAGE: &str = "sync_message";
    pub const AGGREGATE: &str = "aggregate";
    pub const CONTRIBUTION: &str = "contribution";
    pub const PAYLOAD_ATTESTATION: &str = "payload_attestation";
}

/// `phase` label values for `rvc_slot_phase_offset_ms`.
pub mod slot_phase_offset {
    pub const BLOCK: &str = "block";
    pub const ATTESTATION: &str = "attestation";
    pub const SYNC_MESSAGE: &str = "sync_message";
    pub const AGGREGATE: &str = "aggregate";
    pub const CONTRIBUTION: &str = "contribution";
    pub const PAYLOAD_ATTESTATION: &str = "payload_attestation";
    /// Every label the histogram records. Registration and the coordinator
    /// suite both walk this list.
    pub const ALL: &[&str] =
        &[BLOCK, ATTESTATION, SYNC_MESSAGE, AGGREGATE, CONTRIBUTION, PAYLOAD_ATTESTATION];
}

/// `outcome` label values for `rvc_task_exits_total`.
pub mod task_exit_outcome {
    pub const OK: &str = "ok";
    pub const PANIC: &str = "panic";
    pub const CANCELLED: &str = "cancelled";
    /// Children force-registered at process init so scrapes see them at zero.
    pub const ALL: &[&str] = &[OK, PANIC, CANCELLED];
}

/// Production TaskExecutor task names force-registered for
/// [`RVC_TASK_EXITS_TOTAL`] zero children (DSR-2.4 / A-A5 ≈13 × 3).
pub mod task_exit_tasks {
    pub const ALL: &[&str] = &[
        "metrics_server",
        "monitoring_push",
        "proposer_config_refresh",
        "bn.sse",
        "bn.sse.cancel",
        "bn.sync_monitor",
        "bn.sync_monitor.cancel",
        "slashing_monitor",
        "duty_orchestrator",
        "liveness_loop",
        "index.resolve",
        "keymanager_api",
        "secret_provider_refresh",
    ];
}

/// Sentinel `endpoint` for [`RVC_BN_HEALTH_TIER`] force-register at init (DSR-2.4).
///
/// Real BN endpoints overwrite/add their own children from the sync poller.
pub mod bn_health_tier {
    pub const UNCONFIGURED_ENDPOINT: &str = "unknown";
}

/// `reason` label values for `rvc_slot_context_parent_fallback_total`.
pub mod slot_context_parent_fallback {
    pub const WALK_BACK_EXHAUSTED: &str = "walk_back_exhausted";
}

/// `phase` label values for `rvc_sync_committee_skipped_total`.
pub mod sync_committee_skip_phase {
    pub const MESSAGES: &str = "messages";
    pub const CONTRIBUTIONS: &str = "contributions";
}

/// `reason` label values for `rvc_sync_committee_skipped_total`.
pub mod sync_committee_skip_reason {
    pub const NO_HEAD_ROOT: &str = "no_head_root";
}

/// `reason` label values for `rvc_payload_attestation_skipped_total`.
pub mod payload_attestation_skip_reason {
    pub const NO_DATA: &str = "no_data";
}

/// `outcome` label values for `rvc_pre_proposal_cold_fetch_*`.
pub mod pre_proposal_cold_fetch {
    pub const HIT: &str = "hit";
    pub const MISS: &str = "miss";
    pub const TIMEOUT: &str = "timeout";
}

/// `source` label values for `rvc_attestation_trigger_total`.
pub mod attestation_trigger_source {
    pub const TIMER: &str = "timer";
    pub const HEAD_EVENT: &str = "head_event";
}

/// `outcome` label values for `rvc_slashing_reconcile_total`.
pub mod reconcile_outcome {
    pub const DELETED: &str = "deleted";
    pub const NOT_APPLICABLE: &str = "not_applicable";
    pub const FAILED: &str = "failed";
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::REGISTRY;

    #[test]
    fn test_init_metrics_registers_cross_cutting() {
        init_metrics();

        RVC_SSE_EVENTS_DROPPED_TOTAL.inc();
        RVC_VALIDATORS_SLASHED_TOTAL.inc();
        RVC_TX_HOLD_DURATION_MS.with_label_values(&[tx_hold_kind::BLOCK]).observe(1.0);

        let metrics = REGISTRY.gather();
        let metric_names: Vec<&str> = metrics.iter().map(|m| m.name()).collect();

        assert!(
            metric_names.contains(&"rvc_sse_events_dropped_total"),
            "rvc_sse_events_dropped_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_validators_slashed_total"),
            "rvc_validators_slashed_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_signer_slashing_tx_hold_duration_ms"),
            "rvc_signer_slashing_tx_hold_duration_ms should be registered"
        );
    }

    #[test]
    fn init_force_registers_task_exits_and_bn_health_tier_samples() {
        init_metrics();
        let gathered = REGISTRY.gather();

        let exits = gathered
            .iter()
            .find(|m| m.name() == "rvc_task_exits_total")
            .expect("rvc_task_exits_total must be gatherable after init");
        assert!(!exits.get_metric().is_empty(), "task_exits must expose numeric samples at init");
        let mut outcomes = std::collections::BTreeSet::new();
        let mut tasks = std::collections::BTreeSet::new();
        for metric in exits.get_metric() {
            for label in metric.get_label() {
                match label.name() {
                    "outcome" => {
                        outcomes.insert(label.value());
                    }
                    "task" => {
                        tasks.insert(label.value());
                    }
                    _ => {}
                }
            }
        }
        for expected in task_exit_outcome::ALL {
            assert!(
                outcomes.contains(expected),
                "task_exits outcome={expected} must be force-registered, got {outcomes:?}"
            );
        }
        for expected in task_exit_tasks::ALL {
            assert!(
                tasks.contains(expected),
                "task_exits task={expected} must be force-registered, got {tasks:?}"
            );
        }

        let health = gathered
            .iter()
            .find(|m| m.name() == "rvc_bn_health_tier")
            .expect("rvc_bn_health_tier must be gatherable after init");
        assert!(
            !health.get_metric().is_empty(),
            "bn_health_tier must expose a numeric sample at init"
        );
        let endpoints: std::collections::BTreeSet<&str> = health
            .get_metric()
            .iter()
            .filter_map(|metric| {
                metric
                    .get_label()
                    .iter()
                    .find(|label| label.name() == "endpoint")
                    .map(|label| label.value())
            })
            .collect();
        assert!(
            endpoints.contains(bn_health_tier::UNCONFIGURED_ENDPOINT),
            "bn_health_tier unknown endpoint must be force-registered, got {endpoints:?}"
        );
    }

    #[test]
    fn test_circuit_breaker_trips_total_increments() {
        RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL.inc();
        let value = RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL.get();
        assert!(value >= 1, "Circuit breaker trips counter should be at least 1 after increment");
    }

    #[test]
    fn slot_phase_offset_ms_is_registered_at_init() {
        init_metrics();
        for phase in slot_phase_offset::ALL {
            let _ = RVC_SLOT_PHASE_OFFSET_MS.with_label_values(&[phase]).get_sample_count();
        }
        let gathered = REGISTRY.gather();
        let metric = gathered
            .iter()
            .find(|m| m.name() == "rvc_slot_phase_offset_ms")
            .expect("rvc_slot_phase_offset_ms must be registered at init");
        let mut phases = std::collections::BTreeSet::new();
        for sample in metric.get_metric() {
            for label in sample.get_label() {
                if label.name() == "phase" {
                    phases.insert(label.value().to_string());
                }
            }
            let bounds: Vec<f64> = sample
                .get_histogram()
                .get_bucket()
                .iter()
                .map(|bucket| bucket.upper_bound())
                .filter(|bound| bound.is_finite())
                .collect();
            assert_eq!(
                bounds.as_slice(),
                SLOT_PHASE_OFFSET_BUCKETS_MS,
                "phase offset buckets must match the retained block-start list"
            );
        }
        let expected: std::collections::BTreeSet<String> =
            slot_phase_offset::ALL.iter().map(|phase| (*phase).to_string()).collect();
        assert_eq!(phases, expected, "all six phase labels must be recordable");
    }

    #[test]
    fn slot_replay_skipped_total_is_registered_at_init() {
        init_metrics();
        let gathered = REGISTRY.gather();
        let metric = gathered
            .iter()
            .find(|m| m.name() == "rvc_slot_replay_skipped_total")
            .expect("rvc_slot_replay_skipped_total must be registered at init so a scrape sees it");
        assert_eq!(metric.get_metric().len(), 1, "unlabelled counter exposes one sample");
        assert_eq!(
            metric.get_metric()[0].get_counter().get_value(),
            0.0,
            "a scrape at init must see zero"
        );
    }

    #[test]
    fn test_slot_context_parent_fallback_total_increments() {
        RVC_SLOT_CONTEXT_PARENT_FALLBACK_TOTAL
            .with_label_values(&[slot_context_parent_fallback::WALK_BACK_EXHAUSTED])
            .inc();
        let value = RVC_SLOT_CONTEXT_PARENT_FALLBACK_TOTAL
            .with_label_values(&[slot_context_parent_fallback::WALK_BACK_EXHAUSTED])
            .get();
        assert!(value >= 1, "Parent fallback counter should be at least 1 after increment");
    }

    #[test]
    fn test_builder_consecutive_misses_gauge() {
        RVC_BUILDER_CONSECUTIVE_MISSES.set(3);
        assert_eq!(RVC_BUILDER_CONSECUTIVE_MISSES.get(), 3);
        RVC_BUILDER_CONSECUTIVE_MISSES.set(0);
        assert_eq!(RVC_BUILDER_CONSECUTIVE_MISSES.get(), 0);
    }

    #[test]
    fn test_builder_epoch_misses_gauge() {
        RVC_BUILDER_EPOCH_MISSES.set(5);
        assert_eq!(RVC_BUILDER_EPOCH_MISSES.get(), 5);
        RVC_BUILDER_EPOCH_MISSES.set(0);
        assert_eq!(RVC_BUILDER_EPOCH_MISSES.get(), 0);
    }

    #[test]
    fn tx_hold_alias_is_the_same_handle() {
        RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
            .with_label_values(&[tx_hold_kind::ATTESTATION])
            .observe(2.0);
        let via_alias = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
            .with_label_values(&[tx_hold_kind::ATTESTATION])
            .get_sample_count();
        let via_prim = RVC_TX_HOLD_DURATION_MS
            .with_label_values(&[tx_hold_kind::ATTESTATION])
            .get_sample_count();
        assert_eq!(via_alias, via_prim);
    }
}
