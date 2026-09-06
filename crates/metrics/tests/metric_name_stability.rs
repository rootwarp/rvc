//! ARCH-6h / ARCH-P2-3: metric-name-stability gate (VD-6-6).
//!
//! The PRD accepted ARCH-P2-3 against a "metrics-conformance gate" that did not
//! exist at HEAD. This file is that gate: the exposed Prometheus family-name set
//! is pinned and is edit-only. A rename or removal must be a deliberate diff to
//! [`EXPECTED_METRIC_NAMES`] with an operator-facing note — dashboards bind these
//! strings.
//!
//! The ARCH-6h plan cited 24 names against `0ae9a09`. This pin is taken from the
//! pre-change tree (`develop` @ `eaef2fd`), which defined 35 families.
//! Issue 4.6 adds `rvc_ptc_duties_fetched_total` (family delta +1).
//! Issue 4.13 adds `rvc_payload_attestation_skipped_total` (family delta +1).
//! Issue 4.12 adds `rvc_signer_capability` (family delta +1).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rvc_metrics::definitions::init_metrics;
use rvc_metrics::REGISTRY;

/// Constructor prefixes whose first string argument is a Prometheus family name.
const NAME_CTORS: &[&str] = &[
    "Opts::new(",
    "HistogramOpts::new(",
    "IntCounter::new(",
    "IntGauge::new(",
    "Counter::new(",
    "Gauge::new(",
    "define_int_counter(",
    "define_int_counter_vec(",
    "define_int_gauge(",
    "define_int_gauge_vec(",
    "define_gauge(",
    "define_gauge_vec(",
    "define_histogram_vec(",
    "define_int_counter_with_const_labels(",
    "register_metric(",
];

/// Files that declare the pinned families. Owner crates are added as metrics move.
const DEFINITION_FILES: &[&str] = &[
    "crates/metrics/src/definitions.rs",
    "crates/bn-manager/src/metrics.rs",
    "crates/duty-tracker/src/metrics.rs",
    "crates/rvc/src/metrics.rs",
    "crates/signer/src/metrics.rs",
    "crates/slashing/src/metrics.rs",
];

/// Prometheus family names registered by `definitions::init_metrics` on the
/// pre-change tree. Sorted. Edit only with an operator-facing note.
const EXPECTED_METRIC_NAMES: &[&str] = &[
    "rvc_aggregations_total",
    "rvc_attestation_trigger_total",
    "rvc_attestations_total",
    "rvc_attesting_enabled",
    "rvc_bn_health_tier",
    "rvc_builder_circuit_breaker_trips_total",
    "rvc_builder_consecutive_misses",
    "rvc_builder_epoch_misses",
    "rvc_duties_fetched_total",
    "rvc_duty_reorg_detected_total",
    "rvc_monitoring_push_failures_total",
    "rvc_monitoring_push_success_total",
    "rvc_orchestrator_active_attestations",
    "rvc_orchestrator_missed_slots_total",
    "rvc_orchestrator_slot_processing_duration_seconds",
    "rvc_orchestrator_slots_processed_total",
    "rvc_payload_attestation_skipped_total",
    "rvc_pre_proposal_cold_fetch_duration_seconds",
    "rvc_pre_proposal_cold_fetch_total",
    "rvc_proposer_bn_health_score",
    "rvc_proposer_bn_latency_ms",
    "rvc_proposer_config_refresh_failures_total",
    "rvc_proposer_config_refresh_success_total",
    "rvc_ptc_duties_fetched_total",
    "rvc_signer_capability",
    "rvc_signer_slashing_tx_hold_duration_ms",
    "rvc_signing_duration_seconds",
    "rvc_slashing_db_prune_total",
    "rvc_slashing_protection_checks_total",
    "rvc_slashing_reconcile_total",
    "rvc_slashing_reserve_tx_hold_duration_ms",
    "rvc_slot_context_parent_fallback_total",
    "rvc_slot_phase_block_start_offset_ms",
    "rvc_sse_events_dropped_total",
    "rvc_sync_committee_skipped_total",
    "rvc_task_exits_total",
    "rvc_tasks_running",
    "rvc_validators_slashed_total",
];

const DOMAIN_VOCAB: &[&str] = &[
    "ATTESTATION",
    "DUTY",
    "DUTIES",
    "SIGNING",
    "SLASHING",
    "ORCHESTRATOR",
    "PROPOS",
    "AGGREGAT",
    "SYNC_COMMITTEE",
    "BEACON",
];

fn expected_set() -> BTreeSet<String> {
    EXPECTED_METRIC_NAMES.iter().map(|s| (*s).to_string()).collect()
}

fn gathered_rvc_names() -> BTreeSet<String> {
    REGISTRY
        .gather()
        .into_iter()
        .map(|m| m.name().to_string())
        .filter(|n| n.starts_with("rvc_"))
        .collect()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// First string argument of a Prometheus constructor, if it is an `rvc_` family name.
fn first_rvc_ctor_name(src: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for ctor in NAME_CTORS {
        let mut from = 0;
        while let Some(rel) = src[from..].find(ctor) {
            let at = from + rel + ctor.len();
            let rest = src[at..].trim_start();
            if let Some(rest) = rest.strip_prefix('"') {
                if let Some(end) = rest.find('"') {
                    let name = &rest[..end];
                    if name.starts_with("rvc_") {
                        names.insert(name.to_string());
                    }
                }
            }
            from = at;
        }
    }
    names
}

fn defined_rvc_family_names() -> BTreeSet<String> {
    let root = workspace_root();
    let mut names = BTreeSet::new();
    for rel in DEFINITION_FILES {
        let path = root.join(rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {rel}"));
        names.extend(first_rvc_ctor_name(&src));
    }
    names
}

fn definitions_src() -> String {
    let path = workspace_root().join("crates/metrics/src/definitions.rs");
    std::fs::read_to_string(path).expect("read crates/metrics/src/definitions.rs")
}

/// `pub static ref IDENT` names whose identifier matches the domain vocabulary.
fn domain_named_static_refs(src: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let needle = "pub static ref ";
    let mut from = 0;
    while let Some(rel) = src[from..].find(needle) {
        let at = from + rel + needle.len();
        let rest = &src[at..];
        let ident_len =
            rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
        let ident = &rest[..ident_len];
        if DOMAIN_VOCAB.iter().any(|tok| ident.contains(tok)) {
            hits.push(ident.to_string());
        }
        from = at + ident_len;
    }
    hits.sort();
    hits.dedup();
    hits
}

#[test]
fn expected_metric_names_is_sorted_and_unique() {
    let mut sorted = EXPECTED_METRIC_NAMES.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        EXPECTED_METRIC_NAMES,
        sorted.as_slice(),
        "EXPECTED_METRIC_NAMES must be sorted and unique (edit-only list)"
    );
    assert_eq!(
        EXPECTED_METRIC_NAMES.len(),
        38,
        "issue 4.12 +1 family (rvc_signer_capability) on the 4.13 37-family pin"
    );
}

#[test]
fn metric_name_set_is_unchanged() {
    init_metrics();
    let expected = expected_set();
    let actual = defined_rvc_family_names();
    let missing: Vec<&String> = expected.difference(&actual).collect();
    let extra: Vec<&String> = actual.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "metric name set changed; edit EXPECTED_METRIC_NAMES with an operator-facing note.\n  missing: {missing:?}\n  extra: {extra:?}"
    );

    // Empty MetricVecs do not appear in gather() until a child is observed.
    // Anything that *does* gather must still be a pinned family.
    let gathered = gathered_rvc_names();
    let gathered_extra: Vec<&String> = gathered.difference(&expected).collect();
    assert!(
        gathered_extra.is_empty(),
        "REGISTRY gathered an unpinned rvc_ family: {gathered_extra:?}"
    );
}

#[test]
fn forcing_every_metric_twice_does_not_panic() {
    init_metrics();
    init_metrics();
    let first = rvc_metrics::define_int_counter("double_reg_guard_test", "idempotent helper");
    let second = rvc_metrics::define_int_counter("double_reg_guard_test", "idempotent helper");
    first.inc();
    assert_eq!(second.get(), first.get());
}

#[test]
fn no_domain_named_definition_remains_in_metrics() {
    let src = definitions_src();
    let hits = domain_named_static_refs(&src);
    assert!(
        hits.is_empty(),
        "domain-named pub static ref remains in crates/metrics/src/definitions.rs: {}",
        hits.join(", ")
    );
}
