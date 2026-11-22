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
//! Issue 6.7 adds `rvc_bn_capability_state` (family delta +1).
//! Issue 6.20 adds `rvc_proposals_total` (family delta +1; `outcome=envelope_late`).
//! DSR-1.2 / issue #377 force-registers `outcome=success` and `outcome=failed`
//! children and increments them on the propose path (family name unchanged).
//! Issue 7.6 adds `rvc_ptc_duties_total` and `rvc_ptc_attestations_total` (family delta +2).
//! Issue 8.4 adds `rvc_signer_rejections_total` (family delta +1).
//! Issue 8.1 adds `rvc_fork_current_id` and `rvc_fork_next_activation_epoch` (family delta +2).
//! RR-4.1 adds `rvc_slashing_prune_source_bound_raised_total` (family delta +1).
//! RR-4.2 adds `rvc_slashing_import_conflicts_total` (family delta +1): dropped
//! EIP-3076 import rows are counted once each. Dashboards that alert on silent
//! interchange conflicts should bind this name; it has no labels.
//! RR-1.2 adds `rvc_blob_sidecars_published_total` (family delta +1): one increment
//! per pre-Gloas proposal published as `SignedBlockContents`, JSON or SSZ. Label
//! `fork` is the consensus version (`deneb`, `electra`, `fulu`). Blinded and Gloas
//! publishes do not increment it.
//! RR-4.3 adds `rvc_slashing_export_synthetic_records_total` (family delta +1):
//! one increment per synthetic attestation or block floor in an interchange
//! export. It has no labels.
//! RR-2.2 adds `rvc_duty_index_set_size` (family delta +1): live size of the
//! pubkey→index registry. Dashboards that watch duty coverage should bind this
//! gauge; it has no labels.
//! RR-1.6 adds `rvc_dvt_peer_ready` (family delta +1): 0 until the first
//! successful RPC to a configured DVT peer, then 1. Label `peer` is that
//! address. Scraped on `rvc-signer`'s registry.
//! RR-5.1 adds `rvc_keymanager_quiesce_wait_ms` (family delta +1): milliseconds
//! spent waiting to acquire the slashable per-pubkey lock while quiescing.
//! The sample is that wait on both success and timeout; a timeout is still an
//! error. `Ok` from quiesce does not mean non-slashable duties are idle.
//! It has no labels.
//! RR0-07 adds `rvc_slashing_group_commit_batch_size` (family delta +1): one
//! observation per non-empty group-commit drain. Mean batch size is
//! `sample_sum / sample_count`. It has no labels. Dashboards that watch
//! group-commit batching should bind this name.
//! RR1-03 adds `rvc_slot_phase_late_total` (family delta +1): one increment
//! when a slot phase's absolute deadline has already passed and the phase
//! fires immediately. Label `phase` names that phase. Later phases are not
//! shifted. Dashboards that alert on late slot phases should bind this name.
//! RR1-04 adds `rvc_slot_replay_skipped_total` (family delta +1): one increment
//! when the slot loop skips a slot the clock stepped back onto after that
//! slot's phases already ran. It has no labels. Dashboards that alert on a
//! backward clock step should bind this name.
//! RR1-05 adds `rvc_slot_phase_offset_ms` (family delta +1): one observation
//! when a slot phase fires. Label `phase` is block, attestation, sync_message,
//! aggregate, contribution, or payload_attestation. The sample is milliseconds
//! from the true slot start, including a late wake. Buckets match
//! `rvc_slot_phase_block_start_offset_ms`, which is soft-deprecated in favour
//! of `rvc_slot_phase_offset_ms{phase="block"}` but still retained for
//! dashboards (AQ-7 / #611).
//! RR2-12 adds `rvc_slashing_import_duration_ms` and
//! `rvc_slashing_import_conn_hold_ms` (family delta +2). Duration is one sample
//! per interchange import call. Conn-hold is `conn.lock()` through `COMMIT`;
//! a rollback after the lock is taken still records one hold sample, and a
//! rejection before the lock (format version, genesis validators root, or a
//! malformed numeric field) records none. Buckets are 10, 25, 50, 100, 250,
//! 500, 1000, 2500, 5000, and 10000 milliseconds. Neither family has labels.
//! Dashboards that watch import latency or connection occupancy should bind
//! these names (RR4-05 / #541).
//! RR3-02 adds `rvc_slashing_import_deferred_ms` (family delta +1): one sample
//! per deferred interchange import. The sample is the single-flight mutex
//! queue plus the sleep until a free slot window. An import admitted without
//! waiting records nothing. Buckets match the import timing set and add
//! 12000 and 24000 milliseconds so a one-slot and a two-slot wait are not
//! only the +Inf bucket. It has no labels. Dashboards that watch import
//! deferral should bind this name (RR4-05 / #541).
//! RR3-04 adds `rvc_duty_rejected_total` (family delta +1): one increment when
//! the duty cache rejects one attester, proposer, or PTC duty because a numeric
//! field did not parse as a `u64`. Label `field` is that wire name (`slot`,
//! `committee_index`, `validator_index`, `committee_length`,
//! `validator_committee_index`). The rest of the epoch stays cached. Dashboards
//! that alert on malformed beacon duties should bind this name (RR3-04 / #533).
//! RV-1.1 / #639 adds `rvc_bn_broadcast_drain_health_skipped_total` (family
//! delta +1): one increment when a broadcast success health sample is skipped
//! because the health-sample cap is full, or when any sample does not fit on
//! the health-recorder queue. When that queue is full, an error or a timeout
//! sample can be dropped, and that drop is counted. The enqueue does not
//! block the publish. A full pool still records an
//! error or a timeout when the queue has room. The cap limits health
//! recording, not sends. The publish still runs. It has no labels. Dashboards
//! that watch missed beacon-node health samples should bind this name.
//! #721 adds `rvc_bn_broadcast_inflight_waits_total` (family delta +1): one
//! increment when a broadcast waits for a per-beacon-node in-flight permit.
//! Label `endpoint` is the redacted beacon endpoint. A free permit does not
//! increment it. The cap is 4 (2 × the default publish concurrency of 2).
//! The HTTP call starts after the permit is acquired. Dashboards that watch
//! a saturated beacon node should bind this counter. The overflow gauge is
//! unchanged.
//! RV-1.1 / #639 adds `rvc_bn_broadcast_overflow_drains` (family delta +1):
//! in-flight broadcast publishes past the health-sample cap. Label `endpoint`
//! is the redacted beacon endpoint (`scheme://host:port`, userinfo and path
//! stripped) so a slow beacon node's backlog is visible. The gauge drops when
//! that HTTP call finishes, or when that attempt is cancelled or panics,
//! before the health sample is queued. Each publish
//! still runs and ends at the attempt budget, or at the HTTP client timeout
//! when no budget is set, so the series tracks publish rate times that timeout.
//! Dashboards that watch overflow publishes should bind this gauge.
//! #679 adds `rvc_produce_block_fee_recipient_penalty_total` (family delta +1):
//! one increment when a block is signed despite a readable fee-recipient
//! mismatch. A higher-ranked candidate that is skipped before signing, and a
//! drop under `fee_recipient_policy = reject`, are not counted. It has no
//! labels. Dashboards that watch signed fee mismatches should bind this name.
//! #647 adds `rvc_block_shape_rejections_total` (family delta +1): one
//! increment when a produced block is rejected because the selection mode
//! does not allow that shape. Labels are `mode` and `shape`. A Gloas response
//! flagged blinded is not counted. Dashboards that watch mode mismatches
//! should bind this name.
//! #705 adds `rvc_doppelganger_detection_latch` (family delta +1): 0 when the
//! liveness loop starts, 1 after this process stores the doppelganger latch.
//! A boot that exits 12 because the marker file is already present can exit
//! before the loop is scraped. It has no labels. Dashboards that watch an
//! in-process detection should bind this gauge; the marker file is the
//! durable signal.
//! #705 also adds `rvc_doppelganger_marker_write_failures_total` (family delta
//! +1): one increment each time the detection marker write fails. The process
//! stays up and retries. It has no labels. Dashboards that watch a latched
//! process that has not yet exited should bind this counter.
//! #719 adds `rvc_bn_produce_candidates_rejected_total` (family delta +1):
//! one increment per hard-rejected produce candidate, and per fallback body
//! that passes the hard checks and misses the primary parent. Label `reason`
//! is `fork`, `unreadable`, `slot`, `proposer`, `parent`, `fee`, `shape`, or
//! `fallback_parent`. A fee-only penalty is not counted. Health does not move.
//! Dashboards that watch unusable produce bodies should bind this name.
//! #719 adds `rvc_bn_produce_soft_deadline_returns_total` (family delta +1):
//! one increment when a best-of produce round returns because a block is in
//! hand at the soft deadline, or because the first in-hand block arrives
//! after it. A round that finishes every attempt before that deadline is not
//! counted. It has no labels.
//! #719 adds `rvc_bn_produce_fallback_total` (family delta +1): one increment
//! when an unsynced proposal fallback starts an attempt. No candidate above
//! the health floor, and a deadline already closed before that attempt, are
//! not counted. It has no labels.
//! #719 splits best-of drain skips onto
//! `rvc_bn_best_of_drain_health_skipped_total` (family delta +1). Broadcast
//! skips stay on `rvc_bn_broadcast_drain_health_skipped_total`. A dashboard
//! that summed the broadcast counter for best-of skips must add this series.
//! The 16-permit pool is still shared.
//! #774 adds `reason` values to `rvc_slot_context_parent_fallback_total` (no
//! family delta): `unchecked_parse`, `unchecked_error`, `unconfirmed`, and
//! `capture_timeout`, next to `walk_back_exhausted`. Each new reason turns the
//! parent check off for one slot. A slot whose walk-back is exhausted can also
//! count a reason for the `head` fallback. Dashboards that watch an unchecked
//! parent should bind this name.

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
    "crates/block-service/src/metrics.rs",
    "crates/bn-manager/src/metrics.rs",
    "crates/duty-tracker/src/metrics.rs",
    "crates/rvc/src/metrics.rs",
    "crates/signer/src/metrics.rs",
    "crates/slashing/src/metrics.rs",
    "crates/signer-server/src/dvt/peer_ready.rs",
];

/// Prometheus family names registered by `definitions::init_metrics` on the
/// pre-change tree. Sorted. Edit only with an operator-facing note.
const EXPECTED_METRIC_NAMES: &[&str] = &[
    "rvc_aggregations_total",
    "rvc_attestation_trigger_total",
    "rvc_attestations_total",
    "rvc_attesting_enabled",
    "rvc_blob_sidecars_published_total", // operator-facing: pre-Gloas JSON or SSZ SignedBlockContents publishes (RR-1.2)
    "rvc_block_shape_rejections_total", // operator-facing: produced blocks rejected by selection mode; labels mode, shape (#647)
    "rvc_bn_admitted", // operator-facing: 1 while the beacon node may serve duties (#707)
    "rvc_bn_best_of_drain_health_skipped_total", // operator-facing: best-of drain health samples not recorded; broadcast skips stay on the broadcast counter (#719)
    "rvc_bn_broadcast_drain_health_skipped_total", // operator-facing: success skipped at the cap, or any sample when the recorder queue is full; the publish still runs (#639)
    "rvc_bn_broadcast_inflight_waits_total", // operator-facing: waits for a per-beacon-node in-flight permit; the send is not skipped (#721)
    "rvc_bn_broadcast_overflow_drains", // operator-facing: in-flight overflow publishes by redacted endpoint; drops when the HTTP call finishes (#639)
    "rvc_bn_capability_state",
    "rvc_bn_health_tier",
    "rvc_bn_produce_candidates_rejected_total", // operator-facing: dropped produce candidates by reason, including fallback_parent; fee-only penalty is not counted (#719)
    "rvc_bn_produce_fallback_total", // operator-facing: unsynced proposal fallback rounds that started an attempt (#719)
    "rvc_bn_produce_soft_deadline_returns_total", // operator-facing: best-of produce rounds that returned at the soft deadline (#719)
    "rvc_builder_circuit_breaker_trips_total",
    "rvc_builder_consecutive_misses",
    "rvc_builder_epoch_misses",
    "rvc_doppelganger_detection_latch", // operator-facing: 1 after this process stores the detection latch (#705)
    "rvc_doppelganger_marker_write_failures_total", // operator-facing: failed durable marker writes while the latch stays set (#705)
    "rvc_duties_fetched_total",
    "rvc_duty_index_set_size", // operator-facing: pubkey-index registry size (RR-2.2)
    "rvc_duty_rejected_total", // operator-facing: per-duty malformed numeric field (RR3-04 / #533)
    "rvc_duty_reorg_detected_total",
    "rvc_dvt_peer_ready", // operator-facing: 0 until the first successful DVT peer RPC (RR-1.6)
    "rvc_fork_current_id", // operator-facing: resolved current fork id (issue 8.1)
    "rvc_fork_next_activation_epoch", // operator-facing: next fork activation epoch (issue 8.1)
    "rvc_keymanager_quiesce_wait_ms", // operator-facing: drain wait while quiescing a pubkey (RR-5.1)
    "rvc_monitoring_push_failures_total",
    "rvc_monitoring_push_success_total",
    "rvc_orchestrator_active_attestations",
    "rvc_orchestrator_missed_slots_total",
    "rvc_orchestrator_slot_processing_duration_seconds",
    "rvc_orchestrator_slots_processed_total",
    "rvc_payload_attestation_skipped_total",
    "rvc_pre_proposal_cold_fetch_duration_seconds",
    "rvc_pre_proposal_cold_fetch_total",
    "rvc_produce_block_fee_recipient_penalty_total", // operator-facing: signed blocks whose readable fee recipient did not match (#679)
    "rvc_proposals_total", // operator-facing: proposal outcomes success/failed/envelope_late (issue 6.20 / #377)
    "rvc_proposer_bn_health_score",
    "rvc_proposer_bn_latency_ms",
    "rvc_proposer_config_refresh_failures_total",
    "rvc_proposer_config_refresh_success_total",
    "rvc_ptc_attestations_total", // operator-facing: PTC pool-post status (issue 7.6 / 8.2)
    "rvc_ptc_duties_fetched_total",
    "rvc_ptc_duties_total", // operator-facing: PTC duty outcomes (issue 7.6 / 8.2)
    "rvc_signer_capability",
    "rvc_signer_rejections_total", // operator-facing: fail-closed type/version (issue 8.4)
    "rvc_signer_slashing_tx_hold_duration_ms",
    "rvc_signing_duration_seconds",
    "rvc_slashing_db_prune_total",
    "rvc_slashing_export_synthetic_records_total", // operator-facing: synthetic floors in an interchange export (RR-4.3)
    "rvc_slashing_group_commit_batch_size", // operator-facing: reserves drained into one group-commit (RR0-07)
    "rvc_slashing_import_conflicts_total", // operator-facing: dropped interchange import rows (RR-4.2)
    "rvc_slashing_import_conn_hold_ms", // operator-facing: interchange import conn.lock through COMMIT (RR2-12 / #525)
    "rvc_slashing_import_deferred_ms", // operator-facing: mutex queue plus free-window wait (RR3-02 / #531)
    "rvc_slashing_import_duration_ms", // operator-facing: whole interchange import call (RR2-12 / #525)
    "rvc_slashing_protection_checks_total",
    "rvc_slashing_prune_source_bound_raised_total", // operator-facing: prune raised an attestation source floor (RR-4.1)
    "rvc_slashing_reconcile_total",
    "rvc_slashing_reserve_tx_hold_duration_ms",
    "rvc_slot_context_parent_fallback_total", // operator-facing: reason walk_back_exhausted, unchecked_parse, unchecked_error, unconfirmed, capture_timeout (#774)
    "rvc_slot_phase_block_start_offset_ms", // deprecated: use rvc_slot_phase_offset_ms{phase="block"}; retained for dashboards (AQ-7 / #611)
    "rvc_slot_phase_late_total", // operator-facing: phases that fired after their absolute deadline (RR1-03 / #506)
    "rvc_slot_phase_offset_ms", // operator-facing: true offset into the slot when a phase fires (RR1-05 / #508)
    "rvc_slot_replay_skipped_total", // operator-facing: slots skipped after a backward clock step (RR1-04 / #507)
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
    assert_eq!(EXPECTED_METRIC_NAMES.len(), 72, "#721 adds rvc_bn_broadcast_inflight_waits_total");
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
