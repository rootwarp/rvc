//! P1 1.1 slot-processing driver, checked in so 6.14 is reproducible.
//!
//! 200 unique-epoch `process_slot` samples via `pipeline_fixture`, draining
//! exact `sample_sum` / `sample_count` deltas (not `histogram_quantile`).
//!
//! ```text
//! cargo test -p rvc --test slot_processing_profile -- --ignored --nocapture \
//!   --exact test_slot_processing_profile_reports_p99 \
//!   -- --output /tmp/p6-6.14/slot-runN.json
//! ```

mod common;

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use common::pipeline_fixture::{
    make_beacon_attestation_data, pipeline_fixture, PipelineFixtureOpts, SLOTS_PER_EPOCH,
};
use rvc::metrics::RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS;

const SLOT_SAMPLES: usize = 200;

#[derive(Clone, Debug)]
struct Percentiles {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(!sorted.is_empty(), "percentile of empty sample");
    assert!((0.0..=1.0).contains(&p), "percentile p must be in [0, 1]");
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn percentiles_of(mut samples: Vec<f64>) -> Percentiles {
    assert!(!samples.is_empty(), "percentiles of empty sample");
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Percentiles {
        p50: percentile(&samples, 0.50),
        p95: percentile(&samples, 0.95),
        p99: percentile(&samples, 0.99),
        max: samples[samples.len() - 1],
    }
}

fn output_path_from_cli() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(path) = arg.strip_prefix("--output=") {
            return Some(PathBuf::from(path));
        }
        if arg == "--output" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

fn emit_json(json: &str) {
    print!("{json}");
    let _ = std::io::stdout().flush();
    if let Some(path) = output_path_from_cli() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| panic!("create parent dir {}: {e}", parent.display()));
            }
        }
        std::fs::write(&path, json.as_bytes())
            .unwrap_or_else(|e| panic!("write summary {}: {e}", path.display()));
    }
}

/// Recreates the P1 1.1 slot-processing fixture: 200 unique-epoch slots,
/// one successful attestation each, in-memory slashing DB.
#[tokio::test]
#[ignore]
async fn test_slot_processing_profile_reports_p99() {
    let _ = tracing_subscriber::fmt().with_writer(std::io::sink).try_init();

    let mut attestation_data_by_slot = HashMap::new();
    let mut duty_slots = Vec::with_capacity(SLOT_SAMPLES);
    for i in 0..SLOT_SAMPLES {
        let slot = ((i as u64) + 1) * SLOTS_PER_EPOCH;
        let source_epoch = i as u64;
        attestation_data_by_slot
            .insert(slot, make_beacon_attestation_data(slot, source_epoch, 0x22, 0x33, 0x11));
        duty_slots.push(slot);
    }

    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot,
        duty_slots: duty_slots.clone(),
        initial_slot: SLOTS_PER_EPOCH,
        ..Default::default()
    });

    let hist = RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS.with_label_values(&[] as &[&str]);
    let mut prev_count = hist.get_sample_count();
    let mut prev_sum = hist.get_sample_sum();
    let mut samples = Vec::with_capacity(SLOT_SAMPLES);
    let mut successes = 0usize;
    let mut failures = 0usize;

    for slot in duty_slots {
        let results = fixture.process_slot(slot).await.expect("process_slot Ok");
        assert_eq!(results.len(), 1, "empty-duty sample at slot {slot}; discard the run");
        if results[0].success {
            successes += 1;
        } else {
            failures += 1;
        }

        let count = hist.get_sample_count();
        let sum = hist.get_sample_sum();
        let delta_n = count.saturating_sub(prev_count);
        assert_eq!(delta_n, 1, "expected one histogram sample per process_slot");
        samples.push(sum - prev_sum);
        prev_count = count;
        prev_sum = sum;
    }

    assert_eq!(successes, SLOT_SAMPLES, "every process_slot must succeed");
    assert_eq!(failures, 0);
    assert_eq!(samples.len(), SLOT_SAMPLES);

    let s = percentiles_of(samples.clone());
    let sum: f64 = samples.iter().sum();
    let count = samples.len() as u64;
    let json = format!(
        "{{\n  \"issue\": \"6.14\",\n  \"target\": \"rvc-orchestrator\",\n  \
         \"target_reason\": \"signer-server load_profile does not populate RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS\",\n  \
         \"harness\": \"crates/rvc/tests/common/pipeline_fixture.rs\",\n  \
         \"keys\": 1,\n  \"slots\": {count},\n  \"successes\": {successes},\n  \"failures\": {failures},\n  \
         \"slot_processing_s\": {{ \"p50\": {sp50:.9}, \"p95\": {sp95:.9}, \"p99\": {sp99:.9}, \"max\": {smax:.9}, \"count\": {count}, \"sum\": {ssum:.9} }},\n  \
         \"slot_processing_ms\": {{ \"p50\": {mp50:.3}, \"p95\": {mp95:.3}, \"p99\": {mp99:.3}, \"max\": {mmax:.3}, \"count\": {count}, \"sum\": {msum:.3} }}\n}}\n",
        sp50 = s.p50,
        sp95 = s.p95,
        sp99 = s.p99,
        smax = s.max,
        ssum = sum,
        mp50 = s.p50 * 1000.0,
        mp95 = s.p95 * 1000.0,
        mp99 = s.p99 * 1000.0,
        mmax = s.max * 1000.0,
        msum = sum * 1000.0,
    );
    emit_json(&json);
}
