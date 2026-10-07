//! RR0-07 VC scale profile.
//!
//! `#[ignore]`d so `cargo nextest run --workspace` does not run it. Timing is
//! mock-BN call arrival versus this harness's slot start. It does not read
//! `rvc_slot_phase_*`.
//!
//! RR0-08 enables sync-committee and aggregator duties and drives them through
//! `DutyOrchestrator::run` (the public slot loop). `process_slot` alone never
//! publishes a sync message or an aggregate.
//!
//! # Run
//!
//! nextest 0.9 does not forward `--output`. Use `VC_SCALE_OUTPUT`, or pass
//! `--output` through libtest after `--`.
//!
//! ```text
//! VC_SCALE_OUTPUT=/tmp/vc-scale-wall.json VC_SCALE_CLOCK=wall \
//!   cargo nextest run -p rvc --run-ignored ignored-only --no-capture \
//!   -E 'test(vc_scale_profile_emits_a_complete_record)'
//!
//! VC_SCALE_OUTPUT=/tmp/vc-scale-paused.json VC_SCALE_CLOCK=paused \
//!   cargo nextest run -p rvc --run-ignored ignored-only --no-capture \
//!   -E 'test(vc_scale_profile_emits_a_complete_record)'
//!
//! cargo test -p rvc --test vc_scale_profile -- --ignored --nocapture \
//!   --exact vc_scale_profile_emits_a_complete_record \
//!   -- --output /tmp/vc-scale-wall.json --clock wall
//! ```
//!
//! `VC_SCALE_N` / `--validators` and `VC_SCALE_SLOTS` / `--slots` override the
//! defaults (N = 4, one slot). A slot that exceeds 12 s is `overrun` with
//! `overhang_ms`; it is not a test failure. The per-slot budget is 120 s.
//! `--slots` must be 1: one `run` is shut down after that slot's submits.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bn_manager::{
    MockBeaconNodeClient, MockMethod, VersionedAttestation, VersionedSignedAggregateAndProof,
};
use common::pipeline_fixture::{
    make_beacon_attestation_data, pipeline_fixture, PipelineFixture, PipelineFixtureOpts,
    SLOTS_PER_EPOCH,
};
use slashing::metrics::RVC_SLASHING_GROUP_COMMIT_BATCH_SIZE;
use timing::{due_ms, DeadlineBps, SlotClock};

/// 12 s mainnet slot. [`DeadlineBps::default`] is 3999 ms / 8000 ms.
const SLOT_DURATION_MS: u64 = 12_000;
/// Larger than an approximately 20 s N=200 slot, so that slot is recorded
/// as overhang / overrun instead of a timeout failure.
const PER_SLOT_BUDGET: Duration = Duration::from_secs(120);
const REQUEST_DELAY: Duration = Duration::from_millis(50);
/// Past the 8000 ms aggregate due, so `run`'s phase waits are zero and the
/// slot reaches the next-slot sleep. Same offset as the RR0-10 fixture.
const PAST_AGGREGATE_DUE_SECS: u64 = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClockMode {
    Wall,
    Paused,
}

impl ClockMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Wall => "wall",
            Self::Paused => "paused",
        }
    }

    fn parse(raw: &str) -> Self {
        match raw {
            "wall" => Self::Wall,
            "paused" => Self::Paused,
            other => panic!("clock mode must be wall or paused, got {other}"),
        }
    }
}

fn cli_flag(flag: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    let prefix = format!("--{flag}=");
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
        if arg == format!("--{flag}") {
            return args.next();
        }
    }
    None
}

fn arg_or_env(flag: &str, env_key: &str) -> Option<String> {
    if let Some(value) = cli_flag(flag) {
        return Some(value);
    }
    std::env::var(env_key).ok().filter(|value| !value.is_empty())
}

fn parse_usize(flag: &str, env_key: &str, default: usize) -> usize {
    match arg_or_env(flag, env_key) {
        None => default,
        Some(raw) => raw.parse().unwrap_or_else(|_| panic!("invalid --{flag} value {raw}")),
    }
}

fn output_path(clock: &str) -> PathBuf {
    arg_or_env("output", "VC_SCALE_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("vc-scale-profile-{clock}.json")))
}

fn command_stdout(program: &str, args: &[&str]) -> String {
    match std::process::Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8(output.stdout).unwrap_or_default().trim().to_string()
        }
        _ => String::new(),
    }
}

fn host_label() -> String {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".to_string());
    format!("{} {}/{}", hostname.trim(), std::env::consts::OS, std::env::consts::ARCH)
}

fn write_output(path: &Path, json: &str) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|err| panic!("create {}: {err}", parent.display()));
        }
    }
    std::fs::write(path, json).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
}

fn offset_ms(slot_started: tokio::time::Instant, at: tokio::time::Instant) -> f64 {
    at.saturating_duration_since(slot_started).as_secs_f64() * 1000.0
}

struct SlotTally {
    last_publish_after_ms: f64,
    saw_publish: bool,
    aggregate_deadline_misses: u64,
    attestation_data_requests: u64,
    overhang_ms: f64,
    overrun: bool,
    budget_exceeded: bool,
    successes: u64,
    failures: u64,
    sync_publish_ms_after_slot_start: Option<f64>,
    sync_messages_submitted: u64,
    sync_submit_calls: u64,
    aggregate_proofs_submitted: u64,
    aggregate_submit_calls: u64,
    aggregate_proofs_after_deadline: u64,
}

fn sync_message_count(calls: &[Vec<bn_manager::SyncCommitteeMessage>]) -> usize {
    calls.iter().map(Vec::len).sum()
}

fn aggregate_proof_count(calls: &[VersionedSignedAggregateAndProof]) -> usize {
    calls
        .iter()
        .map(|batch| match batch {
            VersionedSignedAggregateAndProof::PreElectra(v) => v.len(),
            VersionedSignedAggregateAndProof::Electra(v)
            | VersionedSignedAggregateAndProof::Fulu(v)
            | VersionedSignedAggregateAndProof::Gloas(v) => v.len(),
        })
        .sum()
}

fn attestation_item_count(calls: &[VersionedAttestation]) -> usize {
    calls
        .iter()
        .map(|batch| match batch {
            VersionedAttestation::PreElectra(v) => v.len(),
            VersionedAttestation::Electra(v)
            | VersionedAttestation::Fulu(v)
            | VersionedAttestation::Gloas(v) => v.len(),
        })
        .sum()
}

fn phase_submits_done(client: &MockBeaconNodeClient, n: usize) -> bool {
    sync_message_count(&client.submit_sync_committee_messages_calls()) >= n
        && aggregate_proof_count(&client.submit_aggregate_and_proofs_calls()) >= n
        && attestation_item_count(&client.submit_attestation_calls()) >= n
}

/// One slot of `DutyOrchestrator::run`, then shutdown.
///
/// Sync duties are prefetched so `maybe_produce_sync_messages` has a cache.
/// The mock clock is moved 8 s into the slot first, which is what makes the
/// attestation and aggregate phase waits zero in the RR0-10 fixture. Submit
/// arrival is still `tokio::time::Instant` from this function's slot start.
async fn drive_slot(
    fixture: &mut PipelineFixture,
    slot: u64,
    n: usize,
    attestation_deadline_ms: f64,
    aggregate_deadline_ms: f64,
    tally: &mut SlotTally,
) {
    let epoch = slot / SLOTS_PER_EPOCH;
    fixture
        .duty_tracker
        .fetch_duties_for_epoch(epoch)
        .await
        .unwrap_or_else(|err| panic!("fetch attester duties for epoch {epoch}: {err}"));
    fixture
        .duty_tracker
        .fetch_sync_committee_duties(epoch)
        .await
        .unwrap_or_else(|err| panic!("fetch sync duties for epoch {epoch}: {err}"));
    fixture.set_slot(slot);
    fixture.clock.advance_time(PAST_AGGREGATE_DUE_SECS);

    let client = Arc::clone(&fixture.beacon_client);
    let before = client.call_stamps().len();
    let started = tokio::time::Instant::now();
    let wall_started = std::time::Instant::now();

    // Disjoint field borrows: `run` needs `&mut orchestrator` while shutdown
    // uses `handle`. Spawning would require moving the orchestrator out.
    let orchestrator = &mut fixture.orchestrator;
    let handle = &fixture.handle;
    let run_fut = orchestrator.run();
    tokio::pin!(run_fut);

    let mut shutdown_sent = false;
    let mut budget_exceeded = false;
    let run_result = loop {
        tokio::select! {
            biased;
            result = &mut run_fut => break result,
            // A bare `yield_now` loop stays runnable, so `tokio::time::pause`
            // never auto-advances the 50 ms mock delay. Sleeping lets the
            // paused clock jump to the next timer. One millisecond is enough
            // to notice completed submits without changing their stamps.
            _ = tokio::time::sleep(Duration::from_millis(1)) => {
                if shutdown_sent {
                    continue;
                }
                if phase_submits_done(&client, n) {
                    handle.shutdown();
                    shutdown_sent = true;
                } else if wall_started.elapsed() > PER_SLOT_BUDGET {
                    budget_exceeded = true;
                    handle.shutdown();
                    shutdown_sent = true;
                }
            }
        }
    };
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    if let Err(err) = run_result {
        eprintln!("slot {slot} orchestrator run error: {err}");
    }

    let slot_overhang = (elapsed_ms - SLOT_DURATION_MS as f64).max(0.0);
    if slot_overhang > tally.overhang_ms {
        tally.overhang_ms = slot_overhang;
    }
    if slot_overhang > 0.0 {
        tally.overrun = true;
    }
    if budget_exceeded {
        tally.budget_exceeded = true;
        tally.overrun = true;
    }

    let attestations = attestation_item_count(&client.submit_attestation_calls()) as u64;
    if attestations >= n as u64 {
        tally.successes += n as u64;
    } else {
        tally.successes += attestations;
        tally.failures += (n as u64).saturating_sub(attestations);
    }

    tally.sync_messages_submitted +=
        sync_message_count(&client.submit_sync_committee_messages_calls()) as u64;
    tally.sync_submit_calls += client.submit_sync_committee_messages_calls().len() as u64;
    let aggregate_calls = client.submit_aggregate_and_proofs_calls();
    tally.aggregate_submit_calls += aggregate_calls.len() as u64;
    tally.aggregate_proofs_submitted += aggregate_proof_count(&aggregate_calls) as u64;

    let stamps = client.call_stamps();
    let mut last_submit_ms: Option<f64> = None;
    let mut first_sync_ms: Option<f64> = None;
    // Proofs ride in one batch per fork. A late batch counts as one arrival
    // (`aggregate_deadline_misses`) and as every proof inside it.
    let mut aggregate_call_index = 0usize;
    for stamp in stamps.iter().skip(before) {
        let off = offset_ms(started, stamp.at);
        match stamp.method {
            MockMethod::SubmitAttestation => {
                last_submit_ms = Some(last_submit_ms.map_or(off, |prev| prev.max(off)));
            }
            MockMethod::SubmitAggregateAndProofs => {
                let proofs = aggregate_calls
                    .get(aggregate_call_index)
                    .map_or(0, |batch| aggregate_proof_count(std::slice::from_ref(batch)));
                aggregate_call_index += 1;
                if off > aggregate_deadline_ms {
                    tally.aggregate_deadline_misses += 1;
                    tally.aggregate_proofs_after_deadline += proofs as u64;
                }
            }
            MockMethod::SubmitSyncCommitteeMessages => {
                first_sync_ms = Some(first_sync_ms.map_or(off, |prev| prev.min(off)));
            }
            MockMethod::GetAttestationData => {
                tally.attestation_data_requests += 1;
            }
            _ => {}
        }
    }
    if let Some(last_submit_ms) = last_submit_ms {
        tally.saw_publish = true;
        let after = last_submit_ms - attestation_deadline_ms;
        if after > tally.last_publish_after_ms {
            tally.last_publish_after_ms = after;
        }
    }
    if tally.sync_publish_ms_after_slot_start.is_none() {
        tally.sync_publish_ms_after_slot_start = first_sync_ms;
    }
}

async fn run_profile(mode: ClockMode, n: usize, slot_count: usize) -> serde_json::Value {
    assert!(n >= 1, "validator count must be >= 1");
    assert!(
        slot_count == 1,
        "orchestrator.run is shut down after one slot; VC_SCALE_SLOTS must be 1, got {slot_count}"
    );

    // Paused mode freezes the clock and auto-advances only to the next timer
    // (the 50 ms mock delay). A manual `advance` loop also moves time while
    // signing blocks the worker, which trips the per-slot budget.
    if mode == ClockMode::Paused {
        tokio::time::pause();
    }

    let slots: Vec<u64> =
        (0..slot_count).map(|index| (index as u64 + 1) * SLOTS_PER_EPOCH).collect();
    let mut attestation_data_by_slot = std::collections::HashMap::new();
    for (index, slot) in slots.iter().copied().enumerate() {
        attestation_data_by_slot
            .insert(slot, make_beacon_attestation_data(slot, index as u64, 0x22, 0x33, 0x11));
    }
    let initial_slot = slots[0];
    let mut fixture = pipeline_fixture(
        PipelineFixtureOpts {
            attestation_data_by_slot,
            duty_slots: slots.clone(),
            initial_slot,
            ..Default::default()
        }
        .with_validators(n)
        .with_sync_committee(true)
        .with_aggregators(true)
        .with_request_delay(REQUEST_DELAY),
    );

    assert_eq!(fixture.clock.slot_duration(), Duration::from_secs(12));
    let deadlines = fixture.clock.deadlines();
    assert_eq!(deadlines, DeadlineBps::default());
    let attestation_deadline_ms = due_ms(deadlines.attestation, SLOT_DURATION_MS);
    let aggregate_deadline_ms = due_ms(deadlines.aggregate, SLOT_DURATION_MS);
    assert_eq!(attestation_deadline_ms, 3999);
    assert_eq!(aggregate_deadline_ms, 8000);

    let hist = &*RVC_SLASHING_GROUP_COMMIT_BATCH_SIZE;
    let batches_before = hist.get_sample_count();
    let sum_before = hist.get_sample_sum();

    let mut tally = SlotTally {
        last_publish_after_ms: f64::NEG_INFINITY,
        saw_publish: false,
        aggregate_deadline_misses: 0,
        attestation_data_requests: 0,
        overhang_ms: 0.0,
        overrun: false,
        budget_exceeded: false,
        successes: 0,
        failures: 0,
        sync_publish_ms_after_slot_start: None,
        sync_messages_submitted: 0,
        sync_submit_calls: 0,
        aggregate_proofs_submitted: 0,
        aggregate_submit_calls: 0,
        aggregate_proofs_after_deadline: 0,
    };
    for slot in slots {
        drive_slot(
            &mut fixture,
            slot,
            n,
            attestation_deadline_ms as f64,
            aggregate_deadline_ms as f64,
            &mut tally,
        )
        .await;
    }

    let batches = hist.get_sample_count().saturating_sub(batches_before);
    let batch_sum = hist.get_sample_sum() - sum_before;
    let mean_batch = if batches == 0 { 0.0 } else { batch_sum / batches as f64 };
    let commits_per_attestation_phase = batches as f64 / slot_count as f64;
    let attestation_data_requests_per_slot =
        tally.attestation_data_requests as f64 / slot_count as f64;
    let last_publish_ms_after_att_deadline =
        if tally.saw_publish { tally.last_publish_after_ms } else { 0.0 };

    serde_json::json!({
        "issue": "RR0-07",
        "sha": command_stdout("git", &["rev-parse", "HEAD"]),
        "host": host_label(),
        "toolchain": command_stdout("rustc", &["--version"]),
        "clock_mode": mode.as_str(),
        "n": n,
        "slots": slot_count,
        "slot_duration_ms": SLOT_DURATION_MS,
        "attestation_deadline_ms": attestation_deadline_ms,
        "aggregate_deadline_ms": aggregate_deadline_ms,
        "request_delay_ms": u64::try_from(REQUEST_DELAY.as_millis()).expect("delay fits u64"),
        "per_slot_budget_ms": u64::try_from(PER_SLOT_BUDGET.as_millis()).expect("budget fits u64"),
        "last_publish_ms_after_att_deadline": last_publish_ms_after_att_deadline,
        "aggregate_deadline_misses": tally.aggregate_deadline_misses,
        "aggregate_proofs_submitted": tally.aggregate_proofs_submitted,
        "aggregate_submit_calls": tally.aggregate_submit_calls,
        "aggregate_proofs_after_deadline": tally.aggregate_proofs_after_deadline,
        "sync_publish_ms_after_slot_start": tally.sync_publish_ms_after_slot_start,
        "sync_messages_submitted": tally.sync_messages_submitted,
        "sync_submit_calls": tally.sync_submit_calls,
        "sync_committee_enabled": true,
        "aggregators_enabled": true,
        "commits_per_attestation_phase": commits_per_attestation_phase,
        "attestation_data_requests_per_slot": attestation_data_requests_per_slot,
        "overhang_ms": tally.overhang_ms,
        "mean_batch": mean_batch,
        "overrun": tally.overrun,
        "budget_exceeded": tally.budget_exceeded,
        "successes": tally.successes,
        "failures": tally.failures,
    })
}

fn assert_complete_record(value: &serde_json::Value, mode: ClockMode, n: usize, slots: usize) {
    for key in [
        "last_publish_ms_after_att_deadline",
        "aggregate_deadline_misses",
        "aggregate_proofs_submitted",
        "aggregate_submit_calls",
        "aggregate_proofs_after_deadline",
        "sync_publish_ms_after_slot_start",
        "sync_messages_submitted",
        "sync_submit_calls",
        "commits_per_attestation_phase",
        "attestation_data_requests_per_slot",
        "overhang_ms",
        "mean_batch",
        "sha",
        "host",
        "toolchain",
        "clock_mode",
    ] {
        assert!(value.get(key).is_some(), "record missing {key}: {value}");
    }
    assert!(value["last_publish_ms_after_att_deadline"].is_number());
    assert!(value["aggregate_deadline_misses"].is_number());
    assert!(value["commits_per_attestation_phase"].is_number());
    assert!(value["attestation_data_requests_per_slot"].is_number());
    assert!(value["overhang_ms"].is_number());
    assert!(value["mean_batch"].is_number());
    assert!(value["overhang_ms"].as_f64().expect("overhang") >= 0.0);

    let sha = value["sha"].as_str().expect("sha");
    assert_eq!(sha.len(), 40, "sha must be a full git revision, got {sha}");
    assert!(sha.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(!value["host"].as_str().expect("host").is_empty());
    let toolchain = value["toolchain"].as_str().expect("toolchain");
    assert!(toolchain.contains("rustc"), "toolchain must name rustc, got {toolchain}");
    assert_eq!(value["clock_mode"].as_str(), Some(mode.as_str()));
    assert_eq!(value["per_slot_budget_ms"].as_u64(), Some(120_000));
    assert!(value["per_slot_budget_ms"].as_u64().expect("budget") > 20_000);

    assert_ne!(
        value["budget_exceeded"].as_bool(),
        Some(true),
        "per-slot budget exceeded before sync and aggregate submits: {value}"
    );
    assert_eq!(value["successes"].as_u64(), Some((n * slots) as u64), "pipeline failures: {value}");
    assert!(value["sync_publish_ms_after_slot_start"].is_number(), "sync publish missing: {value}");
    assert!(
        value["sync_messages_submitted"].as_u64().expect("sync messages") >= (n * slots) as u64,
        "sync messages must be produced, got {value}"
    );
    assert!(
        value["sync_submit_calls"].as_u64().expect("sync calls") > 0,
        "sync submit calls must be non-zero: {value}"
    );
    assert!(
        value["aggregate_proofs_submitted"].as_u64().expect("aggregate proofs")
            >= (n * slots) as u64,
        "aggregate proofs must be produced, got {value}"
    );
    assert!(
        value["aggregate_submit_calls"].as_u64().expect("aggregate calls") > 0,
        "aggregate submit calls must be non-zero: {value}"
    );
    assert!(
        value["mean_batch"].as_f64().expect("mean_batch") > 0.0,
        "mean batch must come from the group-commit instrument"
    );
    assert!(
        value["commits_per_attestation_phase"].as_f64().expect("commits") > 0.0,
        "commits per attestation phase must come from the group-commit instrument"
    );
    let fetches = value["attestation_data_requests_per_slot"].as_f64().expect("fetches");
    assert!(
        fetches + f64::EPSILON >= n as f64,
        "expected at least one attestation-data request per validator, got {fetches}"
    );
}

/// N=4 by default. Writes the JSON record for `--output` / `VC_SCALE_OUTPUT`.
///
/// A slot of about 20 s (N=200 with the 50 ms request delay) stays inside the
/// 120 s budget and is recorded as `overrun` / `overhang_ms`, not a failure.
#[tokio::test(flavor = "current_thread")]
#[ignore = "manual RR0-07 scale profile; excluded from cargo nextest run --workspace"]
async fn vc_scale_profile_emits_a_complete_record() {
    let _ = tracing_subscriber::fmt().with_writer(std::io::sink).try_init();

    let mode = ClockMode::parse(arg_or_env("clock", "VC_SCALE_CLOCK").as_deref().unwrap_or("wall"));
    let n = parse_usize("validators", "VC_SCALE_N", 4);
    let slots = parse_usize("slots", "VC_SCALE_SLOTS", 1);
    let path = output_path(mode.as_str());

    let value = run_profile(mode, n, slots).await;
    let json = format!("{}\n", serde_json::to_string_pretty(&value).expect("json"));
    write_output(&path, &json);
    print!("{json}");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let on_disk = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let parsed: serde_json::Value = serde_json::from_str(&on_disk).expect("output is json");
    assert_complete_record(&parsed, mode, n, slots);
}
