//! RR2-05: aggregates dispatch concurrently, and a late publish is a miss.
//!
//! N = 200 aggregators, 32 slots, every mock beacon call costs 50 ms under a
//! paused clock. A miss is an aggregate publish whose *completion* is more
//! than 8,000 ms after that slot's `orchestrator.produce_aggregations` span
//! opened. `call_stamps` is the pre-delay arrival and only shows that a sign
//! wave was issued together. Completion is
//! `submit_aggregate_and_proofs_completions`, taken when that future returns.
//!
//! Slots 33 through 64 stay pre-Electra (Electra is epoch 50 in the fixture).
//! Slot 64 is the only epoch boundary, so committee subscriptions run once.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bn_manager::{MockBeaconNodeClient, MockMethod, VersionedSignedAggregateAndProof};
use common::pipeline_fixture::{
    make_beacon_attestation_data, pipeline_fixture, PipelineFixtureOpts, SLOTS_PER_EPOCH,
};
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

const N: usize = 200;
const SLOT_COUNT: usize = 32;
const REQUEST_DELAY: Duration = Duration::from_millis(50);
const AGGREGATE_DEADLINE: Duration = Duration::from_millis(8_000);
/// First slot of the run. 33..=64 is 32 slots; only slot 64 is an epoch boundary.
const FIRST_SLOT: u64 = 33;

struct PhaseMark {
    at: tokio::time::Instant,
    completions_before: usize,
}

struct AggPhaseStart {
    marks: Arc<Mutex<Vec<PhaseMark>>>,
    client: Arc<MockBeaconNodeClient>,
}

impl<S> Layer<S> for AggPhaseStart
where
    S: tracing::Subscriber,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        if attrs.metadata().name() == "orchestrator.produce_aggregations" {
            self.marks.lock().expect("phase mark lock").push(PhaseMark {
                at: tokio::time::Instant::now(),
                completions_before: self.client.submit_aggregate_and_proofs_completions().len(),
            });
        }
    }
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

fn proof_len(batch: &VersionedSignedAggregateAndProof) -> usize {
    aggregate_proof_count(std::slice::from_ref(batch))
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn aggregations_are_dispatched_concurrently() {
    let slots: Vec<u64> = (0..SLOT_COUNT as u64).map(|offset| FIRST_SLOT + offset).collect();
    assert_eq!(slots.len(), SLOT_COUNT);
    assert!(slots.iter().all(|slot| slot / SLOTS_PER_EPOCH < 50));

    let mut attestation_data_by_slot = std::collections::HashMap::new();
    for &slot in &slots {
        attestation_data_by_slot
            .insert(slot, make_beacon_attestation_data(slot, 0, 0x22, 0x33, 0x11));
    }
    let mut fixture = pipeline_fixture(
        PipelineFixtureOpts {
            attestation_data_by_slot,
            duty_slots: slots.clone(),
            initial_slot: slots[0],
            ..Default::default()
        }
        .with_validators(N)
        .with_aggregators(true)
        .with_request_delay(REQUEST_DELAY),
    );

    for slot in &slots {
        let epoch = slot / SLOTS_PER_EPOCH;
        if !fixture.duty_tracker.is_epoch_cached(epoch).await {
            fixture
                .duty_tracker
                .fetch_duties_for_epoch(epoch)
                .await
                .unwrap_or_else(|err| panic!("fetch attester duties for epoch {epoch}: {err}"));
        }
    }
    let duties = fixture.duty_tracker.get_duties_for_slot(slots[0]).await;
    assert_eq!(duties.len(), N, "one aggregator duty per validator");
    fixture.set_slot(slots[0]);

    let client = Arc::clone(&fixture.beacon_client);
    let clock = Arc::clone(&fixture.clock);
    let marks = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry()
        .with(AggPhaseStart { marks: Arc::clone(&marks), client: Arc::clone(&client) });
    let _guard = tracing::subscriber::set_default(subscriber);

    let handle = &fixture.handle;
    let run_fut = fixture.orchestrator.run();
    tokio::pin!(run_fut);

    let wall_started = std::time::Instant::now();
    let mut released = 0usize;
    let mut shutdown_sent = false;
    loop {
        tokio::select! {
            biased;
            result = &mut run_fut => {
                result.expect("orchestrator run");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                let proofs = aggregate_proof_count(&client.submit_aggregate_and_proofs_calls());
                if !shutdown_sent && proofs >= (released + 1) * N {
                    if released + 1 == SLOT_COUNT {
                        handle.shutdown();
                        shutdown_sent = true;
                    } else {
                        released += 1;
                        clock.set_slot(slots[released]);
                    }
                }
                assert!(
                    wall_started.elapsed() < Duration::from_secs(180),
                    "aggregation dispatch did not finish {SLOT_COUNT} slots within 180 s of wall time; proofs={proofs}"
                );
            }
        }
    }
    assert!(shutdown_sent, "run returned before {SLOT_COUNT} aggregate slots were published");

    let calls = client.submit_aggregate_and_proofs_calls();
    assert_eq!(
        aggregate_proof_count(&calls),
        N * SLOT_COUNT,
        "one aggregate proof per validator per slot"
    );

    let marks = marks.lock().expect("phase mark lock");
    assert_eq!(marks.len(), SLOT_COUNT, "one aggregation phase per slot");

    let completions = client.submit_aggregate_and_proofs_completions();
    assert_eq!(completions.len(), calls.len(), "every admitted aggregate publish must finish");

    let mut misses = 0u64;
    for (index, mark) in marks.iter().enumerate() {
        let from = mark.completions_before;
        let to =
            marks.get(index + 1).map(|next| next.completions_before).unwrap_or(completions.len());
        assert!(to > from, "slot {} published no aggregate batch", slots[index]);
        let proofs: usize = calls[from..to].iter().map(proof_len).sum();
        assert_eq!(proofs, N, "slot {} published {proofs} proofs, expected {N}", slots[index]);
        for done in &completions[from..to] {
            let landed = done.saturating_duration_since(mark.at);
            if landed > AGGREGATE_DEADLINE {
                misses += 1;
            }
        }
    }
    assert_eq!(
        misses, 0,
        "aggregate publish completions more than {AGGREGATE_DEADLINE:?} after phase start"
    );

    let mut arrivals: Vec<_> = client
        .call_stamps()
        .into_iter()
        .filter(|stamp| stamp.method == MockMethod::SubmitAggregateAndProofs)
        .map(|stamp| stamp.at)
        .collect();
    arrivals.sort_unstable();
    let mut done = completions.clone();
    done.sort_unstable();
    assert_eq!(arrivals.len(), done.len());
    for (arrival, finished) in arrivals.iter().zip(done.iter()) {
        assert_eq!(
            finished.saturating_duration_since(*arrival),
            REQUEST_DELAY,
            "completion is the paused instant the submit future returns, not the pre-delay arrival"
        );
    }

    let phase_start = marks[0].at;
    let mut data_at: Vec<_> = client
        .call_stamps()
        .into_iter()
        .filter(|stamp| stamp.method == MockMethod::GetAttestationData && stamp.at >= phase_start)
        .map(|stamp| stamp.at)
        .collect();
    data_at.sort_unstable();
    assert!(!data_at.is_empty(), "aggregation fetches attestation data");
    let first = data_at[0];
    let burst =
        data_at.iter().filter(|at| at.saturating_duration_since(first) < REQUEST_DELAY).count();
    assert!(
        burst >= 32,
        "sign concurrency must issue one attestation-data wave inside a {REQUEST_DELAY:?} RTT, got {burst}"
    );
}
