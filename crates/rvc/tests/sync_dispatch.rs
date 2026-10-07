//! RR2-04: sync-committee messages dispatch concurrently.
//!
//! N = 200 validators are in the sync committee. Every mock beacon call costs
//! 50 ms under a paused clock. The last sync-message publish must *finish*
//! within 1 s of the sync phase. `call_stamps` is the pre-delay arrival and
//! only proves waves: two publishes inside one 50 ms RTT. Completion is
//! `submit_sync_committee_messages_completions`, taken when that future returns.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bn_manager::MockMethod;
use common::pipeline_fixture::{
    make_beacon_attestation_data, pipeline_fixture, PipelineFixtureOpts, SLOTS_PER_EPOCH, SLOT_A,
};
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

const N: usize = 200;
const REQUEST_DELAY: Duration = Duration::from_millis(50);
/// Just past the 3,999 ms attestation / sync-message deadline, and short of
/// the 8,000 ms aggregate deadline, so contribution fetches stay parked while
/// the sync phase runs.
const PAST_SYNC_DUE_SECS: u64 = 4;

struct SyncPhaseStart {
    at: Arc<Mutex<Option<tokio::time::Instant>>>,
}

impl<S> Layer<S> for SyncPhaseStart
where
    S: tracing::Subscriber,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        if attrs.metadata().name() == "orchestrator.produce_sync_messages" {
            let mut guard = self.at.lock().expect("phase start lock");
            if guard.is_none() {
                *guard = Some(tokio::time::Instant::now());
            }
        }
    }
}

fn sync_message_count(calls: &[Vec<bn_manager::SyncCommitteeMessage>]) -> usize {
    calls.iter().map(Vec::len).sum()
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sync_messages_are_dispatched_concurrently() {
    let mut attestation_data_by_slot = std::collections::HashMap::new();
    attestation_data_by_slot
        .insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));
    let mut fixture = pipeline_fixture(
        PipelineFixtureOpts {
            attestation_data_by_slot,
            duty_slots: vec![SLOT_A],
            initial_slot: SLOT_A,
            ..Default::default()
        }
        .with_validators(N)
        .with_sync_committee(true)
        .with_request_delay(REQUEST_DELAY),
    );

    let epoch = SLOT_A / SLOTS_PER_EPOCH;
    let sync = fixture
        .duty_tracker
        .fetch_sync_committee_duties(epoch)
        .await
        .expect("sync committee duties");
    assert_eq!(sync.len(), N, "every validator is in the sync committee");
    fixture.duty_tracker.fetch_duties_for_epoch(epoch).await.expect("attester duties");
    fixture.set_slot(SLOT_A);
    fixture.clock.advance_time(PAST_SYNC_DUE_SECS);

    let phase_start = Arc::new(Mutex::new(None));
    let subscriber =
        tracing_subscriber::registry().with(SyncPhaseStart { at: Arc::clone(&phase_start) });
    let _guard = tracing::subscriber::set_default(subscriber);

    let client = Arc::clone(&fixture.beacon_client);
    let handle = &fixture.handle;
    let run_fut = fixture.orchestrator.run();
    tokio::pin!(run_fut);

    let wall_started = std::time::Instant::now();
    let mut shutdown_sent = false;
    loop {
        tokio::select! {
            biased;
            result = &mut run_fut => {
                result.expect("orchestrator run");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if !shutdown_sent
                    && sync_message_count(&client.submit_sync_committee_messages_calls()) >= N
                {
                    handle.shutdown();
                    shutdown_sent = true;
                }
                assert!(
                    wall_started.elapsed() < Duration::from_secs(120),
                    "sync phase did not publish {N} messages within 120 s of wall time"
                );
            }
        }
    }

    let calls = client.submit_sync_committee_messages_calls();
    assert_eq!(sync_message_count(&calls), N, "one sync message per validator");
    let mut indices: Vec<u64> =
        calls.iter().flatten().map(|message| message.validator_index).collect();
    indices.sort_unstable();
    indices.dedup();
    assert_eq!(indices.len(), N, "sync messages cover every validator index");

    let phase_start = phase_start.lock().expect("phase start lock").expect("sync phase started");
    let submits: Vec<_> = client
        .call_stamps()
        .into_iter()
        .filter(|stamp| stamp.method == MockMethod::SubmitSyncCommitteeMessages)
        .collect();
    assert!(
        submits.len() >= 2,
        "default duty_dispatch_concurrency waves the publish, got {} call(s)",
        submits.len()
    );
    let earliest = submits.iter().map(|stamp| stamp.at).min().expect("a publish stamp");
    let within_one_rtt = submits
        .iter()
        .filter(|stamp| stamp.at.saturating_duration_since(earliest) < REQUEST_DELAY)
        .count();
    assert!(
        within_one_rtt >= 2,
        "two sync publishes must be in flight inside one {REQUEST_DELAY:?} RTT, got {within_one_rtt}"
    );

    let mut arrivals: Vec<_> = submits.iter().map(|stamp| stamp.at).collect();
    arrivals.sort_unstable();
    let mut completions = client.submit_sync_committee_messages_completions();
    completions.sort_unstable();
    assert_eq!(
        completions.len(),
        arrivals.len(),
        "every admitted sync-message publish must finish"
    );
    for (arrival, done) in arrivals.iter().zip(completions.iter()) {
        assert_eq!(
            done.saturating_duration_since(*arrival),
            REQUEST_DELAY,
            "completion is the paused instant the submit future returns, not the pre-delay arrival"
        );
    }
    let last = completions.into_iter().next_back().expect("a completed publish");
    let landed = last.saturating_duration_since(phase_start);
    assert!(
        landed <= Duration::from_millis(1_000),
        "last sync-message publish completed {landed:?} after sync-phase start; bound is 1s"
    );
}
