//! RR0-10: sync-committee duties and aggregator selections in `pipeline_fixture`.
//!
//! `with_request_delay` is #498 and is not on this tip, so the pause-clock
//! check does not call it.

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bn_manager::{SyncCommitteeMessage, VersionedSignedAggregateAndProof};
use common::pipeline_fixture::{
    make_beacon_attestation_data, pipeline_fixture, PipelineFixtureOpts, PreparedPipelineFixture,
    SLOTS_PER_EPOCH, SLOT_A,
};
use eth_types::is_aggregator;

const N: usize = 200;
/// Seconds past slot start. Aggregate due is 8000 ms into a 12 s slot, so
/// phase waits are zero and the run reaches the next-slot sleep.
const PAST_AGGREGATE_DUE_SECS: u64 = 8;

fn n_opts(n: usize) -> PreparedPipelineFixture {
    let mut attestation_data_by_slot = HashMap::new();
    attestation_data_by_slot
        .insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));
    PipelineFixtureOpts {
        attestation_data_by_slot,
        duty_slots: vec![SLOT_A],
        initial_slot: SLOT_A,
        ..Default::default()
    }
    .with_validators(n)
    .with_sync_committee(true)
    .with_aggregators(true)
}

fn sync_message_count(calls: &[Vec<SyncCommitteeMessage>]) -> usize {
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

struct SlotSubmits {
    sync_messages: usize,
    aggregate_proofs: usize,
    build: Duration,
    slot: Duration,
}

async fn drive_one_slot() -> SlotSubmits {
    let started = Instant::now();
    let fixture = pipeline_fixture(n_opts(N));
    let build = started.elapsed();

    let epoch = SLOT_A / SLOTS_PER_EPOCH;
    let sync = fixture
        .duty_tracker
        .fetch_sync_committee_duties(epoch)
        .await
        .expect("sync committee duties");
    assert_eq!(sync.len(), N, "one sync-committee duty per validator");

    let keys: HashSet<[u8; 48]> =
        fixture.composite_signer.local_public_keys().into_iter().collect();
    let sync_keys: HashSet<[u8; 48]> = sync.iter().map(|duty| duty.pubkey).collect();
    assert_eq!(sync_keys, keys, "sync duties must cover every seeded validator");
    let indices: HashSet<u64> = sync.iter().map(|duty| duty.validator_index).collect();
    assert_eq!(indices.len(), N, "sync duties must use distinct validator indices");

    fixture.duty_tracker.fetch_duties_for_epoch(epoch).await.expect("attester duties");
    let duties = fixture.duty_tracker.get_duties_for_slot(SLOT_A).await;
    assert_eq!(duties.len(), N, "one attester duty per validator");
    let mut selections = 0usize;
    for duty in &duties {
        let committee_length: u64 = duty.committee_length.parse().expect("committee_length");
        // The mock selection is the committee length: modulo 1 selects every proof.
        assert!(
            is_aggregator(committee_length, &[0x00; 96]),
            "committee_length {committee_length} must select a zero proof"
        );
        assert!(
            is_aggregator(committee_length, &[0xff; 96]),
            "committee_length {committee_length} must select every proof"
        );
        selections += 1;
    }
    assert_eq!(selections, N, "one aggregator selection per validator");

    fixture.clock.set_slot(SLOT_A);
    fixture.clock.advance_time(PAST_AGGREGATE_DUE_SECS);

    let client = Arc::clone(&fixture.beacon_client);
    let handle = fixture.handle;
    let mut orchestrator = fixture.orchestrator;
    let task = tokio::spawn(async move { orchestrator.run().await });

    let slot_started = Instant::now();
    let deadline = Duration::from_secs(120);
    loop {
        let sync_messages = sync_message_count(&client.submit_sync_committee_messages_calls());
        let aggregate_proofs = aggregate_proof_count(&client.submit_aggregate_and_proofs_calls());
        if sync_messages >= N && aggregate_proofs >= N {
            break;
        }
        assert!(
            slot_started.elapsed() < deadline,
            "slot did not submit N sync messages and N aggregates within {deadline:?}; \
             sync={sync_messages} aggregates={aggregate_proofs}"
        );
        tokio::task::yield_now().await;
    }

    // Virtual time moving a little, while still short of the next slot, must
    // not create a second submit. `with_request_delay` is absent on this tip.
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    let sync_messages = sync_message_count(&client.submit_sync_committee_messages_calls());
    let aggregate_proofs = aggregate_proof_count(&client.submit_aggregate_and_proofs_calls());
    let slot = slot_started.elapsed();

    handle.shutdown();
    let _ = task.await;

    assert_eq!(sync_messages, N, "one slot submits one sync message per validator");
    assert_eq!(aggregate_proofs, N, "one slot submits one aggregate per validator");
    assert!(
        !client.submit_sync_committee_messages_calls().is_empty(),
        "sync-message submit must be visible on the mock counter"
    );
    assert!(
        !client.submit_aggregate_and_proofs_calls().is_empty(),
        "aggregate submit must be visible on the mock counter"
    );

    SlotSubmits { sync_messages, aggregate_proofs, build, slot }
}

#[tokio::test(start_paused = true)]
async fn fixture_builds_n_sync_duties_and_n_aggregator_selections() {
    let first = drive_one_slot().await;
    let second = drive_one_slot().await;

    assert_eq!(first.sync_messages, second.sync_messages);
    assert_eq!(first.aggregate_proofs, second.aggregate_proofs);
    assert_eq!(first.sync_messages, N);
    assert_eq!(first.aggregate_proofs, N);

    eprintln!(
        "N={N} pipeline_fixture build: {:?} / {:?}; slot: {:?} / {:?}",
        first.build, second.build, first.slot, second.slot
    );
}
