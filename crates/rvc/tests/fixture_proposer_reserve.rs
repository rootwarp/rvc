//! RR3-06: a fixture proposer duty records a block reserve at t=0.
//!
//! The reserve is the slashing-DB row written by `reserve_block`, and it is
//! observable as one `rvc_slashing_reserve_tx_hold_duration_ms{kind="block"}`
//! sample (mutex acquire through COMMIT). The clock is left at the slot start,
//! so the block phase — not a later bps wait — is what writes the row.

mod common;

use std::sync::Arc;
use std::time::Duration;

use block_service::{BeaconBlockClient, BlockServiceError, BuilderConfig};
use common::pipeline_fixture::{
    pipeline_fixture, FixtureBlockProduction, PipelineFixture, PipelineFixtureOpts, SLOTS_PER_EPOCH,
};
use metrics::definitions::{slot_phase_cache, tx_hold_kind, RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS};
use signer::metrics::RVC_SLASHING_RESERVE_TX_HOLD_DURATION_MS;
use slashing::SignedBlock;
use timing::SlotClock;

/// First slot of the Deneb epoch in the fixture fork schedule (epoch 40).
/// Electra is epoch 50, so this slot's body is the Deneb test vector.
const SLOT_S: u64 = 40 * SLOTS_PER_EPOCH;

fn proposer_fixture(production: FixtureBlockProduction) -> PipelineFixture {
    pipeline_fixture(
        PipelineFixtureOpts {
            duty_slots: vec![SLOT_S],
            initial_slot: SLOT_S,
            ..Default::default()
        }
        .with_validators(1)
        .with_proposer(true)
        .with_block_production(production),
    )
}

fn block_hold() -> (u64, f64) {
    let hist = RVC_SLASHING_RESERVE_TX_HOLD_DURATION_MS.with_label_values(&[tx_hold_kind::BLOCK]);
    (hist.get_sample_count(), hist.get_sample_sum())
}

fn cold_block_phase_offset() -> (u64, f64) {
    let hist = RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[slot_phase_cache::COLD]);
    (hist.get_sample_count(), hist.get_sample_sum())
}

/// Drive `run` from t=0 until a block row appears or the budget expires.
async fn drive_proposal(fixture: &mut PipelineFixture) -> Vec<SignedBlock> {
    let pubkey_hex = fixture.pubkey_hex.clone();
    let db = Arc::clone(&fixture.slashing_db);
    let orchestrator = &mut fixture.orchestrator;
    let handle = &fixture.handle;
    let run_fut = orchestrator.run();
    tokio::pin!(run_fut);
    let started = tokio::time::Instant::now();
    let budget = Duration::from_secs(5);
    loop {
        tokio::select! {
            biased;
            result = &mut run_fut => {
                let blocks = db.get_blocks(&pubkey_hex).expect("read blocks after run");
                assert!(
                    result.is_ok(),
                    "orchestrator run failed before the block reserve could be read: {result:?}"
                );
                return blocks;
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                let blocks = db.get_blocks(&pubkey_hex).expect("read blocks");
                if !blocks.is_empty() || started.elapsed() > budget {
                    handle.shutdown();
                }
            }
        }
    }
}

/// Proposer duty for slot S records one block reserve at t=0.
///
/// The reserve is a `conn`-hold interval: one
/// `rvc_slashing_reserve_tx_hold_duration_ms{kind="block"}` sample.
#[tokio::test]
async fn fixture_proposer_duty_produces_a_block_reserve() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let mut fixture = proposer_fixture(FixtureBlockProduction::Deneb);
    assert_eq!(
        fixture.clock.ms_into_slot(SLOT_S),
        0,
        "the mock clock is at the slot start; the block phase is t=0"
    );
    assert!(
        fixture.slashing_db.get_blocks(&fixture.pubkey_hex).expect("blocks").is_empty(),
        "no block row before the proposal"
    );

    let (hold_count_before, hold_sum_before) = block_hold();
    let (offset_count_before, offset_sum_before) = cold_block_phase_offset();

    let blocks = drive_proposal(&mut fixture).await;

    assert_eq!(
        blocks.len(),
        1,
        "a proposer duty for slot {SLOT_S} must record one block reserve at t=0; \
         produce_block_v3/v4 returned Err on NoopBlockBeacon, so the proposal never reserved"
    );
    assert_eq!(blocks[0].slot, SLOT_S, "the reserved block is slot S");
    assert!(
        blocks[0].signing_root.is_some(),
        "the reserve stores the block signing root committed with the row"
    );

    let (hold_count_after, hold_sum_after) = block_hold();
    let hold_samples = hold_count_after - hold_count_before;
    let hold_ms = hold_sum_after - hold_sum_before;
    assert_eq!(
        hold_samples, 1,
        "the block reserve is one conn-hold interval (reserve tx hold sample)"
    );
    assert!(
        hold_ms.is_finite() && hold_ms >= 0.0,
        "conn-hold interval must be a duration, got {hold_ms} ms"
    );

    let (offset_count_after, offset_sum_after) = cold_block_phase_offset();
    let offset_samples = offset_count_after - offset_count_before;
    assert_eq!(offset_samples, 1, "the cold block phase opened once");
    let offset_ms = (offset_sum_after - offset_sum_before) / offset_samples as f64;
    assert!(
        offset_ms < 1_000.0,
        "block phase opened at t=0 (offset {offset_ms} ms), before any bps wait"
    );
}

/// [`FixtureBlockProduction::Noop`] still selects the historical `Err` beacon.
#[tokio::test]
async fn err_returning_block_beacon_remains_selectable() {
    let explicit = proposer_fixture(FixtureBlockProduction::Noop);
    let v3 = explicit
        .block_beacon
        .produce_block_v3(SLOT_S, "0x00", None, Some(0))
        .await
        .expect_err("noop produce_block_v3");
    assert!(
        matches!(v3, BlockServiceError::Beacon(ref msg) if msg == "noop"),
        "explicit Noop production must stay Err(\"noop\"), got {v3}"
    );
    let config = BuilderConfig::default();
    let v4 = explicit
        .block_beacon
        .produce_block_v4(SLOT_S, "0x00", None, &config)
        .await
        .expect_err("noop produce_block_v4");
    assert!(
        matches!(v4, BlockServiceError::Beacon(ref msg) if msg == "noop"),
        "explicit Noop produce_block_v4 must stay Err(\"noop\"), got {v4}"
    );

    let default_fixture = pipeline_fixture(PipelineFixtureOpts {
        duty_slots: vec![SLOT_S],
        initial_slot: SLOT_S,
        ..Default::default()
    });
    let v3 = default_fixture
        .block_beacon
        .produce_block_v3(SLOT_S, "0x00", None, Some(0))
        .await
        .expect_err("default produce_block_v3");
    assert!(
        matches!(v3, BlockServiceError::Beacon(ref msg) if msg == "noop"),
        "the default fixture block beacon must still return Err(\"noop\"), got {v3}"
    );
}
