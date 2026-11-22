//! ARCH-7a / M2: `rvc_slot_phase_block_start_offset_ms` histogram.

use super::*;
use metrics::definitions::{
    slot_phase_cache, slot_phase_offset, RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS,
    RVC_SLOT_PHASE_OFFSET_MS,
};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn empty_duty_body() -> serde_json::Value {
    serde_json::json!({
        "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "execution_optimistic": false,
        "data": []
    })
}

fn slot_from_block_id(slot: &str) -> u64 {
    if slot.is_empty() || !slot.bytes().all(|byte| byte.is_ascii_digit()) {
        return 1;
    }
    let mut value = 0u64;
    for byte in slot.bytes() {
        value = value.saturating_mul(10).saturating_add(u64::from(byte - b'0'));
    }
    value
}

fn consistent_stub_header(slot: &str) -> String {
    let slot_n = slot_from_block_id(slot);
    let parent = [2u8; 32];
    let state = [3u8; 32];
    let body = [4u8; 32];
    let header = eth_types::BeaconBlockHeader {
        slot: slot_n,
        proposer_index: 1,
        parent_root: parent,
        state_root: state,
        body_root: body,
    };
    let root = hex::encode(header.hash_tree_root_bytes());
    format!(
        r#"{{"execution_optimistic":false,"finalized":false,"data":{{"root":"0x{root}","canonical":true,"header":{{"message":{{"slot":"{slot_n}","proposer_index":"1","parent_root":"0x{}","state_root":"0x{}","body_root":"0x{}"}},"signature":"0x00"}}}}}}"#,
        hex::encode(parent),
        hex::encode(state),
        hex::encode(body),
    )
}

fn block_root_body() -> serde_json::Value {
    serde_json::json!({
        "execution_optimistic": false,
        "data": { "root": "0x0000000000000000000000000000000000000000000000000000000000000001" }
    })
}

/// Mount empty attester/proposer duty responses and a block-root for `SlotContext`.
async fn mount_slot_loop_mocks(mock_server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_duty_body()))
        .mount(mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_duty_body()))
        .mount(mock_server)
        .await;

    // Sync committee duties (empty) so the fetch path completes quickly.
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/sync/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_duty_body()))
        .mount(mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/beacon/blocks/.*/root"))
        .respond_with(ResponseTemplate::new(200).set_body_json(block_root_body()))
        .mount(mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/beacon/headers/.*"))
        .respond_with(move |request: &wiremock::Request| {
            let id = request.url.path().rsplit('/').next().unwrap_or("1");
            let slot = if !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()) {
                id
            } else {
                "1"
            };
            ResponseTemplate::new(200).set_body_string(consistent_stub_header(slot))
        })
        .mount(mock_server)
        .await;
}

fn histogram_count(cache: &str) -> u64 {
    RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).get_sample_count()
}

fn histogram_sum(cache: &str) -> f64 {
    RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).get_sample_sum()
}

fn phase_offset_count(phase: &str) -> u64 {
    RVC_SLOT_PHASE_OFFSET_MS.with_label_values(&[phase]).get_sample_count()
}

/// Drive one slot through `run()` and assert the M2 histogram records a sample.
#[tokio::test(flavor = "current_thread")]
async fn test_slot_phase_block_start_offset_is_recorded_each_slot() {
    let _guard = m2_metric_lock().await;

    let mock_server = MockServer::start().await;
    mount_slot_loop_mocks(&mock_server).await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    // Non-boundary slot; past 2/3 so phase waits are zero.
    clock.set_slot(65);
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let cold_before = histogram_count(slot_phase_cache::COLD);
    let warm_before = histogram_count(slot_phase_cache::WARM);
    let cold_sum_before = histogram_sum(slot_phase_cache::COLD);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config().with_timeouts(fast_timeouts()),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    // First slot after boot is cold. Global registry may receive concurrent
    // samples from sibling tests; under the metric lock among M2 cases we
    // still require exactly one new sample from this single-slot drive when
    // no other slot-loop test races us.
    let cold_after = histogram_count(slot_phase_cache::COLD);
    let warm_after = histogram_count(slot_phase_cache::WARM);
    let cold_added = cold_after - cold_before;
    let warm_added = warm_after - warm_before;
    let samples = cold_added + warm_added;
    assert!(
        samples >= 1,
        "at least one sample per driven slot; cold+{cold_added}/warm+{warm_added}"
    );
    assert!(cold_added >= 1, "first slot after boot must be labelled cache=cold");
    // When isolation holds, the single-slot drive records exactly one cold sample.
    if samples == 1 {
        assert_eq!(cold_added, 1);
        assert_eq!(warm_added, 0);
    }

    let cold_sum_after = histogram_sum(slot_phase_cache::COLD);
    let observed = cold_sum_after - cold_sum_before;
    assert!(observed >= 0.0, "offset must be >= 0, got {observed}");
}

/// The t=0 parent-header delay appears in the cold block-start sample
/// (instrument credibility). Paused clock: the delay is the mock's virtual
/// sleep, and the sample is read from this thread's mirror.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_offset_reflects_pre_proposal_work() {
    use bn_manager::MockMethod;

    let _guard = m2_metric_lock().await;

    let delay = Duration::from_secs(2);
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let slot = 65u64;
    clock.set_slot_with_offset_ms(slot, 0);

    let beacon = Arc::new(
        bn_manager::MockBeaconNodeClient::new()
            .with_slot_aware_block_root(slot, &[], |_| format!("0x{}", "01".repeat(32)))
            .with_method_delay(MockMethod::GetBlockHeader, delay)
            .with_method_delay(MockMethod::GetBlockRoot, delay),
    );
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config()
            .with_timeouts(fast_timeouts())
            // Each parent lookup step may use 3 s of 20 s, more than the delay.
            .with_pre_proposal_deadline(Duration::from_secs(20))
            .with_cold_proposer_fetch_deadline(Duration::ZERO),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let (cold_count_before, cold_sum_before) = crate::test_metrics::block_start_cold();
    let (recorded_tx, recorded_rx) = std::sync::mpsc::channel();
    testing_set_phase_block_recorded(Some(recorded_tx));
    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            // Paused sleeps let the clock reach the mock's delay.
            let recorded = tokio::time::timeout(Duration::from_secs(12), async {
                while recorded_rx.try_recv().is_err() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await;
            assert!(recorded.is_ok(), "phase=block was not recorded within one slot");
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }
    testing_set_phase_block_recorded(None);

    let (cold_count, cold_sum) = crate::test_metrics::block_start_cold();
    assert_eq!(cold_count - cold_count_before, 1, "the post-boot slot records one cold sample");
    let sample = cold_sum - cold_sum_before;
    assert_eq!(
        sample,
        delay.as_millis() as f64,
        "the cold sample is the parent-header delay D={}ms, got {sample}ms",
        delay.as_millis()
    );
}

/// After a key_gen invalidation the next slot's offset is labelled `cache=cold`.
#[tokio::test(flavor = "current_thread")]
async fn test_offset_labels_cold_after_key_gen_invalidation() {
    let _guard = m2_metric_lock().await;

    let mock_server = MockServer::start().await;
    mount_slot_loop_mocks(&mock_server).await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(65);
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);

    let cold_before = histogram_count(slot_phase_cache::COLD);
    let warm_before = histogram_count(slot_phase_cache::WARM);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps {
        key_gen_rx,
        ..OrchestratorDeps::for_test(
            clock.clone(),
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            create_test_config().with_timeouts(fast_timeouts()),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        )
    });

    // Drain the initial watch "changed" so only a real bump re-marks cold via key_gen.
    orchestrator.apply_key_gen_cache_invalidation().await;
    // Boot flag is still cold until the first offset sample; first slot → cold.

    let clock_adv = clock.clone();
    tokio::spawn(async move {
        // Slot 65 (cold / post-boot). time_until next ≈ 3 s after advance_time(9).
        tokio::time::sleep(Duration::from_millis(500)).await;
        clock_adv.set_slot(66);
        clock_adv.advance_time(9);

        // Slot 66 (warm): wait for processing after the ~3 s next-slot wait.
        tokio::time::sleep(Duration::from_millis(3500)).await;
        key_gen_tx.send_modify(|gen| *gen += 1);
        clock_adv.set_slot(67);
        clock_adv.advance_time(9);

        // Slot 67 (cold / post-key_gen).
        tokio::time::sleep(Duration::from_millis(3500)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let cold_added = histogram_count(slot_phase_cache::COLD) - cold_before;
    let warm_added = histogram_count(slot_phase_cache::WARM) - warm_before;

    assert!(warm_added >= 1, "steady-state slot after boot must be warm; warm_added={warm_added}");
    assert!(
        cold_added >= 2,
        "post-boot and post-key_gen slots must both be cold; cold_added={cold_added}"
    );
}

/// Anchor captured 600 ms into the slot. The histogram must observe that
/// offset; a whole-second clock read records 0.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn phase_block_start_offset_reports_the_true_offset() {
    let _guard = m2_metric_lock().await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let slot = 65u64;
    clock.set_slot_with_offset_ms(slot, 0);
    clock.advance_ms(600);

    let beacon = Arc::new(bn_manager::MockBeaconNodeClient::new());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config()
            .with_timeouts(fast_timeouts())
            .with_pre_proposal_deadline(Duration::ZERO)
            .with_cold_proposer_fetch_deadline(Duration::ZERO),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let (cold_count_before, cold_sum_before) = crate::test_metrics::block_start_cold();
    let (block_count_before, block_sum_before) = crate::test_metrics::phase_block();

    let (recorded_tx, recorded_rx) = std::sync::mpsc::channel();
    testing_set_phase_block_recorded(Some(recorded_tx));
    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            // `start_paused` does not wake `spawn_blocking`. Poll the signal.
            // Wall time only: a paused sleep here would move the slot clock.
            let wall_deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                match recorded_rx.try_recv() {
                    Ok(()) => break,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        if std::time::Instant::now() >= wall_deadline {
                            panic!("phase=block was not recorded within 30s");
                        }
                        tokio::task::yield_now().await;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        panic!("phase=block was not recorded");
                    }
                }
            }
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }
    testing_set_phase_block_recorded(None);

    let (cold_after, cold_sum_after) = crate::test_metrics::block_start_cold();
    let cold_added = cold_after - cold_count_before;
    let sum_delta = cold_sum_after - cold_sum_before;
    assert!(cold_added >= 1, "post-boot slot must record cache=cold, added {cold_added}");
    let observed = sum_delta / cold_added as f64;
    assert!(
        (550.0..=650.0).contains(&observed),
        "anchor at +600 ms must observe about 600, got {observed} \
         (sum_delta={sum_delta}, cold_added={cold_added})"
    );

    let (block_after, block_sum_after) = crate::test_metrics::phase_block();
    let block_added = block_after - block_count_before;
    let block_sum = block_sum_after - block_sum_before;
    assert!(block_added >= 1, "phase=block must be recorded, added {block_added}");
    let block_observed = block_sum / block_added as f64;
    assert!(
        (550.0..=650.0).contains(&block_observed),
        "rvc_slot_phase_offset_ms{{phase=block}} must observe about 600, got {block_observed}"
    );
}

/// Soft deprecation (AQ-7 / #611): both the deprecated block-start family and
/// `rvc_slot_phase_offset_ms{phase="block"}` must still record on a block phase.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn block_phase_still_records_deprecated_and_labelled_offset_families() {
    let _guard = m2_metric_lock().await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let slot = 65u64;
    clock.set_slot_with_offset_ms(slot, 0);
    clock.advance_ms(600);

    let beacon = Arc::new(bn_manager::MockBeaconNodeClient::new());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config()
            .with_timeouts(fast_timeouts())
            .with_pre_proposal_deadline(Duration::ZERO)
            .with_cold_proposer_fetch_deadline(Duration::ZERO),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let cold_before = histogram_count(slot_phase_cache::COLD);
    let warm_before = histogram_count(slot_phase_cache::WARM);
    let block_before = phase_offset_count(slot_phase_offset::BLOCK);

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    let deprecated_added = (histogram_count(slot_phase_cache::COLD) - cold_before)
        + (histogram_count(slot_phase_cache::WARM) - warm_before);
    let labelled_added = phase_offset_count(slot_phase_offset::BLOCK) - block_before;
    assert!(
        deprecated_added >= 1,
        "deprecated rvc_slot_phase_block_start_offset_ms must still record, added {deprecated_added}"
    );
    assert!(
        labelled_added >= 1,
        "rvc_slot_phase_offset_ms{{phase=block}} must record, added {labelled_added}"
    );
}

/// Every `rvc_slot_phase_offset_ms` phase label is recorded when that phase fires.
/// Gloas is required so payload attestation runs.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn slot_phase_offset_ms_records_every_phase_label() {
    let _guard = m2_metric_lock().await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    // Epoch 70 is the test schedule's Gloas activation.
    let slot = 70 * 32;
    clock.set_slot_with_offset_ms(slot, 0);
    clock.advance_ms(600);

    let beacon = Arc::new(bn_manager::MockBeaconNodeClient::new());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config()
            .with_timeouts(fast_timeouts())
            .with_pre_proposal_deadline(Duration::ZERO)
            .with_cold_proposer_fetch_deadline(Duration::ZERO),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let before: Vec<u64> =
        slot_phase_offset::ALL.iter().map(|phase| phase_offset_count(phase)).collect();

    tokio::select! {
        biased;
        _ = orchestrator.run() => {}
        () = async {
            // Payload attestation is due at 9000 ms from the true start
            // (8400 ms after a 600 ms wake). Shut down after it fires and
            // before the inter-slot wait.
            tokio::time::sleep(Duration::from_millis(8_600)).await;
            handle.shutdown();
            std::future::pending::<()>().await;
        } => {}
    }

    for (phase, before_count) in slot_phase_offset::ALL.iter().zip(before) {
        let added = phase_offset_count(phase) - before_count;
        assert!(added >= 1, "phase={phase} must be recorded when it fires, added {added}");
    }
}
