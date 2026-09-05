//! ARCH-3h: post-duty wait window can host work against a `&self` wait.

use super::*;

fn wait_window_orchestrator(
) -> (DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>, OrchestratorHandle) {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(100);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config(),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ))
}

/// Hosted work must run (and may borrow `duty_management`) before the window
/// yields the next slot. Compiling this test is the VD-32 proof: the wait is
/// `&self`, so it can race an owned-field borrow.
#[tokio::test]
async fn test_post_duty_window_runs_hosted_work_before_the_next_slot() {
    let (orchestrator, _handle) = wait_window_orchestrator();
    let done = AtomicBool::new(false);

    let hosted = async {
        // Simultaneous `&self` use of the owned duty-management field.
        orchestrator.duty_management.epoch_boundary_summary_counts(0, 0).await;
        done.store(true, Ordering::SeqCst);
    };

    let outcome = orchestrator.run_post_duty_window(Duration::from_millis(200), hosted).await;

    assert_eq!(outcome, WaitOutcome::Continue);
    assert!(done.load(Ordering::SeqCst), "hosted work must complete before the next slot");
}

/// A hosted future that never completes must be abandoned when the next slot
/// arrives — the window cannot block the slot loop.
#[tokio::test]
async fn test_post_duty_window_abandons_hosted_work_when_the_slot_arrives_first() {
    let (orchestrator, _handle) = wait_window_orchestrator();

    let outcome = tokio::time::timeout(
        Duration::from_millis(200),
        orchestrator.run_post_duty_window(Duration::from_millis(20), std::future::pending()),
    )
    .await
    .expect("never-completing hosted work must not delay the next slot");

    assert_eq!(outcome, WaitOutcome::Continue);
}

/// Shutdown during the window must surface `WaitOutcome::Shutdown` promptly so
/// `run()` can return `Ok(())` without waiting out the slot.
#[tokio::test]
async fn test_shutdown_during_the_post_duty_window_still_returns() {
    let (orchestrator, handle) = wait_window_orchestrator();

    let outcome = tokio::time::timeout(Duration::from_millis(500), async {
        tokio::select! {
            biased;
            outcome = orchestrator.run_post_duty_window(
                Duration::from_secs(30),
                std::future::pending(),
            ) => outcome,
            () = async {
                handle.shutdown();
                std::future::pending::<()>().await;
            } => unreachable!("shutdown arm must stay pending so the window can return"),
        }
    })
    .await
    .expect("post-duty window must return promptly on shutdown");

    assert_eq!(outcome, WaitOutcome::Shutdown);
}

/// Permanent regression: pre-Gloas mainnet deadlines stay 3999 / 8000 ms.
#[test]
fn test_pre_gloas_mainnet_deadlines_are_3999_and_8000_ms() {
    let (orchestrator, _handle) = wait_window_orchestrator();
    let slot_duration_ms = orchestrator.clock.slot_duration().as_millis() as u64;
    assert_eq!(slot_duration_ms, 12_000);
    assert_eq!(due_ms(orchestrator.config.attestation_due_bps, slot_duration_ms), 3999);
    assert_eq!(due_ms(orchestrator.config.aggregate_due_bps, slot_duration_ms), 8000);
}
