//! Block selection mode / builder boost tests for block-service.

use super::*;
use std::sync::Arc;

#[tokio::test]
async fn test_execution_only_sets_boost_factor_zero() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot));
    let cb = Arc::new(CircuitBreakerState::new(0, 0));
    let service = build_service_with_mode(beacon, &pubkey, cb);

    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly).await;
    assert!(result.is_ok());

    let boost = service.beacon.last_produce_call().builder_boost_factor;
    assert_eq!(boost, Some(0));
}

#[tokio::test]
async fn test_max_profit_uses_configured_boost_factor() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot));
    let cb = Arc::new(CircuitBreakerState::new(0, 0));
    let service = build_service_with_mode(beacon, &pubkey, cb);

    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit).await;
    assert!(result.is_ok());

    // test_validator_store sets builder_boost_factor=150
    let boost = service.beacon.last_produce_call().builder_boost_factor;
    assert_eq!(boost, Some(150));
}

#[tokio::test]
async fn test_builder_always_sets_boost_factor_max() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot));
    let cb = Arc::new(CircuitBreakerState::new(0, 0));
    let service = build_service_with_mode(beacon, &pubkey, cb);

    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways).await;
    assert!(result.is_ok());

    let boost = service.beacon.last_produce_call().builder_boost_factor;
    assert_eq!(boost, Some(u64::MAX));
}

#[tokio::test]
async fn test_builder_always_falls_back_on_circuit_breaker() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot));
    let cb = Arc::new(CircuitBreakerState::new(1, 0));
    cb.record_miss(); // trip it
    assert!(cb.is_tripped());

    let service = build_service_with_mode(beacon, &pubkey, cb);
    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways).await;
    // BuilderAlways falls back to local (boost=0)
    assert!(result.is_ok());
    let boost = service.beacon.last_produce_call().builder_boost_factor;
    assert_eq!(boost, Some(0));
}

#[tokio::test]
async fn test_builder_only_sets_boost_factor_max() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::blinded(test_blinded_block(slot));
    let cb = Arc::new(CircuitBreakerState::new(0, 0));
    let service = build_service_with_mode(beacon, &pubkey, cb);

    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly).await;
    assert!(result.is_ok(), "BuilderOnly signs a blinded block: {result:?}");
    assert!(result.unwrap().is_blinded);

    let boost = service.beacon.last_produce_call().builder_boost_factor;
    assert_eq!(boost, Some(u64::MAX));
}

#[tokio::test]
async fn test_builder_only_fails_on_circuit_breaker_tripped() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = Arc::new(MockBeaconClient::unblinded(test_block(slot)));
    let signer = Arc::new(MockSigner::new());
    let cb = Arc::new(CircuitBreakerState::new(1, 0));
    cb.record_miss(); // trip it
    assert!(cb.is_tripped());

    let service = BlockService::with_circuit_breaker(
        Arc::clone(&signer),
        Arc::clone(&beacon),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
        cb,
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("tripped builder-only misses the slot");
    assert!(
        matches!(err, BlockServiceError::BuilderOnly(ref text) if text.contains("circuit breaker tripped")),
        "{err:?}"
    );
    // Fence, then RANDAO, then this return. Produce has not started.
    assert_eq!(signer.randao_calls.lock().expect("randao").len(), 1);
    assert!(beacon.produce_v3_calls.lock().expect("produce").is_empty());
    assert!(signer.header_calls.lock().expect("headers").is_empty());
}

#[tokio::test]
async fn test_builder_only_fails_on_builder_error() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot)).with_produce_error();
    let cb = Arc::new(CircuitBreakerState::new(0, 0));
    let service = build_service_with_mode(beacon, &pubkey, cb);

    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BlockServiceError::BuilderOnly(_)));
}

#[tokio::test]
async fn test_max_profit_circuit_breaker_tripped_uses_zero() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot));
    let cb = Arc::new(CircuitBreakerState::new(1, 0));
    cb.record_miss();
    assert!(cb.is_tripped());

    let service = build_service_with_mode(beacon, &pubkey, cb);
    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit).await;
    assert!(result.is_ok());
    let boost = service.beacon.last_produce_call().builder_boost_factor;
    assert_eq!(boost, Some(0));
}
#[tokio::test]
async fn test_bn_error_with_builder_boost_returns_builder_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot)).with_produce_error();
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    // BuilderAlways → boost = u64::MAX > 0 → BN error is a builder failure.
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways)
        .await
        .unwrap_err();

    assert!(
        matches!(err, BlockServiceError::BuilderFailure(_)),
        "expected BuilderFailure, got {err:?}"
    );
}

/// H-3: When `produce_block_v3` fails **and** `boost == 0` (ExecutionOnly),
/// `propose_block_impl` must NOT return `BuilderFailure` — it returns a
/// plain `Beacon` error so the coordinator leaves the circuit breaker alone.
#[tokio::test]
async fn test_bn_error_with_zero_boost_returns_beacon_not_builder_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot)).with_produce_error();
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    // ExecutionOnly → boost = 0 → BN error must NOT be tagged BuilderFailure.
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .unwrap_err();

    assert!(
        !matches!(err, BlockServiceError::BuilderFailure(_)),
        "ExecutionOnly BN error must NOT be BuilderFailure, got {err:?}"
    );
}

/// H-3: MaxProfit with non-zero boost returns `BuilderFailure` on BN error.
#[tokio::test]
async fn test_bn_error_with_max_profit_nonzero_boost_returns_builder_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::unblinded(test_block(slot)).with_produce_error();
    let signer = MockSigner::new();
    // build_service wires the validator store with builder_boost_factor = 150.
    let service = build_service(signer, beacon, &pubkey);

    // MaxProfit + circuit breaker not tripped → boost = 150 > 0 → BuilderFailure.
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .unwrap_err();

    assert!(
        matches!(err, BlockServiceError::BuilderFailure(_)),
        "MaxProfit BN error with non-zero boost must be BuilderFailure, got {err:?}"
    );
}

fn tripped(limit: u32) -> Arc<CircuitBreakerState> {
    let breaker = Arc::new(CircuitBreakerState::new(limit, 0));
    breaker.record_miss();
    breaker
}

fn opened(
    beacon: MockBeaconClient,
    signer: Arc<MockSigner>,
    pubkey: &PublicKey,
    breaker: Arc<CircuitBreakerState>,
) -> (BlockService<MockSigner, MockBeaconClient>, Arc<MockBeaconClient>) {
    let beacon = Arc::new(beacon);
    let service = BlockService::with_circuit_breaker(
        signer,
        Arc::clone(&beacon),
        Arc::new(test_validator_store(pubkey)),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
        breaker,
    );
    (service, beacon)
}

#[test]
fn selection_mode_is_execution_only_only_while_tripped() {
    let mode = super::super::selection_effective_mode;
    assert_eq!(mode(BlockSelectionMode::MaxProfit, true), BlockSelectionMode::ExecutionOnly);
    assert_eq!(mode(BlockSelectionMode::BuilderAlways, true), BlockSelectionMode::ExecutionOnly);
    assert_eq!(mode(BlockSelectionMode::MaxProfit, false), BlockSelectionMode::MaxProfit);
    assert_eq!(mode(BlockSelectionMode::BuilderAlways, false), BlockSelectionMode::BuilderAlways);
    assert_eq!(mode(BlockSelectionMode::BuilderOnly, true), BlockSelectionMode::BuilderOnly);
    assert_eq!(mode(BlockSelectionMode::ExecutionOnly, true), BlockSelectionMode::ExecutionOnly);
}

#[test]
fn gloas_self_build_index_matches_the_consensus_constant() {
    assert_eq!(beacon::GLOAS_SELF_BUILD_BUILDER_INDEX, rvc_gloas::BUILDER_INDEX_SELF_BUILD);
}

/// A tripped breaker signs no blinded header under max-profit.
#[tokio::test]
async fn test_tripped_breaker_rejects_a_blinded_block_under_max_profit() {
    let pubkey = test_pubkey();
    let slot = 100;
    let signer = Arc::new(MockSigner::new());
    let breaker = tripped(1);
    let (service, beacon) = opened(
        MockBeaconClient::blinded(test_blinded_block(slot)),
        Arc::clone(&signer),
        &pubkey,
        breaker,
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect_err("tripped max-profit rejects a blinded block");
    assert!(signer.header_calls.lock().expect("headers").is_empty());
    assert!(beacon.publish_blinded_calls.lock().expect("publish").is_empty());
    assert!(matches!(
        err,
        BlockServiceError::ModeShapeMismatch {
            mode: BlockSelectionMode::ExecutionOnly,
            shape: crate::CandidateShape::Blinded,
        }
    ));
}

/// Builder-always uses the same tripped gate.
#[tokio::test]
async fn test_tripped_breaker_rejects_a_blinded_block_under_builder_always() {
    let pubkey = test_pubkey();
    let slot = 100;
    let signer = Arc::new(MockSigner::new());
    let (service, _) = opened(
        MockBeaconClient::blinded(test_blinded_block(slot)),
        Arc::clone(&signer),
        &pubkey,
        tripped(1),
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways)
        .await
        .expect_err("tripped builder-always rejects a blinded block");
    assert!(signer.header_calls.lock().expect("headers").is_empty());
    assert!(matches!(
        err,
        BlockServiceError::ModeShapeMismatch {
            mode: BlockSelectionMode::ExecutionOnly,
            shape: crate::CandidateShape::Blinded,
        }
    ));
}

/// One miss below the limit leaves the breaker clear. The blinded block is signed.
#[tokio::test]
async fn test_miss_below_the_limit_still_signs_a_blinded_block() {
    let pubkey = test_pubkey();
    let slot = 100;
    let signer = Arc::new(MockSigner::new());
    let breaker = Arc::new(CircuitBreakerState::new(2, 0));
    breaker.record_miss();
    assert!(!breaker.is_tripped());
    let (service, _) = opened(
        MockBeaconClient::blinded(test_blinded_block(slot)),
        Arc::clone(&signer),
        &pubkey,
        breaker,
    );
    let result = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect("a clear breaker still signs a blinded block");
    assert!(result.is_blinded);
    assert!(result.builder_path);
    assert_eq!(signer.header_calls.lock().expect("headers").len(), 1);
}

/// A tripped max-profit produce error is not a builder miss. Boost is 0.
#[tokio::test]
async fn test_tripped_max_profit_produce_error_is_not_a_builder_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let (service, beacon) = opened(
        MockBeaconClient::unblinded(test_block(slot)).with_produce_error(),
        Arc::new(MockSigner::new()),
        &pubkey,
        tripped(1),
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect_err("produce failed");
    assert!(
        matches!(err, BlockServiceError::Beacon(_)),
        "tripped max-profit must not tag the produce error as a builder miss, got {err:?}"
    );
    assert_eq!(beacon.last_produce_call().builder_boost_factor, Some(0));
}

/// No admitted node stops before boost, produce, and RANDAO, even when tripped.
#[tokio::test]
async fn test_empty_pool_stops_before_the_breaker_and_the_shape() {
    for mode in [BlockSelectionMode::BuilderOnly, BlockSelectionMode::MaxProfit] {
        let pubkey = test_pubkey();
        let slot = 100;
        let signer = Arc::new(MockSigner::new());
        let mut client = MockBeaconClient::unblinded(test_block(slot));
        client.refuse_admission = true;
        let breaker = tripped(1);
        let before = breaker.consecutive_misses();
        let (service, beacon) = opened(client, Arc::clone(&signer), &pubkey, Arc::clone(&breaker));
        let err = service.propose_block_with_mode(slot, &pubkey, mode).await.expect_err("halted");
        let text = err.to_string();
        assert!(text.contains("no admitted"), "{mode}: {text}");
        assert!(!matches!(
            err,
            BlockServiceError::BuilderOnly(_) | BlockServiceError::BuilderFailure(_)
        ));
        assert!(beacon.produce_v3_calls.lock().expect("produce").is_empty());
        assert!(signer.header_calls.lock().expect("headers").is_empty());
        assert!(signer.randao_calls.lock().expect("randao").is_empty());
        assert_eq!(breaker.consecutive_misses(), before);
        assert!(breaker.is_tripped());
    }
}

/// The duty sent to produce carries the shape from the one breaker sample.
#[tokio::test]
async fn test_duty_shape_follows_the_breaker_sample() {
    let cases = [
        (BlockSelectionMode::MaxProfit, true, crate::ShapeConstraint::LocalOnly, false),
        (BlockSelectionMode::BuilderAlways, true, crate::ShapeConstraint::LocalOnly, false),
        (BlockSelectionMode::BuilderOnly, false, crate::ShapeConstraint::BlindedOnly, true),
        (BlockSelectionMode::MaxProfit, false, crate::ShapeConstraint::Any, false),
        (BlockSelectionMode::BuilderAlways, false, crate::ShapeConstraint::Any, false),
    ];
    for (mode, trip, shape, blinded) in cases {
        let pubkey = test_pubkey();
        let slot = 100;
        let store = test_validator_store(&pubkey);
        store.set_global_block_selection_mode(mode);
        let beacon = if blinded {
            MockBeaconClient::blinded(test_blinded_block(slot))
        } else {
            MockBeaconClient::unblinded(test_block(slot))
        };
        let beacon = Arc::new(beacon);
        let breaker = Arc::new(CircuitBreakerState::new(1, 0));
        if trip {
            breaker.record_miss();
        }
        let service = BlockService::with_circuit_breaker(
            Arc::new(MockSigner::new()),
            Arc::clone(&beacon),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
            breaker,
        );
        let result = service.propose_block(slot, &pubkey, 42, None).await;
        assert!(result.is_ok(), "{mode} tripped={trip}: {result:?}");
        let duty = (*beacon.last_duty.lock().expect("duty")).expect("duty was sent");
        assert_eq!(duty.shape, shape, "{mode} tripped={trip}");
    }
}

/// A tripped breaker does not sign a Gloas external bid. Boost is 0 and the
/// builder list is empty.
#[tokio::test]
async fn test_tripped_breaker_rejects_a_gloas_builder_win() {
    let slot = test_gloas_slot();
    let pubkey = test_pubkey();
    let beacon = Arc::new(super::mode::gloas_beacon(slot));
    let signer = Arc::new(MockSigner::new());
    let service = super::mode::gloas(
        Arc::clone(&signer),
        Arc::clone(&beacon),
        &pubkey,
        test_validator_store(&pubkey),
        tripped(1),
        None,
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect_err("tripped max-profit rejects an external bid");
    super::mode::assert_unsigned(&signer, &beacon);
    assert!(matches!(
        err,
        BlockServiceError::ModeShapeMismatch {
            mode: BlockSelectionMode::ExecutionOnly,
            shape: crate::CandidateShape::BuilderWin,
        }
    ));
    let calls = beacon.produce_v4_calls.lock().expect("v4");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].builder_config.builder_boost_factor, 0);
    assert!(calls[0].builder_config.builders.is_empty());
}

/// The breaker is sampled once, before produce. A trip or a reset that lands
/// after produce does not change the shape of this proposal.
#[tokio::test]
async fn test_breaker_sample_is_not_reread_after_produce() {
    let pubkey = test_pubkey();
    let slot = 100;
    let signer = Arc::new(MockSigner::new());
    let breaker = Arc::new(CircuitBreakerState::new(1, 0));
    let trip = Arc::clone(&breaker);
    let (service, _) = opened(
        MockBeaconClient::blinded(test_blinded_block(slot)),
        Arc::clone(&signer),
        &pubkey,
        Arc::clone(&breaker),
    );
    service.set_after_produce(move || {
        trip.record_miss();
    });
    let result = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect("a clear sample still signs the blinded block");
    assert!(result.builder_path);
    assert_eq!(signer.header_calls.lock().expect("headers").len(), 1);
    assert!(breaker.is_tripped(), "the trip landed after the sample");

    let signer = Arc::new(MockSigner::new());
    let breaker = tripped(1);
    let clear = Arc::clone(&breaker);
    let (service, _) = opened(
        MockBeaconClient::blinded(test_blinded_block(slot)),
        Arc::clone(&signer),
        &pubkey,
        Arc::clone(&breaker),
    );
    service.set_after_produce(move || {
        clear.record_success();
    });
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect_err("a tripped sample still rejects the blinded block");
    assert!(signer.header_calls.lock().expect("headers").is_empty());
    assert!(matches!(
        err,
        BlockServiceError::ModeShapeMismatch {
            mode: BlockSelectionMode::ExecutionOnly,
            shape: crate::CandidateShape::Blinded,
        }
    ));
    assert!(!breaker.is_tripped(), "the reset landed after the sample");
}
