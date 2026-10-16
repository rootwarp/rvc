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
    let beacon = MockBeaconClient::unblinded(test_block(slot));
    let cb = Arc::new(CircuitBreakerState::new(1, 0));
    cb.record_miss(); // trip it
    assert!(cb.is_tripped());

    let service = build_service_with_mode(beacon, &pubkey, cb);
    let result =
        service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BlockServiceError::BuilderOnly(_)));
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
