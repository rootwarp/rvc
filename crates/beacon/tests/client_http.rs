//! HTTP integration tests for [`beacon::BeaconClient`] against wiremock.
//!
//! Pure relocation of the wiremock suite formerly inline in `src/client.rs`
//! (RF6-07 / H1). Unit tests that touch private helpers (`build_path`,
//! `resolve_url`, config/backoff) remain in `src/client.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use beacon::{
    parse_slot_duration_ms, AttestationData, BeaconClient, BeaconClientConfig,
    BeaconCommitteeSubscription, BeaconError, BuilderConfig, Checkpoint, LegacyAttestation,
    ProposerPreparation, SingleAttestation, VersionedAggregateAttestation, VersionedAttestation,
    VersionedSignedAggregateAndProof, HEADER_ETH_BUILDER_URL, HEADER_ETH_CONSENSUS_BLOCK_VALUE,
    HEADER_ETH_CONSENSUS_VERSION, HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED,
    PRODUCE_BLOCK_V4_PATH_PREFIX, QUERY_GRAFFITI, QUERY_INCLUDE_PAYLOAD, QUERY_RANDAO_REVEAL,
    QUERY_SKIP_RANDAO_VERIFICATION,
};
use eth_types::{ForkName, ForkSchedule};
use timing::{SlotClock, SystemSlotClock};

fn fulu_gloas_schedule() -> ForkSchedule {
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.fulu_fork_epoch = 500_000;
    schedule.gloas_fork_epoch = 600_000;
    schedule
}

fn proposer_duties_body() -> serde_json::Value {
    serde_json::json!({
        "dependent_root": "0xabc123",
        "execution_optimistic": true,
        "data": [
            {
                "pubkey": "0xpubkey1",
                "validator_index": "100",
                "slot": "64000"
            }
        ]
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestData {
    value: String,
}

#[tokio::test]
async fn test_get_fork_encodes_reserved_state_id_on_wire() {
    let mock_server = MockServer::start().await;

    // wiremock path matcher sees the decoded path segment form; match the
    // encoded request URL path that leaves the client.
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/foo%2Fbar/fork"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "previous_version": "0x00000000",
                "current_version": "0x00000001",
                "epoch": "0"
            },
            "execution_optimistic": false,
            "finalized": true
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let result = client.get_fork("foo/bar").await;
    assert!(result.is_ok(), "get_fork failed: {result:?}");
}

#[tokio::test]
async fn test_every_request_carries_trace_headers() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;
    use wiremock::matchers::header_exists;

    let config = telemetry::TelemetryConfig::default();
    let (layer, guard) = telemetry::init_tracing(&config).expect("init_tracing");
    let subscriber = Registry::default().with(layer);
    let _default = tracing::subscriber::set_default(subscriber);

    let mock_server = MockServer::start().await;

    // GET path
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .and(header_exists("traceparent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "is_syncing": false,
                "is_optimistic": false,
                "el_offline": false,
                "head_slot": "1",
                "sync_distance": "0"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // POST empty path
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .and(header_exists("traceparent"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client_config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(client_config).unwrap();

    let span = tracing::info_span!("rf4_22_trace_test");
    let _enter = span.enter();

    client.get_node_syncing().await.expect("GET should succeed with traceparent");
    client.prepare_beacon_proposer(&[]).await.expect("POST empty should succeed with traceparent");

    drop(_enter);
    drop(_default);
    telemetry::shutdown_tracing(guard).await;
}

#[tokio::test]
async fn test_get_request_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(TestData { value: "success".to_string() }),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result: TestData = client.get("/eth/v1/test").await.unwrap();
    assert_eq!(result.value, "success");
}

#[tokio::test]
async fn test_post_request_success() {
    let mock_server = MockServer::start().await;

    let request_body = TestData { value: "request".to_string() };
    let response_body = TestData { value: "response".to_string() };

    Mock::given(method("POST"))
        .and(path("/eth/v1/test"))
        .and(body_json(&request_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result: TestData = client.post("/eth/v1/test", &request_body).await.unwrap();
    assert_eq!(result.value, "response");
}

#[tokio::test]
async fn test_client_error_no_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(3);
    let client = BeaconClient::new(config).unwrap();

    let result: Result<TestData, _> = client.get("/eth/v1/test").await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 404);
            assert_eq!(message, "Not Found");
        }
        _ => panic!("Expected ApiError with status 404"),
    }
}

#[tokio::test]
async fn test_server_error_triggers_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(4)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result: Result<TestData, _> = client.get("/eth/v1/test").await;

    match result {
        Err(BeaconError::ApiError { status, .. }) => {
            assert_eq!(status, 500);
        }
        _ => panic!("Expected ApiError with status 500"),
    }
}

#[tokio::test]
async fn test_retry_success_after_failures() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(2)
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(TestData { value: "recovered".to_string() }),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result: TestData = client.get("/eth/v1/test").await.unwrap();
    assert_eq!(result.value, "recovered");
}

#[tokio::test]
async fn test_parse_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result: Result<TestData, _> = client.get("/eth/v1/test").await;

    assert!(matches!(result, Err(BeaconError::ParseError(_))));
}

#[tokio::test]
async fn test_timeout_error_triggers_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .expect(4)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_millis(50))
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result: Result<TestData, _> = client.get("/eth/v1/test").await;

    assert!(matches!(result, Err(BeaconError::Timeout)));
}

// --- RF4-21: single retry engine characterization ---

/// Behavioral proxy that all request paths share one retry loop: each exhausts
/// the same attempt budget (1 + max_retries) against a persistent 503.
#[tokio::test]
async fn test_all_request_paths_share_one_retry_loop() {
    let mock_server = MockServer::start().await;
    let max_retries = 2u32;
    let expected_attempts = u64::from(max_retries) + 1; // 3

    // GET (execute_with_retry / JSON)
    Mock::given(method("GET"))
        .and(path("/eth/v1/rf4-21/get"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .expect(expected_attempts)
        .mount(&mock_server)
        .await;

    // POST with body (execute_with_retry / JSON)
    Mock::given(method("POST"))
        .and(path("/eth/v1/rf4-21/post"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .expect(expected_attempts)
        .mount(&mock_server)
        .await;

    // Empty POST (post_empty_with_headers)
    Mock::given(method("POST"))
        .and(path("/eth/v1/rf4-21/empty"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .expect(expected_attempts)
        .mount(&mock_server)
        .await;

    // Attestation submit
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .expect(expected_attempts)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(max_retries)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let get_err: Result<TestData, _> = client.get("/eth/v1/rf4-21/get").await;
    assert!(
        matches!(get_err, Err(BeaconError::ApiError { status: 503, .. })),
        "GET path: {get_err:?}"
    );

    let body = TestData { value: "x".to_string() };
    let post_err: Result<TestData, _> = client.post("/eth/v1/rf4-21/post", &body).await;
    assert!(
        matches!(post_err, Err(BeaconError::ApiError { status: 503, .. })),
        "POST path: {post_err:?}"
    );

    let empty_err = client.post_empty("/eth/v1/rf4-21/empty", &body).await;
    assert!(
        matches!(empty_err, Err(BeaconError::ApiError { status: 503, .. })),
        "empty POST path: {empty_err:?}"
    );

    let versioned = VersionedAttestation::Electra(vec![]);
    let att_err = client.submit_attestation(&versioned).await;
    assert!(
        matches!(att_err, Err(BeaconError::ApiError { status: 503, .. })),
        "attestation path: {att_err:?}"
    );

    // wiremock enforces expect() counts on drop; reaching here means every path
    // issued exactly expected_attempts requests.
}

/// 400 partial-failure body is parsed per-index and is never retried.
#[tokio::test]
async fn test_400_partial_failure_still_parsed_per_index_and_not_retried() {
    let mock_server = MockServer::start().await;

    let error_response = serde_json::json!({
        "code": 400,
        "message": "Some attestations failed validation",
        "failures": [
            { "index": 0, "message": "Invalid signature" },
            { "index": 2, "message": "Unknown validator" }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(400).set_body_json(&error_response))
        .expect(1) // must not retry
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(3);
    let client = BeaconClient::new(config).unwrap();

    let versioned = VersionedAttestation::Electra(vec![]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(!result.is_success());
    assert_eq!(result.failures().len(), 2);
    assert_eq!(result.failures()[0].index, 0);
    assert_eq!(result.failures()[1].index, 2);
}

/// `max_body_bytes` is enforced on the JSON GET and POST paths that share the engine.
#[tokio::test]
async fn test_max_body_bytes_enforced_on_every_path() {
    let mock_server = MockServer::start().await;
    let cap = 64usize;
    let oversized = "x".repeat(cap + 1);

    Mock::given(method("GET"))
        .and(path("/eth/v1/rf4-21/body-cap-get"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(format!(r#"{{"value":"{oversized}"}}"#)),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/rf4-21/body-cap-post"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(format!(r#"{{"value":"{oversized}"}}"#)),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config =
        BeaconClientConfig::new(mock_server.uri()).with_max_retries(0).with_max_body_bytes(cap);
    let client = BeaconClient::new(config).unwrap();

    let get_result: Result<TestData, _> = client.get("/eth/v1/rf4-21/body-cap-get").await;
    assert!(
        matches!(get_result, Err(BeaconError::BodyTooLarge { expected, .. }) if expected == cap),
        "GET body cap: {get_result:?}"
    );

    let body = TestData { value: "req".to_string() };
    let post_result: Result<TestData, _> = client.post("/eth/v1/rf4-21/body-cap-post", &body).await;
    assert!(
        matches!(post_result, Err(BeaconError::BodyTooLarge { expected, .. }) if expected == cap),
        "POST body cap: {post_result:?}"
    );
}

#[tokio::test]
async fn test_get_attester_duties_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "execution_optimistic": false,
        "data": [
            {
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "25",
                "slot": "10000"
            },
            {
                "pubkey": "0xa1234f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b",
                "validator_index": "5678",
                "committee_index": "2",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "50",
                "slot": "10001"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/100"))
        .and(body_json(["1234", "5678"]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let validator_indices = vec!["1234".to_string(), "5678".to_string()];
    let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

    assert_eq!(
        result.dependent_root,
        "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
    );
    assert!(!result.execution_optimistic);
    assert_eq!(result.data.len(), 2);
    assert_eq!(result.data[0].validator_index, "1234");
    assert_eq!(result.data[0].slot, "10000");
    assert_eq!(result.data[1].validator_index, "5678");
    assert_eq!(result.data[1].slot, "10001");
}

#[tokio::test]
async fn test_get_attester_duties_empty_indices() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "execution_optimistic": false,
        "data": []
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/100"))
        .and(body_json::<Vec<String>>(vec![]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let validator_indices: Vec<String> = vec![];
    let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

    assert_eq!(
        result.dependent_root,
        "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
    );
    assert!(result.data.is_empty());
}

#[tokio::test]
async fn test_get_attester_duties_with_execution_optimistic() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "execution_optimistic": true,
        "data": [
            {
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "25",
                "slot": "10000"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let validator_indices = vec!["1234".to_string()];
    let result = client.get_attester_duties(200, &validator_indices).await.unwrap();

    assert!(result.execution_optimistic);
}

#[tokio::test]
async fn test_get_attester_duties_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/999"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let validator_indices = vec!["1234".to_string()];
    let result = client.get_attester_duties(999, &validator_indices).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid epoch");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_get_attester_duties_server_error_with_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/100"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(2)
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    let response_body = serde_json::json!({
        "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "execution_optimistic": false,
        "data": []
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let validator_indices: Vec<String> = vec![];
    let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

    assert_eq!(
        result.dependent_root,
        "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
    );
}

#[tokio::test]
async fn test_get_attester_duties_dependent_root_changes() {
    let mock_server = MockServer::start().await;

    let response_body_1 = serde_json::json!({
        "dependent_root": "0xroot_a_1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "execution_optimistic": false,
        "data": [{
            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
            "validator_index": "1234",
            "committee_index": "1",
            "committee_length": "128",
            "committees_at_slot": "64",
            "validator_committee_index": "25",
            "slot": "10000"
        }]
    });

    let response_body_2 = serde_json::json!({
        "dependent_root": "0xroot_b_1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "execution_optimistic": false,
        "data": [{
            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
            "validator_index": "1234",
            "committee_index": "2",
            "committee_length": "128",
            "committees_at_slot": "64",
            "validator_committee_index": "30",
            "slot": "10001"
        }]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body_1))
        .expect(1)
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body_2))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let validator_indices = vec!["1234".to_string()];

    let result_1 = client.get_attester_duties(100, &validator_indices).await.unwrap();
    let result_2 = client.get_attester_duties(100, &validator_indices).await.unwrap();

    assert_ne!(result_1.dependent_root, result_2.dependent_root);
    assert_eq!(
        result_1.dependent_root,
        "0xroot_a_1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
    assert_eq!(
        result_2.dependent_root,
        "0xroot_b_1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
}

#[tokio::test]
async fn test_get_attestation_data_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "slot": "1000",
            "index": "1",
            "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "source": {
                "epoch": "100",
                "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
            },
            "target": {
                "epoch": "101",
                "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(wiremock::matchers::query_param("slot", "1000"))
        .and(wiremock::matchers::query_param("committee_index", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_attestation_data(1000, 1).await.unwrap();

    assert_eq!(result.data.slot, "1000");
    assert_eq!(result.data.index, "1");
    assert_eq!(
        result.data.beacon_block_root,
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
    assert_eq!(result.data.source.epoch, "100");
    assert_eq!(result.data.target.epoch, "101");
}

#[tokio::test]
async fn test_get_attestation_data_different_committee_index() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "slot": "2000",
            "index": "5",
            "beacon_block_root": "0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
            "source": {
                "epoch": "200",
                "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
            },
            "target": {
                "epoch": "201",
                "root": "0x4444444444444444444444444444444444444444444444444444444444444444"
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(wiremock::matchers::query_param("slot", "2000"))
        .and(wiremock::matchers::query_param("committee_index", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_attestation_data(2000, 5).await.unwrap();

    assert_eq!(result.data.slot, "2000");
    assert_eq!(result.data.index, "5");
}

#[tokio::test]
async fn test_get_attestation_data_slot_too_early() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Slot requested is in the future"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_attestation_data(999999999, 0).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert!(message.contains("future"));
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_get_attestation_data_slot_in_past() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Slot is in the past"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_attestation_data(1, 0).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert!(message.contains("past"));
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_get_attestation_data_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string("Attestation data not available for requested slot"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_attestation_data(500, 0).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 404);
            assert!(message.contains("not available"));
        }
        _ => panic!("Expected ApiError with status 404"),
    }
}

#[tokio::test]
async fn test_get_attestation_data_server_error_with_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(2)
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    let response_body = serde_json::json!({
        "data": {
            "slot": "1000",
            "index": "0",
            "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "source": {
                "epoch": "100",
                "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
            },
            "target": {
                "epoch": "101",
                "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_attestation_data(1000, 0).await.unwrap();

    assert_eq!(result.data.slot, "1000");
}

#[tokio::test]
async fn test_get_attestation_data_beacon_syncing() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Beacon node is syncing"))
        .expect(4)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_attestation_data(1000, 0).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 503);
            assert!(message.contains("syncing"));
        }
        _ => panic!("Expected ApiError with status 503"),
    }
}

#[tokio::test]
async fn test_submit_attestation_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let attestation = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            source: Checkpoint {
                epoch: "100".to_string(),
                root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            },
            target: Checkpoint {
                epoch: "101".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
        },
        committee_index: 0,
        signature: "0xsignature".to_string(),
    };

    let versioned = VersionedAttestation::Electra(vec![attestation]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(result.is_success());
}

#[tokio::test]
async fn test_submit_attestation_invalid_attestation() {
    let mock_server = MockServer::start().await;

    let error_response = serde_json::json!({
        "code": 400,
        "message": "Invalid attestation",
        "failures": [
            {
                "index": 0,
                "message": "Invalid signature"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(400).set_body_json(&error_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let attestation = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xabcdef".to_string(),
            source: Checkpoint { epoch: "100".to_string(), root: "0x1111".to_string() },
            target: Checkpoint { epoch: "101".to_string(), root: "0x2222".to_string() },
        },
        committee_index: 0,
        signature: "0xinvalid".to_string(),
    };

    let versioned = VersionedAttestation::Electra(vec![attestation]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(!result.is_success());
    assert_eq!(result.failures().len(), 1);
    assert_eq!(result.failures()[0].index, 0);
    assert!(result.failures()[0].message.contains("Invalid signature"));
}

#[tokio::test]
async fn test_submit_attestation_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(4)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let attestation = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xabcdef".to_string(),
            source: Checkpoint { epoch: "100".to_string(), root: "0x1111".to_string() },
            target: Checkpoint { epoch: "101".to_string(), root: "0x2222".to_string() },
        },
        committee_index: 0,
        signature: "0xsignature".to_string(),
    };

    let versioned = VersionedAttestation::Electra(vec![attestation]);
    let result = client.submit_attestation(&versioned).await;

    match result {
        Err(BeaconError::ApiError { status, .. }) => {
            assert_eq!(status, 500);
        }
        _ => panic!("Expected ApiError with status 500"),
    }
}

#[tokio::test]
async fn test_submit_attestation_multiple_attestations() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let attestation1 = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xabcdef".to_string(),
            source: Checkpoint { epoch: "100".to_string(), root: "0x1111".to_string() },
            target: Checkpoint { epoch: "101".to_string(), root: "0x2222".to_string() },
        },
        committee_index: 0,
        signature: "0xsignature1".to_string(),
    };

    let attestation2 = SingleAttestation {
        attester_index: 1,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "2".to_string(),
            beacon_block_root: "0xabcdef".to_string(),
            source: Checkpoint { epoch: "100".to_string(), root: "0x1111".to_string() },
            target: Checkpoint { epoch: "101".to_string(), root: "0x2222".to_string() },
        },
        committee_index: 0,
        signature: "0xsignature2".to_string(),
    };

    let versioned = VersionedAttestation::Electra(vec![attestation1, attestation2]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(result.is_success());
}

#[tokio::test]
async fn test_submit_attestation_partial_failure() {
    let mock_server = MockServer::start().await;

    let error_response = serde_json::json!({
        "code": 400,
        "message": "Some attestations failed validation",
        "failures": [
            {
                "index": 1,
                "message": "Invalid signature"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(400).set_body_json(&error_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let attestation1 = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xabcdef".to_string(),
            source: Checkpoint { epoch: "100".to_string(), root: "0x1111".to_string() },
            target: Checkpoint { epoch: "101".to_string(), root: "0x2222".to_string() },
        },
        committee_index: 0,
        signature: "0xvalid".to_string(),
    };

    let attestation2 = SingleAttestation {
        attester_index: 1,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "2".to_string(),
            beacon_block_root: "0xabcdef".to_string(),
            source: Checkpoint { epoch: "100".to_string(), root: "0x1111".to_string() },
            target: Checkpoint { epoch: "101".to_string(), root: "0x2222".to_string() },
        },
        committee_index: 0,
        signature: "0xinvalid".to_string(),
    };

    let versioned = VersionedAttestation::Electra(vec![attestation1, attestation2]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(!result.is_success());
    assert_eq!(result.failures().len(), 1);
    assert_eq!(result.failures()[0].index, 1);
}

#[tokio::test]
async fn test_submit_attestation_400_with_empty_failures() {
    let mock_server = MockServer::start().await;

    let error_response = serde_json::json!({
        "code": 400,
        "message": "Bad request",
        "failures": []
    });

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(400).set_body_json(&error_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let attestation = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xabcdef".to_string(),
            source: Checkpoint { epoch: "100".to_string(), root: "0x1111".to_string() },
            target: Checkpoint { epoch: "101".to_string(), root: "0x2222".to_string() },
        },
        committee_index: 0,
        signature: "0xsignature".to_string(),
    };

    let versioned = VersionedAttestation::Electra(vec![attestation]);
    let result = client.submit_attestation(&versioned).await;
    match result {
        Err(BeaconError::ApiError { status, .. }) => {
            assert_eq!(status, 400);
        }
        _ => panic!("Expected ApiError for 400 with empty failures"),
    }
}

#[tokio::test]
async fn test_submit_attestation_empty_array() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let versioned = VersionedAttestation::Electra(vec![]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(result.is_success());
}

#[tokio::test]
async fn test_get_config_spec_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "GENESIS_FORK_VERSION": "0x00000000",
            "ALTAIR_FORK_EPOCH": "74240",
            "ALTAIR_FORK_VERSION": "0x01000000",
            "BELLATRIX_FORK_EPOCH": "144896",
            "BELLATRIX_FORK_VERSION": "0x02000000",
            "CAPELLA_FORK_EPOCH": "194048",
            "CAPELLA_FORK_VERSION": "0x03000000",
            "DENEB_FORK_EPOCH": "269568",
            "DENEB_FORK_VERSION": "0x04000000",
            "SECONDS_PER_SLOT": "12",
            "SLOTS_PER_EPOCH": "32"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_config_spec().await.unwrap();
    assert_eq!(result.data.get("GENESIS_FORK_VERSION").unwrap(), &json!("0x00000000"));
    assert_eq!(result.data.get("ALTAIR_FORK_EPOCH").unwrap(), &json!("74240"));
    assert_eq!(result.data.get("BELLATRIX_FORK_EPOCH").unwrap(), &json!("144896"));
    assert_eq!(result.data.get("CAPELLA_FORK_EPOCH").unwrap(), &json!("194048"));
    assert_eq!(result.data.get("DENEB_FORK_EPOCH").unwrap(), &json!("269568"));
    assert_eq!(result.data.get("SECONDS_PER_SLOT").unwrap(), &json!("12"));
    assert_eq!(result.data.get("SLOTS_PER_EPOCH").unwrap(), &json!("32"));
    assert_eq!(result.data.len(), 11);
}

fn slot_clock_from_spec_data(
    data: &std::collections::HashMap<String, serde_json::Value>,
) -> SystemSlotClock {
    let slot_duration_ms = parse_slot_duration_ms(data).unwrap();
    SystemSlotClock::new(1_606_824_023, Duration::from_millis(slot_duration_ms), 32).unwrap()
}

#[tokio::test]
async fn test_get_config_spec_slot_duration_master_keyset() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "GENESIS_FORK_VERSION": "0x00000000",
            "ALTAIR_FORK_EPOCH": "74240",
            "ALTAIR_FORK_VERSION": "0x01000000",
            "BELLATRIX_FORK_EPOCH": "144896",
            "BELLATRIX_FORK_VERSION": "0x02000000",
            "CAPELLA_FORK_EPOCH": "194048",
            "CAPELLA_FORK_VERSION": "0x03000000",
            "DENEB_FORK_EPOCH": "269568",
            "DENEB_FORK_VERSION": "0x04000000",
            "SLOT_DURATION_MS": "12000",
            "SLOTS_PER_EPOCH": "32"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let spec = client.get_config_spec().await.unwrap();
    assert!(!spec.data.contains_key("SECONDS_PER_SLOT"));
    assert!(!spec.data.contains_key("INTERVALS_PER_SLOT"));
    let clock = slot_clock_from_spec_data(&spec.data);
    assert_eq!(clock.slot_duration(), Duration::from_secs(12));
}

#[tokio::test]
async fn test_get_config_spec_slot_duration_legacy_keyset() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "GENESIS_FORK_VERSION": "0x00000000",
            "ALTAIR_FORK_EPOCH": "74240",
            "ALTAIR_FORK_VERSION": "0x01000000",
            "BELLATRIX_FORK_EPOCH": "144896",
            "BELLATRIX_FORK_VERSION": "0x02000000",
            "CAPELLA_FORK_EPOCH": "194048",
            "CAPELLA_FORK_VERSION": "0x03000000",
            "DENEB_FORK_EPOCH": "269568",
            "DENEB_FORK_VERSION": "0x04000000",
            "SECONDS_PER_SLOT": "12",
            "INTERVALS_PER_SLOT": "3",
            "SLOTS_PER_EPOCH": "32"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let spec = client.get_config_spec().await.unwrap();
    assert!(!spec.data.contains_key("SLOT_DURATION_MS"));
    let clock = slot_clock_from_spec_data(&spec.data);
    assert_eq!(clock.slot_duration(), Duration::from_secs(12));
}

#[tokio::test]
async fn test_get_config_spec_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(4)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_config_spec().await;
    match result {
        Err(BeaconError::ApiError { status, .. }) => {
            assert_eq!(status, 500);
        }
        _ => panic!("Expected ApiError with status 500"),
    }
}

#[tokio::test]
async fn test_get_genesis_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "genesis_time": "1606824023",
            "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            "genesis_fork_version": "0x00000000"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_genesis().await.unwrap();
    assert_eq!(result.data.genesis_time, "1606824023");
    assert_eq!(
        result.data.genesis_validators_root,
        "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
    );
    assert_eq!(result.data.genesis_fork_version, "0x00000000");
}

#[tokio::test]
async fn test_get_genesis_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(
            ResponseTemplate::new(404).set_body_string("Chain genesis has not yet occurred"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_genesis().await;
    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 404);
            assert!(message.contains("genesis"));
        }
        _ => panic!("Expected ApiError with status 404"),
    }
}

#[tokio::test]
async fn test_get_genesis_server_error_with_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(2)
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    let response_body = serde_json::json!({
        "data": {
            "genesis_time": "1606824023",
            "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            "genesis_fork_version": "0x00000000"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_genesis().await.unwrap();
    assert_eq!(result.data.genesis_time, "1606824023");
}

#[tokio::test]
async fn test_get_fork_head_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "execution_optimistic": false,
        "finalized": false,
        "data": {
            "previous_version": "0x03000000",
            "current_version": "0x04000000",
            "epoch": "269568"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/fork"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_fork("head").await.unwrap();
    assert!(!result.execution_optimistic);
    assert!(!result.finalized);
    assert_eq!(result.data.previous_version, "0x03000000");
    assert_eq!(result.data.current_version, "0x04000000");
    assert_eq!(result.data.epoch, "269568");
}

#[tokio::test]
async fn test_get_fork_finalized_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "execution_optimistic": false,
        "finalized": true,
        "data": {
            "previous_version": "0x03000000",
            "current_version": "0x04000000",
            "epoch": "269568"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/finalized/fork"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_fork("finalized").await.unwrap();
    assert!(!result.execution_optimistic);
    assert!(result.finalized);
    assert_eq!(result.data.current_version, "0x04000000");
}

#[tokio::test]
async fn test_get_fork_by_slot() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "execution_optimistic": false,
        "finalized": true,
        "data": {
            "previous_version": "0x00000000",
            "current_version": "0x01000000",
            "epoch": "74240"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/2375680/fork"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_fork("2375680").await.unwrap();
    assert_eq!(result.data.previous_version, "0x00000000");
    assert_eq!(result.data.current_version, "0x01000000");
    assert_eq!(result.data.epoch, "74240");
}

#[tokio::test]
async fn test_get_fork_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/99999999999/fork"))
        .respond_with(ResponseTemplate::new(404).set_body_string("State not found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_fork("99999999999").await;
    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 404);
            assert!(message.contains("not found"));
        }
        _ => panic!("Expected ApiError with status 404"),
    }
}

#[tokio::test]
async fn test_get_fork_execution_optimistic() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "execution_optimistic": true,
        "finalized": false,
        "data": {
            "previous_version": "0x04000000",
            "current_version": "0x05000000",
            "epoch": "364544"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/fork"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_fork("head").await.unwrap();
    assert!(result.execution_optimistic);
    assert!(!result.finalized);
    assert_eq!(result.data.current_version, "0x05000000");
    assert_eq!(result.data.epoch, "364544");
}

#[tokio::test]
async fn test_get_fork_schedule_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "GENESIS_FORK_VERSION": "0x00000000",
            "ALTAIR_FORK_EPOCH": "74240",
            "ALTAIR_FORK_VERSION": "0x01000000",
            "BELLATRIX_FORK_EPOCH": "144896",
            "BELLATRIX_FORK_VERSION": "0x02000000",
            "CAPELLA_FORK_EPOCH": "194048",
            "CAPELLA_FORK_VERSION": "0x03000000",
            "DENEB_FORK_EPOCH": "269568",
            "DENEB_FORK_VERSION": "0x04000000",
            "ELECTRA_FORK_EPOCH": "364544",
            "ELECTRA_FORK_VERSION": "0x05000000",
            "FULU_FORK_EPOCH": "18446744073709551615",
            "FULU_FORK_VERSION": "0x06000000",
            "GLOAS_FORK_EPOCH": "18446744073709551615",
            "GLOAS_FORK_VERSION": "0x07000000",
            "SECONDS_PER_SLOT": "12",
            "SLOTS_PER_EPOCH": "32"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let schedule = client.get_fork_schedule().await.unwrap();
    assert_eq!(schedule.genesis_fork_version, [0, 0, 0, 0]);
    assert_eq!(schedule.altair_fork_epoch, 74240);
    assert_eq!(schedule.altair_fork_version, [1, 0, 0, 0]);
    assert_eq!(schedule.bellatrix_fork_epoch, 144896);
    assert_eq!(schedule.capella_fork_epoch, 194048);
    assert_eq!(schedule.deneb_fork_epoch, 269568);
    assert_eq!(schedule.deneb_fork_version, [4, 0, 0, 0]);
    assert_eq!(schedule.electra_fork_epoch, 364544);
    assert_eq!(schedule.electra_fork_version, [5, 0, 0, 0]);
    assert_eq!(schedule.fulu_fork_epoch, u64::MAX);
    assert_eq!(schedule.fulu_fork_version, [6, 0, 0, 0]);
    assert_eq!(schedule.gloas_fork_epoch, u64::MAX);
    assert_eq!(schedule.gloas_fork_version, [7, 0, 0, 0]);
}

#[tokio::test]
async fn test_get_fork_schedule_missing_field() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": {
            "GENESIS_FORK_VERSION": "0x00000000",
            "ALTAIR_FORK_EPOCH": "74240",
            "ALTAIR_FORK_VERSION": "0x01000000"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_fork_schedule().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_proposer_duties_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "execution_optimistic": false,
        "data": [
            {
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "slot": "320000"
            },
            {
                "pubkey": "0xa1234f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b",
                "validator_index": "5678",
                "slot": "320001"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/10000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result =
        client.get_proposer_duties(10000, &ForkSchedule::unscheduled_gloas()).await.unwrap();

    assert_eq!(
        result.dependent_root,
        "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
    );
    assert!(!result.execution_optimistic);
    assert_eq!(result.data.len(), 2);
    assert_eq!(result.data[0].validator_index, "1234");
    assert_eq!(result.data[0].slot, "320000");
    assert_eq!(result.data[1].validator_index, "5678");
    assert_eq!(result.data[1].slot, "320001");
}

#[tokio::test]
async fn test_get_proposer_duties_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/999"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_proposer_duties(999, &ForkSchedule::unscheduled_gloas()).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid epoch");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_produce_block_v3_full_block() {
    let mock_server = MockServer::start().await;

    let block_data = serde_json::json!({
        "slot": "100",
        "proposer_index": "42",
        "parent_root": format!("0x{}", "01".repeat(32)),
        "state_root": format!("0x{}", "02".repeat(32)),
        "body": "0xdead"
    });
    let envelope = serde_json::json!({
        "version": "deneb",
        "execution_optimistic": false,
        "data": block_data
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/100"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&envelope)
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Value", "12345"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(100, "0xrandao", None, None).await.unwrap();

    assert!(!result.is_blinded);
    assert_eq!(result.consensus_version, "deneb");
    assert_eq!(result.execution_payload_value, Some("12345".to_string()));
    assert!(!result.is_ssz);
    assert!(result.ssz_bytes.is_none());
    assert!(!result.payload_included);
    assert!(result.builder_url.is_none());
    assert!(result.consensus_block_value.is_none());

    let block = result.parse_full_block().unwrap();
    assert_eq!(block.block().slot, 100);
    assert_eq!(block.block().proposer_index, 42);
}

#[tokio::test]
async fn test_produce_block_missing_consensus_version_is_rejected() {
    let mock_server = MockServer::start().await;

    let envelope = serde_json::json!({
        "version": "deneb",
        "execution_optimistic": false,
        "data": {
            "slot": "100",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/100"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&envelope)
                .insert_header("Eth-Execution-Payload-Blinded", "false"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(100, "0xrandao", None, None).await;
    match result {
        Err(BeaconError::ParseError(msg)) => {
            assert!(msg.contains("Eth-Consensus-Version"), "{msg}");
        }
        Ok(resp) => panic!(
            "missing Eth-Consensus-Version must be Err, got version {:?}",
            resp.consensus_version
        ),
        other => panic!("expected ParseError, got {other:?}"),
    }
}

#[tokio::test]
async fn test_produce_block_unknown_consensus_version_is_rejected() {
    let mock_server = MockServer::start().await;

    let envelope = serde_json::json!({
        "version": "gloas2",
        "execution_optimistic": false,
        "data": {
            "slot": "100",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/100"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&envelope)
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "gloas2"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(100, "0xrandao", None, None).await;
    match result {
        Err(BeaconError::ParseError(msg)) => {
            assert!(msg.contains("gloas2"), "error should name the value: {msg}");
        }
        Ok(resp) => panic!(
            "unknown Eth-Consensus-Version must be Err, got version {:?}",
            resp.consensus_version
        ),
        other => panic!("expected ParseError, got {other:?}"),
    }
}

/// `produce_block_v3` — the proposer-duty block-production BN call — must run its work
/// inside a `beacon.produce_block_v3` span carrying the canonical `slot` field, at `debug`
/// level, matching its sibling `beacon.*` hot-path spans. Proves the span fires (correct
/// name + level) and that `slot` lands; `skip_all` keeps `randao_reveal` out of the span.
#[tokio::test]
async fn produce_block_v3_emits_debug_span_with_slot() {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::span::Attributes;
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    // (span name, span level, captured field keys) for one created span.
    type SpanRecord = (String, tracing::Level, Vec<String>);

    #[derive(Clone, Default)]
    struct Cap {
        spans: Arc<Mutex<Vec<SpanRecord>>>,
    }
    struct V<'a>(&'a mut Vec<String>);
    impl Visit for V<'_> {
        fn record_debug(&mut self, f: &Field, _v: &dyn std::fmt::Debug) {
            self.0.push(f.name().to_string());
        }
    }
    impl<S> Layer<S> for Cap
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, _id: &tracing::Id, _ctx: Context<'_, S>) {
            let meta = attrs.metadata();
            let mut keys = Vec::new();
            attrs.record(&mut V(&mut keys));
            if let Ok(mut spans) = self.spans.lock() {
                spans.push((meta.name().to_string(), *meta.level(), keys));
            }
        }
    }

    let mock_server = MockServer::start().await;
    let envelope = serde_json::json!({
        "version": "deneb",
        "execution_optimistic": false,
        "data": {
            "slot": "777",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        }
    });
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/777"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&envelope)
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let cap = Cap::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    // `set_default` sets the thread-local dispatcher and returns a drop-guard, so it works
    // inside this async test (unlike `with_default`, whose closure cannot `.await`).
    let _guard = tracing::subscriber::set_default(subscriber);
    let _ = client.produce_block_v3(777, "0xrandao", None, None).await;
    drop(_guard);

    let spans = cap.spans.lock().unwrap();
    let span = spans
        .iter()
        .find(|(name, ..)| name == "beacon.produce_block_v3")
        .expect("beacon.produce_block_v3 span must be created");
    assert_eq!(span.1, tracing::Level::DEBUG, "span must be at DEBUG level");
    assert!(span.2.iter().any(|k| k == "slot"), "span must carry canonical `slot`: {:?}", span.2);
}

#[tokio::test]
async fn test_produce_block_v3_blinded_block() {
    let mock_server = MockServer::start().await;

    let block_data = serde_json::json!({
        "slot": "200",
        "proposer_index": "10",
        "parent_root": format!("0x{}", "03".repeat(32)),
        "state_root": format!("0x{}", "04".repeat(32)),
        "body": "0xbeef"
    });
    let envelope = serde_json::json!({
        "version": "deneb",
        "execution_optimistic": false,
        "data": block_data
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/200"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&envelope)
                .insert_header("Eth-Execution-Payload-Blinded", "true")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(200, "0xrandao", None, None).await.unwrap();

    assert!(result.is_blinded);
    assert_eq!(result.consensus_version, "deneb");
    assert_eq!(result.execution_payload_value, None);
    assert!(!result.is_ssz);
    assert!(result.ssz_bytes.is_none());

    let block = result.parse_blinded_block().unwrap();
    assert_eq!(block.slot, 200);
    assert_eq!(block.proposer_index, 10);
}

#[tokio::test]
async fn test_produce_block_v3_with_graffiti_and_boost() {
    let mock_server = MockServer::start().await;

    let block_body = serde_json::json!({
        "version": "deneb",
        "data": {}
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/300"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .and(wiremock::matchers::query_param("graffiti", "0xgraf"))
        .and(wiremock::matchers::query_param("builder_boost_factor", "50"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&block_body)
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(300, "0xrandao", Some("0xgraf"), Some(50)).await.unwrap();

    assert!(!result.is_blinded);
    assert_eq!(result.consensus_version, "deneb");
}

#[tokio::test]
async fn test_produce_block_v3_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/999"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Slot in the past"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(999, "0xrandao", None, None).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert!(message.contains("past"));
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_produce_block_v3_ssz_response() {
    let mock_server = MockServer::start().await;

    let ssz_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/500"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Value", "99999"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(500, "0xrandao", None, None).await.unwrap();

    assert!(result.is_ssz);
    assert_eq!(result.ssz_bytes, Some(ssz_payload));
    assert_eq!(result.data, serde_json::Value::Null);
    assert!(!result.is_blinded);
    assert_eq!(result.consensus_version, "deneb");
    assert_eq!(result.execution_payload_value, Some("99999".to_string()));
}

#[tokio::test]
async fn test_produce_block_v3_ssz_blinded_response() {
    let mock_server = MockServer::start().await;

    let ssz_payload = vec![0xaa; 256];

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/600"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "true")
                .insert_header("Eth-Consensus-Version", "electra"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(600, "0xrandao", None, None).await.unwrap();

    assert!(result.is_ssz);
    assert_eq!(result.ssz_bytes.as_ref().unwrap().len(), 256);
    assert!(result.is_blinded);
    assert_eq!(result.consensus_version, "electra");
    assert_eq!(result.execution_payload_value, None);
}

#[tokio::test]
async fn test_produce_block_v3_sends_accept_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/700"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"version": "deneb", "data": {}}))
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let _ = client.produce_block_v3(700, "0xrandao", None, None).await.unwrap();

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let accept = requests[0].headers.get("accept").expect("Accept header must be present");
    let accept_str = accept.to_str().unwrap();
    // SSZ preference is disabled until downstream deserialization is implemented.
    // Accept header currently requests JSON only.
    assert!(
        accept_str.contains("application/json"),
        "Accept header must include JSON: {}",
        accept_str
    );
}

#[tokio::test]
async fn test_produce_block_v3_json_fallback_with_charset() {
    let mock_server = MockServer::start().await;

    let block_data = serde_json::json!({
        "slot": "100",
        "proposer_index": "42",
        "parent_root": format!("0x{}", "01".repeat(32)),
        "state_root": format!("0x{}", "02".repeat(32)),
        "body": "0xdead"
    });
    let envelope = serde_json::json!({
        "version": "deneb",
        "data": block_data
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/800"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&envelope)
                .insert_header("Content-Type", "application/json; charset=utf-8")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(800, "0xrandao", None, None).await.unwrap();

    assert!(!result.is_ssz);
    assert!(result.ssz_bytes.is_none());
    let block = result.parse_full_block().unwrap();
    assert_eq!(block.block().slot, 100);
}

/// Stateful responder: returns `first` on call 0, `second` on all subsequent calls.
struct SszThenJsonResponder {
    call_count: AtomicUsize,
    first: ResponseTemplate,
    second: ResponseTemplate,
}

impl wiremock::Respond for SszThenJsonResponder {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        let n = self.call_count.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            self.first.clone()
        } else {
            self.second.clone()
        }
    }
}

#[tokio::test]
async fn test_produce_block_v3_ssz_empty_body_falls_back_to_json() {
    let mock_server = MockServer::start().await;

    let block_data = serde_json::json!({
        "slot": "900",
        "proposer_index": "42",
        "parent_root": format!("0x{}", "01".repeat(32)),
        "state_root": format!("0x{}", "02".repeat(32)),
        "body": "0xdead"
    });
    let json_envelope = serde_json::json!({ "version": "deneb", "data": block_data });

    let responder = SszThenJsonResponder {
        call_count: AtomicUsize::new(0),
        first: ResponseTemplate::new(200)
            .set_body_raw(vec![], "application/octet-stream")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Consensus-Version", "deneb"),
        second: ResponseTemplate::new(200)
            .set_body_json(&json_envelope)
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Consensus-Version", "deneb"),
    };

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/900"))
        .respond_with(responder)
        .expect(2)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(900, "0xrandao", None, None).await.unwrap();

    // Should have fallen back to JSON
    assert!(!result.is_ssz);
    assert!(result.ssz_bytes.is_none());
    assert_eq!(result.consensus_version, "deneb");
    let block = result.parse_full_block().unwrap();
    assert_eq!(block.block().slot, 900);
}

#[tokio::test]
async fn test_produce_block_v3_ssz_fallback_json_gets_correct_headers() {
    let mock_server = MockServer::start().await;

    let block_data = serde_json::json!({
        "slot": "950",
        "proposer_index": "55",
        "parent_root": format!("0x{}", "03".repeat(32)),
        "state_root": format!("0x{}", "04".repeat(32)),
        "body": "0xbeef"
    });
    let json_envelope = serde_json::json!({ "version": "electra", "data": block_data });

    let responder = SszThenJsonResponder {
        call_count: AtomicUsize::new(0),
        first: ResponseTemplate::new(200)
            .set_body_raw(vec![], "application/octet-stream")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Consensus-Version", "deneb"),
        second: ResponseTemplate::new(200)
            .set_body_json(&json_envelope)
            .insert_header("Eth-Execution-Payload-Blinded", "true")
            .insert_header("Eth-Consensus-Version", "electra")
            .insert_header("Eth-Execution-Payload-Value", "77777"),
    };

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/950"))
        .respond_with(responder)
        .expect(2)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(950, "0xrandao", None, None).await.unwrap();

    // Headers come from the JSON fallback response, not the original SSZ response
    assert!(!result.is_ssz);
    assert!(result.is_blinded);
    assert_eq!(result.consensus_version, "electra");
    assert_eq!(result.execution_payload_value, Some("77777".to_string()));
}

#[tokio::test]
async fn test_produce_block_v3_valid_ssz_no_fallback() {
    let mock_server = MockServer::start().await;

    let ssz_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/960"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        // Must be called exactly once — no fallback attempt
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(960, "0xrandao", None, None).await.unwrap();

    assert!(result.is_ssz);
    assert_eq!(result.ssz_bytes, Some(ssz_payload));
}

#[tokio::test]
async fn test_produce_block_v3_ssz_fallback_network_error_propagated() {
    let mock_server = MockServer::start().await;

    // Both calls return SSZ empty body — fallback also gets SSZ, which fails JSON parse
    let responder = SszThenJsonResponder {
        call_count: AtomicUsize::new(0),
        first: ResponseTemplate::new(200)
            .set_body_raw(vec![], "application/octet-stream")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Consensus-Version", "deneb"),
        second: ResponseTemplate::new(500),
    };

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/970"))
        .respond_with(responder)
        .expect(2)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(970, "0xrandao", None, None).await;
    // The JSON fallback request gets a 500 server error, which propagates
    assert!(result.is_err());
}

/// Query names declared in `v4_wire.rs`. Allowlist only — do not assert a param count.
const V4_DECLARED_QUERY_NAMES: &[&str] =
    &[QUERY_RANDAO_REVEAL, QUERY_GRAFFITI, QUERY_SKIP_RANDAO_VERIFICATION, QUERY_INCLUDE_PAYLOAD];

fn v4_blocks_path(slot: u64) -> String {
    format!("{PRODUCE_BLOCK_V4_PATH_PREFIX}/{slot}")
}

fn v4_json_envelope(slot: u64) -> serde_json::Value {
    json!({
        "version": "gloas",
        "execution_optimistic": false,
        "data": {
            "slot": slot.to_string(),
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        }
    })
}

fn v4_json_success(slot: u64) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(v4_json_envelope(slot))
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Consensus-Version", "gloas")
        .insert_header("Eth-Execution-Payload-Value", "12345")
        .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true")
}

fn assert_v4_query_names(req: &wiremock::Request) {
    let mut saw_include_payload = false;
    for (name, value) in req.url.query_pairs() {
        assert!(
            V4_DECLARED_QUERY_NAMES.contains(&name.as_ref()),
            "query name {name:?} is not declared in v4_wire.rs"
        );
        if name.as_ref() == QUERY_INCLUDE_PAYLOAD {
            assert_eq!(value.as_ref(), "true", "include_payload must be true on every request");
            saw_include_payload = true;
        }
    }
    assert!(saw_include_payload, "include_payload=true must be sent on every V4 request");
    let version = req
        .headers
        .get(HEADER_ETH_CONSENSUS_VERSION)
        .unwrap_or_else(|| panic!("{HEADER_ETH_CONSENSUS_VERSION} request header must be present"));
    assert_eq!(version.to_str().expect("utf-8 consensus version header"), ForkName::Gloas.as_ref());
}

#[tokio::test]
async fn test_produce_block_v4_posts_path_body_and_declared_query_names() {
    let mock_server = MockServer::start().await;
    let slot = 100u64;
    let builder_config =
        BuilderConfig { min_bid: 10_000_000, builder_boost_factor: 100, builders: Vec::new() };

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .and(body_json(&builder_config))
        .respond_with(v4_json_success(slot))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result =
        client.produce_block_v4(slot, "0xrandao", Some("0xgraf"), &builder_config).await.unwrap();

    assert!(!result.is_ssz);
    assert!(result.ssz_bytes.is_none());
    assert_eq!(result.consensus_version, "gloas");
    let block = result.parse_full_block().unwrap();
    assert_eq!(block.block().slot, slot);

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(req.method.as_str(), "POST");
    assert_eq!(req.url.path(), v4_blocks_path(slot));
    let sent: BuilderConfig = serde_json::from_slice(&req.body).expect("BuilderConfig JSON body");
    assert_eq!(sent, builder_config);
    assert_v4_query_names(req);
    let pairs: Vec<(String, String)> =
        req.url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    assert!(pairs.iter().any(|(n, v)| n == QUERY_RANDAO_REVEAL && v == "0xrandao"));
    assert!(pairs.iter().any(|(n, v)| n == QUERY_GRAFFITI && v == "0xgraf"));
}

#[tokio::test]
async fn test_produce_block_v4_include_payload_true_without_graffiti() {
    let mock_server = MockServer::start().await;
    let slot = 101u64;
    let builder_config = BuilderConfig::default();

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v4(slot, "0xrandao", None, &builder_config).await.unwrap();
    assert_eq!(result.consensus_version, "gloas");

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_v4_query_names(&requests[0]);
    let pairs: Vec<(String, String)> =
        requests[0].url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    assert!(!pairs.iter().any(|(n, _)| n == QUERY_GRAFFITI));
}

#[tokio::test]
async fn test_produce_block_v4_400_is_typed_and_not_retried() {
    let mock_server = MockServer::start().await;
    let slot = 400u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(ResponseTemplate::new(400).set_body_string("missing or undecodable body"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert!(message.contains("undecodable") || message.contains("missing"), "{message}");
        }
        other => panic!("expected ApiError with status 400, got {other:?}"),
    }

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "400 must not be retried against the same BN");
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_v4_query_names(&requests[0]);
}

#[tokio::test]
async fn test_produce_block_v4_ssz_response() {
    let mock_server = MockServer::start().await;
    let slot = 500u64;
    let ssz_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "gloas")
                .insert_header("Eth-Execution-Payload-Value", "99999")
                .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result =
        client.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();

    assert!(result.is_ssz);
    assert_eq!(result.ssz_bytes, Some(ssz_payload));
    assert_eq!(result.data, serde_json::Value::Null);
    assert_eq!(result.consensus_version, "gloas");
    assert_eq!(result.execution_payload_value, Some("99999".to_string()));

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_v4_query_names(&requests[0]);
}

#[tokio::test]
async fn test_produce_block_v4_ssz_empty_body_falls_back_to_json() {
    let mock_server = MockServer::start().await;
    let slot = 900u64;
    let json_envelope = v4_json_envelope(slot);

    let responder = SszThenJsonResponder {
        call_count: AtomicUsize::new(0),
        first: ResponseTemplate::new(200)
            .set_body_raw(vec![], "application/octet-stream")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Consensus-Version", "gloas")
            .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true"),
        second: ResponseTemplate::new(200)
            .set_body_json(&json_envelope)
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Consensus-Version", "gloas")
            .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true"),
    };

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(responder)
        .expect(2)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result =
        client.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();

    assert!(!result.is_ssz);
    assert!(result.ssz_bytes.is_none());
    assert_eq!(result.consensus_version, "gloas");
    let block = result.parse_full_block().unwrap();
    assert_eq!(block.block().slot, slot);

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for req in &requests {
        assert_eq!(req.method.as_str(), "POST");
        assert_v4_query_names(req);
    }
}

fn v4_json_headers(
    slot: u64,
    payload_included: &str,
    builder_url: Option<&str>,
    consensus_block_value: Option<&str>,
) -> ResponseTemplate {
    let mut template = ResponseTemplate::new(200)
        .set_body_json(v4_json_envelope(slot))
        .insert_header(HEADER_ETH_CONSENSUS_VERSION, "gloas")
        .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, payload_included);
    if let Some(url) = builder_url {
        template = template.insert_header(HEADER_ETH_BUILDER_URL, url);
    }
    if let Some(value) = consensus_block_value {
        template = template.insert_header(HEADER_ETH_CONSENSUS_BLOCK_VALUE, value);
    }
    template
}

#[tokio::test]
async fn test_produce_block_v4_payload_included_true_and_false() {
    for included in [true, false] {
        let mock_server = MockServer::start().await;
        let slot = 110u64;
        let header_value = if included { "true" } else { "false" };

        Mock::given(method("POST"))
            .and(path(v4_blocks_path(slot)))
            .respond_with(v4_json_headers(slot, header_value, None, None))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BeaconClient::new(BeaconClientConfig::new(mock_server.uri())).unwrap();
        let result = client
            .produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default())
            .await
            .unwrap();

        assert_eq!(
            result.payload_included, included,
            "{HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED}={header_value}"
        );
    }
}

#[tokio::test]
async fn test_produce_block_v4_missing_payload_included_is_rejected() {
    let mock_server = MockServer::start().await;
    let slot = 111u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(v4_json_envelope(slot))
                .insert_header("Eth-Consensus-Version", "gloas"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = BeaconClient::new(BeaconClientConfig::new(mock_server.uri())).unwrap();
    let result = client.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    match result {
        Err(BeaconError::ParseError(msg)) => {
            assert!(
                msg.contains(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED),
                "error must name {HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED}: {msg}"
            );
        }
        Ok(resp) => panic!(
            "missing {HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED} must be Err, got payload_included={}",
            resp.payload_included
        ),
        other => panic!("expected ParseError, got {other:?}"),
    }
}

#[tokio::test]
async fn test_produce_block_v4_unparseable_payload_included_is_rejected() {
    let mock_server = MockServer::start().await;
    let slot = 112u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_headers(slot, "yes", None, None))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = BeaconClient::new(BeaconClientConfig::new(mock_server.uri())).unwrap();
    let result = client.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    match result {
        Err(BeaconError::ParseError(msg)) => {
            assert!(
                msg.contains(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED),
                "error must name {HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED}: {msg}"
            );
        }
        Ok(resp) => panic!(
            "unparseable {HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED} must be Err, got payload_included={}",
            resp.payload_included
        ),
        other => panic!("expected ParseError, got {other:?}"),
    }
}

#[tokio::test]
async fn test_produce_block_v4_builder_url_and_consensus_block_value() {
    let slot = 113u64;
    let huge_value = "999999999999999999999";
    let builder = "https://builder.example.com";

    let mock_present = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_headers(slot, "true", Some(builder), Some(huge_value)))
        .expect(1)
        .mount(&mock_present)
        .await;
    let present = BeaconClient::new(BeaconClientConfig::new(mock_present.uri()))
        .unwrap()
        .produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default())
        .await
        .unwrap();
    assert_eq!(present.builder_url.as_deref(), Some(builder));
    assert_eq!(present.consensus_block_value.as_deref(), Some(huge_value));

    let mock_absent = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_headers(slot, "false", None, None))
        .expect(1)
        .mount(&mock_absent)
        .await;
    let absent = BeaconClient::new(BeaconClientConfig::new(mock_absent.uri()))
        .unwrap()
        .produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default())
        .await
        .unwrap();
    assert_eq!(absent.builder_url, None);
    assert_eq!(absent.consensus_block_value, None);
}

#[tokio::test]
async fn test_produce_block_v4_ssz_payload_included_and_optional_headers() {
    let mock_server = MockServer::start().await;
    let slot = 114u64;
    let ssz_payload = vec![0xde, 0xad, 0xbe, 0xef];
    let builder = "https://relay.example";
    let value = "42";

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                .insert_header("Eth-Consensus-Version", "gloas")
                .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "false")
                .insert_header(HEADER_ETH_BUILDER_URL, builder)
                .insert_header(HEADER_ETH_CONSENSUS_BLOCK_VALUE, value),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = BeaconClient::new(BeaconClientConfig::new(mock_server.uri()))
        .unwrap()
        .produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default())
        .await
        .unwrap();

    assert!(result.is_ssz);
    assert!(!result.payload_included);
    assert_eq!(result.builder_url.as_deref(), Some(builder));
    assert_eq!(result.consensus_block_value.as_deref(), Some(value));
}

#[tokio::test]
async fn test_produce_block_v4_ssz_missing_payload_included_is_rejected() {
    let mock_server = MockServer::start().await;
    let slot = 115u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![0xde, 0xad, 0xbe, 0xef], "application/octet-stream")
                .insert_header("Eth-Consensus-Version", "gloas"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = BeaconClient::new(BeaconClientConfig::new(mock_server.uri()))
        .unwrap()
        .produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default())
        .await;
    match result {
        Err(BeaconError::ParseError(msg)) => {
            assert!(
                msg.contains(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED),
                "error must name {HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED}: {msg}"
            );
        }
        Ok(_) => panic!("SSZ missing {HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED} must be Err"),
        other => panic!("expected ParseError, got {other:?}"),
    }
}

#[tokio::test]
async fn test_publish_block() {
    let mock_server = MockServer::start().await;

    let signed_block = serde_json::json!({
        "message": {
            "slot": "100",
            "proposer_index": "42",
            "parent_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
            "state_root": "0x0202020202020202020202020202020202020202020202020202020202020202",
            "body": "0xdead"
        },
        "signature": "0xaabbcc"
    });

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .and(body_json(&signed_block))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "deneb"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    client.publish_block(&signed_block, "deneb").await.unwrap();
}

#[tokio::test]
async fn test_publish_block_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid block"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let signed_block = serde_json::json!({"message": {}});
    let result = client.publish_block(&signed_block, "deneb").await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert!(message.contains("Invalid block"));
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_publish_blinded_block() {
    let mock_server = MockServer::start().await;

    let signed_blinded_block = serde_json::json!({
        "message": {
            "slot": "200",
            "proposer_index": "10",
            "parent_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
            "state_root": "0x0202020202020202020202020202020202020202020202020202020202020202",
            "body": "0xbeef"
        },
        "signature": "0xbbccdd"
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .and(body_json(&signed_blinded_block))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "deneb"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    client.publish_blinded_block(&signed_blinded_block, "deneb").await.unwrap();
}

#[tokio::test]
async fn test_publish_blinded_block_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid blinded block"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let signed_block = serde_json::json!({"message": {}});
    let result = client.publish_blinded_block(&signed_block, "deneb").await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert!(message.contains("Invalid blinded block"));
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_get_proposer_duties_with_dependent_root() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "dependent_root": "0xabc123",
        "execution_optimistic": true,
        "data": [
            {
                "pubkey": "0xpubkey1",
                "validator_index": "100",
                "slot": "64000"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/2000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result =
        client.get_proposer_duties(2000, &ForkSchedule::unscheduled_gloas()).await.unwrap();

    assert_eq!(result.dependent_root, "0xabc123");
    assert!(result.execution_optimistic);
    assert_eq!(result.data.len(), 1);
    assert_eq!(result.data[0].pubkey, "0xpubkey1");
}

#[tokio::test]
async fn test_get_proposer_duties_v1_at_fulu_epoch() {
    let mock_server = MockServer::start().await;
    let body = proposer_duties_body();

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/550000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/duties/proposer/550000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let result = client.get_proposer_duties(550_000, &fulu_gloas_schedule()).await.unwrap();
    assert_eq!(result.dependent_root, "0xabc123");
    assert_eq!(result.data[0].validator_index, "100");
}

#[tokio::test]
async fn test_get_proposer_duties_v2_at_gloas_epoch() {
    let mock_server = MockServer::start().await;
    let body = proposer_duties_body();

    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/duties/proposer/600000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/600000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let result = client.get_proposer_duties(600_000, &fulu_gloas_schedule()).await.unwrap();
    assert_eq!(result.dependent_root, "0xabc123");
    assert!(result.execution_optimistic);
    assert_eq!(result.data.len(), 1);
    assert_eq!(result.data[0].pubkey, "0xpubkey1");
}

#[tokio::test]
async fn test_get_proposer_duties_v2_404_is_error_not_downgrade() {
    let mock_server = MockServer::start().await;
    let body = proposer_duties_body();

    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/duties/proposer/600000"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/600000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let result = client.get_proposer_duties(600_000, &fulu_gloas_schedule()).await;
    match result {
        Err(BeaconError::ApiError { status, .. }) => assert_eq!(status, 404),
        other => panic!("expected ApiError 404, got {other:?}"),
    }
}

#[tokio::test]
async fn test_publish_block_server_error_with_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(2)
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let signed_block = serde_json::json!({"message": {}});
    client.publish_block(&signed_block, "deneb").await.unwrap();
}

#[tokio::test]
async fn test_post_sync_committee_duties_success() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "execution_optimistic": false,
        "data": [
            {
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "validator_sync_committee_indices": ["0", "128", "256"]
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/sync/100"))
        .and(body_json(["1234"]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let indices = vec!["1234".to_string()];
    let result = client.post_sync_committee_duties(100, &indices).await.unwrap();

    assert!(!result.execution_optimistic);
    assert_eq!(result.data.len(), 1);
    assert_eq!(result.data[0].validator_index, 1234);
    assert_eq!(result.data[0].validator_sync_committee_indices, vec![0, 128, 256]);
}

#[tokio::test]
async fn test_post_sync_committee_duties_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/sync/999"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let indices = vec!["1234".to_string()];
    let result = client.post_sync_committee_duties(999, &indices).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid epoch");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_submit_sync_committee_messages_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/sync_committees"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let messages = vec![eth_types::SyncCommitteeMessage {
        slot: 100,
        beacon_block_root: [1u8; 32],
        validator_index: 42,
        signature: vec![0xaa; 96],
    }];

    let result = client.submit_sync_committee_messages(&messages).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_sync_committee_messages_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/sync_committees"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid message"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let messages = vec![eth_types::SyncCommitteeMessage {
        slot: 100,
        beacon_block_root: [1u8; 32],
        validator_index: 42,
        signature: vec![0xaa; 96],
    }];

    let result = client.submit_sync_committee_messages(&messages).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid message");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_get_sync_committee_contribution_success() {
    let mock_server = MockServer::start().await;

    let contribution = eth_types::SyncCommitteeContribution {
        slot: 100,
        beacon_block_root: [1u8; 32],
        subcommittee_index: 2,
        aggregation_bits: vec![0xff; 16],
        signature: vec![0xbb; 96],
    };
    let response_body = serde_json::json!({
        "data": serde_json::to_value(&contribution).unwrap()
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/sync_committee_contribution"))
        .and(wiremock::matchers::query_param("slot", "100"))
        .and(wiremock::matchers::query_param("subcommittee_index", "2"))
        .and(wiremock::matchers::query_param("beacon_block_root", "0xbeefbeef"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_sync_committee_contribution(100, 2, "0xbeefbeef").await.unwrap();

    assert_eq!(result.data.slot, 100);
    assert_eq!(result.data.subcommittee_index, 2);
}

#[tokio::test]
async fn test_get_sync_committee_contribution_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/sync_committee_contribution"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Contribution not available"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_sync_committee_contribution(100, 2, "0xbeefbeef").await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 404);
            assert!(message.contains("not available"));
        }
        _ => panic!("Expected ApiError with status 404"),
    }
}

#[tokio::test]
async fn test_submit_contribution_and_proofs_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/contribution_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs = vec![eth_types::SignedContributionAndProof {
        message: eth_types::ContributionAndProof {
            aggregator_index: 42,
            contribution: eth_types::SyncCommitteeContribution {
                slot: 100,
                beacon_block_root: [1u8; 32],
                subcommittee_index: 2,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xbb; 96],
            },
            selection_proof: vec![0xcc; 96],
        },
        signature: vec![0xdd; 96],
    }];

    let result = client.submit_contribution_and_proofs(&proofs).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_contribution_and_proofs_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/contribution_and_proofs"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid proof"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs = vec![eth_types::SignedContributionAndProof {
        message: eth_types::ContributionAndProof {
            aggregator_index: 42,
            contribution: eth_types::SyncCommitteeContribution {
                slot: 100,
                beacon_block_root: [1u8; 32],
                subcommittee_index: 2,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xbb; 96],
            },
            selection_proof: vec![0xcc; 96],
        },
        signature: vec![0xdd; 96],
    }];

    let result = client.submit_contribution_and_proofs(&proofs).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid proof");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

// Aggregation endpoint tests

#[tokio::test]
async fn test_get_aggregate_attestation_success() {
    let mock_server = MockServer::start().await;

    let att_data_root = format!("0x{}", "ab".repeat(32));
    let block_root_hex = format!("0x{}", "01".repeat(32));
    let source_root_hex = format!("0x{}", "02".repeat(32));
    let target_root_hex = format!("0x{}", "03".repeat(32));
    let sig_hex = format!("0x{}", "aa".repeat(96));
    let bits_hex = format!("0x{}", "ff".repeat(4));

    let response_body = serde_json::json!({
        "data": {
            "aggregation_bits": bits_hex,
            "data": {
                "slot": "100",
                "index": "1",
                "beacon_block_root": block_root_hex,
                "source": {
                    "epoch": "3",
                    "root": source_root_hex,
                },
                "target": {
                    "epoch": "4",
                    "root": target_root_hex,
                }
            },
            "signature": sig_hex
        }
    });

    let expected_path = "/eth/v1/validator/aggregate_attestation";

    Mock::given(method("GET"))
        .and(path(expected_path))
        .and(wiremock::matchers::query_param("slot", "100"))
        .and(wiremock::matchers::query_param("attestation_data_root", &att_data_root))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_aggregate_attestation(100, &att_data_root, None).await.unwrap();

    match result {
        VersionedAggregateAttestation::PreElectra(att) => {
            assert_eq!(att.data.slot, 100);
            assert_eq!(att.data.index, 1);
            assert_eq!(att.aggregation_bits, vec![0xff; 4]);
            assert_eq!(att.signature, vec![0xaa; 96]);
        }
        other => panic!("Expected PreElectra variant, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_aggregate_attestation_not_found() {
    let mock_server = MockServer::start().await;

    let att_data_root = format!("0x{}", "ab".repeat(32));

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Attestation not found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_aggregate_attestation(100, &att_data_root, None).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 404);
            assert_eq!(message, "Attestation not found");
        }
        _ => panic!("Expected ApiError with status 404"),
    }
}

#[tokio::test]
async fn test_submit_aggregate_and_proofs_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs =
        VersionedSignedAggregateAndProof::PreElectra(vec![eth_types::SignedAggregateAndProof {
            message: eth_types::AggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::Attestation {
                    aggregation_bits: vec![0xff; 4],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        }]);

    let result = client.submit_aggregate_and_proofs(&proofs).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_aggregate_and_proofs_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid proof"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs =
        VersionedSignedAggregateAndProof::PreElectra(vec![eth_types::SignedAggregateAndProof {
            message: eth_types::AggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::Attestation {
                    aggregation_bits: vec![0xff; 4],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        }]);

    let result = client.submit_aggregate_and_proofs(&proofs).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid proof");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_submit_attestation_pre_electra_body() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "phase0"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let legacy = LegacyAttestation {
        aggregation_bits: "0xff03".to_string(),
        data: AttestationData {
            slot: "100".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xroot".to_string(),
            source: Checkpoint { epoch: "3".to_string(), root: "0xsource".to_string() },
            target: Checkpoint { epoch: "4".to_string(), root: "0xtarget".to_string() },
        },
        signature: "0xsig".to_string(),
    };

    let versioned = VersionedAttestation::PreElectra(vec![legacy]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(result.is_success());
}

#[tokio::test]
async fn test_get_aggregate_attestation_with_committee_index() {
    let mock_server = MockServer::start().await;

    let att_data_root = format!("0x{}", "ab".repeat(32));
    let sig_hex = format!("0x{}", "aa".repeat(96));
    let committee_bits_hex = "0x2000000000000000";
    let response_body = serde_json::json!({
        "data": {
            "aggregation_bits": format!("0x{}", "ff".repeat(4)),
            "data": {
                "slot": "100",
                "index": "1",
                "beacon_block_root": format!("0x{}", "01".repeat(32)),
                "source": {
                    "epoch": "3",
                    "root": format!("0x{}", "02".repeat(32))
                },
                "target": {
                    "epoch": "4",
                    "root": format!("0x{}", "03".repeat(32))
                }
            },
            "signature": sig_hex,
            "committee_bits": committee_bits_hex
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(wiremock::matchers::query_param("slot", "100"))
        .and(wiremock::matchers::query_param("attestation_data_root", &att_data_root))
        .and(wiremock::matchers::query_param("committee_index", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_aggregate_attestation(100, &att_data_root, Some(5)).await.unwrap();
    match result {
        VersionedAggregateAttestation::Electra(att) => {
            assert_eq!(att.data.slot, 100);
        }
        other => panic!("Expected Electra variant, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_submit_aggregate_and_proofs_electra() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs = VersionedSignedAggregateAndProof::Electra(vec![
        eth_types::SignedElectraAggregateAndProof {
            message: eth_types::ElectraAggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::ElectraAttestation {
                    aggregation_bits: vec![0xff; 4],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                    committee_bits: vec![0x01; 8],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        },
    ]);

    let result = client.submit_aggregate_and_proofs(&proofs).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_prepare_beacon_proposer_success() {
    let mock_server = MockServer::start().await;

    let preparations = vec![
        ProposerPreparation {
            validator_index: "1234".to_string(),
            fee_recipient: "0xabcf8e0d4e9587369b2301d0790347320302cc09".to_string(),
        },
        ProposerPreparation {
            validator_index: "5678".to_string(),
            fee_recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        },
    ];

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .and(body_json(&preparations))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.prepare_beacon_proposer(&preparations).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_prepare_beacon_proposer_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid preparation data"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let preparations = vec![ProposerPreparation {
        validator_index: "1234".to_string(),
        fee_recipient: "0xabcf8e0d4e9587369b2301d0790347320302cc09".to_string(),
    }];

    let result = client.prepare_beacon_proposer(&preparations).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid preparation data");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_submit_beacon_committee_subscriptions_success() {
    let mock_server = MockServer::start().await;

    let subscriptions = vec![
        BeaconCommitteeSubscription {
            validator_index: "1234".to_string(),
            committee_index: "1".to_string(),
            committees_at_slot: "64".to_string(),
            slot: "10000".to_string(),
            is_aggregator: true,
        },
        BeaconCommitteeSubscription {
            validator_index: "5678".to_string(),
            committee_index: "2".to_string(),
            committees_at_slot: "64".to_string(),
            slot: "10000".to_string(),
            is_aggregator: false,
        },
    ];

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .and(body_json(&subscriptions))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.submit_beacon_committee_subscriptions(&subscriptions).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_beacon_committee_subscriptions_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid subscription data"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let subscriptions = vec![BeaconCommitteeSubscription {
        validator_index: "1234".to_string(),
        committee_index: "1".to_string(),
        committees_at_slot: "64".to_string(),
        slot: "10000".to_string(),
        is_aggregator: true,
    }];

    let result = client.submit_beacon_committee_subscriptions(&subscriptions).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid subscription data");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_post_validator_liveness_success() {
    let mock_server = MockServer::start().await;

    // Standard spec response: only index + is_live, no epoch.
    let response_body = serde_json::json!({
        "data": [
            {
                "index": "1234",
                "is_live": true
            },
            {
                "index": "5678",
                "is_live": false
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/100"))
        .and(body_json(["1234", "5678"]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let indices = vec!["1234".to_string(), "5678".to_string()];
    let result = client.post_validator_liveness(100, &indices).await.unwrap();

    assert_eq!(result.data.len(), 2);
    assert_eq!(result.data[0].index, "1234");
    assert!(result.data[0].is_live);
    assert_eq!(result.data[1].index, "5678");
    assert!(!result.data[1].is_live);
}

#[tokio::test]
async fn test_post_validator_liveness_lighthouse_compat() {
    let mock_server = MockServer::start().await;

    // Lighthouse returns an extra `epoch` field; serde ignores it.
    let response_body = serde_json::json!({
        "data": [
            {
                "index": "1234",
                "epoch": "100",
                "is_live": true
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/100"))
        .and(body_json(["1234"]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let indices = vec!["1234".to_string()];
    let result = client.post_validator_liveness(100, &indices).await.unwrap();

    assert_eq!(result.data.len(), 1);
    assert_eq!(result.data[0].index, "1234");
    assert!(result.data[0].is_live);
}

#[tokio::test]
async fn test_post_validator_liveness_empty_indices() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "data": []
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/100"))
        .and(body_json::<Vec<String>>(vec![]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let indices: Vec<String> = vec![];
    let result = client.post_validator_liveness(100, &indices).await.unwrap();

    assert!(result.data.is_empty());
}

#[tokio::test]
async fn test_post_validator_liveness_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/999"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let indices = vec!["1234".to_string()];
    let result = client.post_validator_liveness(999, &indices).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid epoch");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

// --- Voluntary exit tests ---

#[tokio::test]
async fn test_submit_voluntary_exit_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/voluntary_exits"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let signed_exit = eth_types::SignedVoluntaryExit {
        message: eth_types::VoluntaryExit { epoch: 100, validator_index: 42 },
        signature: vec![0xaa; 96],
    };

    let result = client.submit_voluntary_exit(&signed_exit).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_voluntary_exit_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/voluntary_exits"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid exit"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let signed_exit = eth_types::SignedVoluntaryExit {
        message: eth_types::VoluntaryExit { epoch: 100, validator_index: 42 },
        signature: vec![0xaa; 96],
    };

    let result = client.submit_voluntary_exit(&signed_exit).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid exit");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

// -- get_node_syncing tests --

#[tokio::test]
async fn test_get_node_syncing_synced() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_node_syncing().await.unwrap();
    assert_eq!(result.data.head_slot, "1000");
    assert_eq!(result.data.sync_distance, "0");
    assert!(!result.data.is_syncing);
    assert!(!result.data.is_optimistic);
    assert!(!result.data.el_offline);
}

#[tokio::test]
async fn test_get_node_syncing_still_syncing() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"head_slot":"500","sync_distance":"500","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_node_syncing().await.unwrap();
    assert_eq!(result.data.head_slot, "500");
    assert_eq!(result.data.sync_distance, "500");
    assert!(result.data.is_syncing);
}

#[tokio::test]
async fn test_get_node_syncing_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_node_syncing().await;
    assert!(result.is_err());
}

// -- get_node_version tests --

fn node_version_v2_body() -> serde_json::Value {
    serde_json::json!({
        "data": {
            "beacon_node": {
                "code": "LH",
                "name": "Lighthouse",
                "version": "v8.0.1",
                "commit": "0xced49dd2"
            },
            "execution_client": {
                "code": "NM",
                "name": "Nethermind",
                "version": "v1.35.8",
                "commit": "0xc066aee2"
            }
        }
    })
}

#[tokio::test]
async fn test_get_node_version_v2() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v2/node/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(node_version_v2_body()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "version": "should-not-be-used" }
        })))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let version = client.get_node_version().await.unwrap();
    assert_eq!(version, "Lighthouse/v8.0.1");
}

#[tokio::test]
async fn test_get_node_version_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v2/node/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(node_version_v2_body()))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let version = client.get_node_version().await.unwrap();
    assert_eq!(version, "Lighthouse/v8.0.1");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_get_node_version_falls_back_to_v1_on_404() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v2/node/version"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(2)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"version":"Lighthouse/v7.1.0-a1b2c3d/x86_64-linux"}}"#,
            ),
        )
        .expect(2)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let first = client.get_node_version().await.unwrap();
    let second = client.get_node_version().await.unwrap();
    assert_eq!(first, "Lighthouse/v7.1.0-a1b2c3d/x86_64-linux");
    assert_eq!(second, first);

    logs_assert(|lines: &[&str]| {
        let n = lines.iter().filter(|l| l.contains("falling back to /eth/v1/node/version")).count();
        if n != 1 {
            return Err(format!("expected fallback log once, got {n}: {lines:?}"));
        }
        Ok(())
    });
}

#[tokio::test]
async fn test_get_node_version_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v2/node/version"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":{"version":"should-not-fallback"}}"#),
        )
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();
    let result = client.get_node_version().await;
    assert!(result.is_err());
}

// -- Builder registration tests --

fn sample_signed_registration() -> eth_types::SignedValidatorRegistration {
    eth_types::SignedValidatorRegistration {
        message: eth_types::ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: [0xcd; 48],
        },
        signature: vec![0xee; 96],
    }
}

#[tokio::test]
async fn test_builder_register_validators_success() {
    let mock_server = MockServer::start().await;

    let registrations = vec![sample_signed_registration()];

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/register_validator"))
        .and(body_json(&registrations))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.register_validators(&registrations).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_builder_register_validators_multiple() {
    let mock_server = MockServer::start().await;

    let mut reg2 = sample_signed_registration();
    reg2.message.pubkey = [0xdd; 48];
    reg2.message.fee_recipient = [0xbc; 20];

    let registrations = vec![sample_signed_registration(), reg2];

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/register_validator"))
        .and(body_json(&registrations))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.register_validators(&registrations).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_builder_register_validators_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/register_validator"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid registration data"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let registrations = vec![sample_signed_registration()];
    let result = client.register_validators(&registrations).await;

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert_eq!(message, "Invalid registration data");
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_parse_error_includes_body_preview() {
    let mock_server = MockServer::start().await;

    let invalid_body = "this is not valid json at all";

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string(invalid_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result: Result<TestData, _> = client.get("/eth/v1/test").await;

    match result {
        Err(BeaconError::ParseError(msg)) => {
            // New format: "error decoding response body: <serde error>"
            // Old format was just "error decoding response body" from reqwest
            assert!(
                msg.starts_with("error decoding response body: "),
                "Expected error message to start with 'error decoding response body: ', got: {msg}"
            );
        }
        other => panic!("Expected ParseError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_parse_error_truncates_large_body() {
    let mock_server = MockServer::start().await;

    // Create a body larger than 1024 bytes that is invalid JSON
    let large_body = "x".repeat(2048);

    Mock::given(method("GET"))
        .and(path("/eth/v1/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&large_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result: Result<TestData, _> = client.get("/eth/v1/test").await;

    match result {
        Err(BeaconError::ParseError(msg)) => {
            assert!(
                msg.starts_with("error decoding response body: "),
                "Expected error message to start with 'error decoding response body: ', got: {msg}"
            );
        }
        other => panic!("Expected ParseError, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_aggregate_attestation_pre_electra() {
    let mock_server = MockServer::start().await;

    let att_data_root = format!("0x{}", "ab".repeat(32));
    let block_root_hex = format!("0x{}", "01".repeat(32));
    let source_root_hex = format!("0x{}", "02".repeat(32));
    let target_root_hex = format!("0x{}", "03".repeat(32));
    let sig_hex = format!("0x{}", "aa".repeat(96));
    let bits_hex = format!("0x{}", "ff".repeat(4));

    let response_body = serde_json::json!({
        "data": {
            "aggregation_bits": bits_hex,
            "data": {
                "slot": "100",
                "index": "1",
                "beacon_block_root": block_root_hex,
                "source": { "epoch": "3", "root": source_root_hex },
                "target": { "epoch": "4", "root": target_root_hex }
            },
            "signature": sig_hex
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(wiremock::matchers::query_param("slot", "100"))
        .and(wiremock::matchers::query_param("attestation_data_root", &att_data_root))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_aggregate_attestation(100, &att_data_root, None).await.unwrap();
    match result {
        VersionedAggregateAttestation::PreElectra(att) => {
            assert_eq!(att.data.slot, 100);
            assert_eq!(att.data.index, 1);
            assert_eq!(att.aggregation_bits, vec![0xff; 4]);
            assert_eq!(att.signature, vec![0xaa; 96]);
        }
        other => panic!("Expected PreElectra variant, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_get_aggregate_attestation_electra() {
    let mock_server = MockServer::start().await;

    let att_data_root = format!("0x{}", "ab".repeat(32));
    let block_root_hex = format!("0x{}", "01".repeat(32));
    let source_root_hex = format!("0x{}", "02".repeat(32));
    let target_root_hex = format!("0x{}", "03".repeat(32));
    let sig_hex = format!("0x{}", "aa".repeat(96));
    let bits_hex = format!("0x{}", "ff".repeat(4));
    let committee_bits_hex = "0x2000000000000000";

    let response_body = serde_json::json!({
        "data": {
            "aggregation_bits": bits_hex,
            "data": {
                "slot": "100",
                "index": "1",
                "beacon_block_root": block_root_hex,
                "source": { "epoch": "3", "root": source_root_hex },
                "target": { "epoch": "4", "root": target_root_hex }
            },
            "signature": sig_hex,
            "committee_bits": committee_bits_hex
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(wiremock::matchers::query_param("slot", "100"))
        .and(wiremock::matchers::query_param("attestation_data_root", &att_data_root))
        .and(wiremock::matchers::query_param("committee_index", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_aggregate_attestation(100, &att_data_root, Some(5)).await.unwrap();
    match result {
        VersionedAggregateAttestation::Electra(att) => {
            assert_eq!(att.data.slot, 100);
            assert_eq!(att.data.index, 1);
            assert_eq!(att.aggregation_bits, vec![0xff; 4]);
            assert_eq!(att.signature, vec![0xaa; 96]);
            assert_eq!(att.committee_bits, vec![0x20, 0, 0, 0, 0, 0, 0, 0]);
        }
        other => panic!("Expected Electra variant, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_submit_aggregate_and_proofs_electra_has_version_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs = VersionedSignedAggregateAndProof::Electra(vec![
        eth_types::SignedElectraAggregateAndProof {
            message: eth_types::ElectraAggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::ElectraAttestation {
                    aggregation_bits: vec![0xff; 4],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                    committee_bits: vec![0x01; 8],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        },
    ]);

    let result = client.submit_aggregate_and_proofs(&proofs).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_aggregate_and_proofs_fulu_has_version_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "fulu"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs =
        VersionedSignedAggregateAndProof::Fulu(vec![eth_types::SignedElectraAggregateAndProof {
            message: eth_types::ElectraAggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::ElectraAttestation {
                    aggregation_bits: vec![0xff; 4],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                    committee_bits: vec![0x01; 8],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        }]);

    let result = client.submit_aggregate_and_proofs(&proofs).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_attestation_fulu_has_version_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "fulu"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let attestation = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "0".to_string(),
            beacon_block_root: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            source: Checkpoint {
                epoch: "100".to_string(),
                root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            },
            target: Checkpoint {
                epoch: "101".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
        },
        committee_index: 0,
        signature: "0xsignature".to_string(),
    };
    let versioned = VersionedAttestation::Fulu(vec![attestation]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(result.is_success());
}

#[tokio::test]
async fn test_submit_attestation_gloas_has_version_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let attestation = SingleAttestation {
        attester_index: 0,
        data: AttestationData {
            slot: "1000".to_string(),
            index: "1".to_string(),
            beacon_block_root: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            source: Checkpoint {
                epoch: "100".to_string(),
                root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            },
            target: Checkpoint {
                epoch: "101".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
        },
        committee_index: 0,
        signature: "0xsignature".to_string(),
    };
    let versioned = VersionedAttestation::Gloas(vec![attestation]);
    let result = client.submit_attestation(&versioned).await.unwrap();
    assert!(result.is_success());
}

#[tokio::test]
async fn test_submit_aggregate_and_proofs_gloas_has_version_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let proofs =
        VersionedSignedAggregateAndProof::Gloas(vec![eth_types::SignedElectraAggregateAndProof {
            message: eth_types::ElectraAggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::ElectraAttestation {
                    aggregation_bits: vec![0xff; 4],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                    committee_bits: vec![0x01; 8],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        }]);

    let result = client.submit_aggregate_and_proofs(&proofs).await;
    assert!(result.is_ok());
}

// FIX-07: URL-encode graffiti tests

#[tokio::test]
async fn test_produce_block_v3_encodes_graffiti_special_chars() {
    let mock_server = MockServer::start().await;

    let block_body = serde_json::json!({
        "version": "deneb",
        "data": {}
    });

    // The encoded graffiti "hello&world=bad" should arrive as a single parameter
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/100"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .and(wiremock::matchers::query_param("graffiti", "hello&world=bad"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&block_body)
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(100, "0xrandao", Some("hello&world=bad"), None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_produce_block_v3_encodes_graffiti_spaces_and_unicode() {
    let mock_server = MockServer::start().await;

    let block_body = serde_json::json!({
        "version": "deneb",
        "data": {}
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/101"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .and(wiremock::matchers::query_param("graffiti", "hello world 🚀"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&block_body)
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(101, "0xrandao", Some("hello world 🚀"), None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_produce_block_v3_no_graffiti_no_param() {
    let mock_server = MockServer::start().await;

    let block_body = serde_json::json!({
        "version": "deneb",
        "data": {}
    });

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/102"))
        .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&block_body)
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.produce_block_v3(102, "0xrandao", None, None).await;
    assert!(result.is_ok());
}

// FIX-08: publish_block_ssz retry tests

#[tokio::test]
async fn test_publish_block_ssz_retries_on_503() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(2)
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let ssz_bytes = vec![0x01, 0x02, 0x03];
    let result = client.publish_block_ssz(&ssz_bytes, "deneb", false).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_publish_block_ssz_fails_on_400_no_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid block"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let ssz_bytes = vec![0x01, 0x02, 0x03];
    let result = client.publish_block_ssz(&ssz_bytes, "deneb", false).await;

    match result {
        Err(BeaconError::ApiError { status, .. }) => {
            assert_eq!(status, 400);
        }
        _ => panic!("Expected ApiError with status 400"),
    }
}

#[tokio::test]
async fn test_publish_block_ssz_exhausts_retries() {
    let mock_server = MockServer::start().await;

    // 1 initial + 3 retries = 4 total requests
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(4)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let ssz_bytes = vec![0x01, 0x02, 0x03];
    let result = client.publish_block_ssz(&ssz_bytes, "deneb", false).await;

    match result {
        Err(BeaconError::ApiError { status, .. }) => {
            assert_eq!(status, 503);
        }
        _ => panic!("Expected ApiError with status 503"),
    }
}

// --- COR-08: 429 Retry-After tests ---

#[tokio::test]
async fn test_429_retried_with_retry_after_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
    .and(path("/eth/v1/beacon/genesis"))
    .respond_with(ResponseTemplate::new(200).set_body_string(
        r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000","genesis_fork_version":"0x00000000"}}"#
    ))
    .mount(&server)
    .await;

    let config = BeaconClientConfig::new(server.uri())
        .with_max_retries(2)
        .with_initial_backoff(Duration::from_millis(10));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_genesis().await;
    assert!(result.is_ok(), "Should succeed after 429 retry: {:?}", result);
}

#[tokio::test]
async fn test_429_exhausts_retries() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let config = BeaconClientConfig::new(server.uri())
        .with_max_retries(1)
        .with_initial_backoff(Duration::from_millis(10));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_genesis().await;
    assert!(result.is_err());
    match result.unwrap_err() {
        BeaconError::ApiError { status, .. } => assert_eq!(status, 429),
        e => panic!("expected ApiError(429), got: {e:?}"),
    }
}

#[tokio::test]
async fn test_429_post_retried() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = BeaconClientConfig::new(server.uri())
        .with_max_retries(2)
        .with_initial_backoff(Duration::from_millis(10));
    let client = BeaconClient::new(config).unwrap();

    let preparations = vec![ProposerPreparation {
        validator_index: "1".to_string(),
        fee_recipient: "0x0000000000000000000000000000000000000001".to_string(),
    }];
    let result = client.prepare_beacon_proposer(&preparations).await;
    assert!(result.is_ok(), "POST should succeed after 429 retry: {:?}", result);
}

#[tokio::test]
async fn test_429_with_retry_after_header_respected() {
    let server = MockServer::start().await;

    // Return 429 with Retry-After: 1 once, then succeed
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
    .and(path("/eth/v1/beacon/genesis"))
    .respond_with(ResponseTemplate::new(200).set_body_string(
        r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000","genesis_fork_version":"0x00000000"}}"#
    ))
    .mount(&server)
    .await;

    let config = BeaconClientConfig::new(server.uri())
        .with_max_retries(2)
        .with_initial_backoff(Duration::from_millis(10));
    let client = BeaconClient::new(config).unwrap();

    let start = tokio::time::Instant::now();
    let result = client.get_genesis().await;
    let elapsed = start.elapsed();

    assert!(result.is_ok());
    // Retry-After: 1 means at least 1 second delay
    assert!(
        elapsed >= Duration::from_millis(900),
        "Should wait for Retry-After period: {elapsed:?}"
    );
}

// --- COR-09: POST for large validator sets ---

fn make_validators_response(count: usize) -> String {
    let validators: Vec<serde_json::Value> = (0..count)
        .map(|i| {
            json!({
                "index": i.to_string(),
                "status": "active_ongoing",
                "validator": {
                    "pubkey": format!("0x{:096x}", i)
                }
            })
        })
        .collect();
    json!({ "data": validators }).to_string()
}

#[tokio::test]
async fn test_get_validators_small_set_uses_get() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/validators"))
        .respond_with(ResponseTemplate::new(200).set_body_string(make_validators_response(3)))
        .expect(1)
        .mount(&server)
        .await;

    let config = BeaconClientConfig::new(server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let pubkeys: Vec<String> = (0..3).map(|i| format!("0x{:096x}", i)).collect();
    let result = client.get_validators(&pubkeys).await;
    assert!(result.is_ok(), "Small set should use GET: {:?}", result);
    assert_eq!(result.unwrap().data.len(), 3);
}

/// Issue 2.5: credentials embedded in the beacon endpoint must be redacted
/// in every emitted log field (bn_url + endpoint), never appearing raw.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_credentialed_endpoint_redacted_in_logs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/validators"))
        .respond_with(ResponseTemplate::new(200).set_body_string(make_validators_response(1)))
        .mount(&server)
        .await;

    // Embed basic-auth credentials in the configured endpoint URL.
    let credentialed = server.uri().replace("http://", "http://user:secretpw@");
    let config = BeaconClientConfig::new(credentialed).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let pubkeys = vec![format!("0x{:096x}", 1)];
    let result = client.get_validators(&pubkeys).await;
    assert!(result.is_ok(), "credentialed request should still succeed: {result:?}");

    // The emitted log fields show the redacted form, never the password.
    assert!(logs_contain("***:***@"), "credentials must be redacted (bn_url/endpoint)");
    assert!(!logs_contain("secretpw"), "the password must never appear in any log line");
}

#[tokio::test]
async fn test_get_validators_large_set_uses_post() {
    let server = MockServer::start().await;

    // Only mount POST — GET should NOT be called
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/states/head/validators"))
        .respond_with(ResponseTemplate::new(200).set_body_string(make_validators_response(51)))
        .expect(1)
        .mount(&server)
        .await;

    let config = BeaconClientConfig::new(server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let pubkeys: Vec<String> = (0..51).map(|i| format!("0x{:096x}", i)).collect();
    let result = client.get_validators(&pubkeys).await;
    assert!(result.is_ok(), "Large set should use POST: {:?}", result);
    assert_eq!(result.unwrap().data.len(), 51);
}

#[tokio::test]
async fn test_get_validators_threshold_boundary_uses_get() {
    let server = MockServer::start().await;

    // Exactly 50 should use GET
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/validators"))
        .respond_with(ResponseTemplate::new(200).set_body_string(make_validators_response(50)))
        .expect(1)
        .mount(&server)
        .await;

    let config = BeaconClientConfig::new(server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let pubkeys: Vec<String> = (0..50).map(|i| format!("0x{:096x}", i)).collect();
    let result = client.get_validators(&pubkeys).await;
    assert!(result.is_ok(), "50 pubkeys should use GET: {:?}", result);
}

#[tokio::test]
async fn test_429_without_retry_after_uses_exponential_backoff() {
    let server = MockServer::start().await;

    // Return 429 without Retry-After, then succeed
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
    .and(path("/eth/v1/beacon/genesis"))
    .respond_with(ResponseTemplate::new(200).set_body_string(
        r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000","genesis_fork_version":"0x00000000"}}"#
    ))
    .mount(&server)
    .await;

    let config = BeaconClientConfig::new(server.uri())
        .with_max_retries(2)
        .with_initial_backoff(Duration::from_millis(50));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_genesis().await;
    assert!(result.is_ok(), "Should succeed after 429 retry with fallback backoff");
}

#[tokio::test]
async fn test_post_ptc_duties_parses_dependent_root_field() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "execution_optimistic": true,
        "data": [
            {
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "slot": "10000"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/ptc/100"))
        .and(body_json(["1234"]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.post_ptc_duties(100, &["1234".to_string()]).await.unwrap();

    assert_eq!(
        result.dependent_root,
        "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
    );
    assert!(result.execution_optimistic);
    assert_eq!(result.data.len(), 1);
    assert_eq!(result.data[0].validator_index, "1234");
    assert_eq!(result.data[0].slot, "10000");
}

#[tokio::test]
async fn test_post_ptc_duties_500_is_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/ptc/100"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let result = client.post_ptc_duties(100, &["1234".to_string()]).await;
    match result {
        Err(BeaconError::ApiError { status, .. }) => assert_eq!(status, 500),
        Ok(resp) => panic!("500 must not become an empty duty list, got {} items", resp.data.len()),
        other => panic!("expected ApiError with status 500, got {other:?}"),
    }
}

#[tokio::test]
async fn test_get_payload_attestation_data_204_returns_none() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(wiremock::matchers::query_param("slot", "42"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri())
        .with_max_retries(3)
        .with_initial_backoff(Duration::from_millis(1));
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_payload_attestation_data(42).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_payload_attestation_data_200_parses_data() {
    let mock_server = MockServer::start().await;
    let root = format!("0x{}", "11".repeat(32));

    let response_body = serde_json::json!({
        "version": "gloas",
        "data": {
            "beacon_block_root": root,
            "slot": "42",
            "payload_present": true,
            "blob_data_available": false
        }
    });

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(wiremock::matchers::query_param("slot", "42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_payload_attestation_data(42).await.unwrap().unwrap();
    assert_eq!(result.data.slot, 42);
    assert!(result.data.payload_present);
    assert!(!result.data.blob_data_available);
    assert_eq!(result.data.beacon_block_root, [0x11; 32]);
}

#[tokio::test]
async fn test_get_payload_attestation_data_500_is_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(wiremock::matchers::query_param("slot", "42"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    let result = client.get_payload_attestation_data(42).await;
    match result {
        Err(BeaconError::ApiError { status, .. }) => assert_eq!(status, 500),
        Ok(None) => panic!("500 must not be treated as a 204 skip"),
        other => panic!("expected ApiError with status 500, got {other:?}"),
    }
}

#[tokio::test]
async fn test_submit_payload_attestations_sends_consensus_version() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/payload_attestations"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/payload_attestations"))
        .respond_with(ResponseTemplate::new(400).set_body_string("missing Eth-Consensus-Version"))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    client.submit_payload_attestations(&[]).await.expect("header must be sent");

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let version = requests[0]
        .headers
        .get("Eth-Consensus-Version")
        .expect("Eth-Consensus-Version header must be present");
    assert_eq!(version.to_str().unwrap(), "gloas");
}

#[tokio::test]
async fn test_submit_payload_attestations_500_is_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/payload_attestations"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let client = BeaconClient::new(config).unwrap();

    match client.submit_payload_attestations(&[]).await {
        Err(BeaconError::ApiError { status, .. }) => assert_eq!(status, 500),
        other => panic!("expected ApiError with status 500, got {other:?}"),
    }
}

/// 4.16 KAT object (`gloas_prefs_fixture`) plus a 96-byte signature.
fn gloas_signed_proposer_preferences() -> eth_types::SignedProposerPreferences {
    eth_types::SignedProposerPreferences {
        message: eth_types::ProposerPreferences {
            dependent_root: [0x33; 32],
            proposal_slot: 32,
            validator_index: 3,
            fee_recipient: [0x44; 20],
            target_gas_limit: 36_000_000,
        },
        signature: vec![0xaa; 96],
    }
}

#[tokio::test]
async fn test_submit_proposer_preferences_sends_consensus_version() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/proposer_preferences"))
        .and(wiremock::matchers::header("Eth-Consensus-Version", "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/proposer_preferences"))
        .respond_with(ResponseTemplate::new(400).set_body_string("missing Eth-Consensus-Version"))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    client.submit_proposer_preferences(&[]).await.expect("header must be sent");

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let version = requests[0]
        .headers
        .get("Eth-Consensus-Version")
        .expect("Eth-Consensus-Version header must be present");
    assert_eq!(version.to_str().unwrap(), "gloas");

    // A BN rejecting the request surfaces as an error, never a silent skip.
    let reject_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/proposer_preferences"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid proposer preferences"))
        .expect(1)
        .mount(&reject_server)
        .await;

    let reject_client =
        BeaconClient::new(BeaconClientConfig::new(reject_server.uri()).with_max_retries(0))
            .unwrap();
    match reject_client.submit_proposer_preferences(&[]).await {
        Err(BeaconError::ApiError { status, .. }) => assert_eq!(status, 400),
        other => panic!("BN reject must surface as error, never a silent skip, got {other:?}"),
    }
}

#[tokio::test]
async fn test_submit_proposer_preferences_round_trips_signed_bytes() {
    let mock_server = MockServer::start().await;
    let signed = gloas_signed_proposer_preferences();
    let expected_body = serde_json::to_vec(std::slice::from_ref(&signed)).expect("serialize");

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/proposer_preferences"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();

    client.submit_proposer_preferences(std::slice::from_ref(&signed)).await.expect("submit");

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body, expected_body,
        "wire body must be byte-identical to the signed object JSON"
    );
}
