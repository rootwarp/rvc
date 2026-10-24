//! Strategy / multi-BN integration tests for [`rvc_bn_manager::BnManager`] against wiremock.
//!
//! Pure relocation of the wiremock suite formerly inline in `src/manager.rs`
//! (RF6-08 / H1). Unit tests that touch private helpers (`primary_endpoint`,
//! `is_better_block`) remain in `src/manager.rs`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use beacon::{
    BeaconClient, BeaconClientConfig, HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED,
    PRODUCE_BLOCK_V4_PATH_PREFIX,
};
use eth_types::{ForkName, ForkSchedule};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use rvc_bn_manager::metrics::{
    RVC_BN_CAPABILITY_STATE, RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL, RVC_PROPOSER_BN_LATENCY_MS,
};
use rvc_bn_manager::types::bn_capability;
use rvc_bn_manager::{
    AttestationApi, AttestationData, BeaconError, BeaconNodeClient, BlockProducer, BnManager,
    BnManagerConfig, BnRole, BnSyncDetail, BnSyncStatus, BuilderConfig, Checkpoint, DutiesProvider,
    FeeRecipientPolicy, LivenessApi, NodeStatusApi, OperationTimeouts, PayloadAttestationApi,
    ProduceDuty, Propagator, ShapeConstraint, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SingleAttestation, SubmitAttestationResult, SyncCommitteeApi, VersionedAttestation,
    VersionedSignedAggregateAndProof,
};

// -- Helper --

fn make_manager(endpoint: &str) -> BnManager {
    let config = BnManagerConfig::new(vec![endpoint.to_string()]);
    BnManager::new(config).unwrap()
}

fn make_multi_manager(endpoints: &[&str]) -> BnManager {
    let config = BnManagerConfig::new(endpoints.iter().map(|e| e.to_string()).collect());
    BnManager::new(config).unwrap()
}

/// A peer's publish can arrive on the drain after the call returns.
///
/// Match method and path. A prior `GET /eth/v1/node/syncing` must not satisfy
/// a wait for the publish.
async fn poll_received(server: &MockServer, method: &str, path: &str, n: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let requests = server.received_requests().await.expect("received_requests");
        let got = requests
            .iter()
            .filter(|req| req.method.as_str() == method && req.url.path() == path)
            .count();
        if got >= n {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {n} {method} {path}, saw {got}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Broadcast health is recorded by the drain, which can finish after the call returns.
async fn poll_broadcast_health(
    manager: &BnManager,
    pred: impl Fn(&[rvc_bn_manager::BnHealthScore]) -> bool,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let scores = manager.health_scores().await;
        if pred(&scores) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the broadcast drain to record health: {scores:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

const GENESIS_RESPONSE: &str = r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}"#;

// -- Single-BN delegation tests --

#[tokio::test]
async fn test_get_genesis_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().data.genesis_time, "1606824023");
}

#[tokio::test]
async fn test_get_config_spec_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"data":{"SECONDS_PER_SLOT":"12"}}"#),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_config_spec().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().data.get("SECONDS_PER_SLOT").unwrap(), &json!("12"));
}

#[tokio::test]
async fn test_get_fork_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/fork"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"execution_optimistic":false,"finalized":true,"data":{"previous_version":"0x00000000","current_version":"0x01000000","epoch":"0"}}"#,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_fork("head").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_proposer_duties_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/10"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"dependent_root":"0xabc","execution_optimistic":false,"data":[]}"#,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_proposer_duties(10, &ForkSchedule::unscheduled_gloas()).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_attester_duties_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/5"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"dependent_root":"0xdef","execution_optimistic":false,"data":[]}"#,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_attester_duties(5, &["1".to_string(), "2".to_string()]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_post_ptc_duties_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/ptc/5"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"dependent_root":"0xptc","execution_optimistic":false,"data":[]}"#,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.post_ptc_duties(5, &["1".to_string(), "2".to_string()]).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().dependent_root, "0xptc");
}

#[tokio::test]
async fn test_get_block_root_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/blocks/head/root"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":{"root":"0xabcdef"}}"#))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_block_root("head").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_attestation_data_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", "100"))
        .and(query_param("committee_index", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"slot":"100","index":"0","beacon_block_root":"0xabc","source":{"epoch":"3","root":"0x01"},"target":{"epoch":"4","root":"0x02"}}}"#,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_attestation_data(100, 0).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_payload_attestation_data_delegates() {
    let mock_server = MockServer::start().await;
    let root = format!("0x{}", "11".repeat(32));
    let body = format!(
        r#"{{"data":{{"beacon_block_root":"{root}","slot":"42","payload_present":true,"blob_data_available":false}}}}"#
    );

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(query_param("slot", "42"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_payload_attestation_data(42).await.unwrap().unwrap();
    assert_eq!(result.data.slot, 42);
    assert!(result.data.payload_present);
}

#[tokio::test]
async fn test_submit_payload_attestations_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/payload_attestations"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.submit_payload_attestations(&[]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_sync_committee_messages_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/sync_committees"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.submit_sync_committee_messages(&[]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_prepare_beacon_proposer_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.prepare_beacon_proposer(&[]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_proposer_preferences_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/proposer_preferences"))
        .and(header("Eth-Consensus-Version", "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.submit_proposer_preferences(&[]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_builder_preferences_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/builder_preferences"))
        .and(header("Eth-Consensus-Version", "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.submit_builder_preferences(&[]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_builder_preferences_indexed_does_not_penalize_health() {
    let mock_server = MockServer::start().await;
    let body = serde_json::json!({
        "code": 400,
        "message": "some failures",
        "failures": [{ "index": 0, "message": "builder rejected" }]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/builder_preferences"))
        .respond_with(ResponseTemplate::new(400).set_body_json(body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.submit_builder_preferences(&[]).await.unwrap();
    match result {
        rvc_bn_manager::SubmitBuilderPreferencesResult::PartialFailure { failures } => {
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].index, 0);
        }
        other => panic!("expected PartialFailure, got {other:?}"),
    }
    let scores = manager.health_scores().await;
    assert_eq!(scores[0].error_rate, 0.0, "Indexed 400 must not count as a BN fault");
    assert!(scores[0].score > 0.5, "score should stay high after Indexed 400");
}

#[tokio::test]
async fn test_submit_beacon_committee_subscriptions_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.submit_beacon_committee_subscriptions(&[]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_aggregate_and_proofs_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let proofs = VersionedSignedAggregateAndProof::PreElectra(vec![]);
    let result = manager.submit_aggregate_and_proofs(&proofs).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_contribution_and_proofs_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/contribution_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.submit_contribution_and_proofs(&[]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_post_sync_committee_duties_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/sync/3"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"execution_optimistic":false,"data":[]}"#),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.post_sync_committee_duties(3, &["1".to_string()]).await;
    assert!(result.is_ok());
}

// -- BeaconClient direct trait impl tests --

#[tokio::test]
async fn test_beacon_client_get_genesis_via_trait() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = beacon::BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let dyn_client: &dyn BeaconNodeClient = &client;
    let result = dyn_client.get_genesis().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().data.genesis_time, "1606824023");
}

#[tokio::test]
async fn test_beacon_client_get_block_root_via_trait() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/blocks/head/root"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":{"root":"0xabcdef"}}"#))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = beacon::BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let dyn_client: &dyn BeaconNodeClient = &client;
    let result = dyn_client.get_block_root("head").await;
    assert!(result.is_ok());
}

// -- Error propagation --

#[tokio::test]
async fn test_error_propagated_from_beacon_client() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let result = manager.get_genesis().await;
    assert!(result.is_err());
}

// ===================================================================
// Multi-BN tests
// ===================================================================

// -- First strategy: failover --

#[tokio::test]
async fn test_multi_query_first_uses_primary() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&primary)
        .await;

    // Secondary should NOT be called
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(0)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().data.genesis_time, "1606824023");
}

#[tokio::test]
async fn test_multi_query_first_failover_on_error() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary returns error
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&primary)
        .await;

    // Secondary returns success
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().data.genesis_time, "1606824023");
}

#[tokio::test]
async fn test_multi_query_first_all_fail() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Unavailable"))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_genesis().await;
    assert!(result.is_err());
}

/// SEC-2c: post_validator_liveness uses query_first multi-BN failover.
#[tokio::test]
async fn test_post_validator_liveness_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(ResponseTemplate::new(500).set_body_string("primary down"))
        .expect(1)
        .mount(&primary)
        .await;

    let body = r#"{"data":[{"index":"1","is_live":false},{"index":"2","is_live":true}]}"#;
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let indices = vec!["1".to_string(), "2".to_string()];
    let result = manager.post_validator_liveness(42, &indices).await;
    assert!(result.is_ok(), "failover must succeed: {result:?}");
    let data = result.unwrap().data;
    assert_eq!(data.len(), 2);
    assert!(!data[0].is_live);
    assert!(data[1].is_live);
}

/// `post_ptc_duties` uses query_first + duty_fetch timeout (same as attester duties).
#[tokio::test]
async fn test_post_ptc_duties_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/ptc/42"))
        .respond_with(ResponseTemplate::new(500).set_body_string("primary down"))
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/ptc/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"dependent_root":"0xsecondary","execution_optimistic":false,"data":[]}"#,
        ))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.post_ptc_duties(42, &["1".to_string()]).await;
    assert!(result.is_ok(), "failover must succeed: {result:?}");
    assert_eq!(result.unwrap().dependent_root, "0xsecondary");
}

/// `get_payload_attestation_data` fails over on error (same as attestation data).
#[tokio::test]
async fn test_get_payload_attestation_data_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let root = format!("0x{}", "11".repeat(32));
    let body = format!(
        r#"{{"data":{{"beacon_block_root":"{root}","slot":"7","payload_present":true,"blob_data_available":false}}}}"#
    );

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(query_param("slot", "7"))
        .respond_with(ResponseTemplate::new(500).set_body_string("primary down"))
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(query_param("slot", "7"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_payload_attestation_data(7).await;
    assert!(result.is_ok(), "failover must succeed: {result:?}");
    let data = result.unwrap().unwrap().data;
    assert_eq!(data.slot, 7);
    assert!(data.payload_present);
}

/// A per-BN 204 is not the cluster answer: continue until a peer returns data.
#[tokio::test]
async fn test_get_payload_attestation_data_failover_204_then_200() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let root = format!("0x{}", "11".repeat(32));
    let body = format!(
        r#"{{"data":{{"beacon_block_root":"{root}","slot":"7","payload_present":true,"blob_data_available":false}}}}"#
    );

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(query_param("slot", "7"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/payload_attestation_data"))
        .and(query_param("slot", "7"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_payload_attestation_data(7).await;
    assert!(result.is_ok(), "204 must fail over: {result:?}");
    let data = result.unwrap().unwrap().data;
    assert_eq!(data.slot, 7);
    assert!(data.payload_present);
}

/// Every eligible BN 204s (none returns Some) ⇒ `Ok(None)`.
#[tokio::test]
async fn test_get_payload_attestation_data_all_204_returns_none() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    for server in [&primary, &secondary] {
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/payload_attestation_data"))
            .and(query_param("slot", "7"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_payload_attestation_data(7).await;
    assert!(result.is_ok(), "all-204 must be Ok(None), not an error: {result:?}");
    assert!(result.unwrap().is_none());
}

/// `submit_payload_attestations` broadcasts like `submit_attestation`: any success wins.
#[tokio::test]
async fn test_submit_payload_attestations_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/payload_attestations"))
        .respond_with(ResponseTemplate::new(500).set_body_string("primary down"))
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/payload_attestations"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.submit_payload_attestations(&[]).await;
    assert!(result.is_ok(), "broadcast any-success must succeed: {result:?}");
    poll_received(&primary, "POST", "/eth/v1/beacon/pool/payload_attestations", 1).await;
    poll_received(&secondary, "POST", "/eth/v1/beacon/pool/payload_attestations", 1).await;
}

/// ARCH-P1-13 / ARCH-3n: fail-safe OR-merge — any BN reporting live wins.
///
/// A lagging primary that answers `is_live = false` must not suppress a
/// secondary that saw activity. `query_first` would take A's answer and stop.
#[tokio::test]
async fn test_merged_liveness_reports_live_when_any_bn_says_live_fail_safe() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":[{"index":"1","is_live":false}]}"#),
        )
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":[{"index":"1","is_live":true}]}"#),
        )
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let indices = vec!["1".to_string()];
    let result = manager.post_validator_liveness_merged(42, &indices).await;
    assert!(result.is_ok(), "merge must succeed: {result:?}");
    let entry = result
        .unwrap()
        .data
        .into_iter()
        .find(|v| v.index == "1")
        .expect("merged response must include index 1");
    assert!(entry.is_live, "fail-safe: any BN reporting live must win over a not-live peer");
}

/// A later BN that reports live after another BN's 200 still wins the merge.
/// `first_ok` would return the fast not-live answer and drop this report.
#[tokio::test]
async fn merged_liveness_waits_for_a_bn_that_reports_live_after_a_200() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":[{"index":"1","is_live":false}]}"#),
        )
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":[{"index":"1","is_live":true}]}"#)
                .set_delay(Duration::from_millis(150)),
        )
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let indices = vec!["1".to_string()];
    let result = manager.post_validator_liveness_merged(42, &indices).await;
    assert!(result.is_ok(), "merge must wait for every BN: {result:?}");
    let entry = result
        .unwrap()
        .data
        .into_iter()
        .find(|v| v.index == "1")
        .expect("merged response must include index 1");
    assert!(entry.is_live, "a late is_live=true must still win the OR-merge");
}

/// An erroring BN contributes nothing (not live, not not-live).
#[tokio::test]
async fn test_merged_liveness_ignores_a_failing_bn() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(ResponseTemplate::new(500).set_body_string("primary down"))
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":[{"index":"1","is_live":false}]}"#),
        )
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    // Not-live counts only from a synced witness. The secondary is the sole
    // success, so it has to be that witness. The assertion is unchanged.
    manager.sync_statuses().write().await[1] = BnSyncDetail {
        status: BnSyncStatus::Synced,
        sync_distance: Some(0),
        head_slot: Some(32),
        is_optimistic: false,
        el_offline: false,
    };
    let indices = vec!["1".to_string()];
    let result = manager.post_validator_liveness_merged(42, &indices).await;
    assert!(result.is_ok(), "partial failure must not fail the merge: {result:?}");
    let entry = result
        .unwrap()
        .data
        .into_iter()
        .find(|v| v.index == "1")
        .expect("merged response must include index 1");
    assert!(!entry.is_live, "a failing BN must not be read as live; sole success is not-live");
}

/// Every BN failing returns Err so the observation loop stays fail-closed.
#[tokio::test]
async fn test_merged_liveness_errors_when_every_bn_fails() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(ResponseTemplate::new(500).set_body_string("primary down"))
        .expect(1)
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/42"))
        .respond_with(ResponseTemplate::new(503).set_body_string("secondary down"))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let indices = vec!["1".to_string()];
    let result = manager.post_validator_liveness_merged(42, &indices).await;
    assert!(result.is_err(), "all-fail must return Err so the loop fail-closes");
}

/// Single-BN `BeaconClient` implements the merge as a self-delegation.
#[tokio::test]
async fn test_single_bn_client_merged_liveness_delegates_to_itself() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/liveness/7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":[{"index":"1","is_live":true}]}"#),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = BeaconClient::new(BeaconClientConfig::new(mock_server.uri())).unwrap();
    let beacon: Arc<dyn BeaconNodeClient> = Arc::new(client);
    let indices = vec!["1".to_string()];
    let result = beacon.post_validator_liveness_merged(7, &indices).await;
    assert!(result.is_ok(), "single-BN merge must delegate: {result:?}");
    let data = result.unwrap().data;
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].index, "1");
    assert!(data[0].is_live);
}

#[tokio::test]
async fn test_multi_query_first_failover_three_bns() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;
    let bn3 = MockServer::start().await;

    // First two fail
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn2)
        .await;

    // Third succeeds
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&bn3)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri(), &bn3.uri()]);
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_multi_duties_use_first_strategy() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary fails
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&primary)
        .await;

    // Secondary succeeds
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"dependent_root":"0xabc","execution_optimistic":false,"data":[]}"#,
        ))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_proposer_duties(1, &ForkSchedule::unscheduled_gloas()).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_multi_attestation_data_uses_first_strategy() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary fails
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&primary)
        .await;

    // Secondary succeeds
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", "100"))
        .and(query_param("committee_index", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"slot":"100","index":"0","beacon_block_root":"0xabc","source":{"epoch":"3","root":"0x01"},"target":{"epoch":"4","root":"0x02"}}}"#,
        ))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.get_attestation_data(100, 0).await;
    assert!(result.is_ok());
}

// -- Best strategy: block production --

#[tokio::test]
async fn test_multi_best_picks_higher_value_block() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Execution 10 + consensus 0 loses to execution 5 + consensus 10.
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "10")
            .insert_header("Eth-Consensus-Block-Value", "0")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "5")
            .insert_header("Eth-Consensus-Block-Value", "10")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let block = manager.produce_block_v3(1, "0xrandao", None, None).await.expect("ranked head");
    assert_eq!(block.execution_payload_value.as_deref(), Some("5"));
    assert_eq!(block.consensus_block_value.as_deref(), Some("10"));
}

#[tokio::test]
async fn test_multi_best_missing_headers_rank_as_zero() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Missing headers are 0. Equal to an explicit 0, so the lower index wins.
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "0")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"1","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let tied =
        manager.produce_block_v3(1, "0xrandao", None, None).await.expect("tie keeps index 0");
    assert_eq!(tied.execution_payload_value, None);
    assert_eq!(tied.consensus_block_value, None);

    let bn3 = MockServer::start().await;
    let bn4 = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/2"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .set_body_string(r#"{"data":{"slot":"2","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn3)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/2"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "1")
            .set_body_string(r#"{"data":{"slot":"2","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn4)
        .await;

    let manager = make_multi_manager(&[&bn3.uri(), &bn4.uri()]);
    let positive =
        manager.produce_block_v3(2, "0xrandao", None, None).await.expect("1 beats missing");
    assert_eq!(positive.execution_payload_value.as_deref(), Some("1"));
    assert_eq!(positive.consensus_block_value, None);
}

#[tokio::test]
async fn test_multi_best_picks_only_successful_response() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1 fails
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    // BN2 succeeds
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "3000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().execution_payload_value, Some("3000".to_string()));
}

#[tokio::test]
async fn test_multi_best_all_fail() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Unavailable"))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_multi_best_single_bn_falls_back_to_first() {
    let bn = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "2000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn)
        .await;

    let manager = make_manager(&bn.uri());
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());
}

fn produce_block_v3_ok(value: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Execution-Payload-Value", value)
        .set_body_string(
            r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#,
        )
}

fn manager_with_block_budget(endpoints: &[&str], budget: Duration) -> BnManager {
    let config = BnManagerConfig::new(endpoints.iter().map(|e| e.to_string()).collect());
    BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
        block_production: budget,
        ..OperationTimeouts::default()
    })
}

/// B-002: a block already in hand is returned at the soft deadline. The slow
/// peer's timeout is recorded as an error instead of discarding the block.
///
/// Budget 3 s, so the soft deadline is 1.5 s. BN-A answers in 300 ms. BN-B
/// answers in 4 s with a higher payload value. The call must keep BN-A.
#[tokio::test]
async fn test_best_of_returns_ready_block_at_soft_deadline_when_peer_is_slow() {
    let bn_a = MockServer::start().await;
    let bn_b = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .and(query_param("randao_reveal", "0xrandao"))
        .respond_with(produce_block_v3_ok("1000").set_delay(Duration::from_millis(300)))
        .expect(1)
        .mount(&bn_a)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(produce_block_v3_ok("9000").set_delay(Duration::from_secs(4)))
        .expect(1)
        .mount(&bn_b)
        .await;

    let manager = manager_with_block_budget(&[&bn_a.uri(), &bn_b.uri()], Duration::from_secs(3));
    let start = tokio::time::Instant::now();
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    let elapsed = start.elapsed();

    let block = result.expect("BN-A's block must be kept");
    assert_eq!(block.execution_payload_value.as_deref(), Some("1000"));
    assert!(
        elapsed >= Duration::from_millis(1000),
        "returned before the soft deadline ({elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_millis(2800),
        "waited for the budget instead of the soft deadline ({elapsed:?})"
    );

    poll_broadcast_health(&manager, |scores| scores[1].error_rate == 1.0).await;
    let scores = manager.health_scores().await;
    assert!(scores[0].latency_ms > 0.0, "BN-A's success must be recorded: {scores:?}");
}

/// No block has arrived at the soft deadline. The one that arrives at 2 s is
/// returned then, not held until the 3 s budget.
#[tokio::test]
async fn test_best_of_returns_first_block_after_soft_without_waiting_for_budget() {
    let bn_a = MockServer::start().await;
    let bn_b = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(produce_block_v3_ok("1000").set_delay(Duration::from_secs(2)))
        .expect(1)
        .mount(&bn_a)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(produce_block_v3_ok("9000").set_delay(Duration::from_secs(4)))
        .expect(1)
        .mount(&bn_b)
        .await;

    let manager = manager_with_block_budget(&[&bn_a.uri(), &bn_b.uri()], Duration::from_secs(3));
    let start = tokio::time::Instant::now();
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    let elapsed = start.elapsed();

    let block = result.expect("the block that arrived at 2s");
    assert_eq!(block.execution_payload_value.as_deref(), Some("1000"));
    assert!(
        elapsed >= Duration::from_millis(1700) && elapsed < Duration::from_millis(2800),
        "expected return near 2s, not at the 3s budget; took {elapsed:?}"
    );
}

/// Every synced BN misses the hard deadline. A small-lag proposal-role BN is
/// tried inside the backstop when the parent root is known, and its block is
/// returned.
#[tokio::test]
async fn test_best_of_falls_back_to_unsynced_when_every_synced_bn_times_out() {
    let synced = MockServer::start().await;
    let unsynced = MockServer::start().await;
    let parent = [0xabu8; 32];
    let body = produce_json(preparable_data("full", 1, 0, &"ab".repeat(32), false));
    let fallback_ok = ResponseTemplate::new(200)
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Execution-Payload-Value", "7000")
        .set_body_string(body);

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&synced)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(produce_block_v3_ok("1111").set_delay(Duration::from_secs(5)))
        .expect(1)
        .mount(&synced)
        .await;

    const SMALL_LAG_RESPONSE: &str = r#"{"data":{"head_slot":"991","sync_distance":"9","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SMALL_LAG_RESPONSE))
        .mount(&unsynced)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(fallback_ok)
        .expect(1)
        .mount(&unsynced)
        .await;

    let manager =
        manager_with_block_budget(&[&synced.uri(), &unsynced.uri()], Duration::from_millis(400));
    manager.check_sync_status().await;

    let start = tokio::time::Instant::now();
    let result = manager
        .produce_block_v3_for_duty(
            1,
            "0xrandao",
            None,
            None,
            ProduceDuty {
                expected_proposer_index: 0,
                expected_parent_root: Some(parent),
                alternate_parent_root: None,
                parent_closed: false,
                expected_fee_recipient: None,
                expected_consensus_version: ForkName::Deneb,
                shape: ShapeConstraint::Any,
            },
        )
        .await;
    let elapsed = start.elapsed();

    let block = result.expect("small-lag fallback block");
    assert_eq!(block.execution_payload_value.as_deref(), Some("7000"));
    assert!(
        elapsed < Duration::from_secs(2),
        "fallback must finish inside the backstop, took {elapsed:?}"
    );
}

fn duty_block_body(parent: &str, proposer: u64, fee: &str) -> String {
    let mut data = preparable_data("full", 1, proposer, parent, false);
    data["body"]["execution_payload"]["fee_recipient"] =
        serde_json::Value::String(format!("0x{fee}"));
    produce_json(data)
}

fn mount_duty_block(value: &str, body: String) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Execution-Payload-Value", value)
        .set_body_string(body)
}

fn deneb_fee_duty(fee: [u8; 20]) -> ProduceDuty {
    ProduceDuty {
        expected_proposer_index: 7,
        expected_parent_root: Some([0xab; 32]),
        alternate_parent_root: None,
        parent_closed: false,
        expected_fee_recipient: Some(fee),
        expected_consensus_version: ForkName::Deneb,
        shape: ShapeConstraint::Any,
    }
}

/// A sole beacon node whose payload fee recipient does not match the duty
/// still returns the block. The penalty is recorded when that block is signed,
/// not when it is returned.
#[tokio::test]
#[tracing_test::traced_test]
async fn produce_block_v3_for_duty_returns_a_mismatched_fee_for_signing() {
    let bn = MockServer::start().await;
    let parent = "ab".repeat(32);
    let fee = "22".repeat(20);
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("9000", duty_block_body(&parent, 7, &fee)))
        .expect(1)
        .mount(&bn)
        .await;

    let manager = manager_with_block_budget(&[&bn.uri()], Duration::from_millis(400));
    let before = RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL.get();
    let result = manager
        .produce_block_v3_for_duty(1, "0xrandao", None, None, deneb_fee_duty([0x11; 20]))
        .await;
    let block = result.expect("a mismatched fee must still be returned for signing");
    assert_eq!(block.execution_payload_value.as_deref(), Some("9000"));
    assert!(
        !logs_contain("signing block with fee-recipient mismatch"),
        "returning a mismatch must not log the signing penalty"
    );
    assert_eq!(RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL.get(), before);
}

/// `fee_recipient_policy = "reject"` drops a readable mismatch.
#[tokio::test]
#[tracing_test::traced_test]
async fn produce_block_v3_for_duty_rejects_a_mismatched_fee_when_configured() {
    let bn = MockServer::start().await;
    let parent = "ab".repeat(32);
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("9000", duty_block_body(&parent, 7, &"22".repeat(20))))
        .expect(1)
        .mount(&bn)
        .await;

    let manager = manager_with_block_budget(&[&bn.uri()], Duration::from_millis(400))
        .with_fee_recipient_policy(FeeRecipientPolicy::Reject);
    let before = RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL.get();
    let result = manager
        .produce_block_v3_for_duty(1, "0xrandao", None, None, deneb_fee_duty([0x11; 20]))
        .await;
    assert!(result.is_err(), "reject policy must drop a wrong fee: {result:?}");
    assert!(logs_contain("best-of candidate rejected"));
    assert!(logs_contain("reason=fee") || logs_contain("reason=\"fee\""));
    assert!(!logs_contain("signing block with fee-recipient mismatch"));
    assert_eq!(RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL.get(), before);
}

/// The production reject path logs the duty comparison, not only a test double.
#[tokio::test]
#[tracing_test::traced_test]
async fn produce_block_v3_for_duty_logs_a_hard_reject() {
    let bn = MockServer::start().await;
    let parent = "ab".repeat(32);
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("1", duty_block_body(&parent, 99, &"11".repeat(20))))
        .expect(1)
        .mount(&bn)
        .await;

    let manager = manager_with_block_budget(&[&bn.uri()], Duration::from_millis(400));
    let result = manager
        .produce_block_v3_for_duty(1, "0xrandao", None, None, deneb_fee_duty([0x11; 20]))
        .await;
    assert!(result.is_err(), "a wrong proposer must be rejected: {result:?}");
    assert!(logs_contain("best-of candidate rejected"));
    assert!(logs_contain("reason=proposer") || logs_contain("reason=\"proposer\""));
    assert!(logs_contain("proposer_expected=7"));
    assert!(logs_contain("proposer_got=99"));
    assert!(logs_contain("slot_expected=1"));
    assert!(!logs_contain("signing block with fee-recipient mismatch"));
}

/// Every candidate is a hard reject. The error names each reason in index order.
#[tokio::test]
async fn all_rejected_round_names_the_reject_reasons() {
    let slot_bn = MockServer::start().await;
    let proposer_bn = MockServer::start().await;
    let parent = "ab".repeat(32);
    let fee = "11".repeat(20);
    let state = "00".repeat(32);
    let wrong_slot = format!(
        r#"{{"data":{{"slot":"9","proposer_index":"7","parent_root":"0x{parent}","state_root":"0x{state}","body":{{"execution_payload":{{"fee_recipient":"0x{fee}"}}}}}}}}"#
    );
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("9000", wrong_slot))
        .expect(1)
        .mount(&slot_bn)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("8000", duty_block_body(&parent, 99, &fee)))
        .expect(1)
        .mount(&proposer_bn)
        .await;

    let manager = manager_with_block_budget(
        &[&slot_bn.uri(), &proposer_bn.uri()],
        Duration::from_millis(400),
    );
    let slot_before = rvc_bn_manager::metrics::RVC_BN_PRODUCE_CANDIDATES_REJECTED_TOTAL
        .with_label_values(&["slot"])
        .get();
    let proposer_before = rvc_bn_manager::metrics::RVC_BN_PRODUCE_CANDIDATES_REJECTED_TOTAL
        .with_label_values(&["proposer"])
        .get();
    let err = manager
        .produce_block_v3_for_duty(1, "0xrandao", None, None, deneb_fee_duty([0x11; 20]))
        .await
        .expect_err("both candidates are hard rejects");
    assert_eq!(
        err.to_string(),
        "produce_block_v3: all candidates rejected: bn 0 slot, bn 1 proposer"
    );
    let slot_after = rvc_bn_manager::metrics::RVC_BN_PRODUCE_CANDIDATES_REJECTED_TOTAL
        .with_label_values(&["slot"])
        .get();
    let proposer_after = rvc_bn_manager::metrics::RVC_BN_PRODUCE_CANDIDATES_REJECTED_TOTAL
        .with_label_values(&["proposer"])
        .get();
    assert!(slot_after > slot_before, "slot rejects are counted");
    assert!(proposer_after > proposer_before, "proposer rejects are counted");
}

/// A higher-value candidate with the wrong fee recipient ranks below a
/// matching one. The signed block is the match, and the penalty warning is
/// not emitted for the candidate that lost.
#[tokio::test]
#[tracing_test::traced_test]
async fn produce_block_v3_for_duty_ranks_a_fee_mismatch_below_a_match() {
    let mismatch = MockServer::start().await;
    let matching = MockServer::start().await;
    let parent = "ab".repeat(32);
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("9000", duty_block_body(&parent, 7, &"22".repeat(20))))
        .expect(1)
        .mount(&mismatch)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("1000", duty_block_body(&parent, 7, &"11".repeat(20))))
        .expect(1)
        .mount(&matching)
        .await;

    let manager =
        manager_with_block_budget(&[&mismatch.uri(), &matching.uri()], Duration::from_secs(3));
    let block = manager
        .produce_block_v3_for_duty(1, "0xrandao", None, None, deneb_fee_duty([0x11; 20]))
        .await
        .expect("a matching candidate must be returned");
    assert_eq!(
        block.execution_payload_value.as_deref(),
        Some("1000"),
        "the matching fee recipient must outrank the higher mismatched value"
    );
    assert!(
        !logs_contain("signing block with fee-recipient mismatch"),
        "the penalty warning is only for the block that is signed"
    );
}

/// A fee-penalized block stays on the ranked list, behind the preferred one.
#[tokio::test]
async fn produce_block_v3_ranked_lists_a_held_fee_mismatch_after_the_preferred_block() {
    let mismatch = MockServer::start().await;
    let matching = MockServer::start().await;
    let parent = "ab".repeat(32);
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("9000", duty_block_body(&parent, 7, &"22".repeat(20))))
        .expect(1)
        .mount(&mismatch)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block("1000", duty_block_body(&parent, 7, &"11".repeat(20))))
        .expect(1)
        .mount(&matching)
        .await;

    let manager =
        manager_with_block_budget(&[&mismatch.uri(), &matching.uri()], Duration::from_secs(3));
    let ranked = manager
        .produce_block_v3_ranked(1, "0xrandao", None, None, Some(deneb_fee_duty([0x11; 20])))
        .await
        .expect("both candidates must be returned");
    assert_eq!(ranked.len(), 2, "the held fee mismatch stays behind the preferred block");
    assert_eq!(ranked[0].response.execution_payload_value.as_deref(), Some("1000"));
    assert_eq!(ranked[1].response.execution_payload_value.as_deref(), Some("9000"));
}

/// No duty, so the parent is unknown. A small-lag proposal BN is not asked.
#[tokio::test]
async fn produce_block_v3_without_a_parent_does_not_ask_a_small_lag_bn() {
    let synced = MockServer::start().await;
    let small = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&synced)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(503).set_body_string("down"))
        .expect(1)
        .mount(&synced)
        .await;

    const SMALL_LAG_RESPONSE: &str = r#"{"data":{"head_slot":"991","sync_distance":"9","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SMALL_LAG_RESPONSE))
        .mount(&small)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(produce_block_v3_ok("7000"))
        .expect(0)
        .mount(&small)
        .await;

    let manager =
        manager_with_block_budget(&[&synced.uri(), &small.uri()], Duration::from_millis(400));
    manager.check_sync_status().await;

    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_err(), "no parent must not fall back to the small-lag BN: {result:?}");
}

// -- V4 sequential failover (issue 6.6 / D29) --

fn v4_blocks_path(slot: u64) -> String {
    format!("{PRODUCE_BLOCK_V4_PATH_PREFIX}/{slot}")
}

fn v4_json_success(slot: u64, parent_byte: u8, payload_value: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({
            "version": "gloas",
            "data": {
                "slot": slot.to_string(),
                "proposer_index": "42",
                "parent_root": format!("0x{}", hex_repeat(parent_byte)),
                "state_root": format!("0x{}", hex_repeat(0x02)),
                "body": "0xdead"
            }
        }))
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Consensus-Version", "gloas")
        .insert_header("Eth-Execution-Payload-Value", payload_value)
        .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true")
}

fn hex_repeat(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

struct InflightProbe {
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
    delay: Duration,
    template: ResponseTemplate,
}

impl wiremock::Respond for InflightProbe {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.template.clone()
    }
}

struct SeqRespond {
    n: Arc<AtomicUsize>,
    first: ResponseTemplate,
    rest: ResponseTemplate,
}

impl wiremock::Respond for SeqRespond {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        if self.n.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first.clone()
        } else {
            self.rest.clone()
        }
    }
}

#[tokio::test]
async fn test_produce_block_v4_three_healthy_reaches_exactly_one_bn() {
    let bns = [MockServer::start().await, MockServer::start().await, MockServer::start().await];
    let slot = 7u64;
    for bn in &bns {
        Mock::given(method("POST"))
            .and(path(v4_blocks_path(slot)))
            .respond_with(v4_json_success(slot, 0x11, "1000"))
            .mount(bn)
            .await;
    }

    let manager = make_multi_manager(&[&bns[0].uri(), &bns[1].uri(), &bns[2].uri()]);
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    assert!(result.is_ok(), "first 2xx must succeed: {result:?}");

    let mut counts = Vec::new();
    for bn in &bns {
        counts.push(bn.received_requests().await.unwrap().len());
    }
    assert_eq!(
        counts.iter().sum::<usize>(),
        1,
        "exactly one BN must see produce_block_v4; per-BN counts={counts:?}"
    );
    assert_eq!(counts.iter().filter(|&&c| c == 1).count(), 1);
}

#[tokio::test]
async fn test_produce_block_v4_5xx_failsover_sequentially_never_two_in_flight() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let slot = 8u64;
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let delay = Duration::from_millis(80);

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(InflightProbe {
            in_flight: Arc::clone(&in_flight),
            max_in_flight: Arc::clone(&max_in_flight),
            delay,
            template: ResponseTemplate::new(500).set_body_string("primary 5xx"),
        })
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(InflightProbe {
            in_flight: Arc::clone(&in_flight),
            max_in_flight: Arc::clone(&max_in_flight),
            delay,
            template: v4_json_success(slot, 0x22, "5000"),
        })
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager
        .produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default())
        .await
        .expect("5xx on the first BN must fail over");
    assert_eq!(result.execution_payload_value.as_deref(), Some("5000"));

    let primary_n = primary.received_requests().await.unwrap().len();
    let secondary_n = secondary.received_requests().await.unwrap().len();
    assert_eq!(primary_n, 1, "primary 5xx must be tried once");
    assert_eq!(secondary_n, 1, "secondary must be tried after 5xx");
    assert_eq!(
        max_in_flight.load(Ordering::SeqCst),
        1,
        "produce_block_v4 must never fan out; max in-flight was {}",
        max_in_flight.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn test_produce_block_v4_connect_error_failsover() {
    let secondary = MockServer::start().await;
    let slot = 9u64;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x33, "3000"))
        .expect(1)
        .mount(&secondary)
        .await;

    // Port 1 refuses connections immediately on loopback.
    let manager = make_multi_manager(&["http://127.0.0.1:1", &secondary.uri()]);
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    assert!(result.is_ok(), "connect error must fail over: {result:?}");
    assert_eq!(result.unwrap().execution_payload_value.as_deref(), Some("3000"));
}

#[tokio::test]
async fn test_produce_block_v4_timeout_failsover_within_block_production_budget() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let slot = 10u64;
    let budget = Duration::from_millis(400);

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x11, "1000").set_delay(Duration::from_secs(5)))
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x44, "4000"))
        .mount(&secondary)
        .await;

    let config = BnManagerConfig::new(vec![primary.uri(), secondary.uri()]);
    let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
        block_production: budget,
        ..OperationTimeouts::default()
    });

    let start = tokio::time::Instant::now();
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "timed-out primary must fail over: {result:?}");
    assert_eq!(result.unwrap().execution_payload_value.as_deref(), Some("4000"));
    assert_eq!(
        secondary.received_requests().await.unwrap().len(),
        1,
        "secondary must receive the sequential retry"
    );
    assert!(
        elapsed < budget + Duration::from_millis(150),
        "total production must stay within t.block_production ({budget:?}), took {elapsed:?}"
    );
}

#[tokio::test]
async fn test_produce_block_v4_2xx_never_followed_by_second_production() {
    let first = MockServer::start().await;
    let second = MockServer::start().await;
    let slot = 11u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x01, "1111"))
        .mount(&first)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x02, "2222"))
        .mount(&second)
        .await;

    let manager = make_multi_manager(&[&first.uri(), &second.uri()]);
    let result =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();

    let n0 = first.received_requests().await.unwrap().len();
    let n1 = second.received_requests().await.unwrap().len();
    assert_eq!(n0 + n1, 1, "2xx must not be followed by a second production request ({n0}+{n1})");
    assert_eq!(result.execution_payload_value.as_deref(), Some("1111"));
}

#[tokio::test]
async fn test_produce_block_v4_4xx_does_not_failover() {
    let bns = [MockServer::start().await, MockServer::start().await, MockServer::start().await];
    let slot = 12u64;
    for bn in &bns {
        Mock::given(method("POST"))
            .and(path(v4_blocks_path(slot)))
            .respond_with(ResponseTemplate::new(400).set_body_string("missing or undecodable body"))
            .mount(bn)
            .await;
    }

    let manager = make_multi_manager(&[&bns[0].uri(), &bns[1].uri(), &bns[2].uri()]);
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    match result {
        Err(BeaconError::ApiError { status, .. }) => assert_eq!(status, 400),
        other => panic!("expected 400 ApiError, got {other:?}"),
    }

    let counts: Vec<usize> = {
        let mut v = Vec::new();
        for bn in &bns {
            v.push(bn.received_requests().await.unwrap().len());
        }
        v
    };
    assert_eq!(
        counts.iter().sum::<usize>(),
        1,
        "4xx is not connect/timeout/5xx; must not fail over; counts={counts:?}"
    );
    {
        let trackers = manager.health_trackers().read().await;
        assert!(
            trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4),
            "400 is a understood bad request, not a missing /eth/v4 gap"
        );
        let ep = trackers[0].endpoint().to_string();
        assert_eq!(
            capability_state(&ep, bn_capability::PRODUCE_BLOCK_V4),
            1,
            "400 must not publish capability 0"
        );
    }
}

#[tokio::test]
async fn test_produce_block_v4_2xx_parse_error_does_not_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let slot = 13u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("not-json")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "gloas")
                .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true"),
        )
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x55, "5555"))
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    assert!(
        matches!(result, Err(BeaconError::ParseError(_))),
        "2xx must commit the attempt even if the body is unusable: {result:?}"
    );
    assert_eq!(
        secondary.received_requests().await.unwrap().len(),
        0,
        "never retry produce_block_v4 after a 2xx"
    );
}

#[tokio::test]
async fn test_produce_block_v4_two_candidates_uses_first_2xx_only() {
    let bn_a = MockServer::start().await;
    let bn_b = MockServer::start().await;
    let slot = 14u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0xaa, "100"))
        .mount(&bn_a)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0xbb, "99999"))
        .mount(&bn_b)
        .await;

    let manager = make_multi_manager(&[&bn_a.uri(), &bn_b.uri()]);
    let result =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();

    assert_eq!(result.execution_payload_value.as_deref(), Some("100"));
    assert_eq!(bn_a.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        bn_b.received_requests().await.unwrap().len(),
        0,
        "second distinct BlockContents must never be requested after a 2xx"
    );
}

#[tokio::test]
async fn test_produce_block_v4_empty_ssz_2xx_does_not_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let slot = 15u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![], "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "gloas")
                .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true"),
        )
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x66, "6666"))
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    assert!(
        matches!(result, Err(BeaconError::ParseError(_))),
        "empty SSZ 2xx must be ParseError, not a second produce: {result:?}"
    );
    assert_eq!(primary.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        secondary.received_requests().await.unwrap().len(),
        0,
        "2xx empty SSZ must not POST produce_block_v4 to another BN"
    );
}

#[tokio::test]
async fn test_produce_block_v4_429_does_not_sleep_into_timeout_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let slot = 16u64;
    let budget = Duration::from_millis(400);

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "30"))
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x77, "7777"))
        .mount(&secondary)
        .await;

    let config = BnManagerConfig::new(vec![primary.uri(), secondary.uri()]);
    let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
        block_production: budget,
        ..OperationTimeouts::default()
    });

    let start = tokio::time::Instant::now();
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    let elapsed = start.elapsed();
    match result {
        Err(BeaconError::ApiError { status, .. }) => assert_eq!(status, 429),
        other => panic!("429 must surface as ApiError, not Timeout failover: {other:?}"),
    }
    assert_eq!(secondary.received_requests().await.unwrap().len(), 0);
    assert!(
        elapsed < budget + Duration::from_millis(150),
        "429 with max_retries=0 must not sleep Retry-After, took {elapsed:?}"
    );
}

#[tokio::test]
async fn test_produce_block_v4_tries_higher_health_score_first() {
    let low = MockServer::start().await;
    let high = MockServer::start().await;
    let slot = 17u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x10, "low"))
        .mount(&low)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x20, "high"))
        .mount(&high)
        .await;

    let manager = make_multi_manager(&[&low.uri(), &high.uri()]);
    {
        let mut trackers = manager.health_trackers().write().await;
        trackers[1].record_success(Duration::from_millis(1));
    }

    let result =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(result.execution_payload_value.as_deref(), Some("high"));
    assert_eq!(high.received_requests().await.unwrap().len(), 1);
    assert_eq!(low.received_requests().await.unwrap().len(), 0);
}

fn capability_state(endpoint: &str, capability: &str) -> i64 {
    RVC_BN_CAPABILITY_STATE.with_label_values(&[endpoint, capability]).get()
}

async fn v3_request_count(bn: &MockServer) -> usize {
    bn.received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|req| req.url.path().contains("/eth/v3/validator/blocks"))
        .count()
}

// -- V4 per-endpoint capability health (issue 6.7) --

#[tokio::test]
async fn test_produce_block_v4_404_excludes_bn_from_next_selection() {
    let missing = MockServer::start().await;
    let ok = MockServer::start().await;
    let slot = 21u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(ResponseTemplate::new(404).set_body_string("no /eth/v4"))
        .mount(&missing)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x21, "2100"))
        .mount(&ok)
        .await;

    let manager = make_multi_manager(&[&missing.uri(), &ok.uri()]);
    let missing_ep = manager.health_trackers().read().await[0].endpoint().to_string();
    assert_eq!(
        capability_state(&missing_ep, bn_capability::PRODUCE_BLOCK_V4),
        1,
        "gauge starts capable so a later 0 is a real transition"
    );
    let first =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(first.execution_payload_value.as_deref(), Some("2100"));
    assert_eq!(missing.received_requests().await.unwrap().len(), 1);
    assert_eq!(ok.received_requests().await.unwrap().len(), 1);

    {
        let mut trackers = manager.health_trackers().write().await;
        assert!(!trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
        assert!(trackers[1].is_capable(bn_capability::PRODUCE_BLOCK_V4));
        // Restore EMA health so exclusion is capability, not the error-rate cut.
        for _ in 0..20 {
            trackers[0].record_success(Duration::from_millis(1));
        }
        assert!(trackers[0].is_healthy());
        assert!(!trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
    }
    assert_eq!(
        capability_state(&missing_ep, bn_capability::PRODUCE_BLOCK_V4),
        0,
        "404 must publish capability 0 after a 1→0 transition"
    );

    let second =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(second.execution_payload_value.as_deref(), Some("2100"));
    assert_eq!(
        missing.received_requests().await.unwrap().len(),
        1,
        "404 BN must be excluded from the next produce_block_v4 selection"
    );
    assert_eq!(ok.received_requests().await.unwrap().len(), 2);
}

async fn v4_status_excludes_from_next_selection(status: u16) {
    let missing = MockServer::start().await;
    let ok = MockServer::start().await;
    let slot = 30 + u64::from(status);

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(ResponseTemplate::new(status).set_body_string("no /eth/v4"))
        .mount(&missing)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x30, "3000"))
        .mount(&ok)
        .await;

    let manager = make_multi_manager(&[&missing.uri(), &ok.uri()]);
    let missing_ep = manager.health_trackers().read().await[0].endpoint().to_string();
    assert_eq!(capability_state(&missing_ep, bn_capability::PRODUCE_BLOCK_V4), 1);

    let first =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(first.execution_payload_value.as_deref(), Some("3000"));
    assert_eq!(missing.received_requests().await.unwrap().len(), 1);

    {
        let mut trackers = manager.health_trackers().write().await;
        assert!(!trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
        for _ in 0..20 {
            trackers[0].record_success(Duration::from_millis(1));
        }
        assert!(trackers[0].is_healthy());
    }
    assert_eq!(
        capability_state(&missing_ep, bn_capability::PRODUCE_BLOCK_V4),
        0,
        "{status} must publish capability 0"
    );

    let second =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(second.execution_payload_value.as_deref(), Some("3000"));
    assert_eq!(
        missing.received_requests().await.unwrap().len(),
        1,
        "{status} BN must be excluded from the next produce_block_v4 selection"
    );
}

#[tokio::test]
async fn test_produce_block_v4_405_excludes_bn_from_next_selection() {
    v4_status_excludes_from_next_selection(405).await;
}

#[tokio::test]
async fn test_produce_block_v4_501_excludes_bn_from_next_selection() {
    v4_status_excludes_from_next_selection(501).await;
}

#[tokio::test]
async fn test_produce_block_v4_reprobes_incapable_bn_while_peer_stays_healthy() {
    let recovered = MockServer::start().await;
    let healthy = MockServer::start().await;
    let slot = 27u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(SeqRespond {
            n: Arc::new(AtomicUsize::new(0)),
            first: ResponseTemplate::new(404).set_body_string("no /eth/v4"),
            rest: v4_json_success(slot, 0xaa, "recovered"),
        })
        .mount(&recovered)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0xbb, "healthy"))
        .mount(&healthy)
        .await;

    let manager = make_multi_manager(&[&recovered.uri(), &healthy.uri()]);

    let first =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(first.execution_payload_value.as_deref(), Some("healthy"));
    assert_eq!(recovered.received_requests().await.unwrap().len(), 1);
    assert_eq!(healthy.received_requests().await.unwrap().len(), 1);

    {
        let mut trackers = manager.health_trackers().write().await;
        assert!(!trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
        for _ in 0..20 {
            trackers[0].record_success(Duration::from_millis(1));
        }
        assert!(trackers[0].is_healthy());
        assert!(trackers[1].is_healthy());
    }

    let skip =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(skip.execution_payload_value.as_deref(), Some("healthy"));
    assert_eq!(
        recovered.received_requests().await.unwrap().len(),
        1,
        "incapable BN is excluded from the immediately next selection"
    );

    let reprobe =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(
        reprobe.execution_payload_value.as_deref(),
        Some("recovered"),
        "re-probe must contact the recovered BN while the peer stays healthy"
    );
    assert_eq!(recovered.received_requests().await.unwrap().len(), 2);
    {
        let trackers = manager.health_trackers().read().await;
        assert!(trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
    }
}

#[tokio::test]
async fn test_produce_block_v4_all_incapable_returns_no_eligible_bn_not_v3() {
    let bn_a = MockServer::start().await;
    let bn_b = MockServer::start().await;
    let slot = 22u64;

    for bn in [&bn_a, &bn_b] {
        Mock::given(method("POST"))
            .and(path(v4_blocks_path(slot)))
            .respond_with(ResponseTemplate::new(404).set_body_string("no /eth/v4"))
            .mount(bn)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/eth/v3/validator/blocks/{slot}")))
            .respond_with(ResponseTemplate::new(200).set_body_string("should never be called"))
            .expect(0)
            .mount(bn)
            .await;
    }

    let manager = make_multi_manager(&[&bn_a.uri(), &bn_b.uri()]);
    let result = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    match result {
        Err(BeaconError::NoEligibleBn { operation, role }) => {
            assert_eq!(operation, "produce_block_v4");
            assert_eq!(role, "proposal");
        }
        other => panic!("expected NoEligibleBn, got {other:?}"),
    }
    assert_eq!(v3_request_count(&bn_a).await, 0);
    assert_eq!(v3_request_count(&bn_b).await, 0);

    let again = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    match again {
        Err(BeaconError::NoEligibleBn { operation, role }) => {
            assert_eq!(operation, "produce_block_v4");
            assert_eq!(role, "proposal");
        }
        other => panic!("re-probe of all-incapable must stay NoEligibleBn, got {other:?}"),
    }
    assert_eq!(v3_request_count(&bn_a).await, 0);
    assert_eq!(v3_request_count(&bn_b).await, 0);
}

#[tokio::test]
async fn test_produce_block_v4_200_clears_capability_and_is_selectable() {
    let bn = MockServer::start().await;
    let slot_miss = 23u64;
    let slot_ok = 24u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot_miss)))
        .respond_with(ResponseTemplate::new(404).set_body_string("no /eth/v4"))
        .mount(&bn)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot_ok)))
        .respond_with(v4_json_success(slot_ok, 0x24, "2400"))
        .mount(&bn)
        .await;

    let manager = make_manager(&bn.uri());
    let first =
        manager.produce_block_v4(slot_miss, "0xrandao", None, &BuilderConfig::default()).await;
    match first {
        Err(BeaconError::NoEligibleBn { operation, .. }) => {
            assert_eq!(operation, "produce_block_v4");
        }
        other => panic!("single 404 BN must be NoEligibleBn, got {other:?}"),
    }
    {
        let trackers = manager.health_trackers().read().await;
        assert!(!trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
    }

    let recovered = manager
        .produce_block_v4(slot_ok, "0xrandao", None, &BuilderConfig::default())
        .await
        .unwrap();
    assert_eq!(recovered.execution_payload_value.as_deref(), Some("2400"));
    let endpoint = manager.health_trackers().read().await[0].endpoint().to_string();
    {
        let trackers = manager.health_trackers().read().await;
        assert!(
            trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4),
            "a subsequent 200 must clear the sticky capability flag"
        );
    }
    assert_eq!(capability_state(&endpoint, bn_capability::PRODUCE_BLOCK_V4), 1);

    let still = manager
        .produce_block_v4(slot_ok, "0xrandao", None, &BuilderConfig::default())
        .await
        .unwrap();
    assert_eq!(still.execution_payload_value.as_deref(), Some("2400"));
}

#[tokio::test]
async fn test_produce_block_v4_404_does_not_affect_duties_or_attestations() {
    let bn = MockServer::start().await;
    let slot = 25u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(ResponseTemplate::new(404).set_body_string("no /eth/v4"))
        .mount(&bn)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/5"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"dependent_root":"0xdef","execution_optimistic":false,"data":[]}"#,
        ))
        .mount(&bn)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", "100"))
        .and(query_param("committee_index", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"slot":"100","index":"0","beacon_block_root":"0xabc","source":{"epoch":"3","root":"0x01"},"target":{"epoch":"4","root":"0x02"}}}"#,
        ))
        .mount(&bn)
        .await;

    let manager = make_manager(&bn.uri());
    let v4 = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    assert!(
        matches!(v4, Err(BeaconError::NoEligibleBn { .. })),
        "v4 404 must not fall through to v3: {v4:?}"
    );

    let duties = manager.get_attester_duties(5, &["1".to_string()]).await;
    assert!(duties.is_ok(), "duty-fetch on the same BN must remain available: {duties:?}");
    let att = manager.get_attestation_data(100, 0).await;
    assert!(att.is_ok(), "attestation path on the same BN must remain available: {att:?}");

    {
        let trackers = manager.health_trackers().read().await;
        assert!(!trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
        assert!(trackers[0].is_capable("get_attester_duties"));
        assert!(trackers[0].is_capable("get_attestation_data"));
    }

    let v4_again =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    assert!(
        matches!(v4_again, Err(BeaconError::NoEligibleBn { .. })),
        "duties success must not clear produce_block_v4 capability: {v4_again:?}"
    );
}

#[tokio::test]
async fn test_produce_block_v4_unrecognised_fork_excludes_from_next_selection() {
    let unknown = MockServer::start().await;
    let ok = MockServer::start().await;
    let slot = 26u64;

    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"version": "gloas2", "data": {}}))
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "gloas2")
                .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true"),
        )
        .mount(&unknown)
        .await;
    Mock::given(method("POST"))
        .and(path(v4_blocks_path(slot)))
        .respond_with(v4_json_success(slot, 0x26, "2600"))
        .mount(&ok)
        .await;

    let manager = make_multi_manager(&[&unknown.uri(), &ok.uri()]);
    let first = manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await;
    assert!(
        matches!(first, Err(BeaconError::NoEligibleBn { .. } | BeaconError::ParseError(_))),
        "unrecognised fork must fail closed, not V3: {first:?}"
    );
    assert_eq!(ok.received_requests().await.unwrap().len(), 0, "2xx is not failover-retryable");

    {
        let mut trackers = manager.health_trackers().write().await;
        assert!(!trackers[0].is_capable(bn_capability::PRODUCE_BLOCK_V4));
        assert!(!trackers[0].is_capable(bn_capability::FORK_RECOGNISED));
        for _ in 0..20 {
            trackers[0].record_success(Duration::from_millis(1));
        }
    }

    let second =
        manager.produce_block_v4(slot, "0xrandao", None, &BuilderConfig::default()).await.unwrap();
    assert_eq!(second.execution_payload_value.as_deref(), Some("2600"));
    assert_eq!(unknown.received_requests().await.unwrap().len(), 1);
    assert_eq!(ok.received_requests().await.unwrap().len(), 1);
}

// -- Broadcast: submissions --

#[tokio::test]
async fn test_multi_broadcast_sends_to_all_bns() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.prepare_beacon_proposer(&[]).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
}

#[tokio::test]
async fn test_multi_broadcast_succeeds_if_one_bn_ok() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1 fails
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    // BN2 succeeds
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.prepare_beacon_proposer(&[]).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
}

#[tokio::test]
async fn test_multi_broadcast_fails_if_all_fail() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Unavailable"))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.prepare_beacon_proposer(&[]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_multi_broadcast_sync_messages() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/sync_committees"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/sync_committees"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.submit_sync_committee_messages(&[]).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/beacon/pool/sync_committees", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/beacon/pool/sync_committees", 1).await;
}

#[tokio::test]
async fn test_multi_broadcast_aggregate_proofs() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let proofs = VersionedSignedAggregateAndProof::PreElectra(vec![]);
    let result = manager.submit_aggregate_and_proofs(&proofs).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/validator/aggregate_and_proofs", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/validator/aggregate_and_proofs", 1).await;
}

#[tokio::test]
async fn test_multi_broadcast_committee_subscriptions() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.submit_beacon_committee_subscriptions(&[]).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/validator/beacon_committee_subscriptions", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/validator/beacon_committee_subscriptions", 1).await;
}

#[tokio::test]
async fn test_multi_broadcast_contribution_proofs() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/contribution_and_proofs"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/contribution_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let result = manager.submit_contribution_and_proofs(&[]).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/validator/contribution_and_proofs", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/validator/contribution_and_proofs", 1).await;
}

// ===================================================================
// Sync status integration tests
// ===================================================================

const SYNCED_RESPONSE: &str = r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#;
const SYNCING_SYNCING_RESPONSE: &str = r#"{"data":{"head_slot":"500","sync_distance":"500","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;
const EL_OFFLINE_RESPONSE: &str = r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":true}}"#;

#[tokio::test]
async fn test_sync_check_sync_status_marks_synced() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    manager.check_sync_status().await;

    let guard = manager.sync_statuses().read().await;
    assert_eq!(guard[0].status, BnSyncStatus::Synced);
}

#[tokio::test]
async fn test_sync_check_sync_status_marks_syncing() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    manager.check_sync_status().await;

    let guard = manager.sync_statuses().read().await;
    assert_eq!(guard[0].status, BnSyncStatus::Syncing);
}

#[tokio::test]
async fn test_sync_check_sync_status_marks_unreachable() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    manager.check_sync_status().await;

    let guard = manager.sync_statuses().read().await;
    assert_eq!(guard[0].status, BnSyncStatus::Unreachable);
}

#[tokio::test]
async fn test_sync_query_first_skips_unsynced_bn() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary: syncing, has genesis endpoint
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&primary)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(0) // Should NOT be called because primary is syncing
        .mount(&primary)
        .await;

    // Secondary: synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&secondary)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    manager.check_sync_status().await;

    let result = manager.get_genesis().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().data.genesis_time, "1606824023");
}

#[tokio::test]
async fn test_sync_query_first_falls_back_when_all_unsynced() {
    let primary = MockServer::start().await;

    // Syncing but still the only BN — should be used with warning
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&primary)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&primary)
        .await;

    let manager = make_manager(&primary.uri());
    manager.check_sync_status().await;

    // Should still work despite syncing status (single-BN fallback)
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_sync_query_best_skips_unsynced_bn() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1: syncing
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "9999")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(0) // Should NOT be called
        .mount(&bn1)
        .await;

    // BN2: synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn2)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "5000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().execution_payload_value, Some("5000".to_string()));
}

#[tokio::test]
async fn test_sync_broadcast_sends_to_all_regardless_of_sync_status() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1: syncing
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&bn1)
        .await;

    // BN2: synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn2)
        .await;

    // Both should receive the broadcast
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    let result = manager.prepare_beacon_proposer(&[]).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
}

#[tokio::test]
async fn test_sync_start_sync_monitor() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let handle = manager.start_sync_monitor(Some(Duration::from_millis(50)), shutdown_rx);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let guard = manager.sync_statuses().read().await;
    assert_eq!(guard[0].status, BnSyncStatus::Synced);
    drop(guard);

    shutdown_tx.send(true).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn test_sync_multi_bn_all_unsynced_falls_back_to_all() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Both syncing
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&bn2)
        .await;

    // BN1 fails genesis, BN2 succeeds — tests that fallback tries all
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_sync_query_best_falls_back_to_unsynced_when_synced_fail() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1: synced but block production fails
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(2)
        .mount(&bn1)
        .await;

    // BN2 starts below the fallback floor. One sync read consumes this mock;
    // the small-lag mock mounted later is what the duty call sees.
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .up_to_n_times(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    // No known parent: a distance-500 node is below the fallback floor and
    // produce_block_v3 does not fall back.
    let without_parent = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(
        without_parent.is_err(),
        "unsynced fallback requires a known parent: {without_parent:?}"
    );

    // Same nodes, but BN2 is small-lag and the parent is known.
    let parent = [0xabu8; 32];
    let body = produce_json(preparable_data("full", 1, 0, &"ab".repeat(32), false));
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"head_slot":"991","sync_distance":"9","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#,
        ))
        .mount(&bn2)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "7000")
                .set_body_string(body),
        )
        .expect(1)
        .mount(&bn2)
        .await;
    manager.check_sync_status().await;
    let result = manager
        .produce_block_v3_for_duty(
            1,
            "0xrandao",
            None,
            None,
            ProduceDuty {
                expected_proposer_index: 0,
                expected_parent_root: Some(parent),
                alternate_parent_root: None,
                parent_closed: false,
                expected_fee_recipient: None,
                expected_consensus_version: ForkName::Deneb,
                shape: ShapeConstraint::Any,
            },
        )
        .await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(result.unwrap().execution_payload_value, Some("7000".to_string()));
}

#[tokio::test]
async fn test_sync_initial_status_is_unknown() {
    // Before any sync check, all BNs default to Unknown
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());

    let guard = manager.sync_statuses().read().await;
    assert_eq!(guard[0].status, BnSyncStatus::Unknown);
    drop(guard);

    // Without calling check_sync_status, BN should still be tried via fallback
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

// ===================================================================
// Health scoring tests
// ===================================================================

#[tokio::test]
async fn test_health_scores_tracked_after_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    let _ = manager.get_genesis().await.unwrap();

    let scores = manager.health_scores().await;
    assert_eq!(scores.len(), 1);
    assert!(scores[0].latency_ms > 0.0, "latency should be recorded");
    assert_eq!(scores[0].error_rate, 0.0);
    assert!(scores[0].score > 0.5, "score should be high after success");
}

#[tokio::test]
async fn test_health_scores_tracked_after_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    let _ = manager.get_genesis().await;

    let scores = manager.health_scores().await;
    assert_eq!(scores[0].error_rate, 1.0);
    assert!(scores[0].score < 0.5, "score should be low after error");
}

#[tokio::test]
async fn test_health_scores_tracked_in_broadcast() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let _ = manager.prepare_beacon_proposer(&[]).await;

    poll_broadcast_health(&manager, |scores| {
        scores[0].error_rate == 0.0 && scores[0].score > 0.8 && scores[1].error_rate == 1.0
    })
    .await;
    let scores = manager.health_scores().await;
    // BN1 succeeded
    assert_eq!(scores[0].error_rate, 0.0);
    // BN2 failed
    assert_eq!(scores[1].error_rate, 1.0);
}

#[tokio::test]
async fn test_health_healthy_bn_preferred_in_failover() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Both synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    // Degrade BN1 health by recording errors
    {
        let mut guard = manager.health_trackers().write().await;
        for _ in 0..50 {
            guard[0].record_error();
        }
        // BN2 is healthy — record successes
        for _ in 0..50 {
            guard[1].record_success(Duration::from_millis(10));
        }
    }

    // BN2 should be tried first (higher score) due to health ordering
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&bn2)
        .await;

    // BN1 should NOT be called (BN2 succeeds first)
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(0)
        .mount(&bn1)
        .await;

    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_health_unhealthy_bn_excluded() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Both synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    // Make BN1 unhealthy (100% error rate → score=0.2, below 0.2 threshold)
    {
        let mut guard = manager.health_trackers().write().await;
        for _ in 0..100 {
            guard[0].record_error();
        }
        // BN2 is healthy
        for _ in 0..10 {
            guard[1].record_success(Duration::from_millis(50));
        }
    }

    // Only BN2 should be called
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&bn2)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(0)
        .mount(&bn1)
        .await;

    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_health_recovery_readds_bn() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Both synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    // Make BN1 unhealthy
    {
        let mut guard = manager.health_trackers().write().await;
        for _ in 0..100 {
            guard[0].record_error();
        }
        for _ in 0..10 {
            guard[1].record_success(Duration::from_millis(50));
        }
    }

    // Verify BN1 is excluded
    let guard = manager.health_trackers().read().await;
    assert!(!guard[0].is_healthy());
    drop(guard);

    // Now recover BN1 by adding many successes
    {
        let mut guard = manager.health_trackers().write().await;
        for _ in 0..100 {
            guard[0].record_success(Duration::from_millis(20));
        }
    }

    // BN1 should be healthy again
    let guard = manager.health_trackers().read().await;
    assert!(guard[0].is_healthy());
    drop(guard);

    // BN1 (now recovered & low latency) should have higher score than BN2
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(0)
        .mount(&bn2)
        .await;

    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_health_all_unhealthy_falls_back_to_all() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Both synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn1)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    // Make both unhealthy
    {
        let mut guard = manager.health_trackers().write().await;
        for _ in 0..100 {
            guard[0].record_error();
            guard[1].record_error();
        }
    }

    // Should still work despite both being unhealthy (fallback to all)
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&bn1)
        .await;

    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_health_scores_accumulate_over_operations() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());

    // Multiple operations should update EMA
    for _ in 0..5 {
        let _ = manager.get_genesis().await.unwrap();
    }

    let scores = manager.health_scores().await;
    assert!(scores[0].latency_ms > 0.0);
    assert_eq!(scores[0].error_rate, 0.0);
    assert!(scores[0].score > 0.9, "should be very healthy after 5 successes");
}

#[tokio::test]
async fn test_health_best_strategy_records_health() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1 returns lower value block
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "1000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .mount(&bn1)
        .await;

    // BN2 returns higher value block
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "5000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    let _ = manager.produce_block_v3(1, "0xrandao", None, None).await.unwrap();

    // Health is queued and applied after the call returns.
    poll_broadcast_health(&manager, |scores| {
        scores[0].latency_ms > 0.0 && scores[1].latency_ms > 0.0
    })
    .await;
    let scores = manager.health_scores().await;
    assert!(scores[0].latency_ms > 0.0, "BN1 latency should be tracked");
    assert!(scores[1].latency_ms > 0.0, "BN2 latency should be tracked");
    assert_eq!(scores[0].error_rate, 0.0);
    assert_eq!(scores[1].error_rate, 0.0);
}

// -- get_node_version tests --

#[tokio::test]
async fn test_get_node_version_via_trait() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"version":"Lighthouse/v7.1.0-a1b2c3d/x86_64-linux"}}"#,
            ),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = beacon::BeaconClientConfig::new(mock_server.uri());
    let client = BeaconClient::new(config).unwrap();
    let dyn_client: &dyn BeaconNodeClient = &client;
    let version = dyn_client.get_node_version().await.unwrap();
    assert_eq!(version, "Lighthouse/v7.1.0-a1b2c3d/x86_64-linux");
}

#[tokio::test]
async fn test_get_node_version_bn_manager_delegates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":{"version":"Prysm/v5.0.0/linux-amd64"}}"#),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let manager = make_manager(&mock_server.uri());
    let version = manager.get_node_version().await.unwrap();
    assert_eq!(version, "Prysm/v5.0.0/linux-amd64");
}

#[tokio::test]
async fn test_get_node_version_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&primary)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&secondary)
        .await;

    // Primary fails
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(ResponseTemplate::new(500).set_body_string("error"))
        .expect(1)
        .mount(&primary)
        .await;

    // Secondary succeeds
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"data":{"version":"Teku/v24.0.0"}}"#),
        )
        .expect(1)
        .mount(&secondary)
        .await;

    let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
    let version = manager.get_node_version().await.unwrap();
    assert_eq!(version, "Teku/v24.0.0");
}

#[tokio::test]
async fn test_health_scores_reflect_sync_status_synced() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());

    // Set sync status to Synced
    {
        let mut statuses = manager.sync_statuses().write().await;
        statuses[0] = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(0),
            head_slot: Some(1000),
            is_optimistic: false,
            el_offline: false,
        };
    }

    let scores = manager.health_scores().await;
    assert_eq!(scores.len(), 1);
    assert!(scores[0].is_reachable);
    assert!(scores[0].is_synced);
    assert_eq!(scores[0].head_slot, Some(1000));
}

#[tokio::test]
async fn test_health_scores_reflect_sync_status_syncing() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());

    // Set sync status to Syncing
    {
        let mut statuses = manager.sync_statuses().write().await;
        statuses[0] = BnSyncDetail {
            status: BnSyncStatus::Syncing,
            sync_distance: Some(100),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
    }

    let scores = manager.health_scores().await;
    assert!(scores[0].is_reachable);
    assert!(!scores[0].is_synced);
}

#[tokio::test]
async fn test_health_scores_reflect_sync_status_unreachable() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());

    // Set sync status to Unreachable
    {
        let mut statuses = manager.sync_statuses().write().await;
        statuses[0] = BnSyncDetail {
            status: BnSyncStatus::Unreachable,
            sync_distance: None,
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
    }

    let scores = manager.health_scores().await;
    assert!(!scores[0].is_reachable);
    assert!(!scores[0].is_synced);
}

#[tokio::test]
async fn test_health_scores_reflect_sync_status_unknown() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    // Default is Unknown — don't set anything

    let scores = manager.health_scores().await;
    // Unknown is not unreachable (we don't know), but not synced either
    assert!(scores[0].is_reachable);
    assert!(!scores[0].is_synced);
}

// -- Per-operation timeout tests --

#[tokio::test]
async fn test_operation_timeout_fires_on_slow_bn() {
    let server = MockServer::start().await;

    // Simulate a slow BN: 10s delay on attestation data endpoint
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"{"data":{"slot":"1","index":"0","beacon_block_root":"0x0000000000000000000000000000000000000000000000000000000000000000","source":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"}}}"#,
                )
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&server)
        .await;

    let config = BnManagerConfig::new(vec![server.uri()]);
    let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
        attestation_fetch: Duration::from_millis(100),
        ..OperationTimeouts::default()
    });

    let start = tokio::time::Instant::now();
    let result = manager.get_attestation_data(1, 0).await;
    let elapsed = start.elapsed();

    assert!(result.is_err());
    let err = result.unwrap_err();
    // The absolute deadline is taken before the attempt, so the recorded bound
    // is the time still left: at most the configured 100ms, not that duration
    // exactly, and not the attempt floor.
    assert!(
        matches!(&err, BeaconError::OperationTimeout { operation, timeout }
            if operation == "get_attestation_data"
                && *timeout <= Duration::from_millis(100)
                && *timeout > Duration::from_millis(50)),
        "expected OperationTimeout inside the 100ms budget, got: {err}"
    );
    assert!(elapsed < Duration::from_secs(2), "should have timed out quickly, took {elapsed:?}");
}

#[tokio::test]
async fn test_no_operation_timeout_completes_normally() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"slot":"1","index":"0","beacon_block_root":"0x0000000000000000000000000000000000000000000000000000000000000000","source":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"}}}"#,
            ),
        )
        .mount(&server)
        .await;

    // No operation_timeouts set
    let manager = make_manager(&server.uri());

    let result = manager.get_attestation_data(1, 0).await;
    assert!(result.is_ok(), "should succeed without per-op timeout: {:?}", result.err());
}

#[tokio::test]
async fn test_operation_timeout_on_block_production() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"{"version":"deneb","execution_payload_blinded":false,"execution_payload_value":"0","consensus_block_value":"0","data":{}}"#,
                )
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&server)
        .await;

    let config = BnManagerConfig::new(vec![server.uri()]);
    let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
        block_production: Duration::from_millis(100),
        ..OperationTimeouts::default()
    });

    let result = manager.produce_block_v3(1, "0xabc", None, None).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), BeaconError::OperationTimeout { operation, .. } if operation == "produce_block_v3"),
    );
}

#[tokio::test]
async fn test_operation_timeout_on_duty_fetch() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"{"dependent_root":"0x0000000000000000000000000000000000000000000000000000000000000000","execution_optimistic":false,"data":[]}"#,
                )
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&server)
        .await;

    let config = BnManagerConfig::new(vec![server.uri()]);
    let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
        duty_fetch: Duration::from_millis(100),
        ..OperationTimeouts::default()
    });

    let result = manager.get_proposer_duties(1, &ForkSchedule::unscheduled_gloas()).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), BeaconError::OperationTimeout { operation, .. } if operation == "get_proposer_duties"),
    );
}

// ===================================================================
// EL-offline sync status integration tests
// ===================================================================

#[tokio::test]
async fn test_el_offline_bn_marks_el_offline_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(EL_OFFLINE_RESPONSE))
        .mount(&server)
        .await;

    let manager = make_manager(&server.uri());
    manager.check_sync_status().await;

    let guard = manager.sync_statuses().read().await;
    assert_eq!(guard[0].status, BnSyncStatus::ElOffline);
}

#[tokio::test]
async fn test_el_offline_bn_used_for_non_el_operations() {
    let el_offline_bn = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(EL_OFFLINE_RESPONSE))
        .mount(&el_offline_bn)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&el_offline_bn)
        .await;

    let manager = make_manager(&el_offline_bn.uri());
    manager.check_sync_status().await;

    // get_genesis is non-EL, so ElOffline BN should be used
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().data.genesis_time, "1606824023");
}

#[tokio::test]
async fn test_el_offline_bn_skipped_for_block_production() {
    let el_offline_bn = MockServer::start().await;
    let synced_bn = MockServer::start().await;

    // BN1: EL offline
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(EL_OFFLINE_RESPONSE))
        .mount(&el_offline_bn)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "9999")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(0) // Should NOT be called — EL offline
        .mount(&el_offline_bn)
        .await;

    // BN2: synced
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&synced_bn)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "5000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&synced_bn)
        .await;

    let manager = make_multi_manager(&[&el_offline_bn.uri(), &synced_bn.uri()]);
    manager.check_sync_status().await;

    // produce_block_v3 is EL-dependent, so ElOffline BN should be skipped
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().execution_payload_value, Some("5000".to_string()));
}

#[tokio::test]
async fn test_el_offline_bn_preferred_over_syncing_for_duties() {
    let el_offline_bn = MockServer::start().await;
    let syncing_bn = MockServer::start().await;

    // BN1: EL offline (CL is synced)
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(EL_OFFLINE_RESPONSE))
        .mount(&el_offline_bn)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(1)
        .mount(&el_offline_bn)
        .await;

    // BN2: syncing
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&syncing_bn)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .expect(0) // Should NOT be called — syncing BN is less preferred
        .mount(&syncing_bn)
        .await;

    let manager = make_multi_manager(&[&el_offline_bn.uri(), &syncing_bn.uri()]);
    manager.check_sync_status().await;

    // get_genesis is non-EL: ElOffline BN should be used, Syncing BN should be skipped
    let result = manager.get_genesis().await;
    assert!(result.is_ok());
}

// ===================================================================
// Broadcast partial failure tests
// ===================================================================

#[tokio::test]
async fn test_broadcast_partial_failure_still_succeeds() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1: returns 400 for prepare_beacon_proposer
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .expect(1)
        .mount(&bn1)
        .await;

    // BN2: returns 200
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);

    // Overall result should be Ok despite BN1 failing
    let result = manager.prepare_beacon_proposer(&[]).await;
    assert!(result.is_ok());
    poll_received(&bn1, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
    poll_received(&bn2, "POST", "/eth/v1/validator/prepare_beacon_proposer", 1).await;
}

#[tokio::test]
async fn test_broadcast_all_fail_returns_error() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // Both BNs return 500
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .expect(1)
        .mount(&bn1)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);

    let result = manager.prepare_beacon_proposer(&[]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_broadcast_partial_failure_records_health() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;

    // BN1: returns 400
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&bn1)
        .await;

    // BN2: returns 200
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/prepare_beacon_proposer"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);

    let _ = manager.prepare_beacon_proposer(&[]).await;

    poll_broadcast_health(&manager, |scores| {
        scores[0].error_rate == 1.0 && scores[1].error_rate == 0.0 && scores[1].score > 0.8
    })
    .await;
    // BN1 should have error recorded, BN2 should have success
    let health = manager.health_trackers().read().await;
    assert!(health[0].score() < health[1].score());
}

// ===================================================================
// RF4-26: batched health updates + submit() topic dispatch
// ===================================================================

fn sample_signed_block() -> SignedBeaconBlock {
    SignedBeaconBlock {
        message: eth_types::external_vector_deneb_block(),
        signature: vec![0xaa; 96],
    }
}

fn sample_signed_blinded_block() -> SignedBlindedBeaconBlock {
    SignedBlindedBeaconBlock {
        message: eth_types::external_vector_deneb_blinded_block(),
        signature: vec![0xbb; 96],
    }
}

/// `message.body` must be a JSON object. A hex string does not match.
struct MessageBodyObject;

impl wiremock::Match for MessageBodyObject {
    fn matches(&self, request: &wiremock::Request) -> bool {
        serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|value| value.pointer("/message/body").cloned())
            .is_some_and(|body| body.is_object())
    }
}

fn blinded_post_body(requests: &[wiremock::Request]) -> serde_json::Value {
    let post = requests
        .iter()
        .find(|req| {
            req.method.as_str() == "POST" && req.url.path() == "/eth/v1/beacon/blinded_blocks"
        })
        .expect("blinded publish");
    serde_json::from_slice(&post.body).expect("json body")
}

/// A best-of round queues one health sample per BN. The call returns without
/// waiting on the health write lock; the recorder applies the samples after.
#[tokio::test]
async fn test_health_tracker_write_lock_taken_once_per_selection_round() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;
    let bn3 = MockServer::start().await;

    for bn in [&bn1, &bn2, &bn3] {
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(bn)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Eth-Consensus-Version", "deneb")
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Execution-Payload-Value", "1000")
                    .set_body_string(
                        r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#,
                    ),
            )
            .expect(1)
            .mount(bn)
            .await;
    }

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri(), &bn3.uri()]);
    manager.check_sync_status().await;

    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());

    poll_broadcast_health(&manager, |scores| scores.iter().all(|score| score.latency_ms > 0.0))
        .await;
}

/// Fallback health is queued per attempt. The block is returned without
/// waiting on the health write lock.
#[tokio::test]
async fn test_health_tracker_write_lock_once_on_unsynced_fallback() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;
    let bn3 = MockServer::start().await;

    // BN1: synced but production fails
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&bn1)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn1)
        .await;

    // BN2, BN3: small lag (above the fallback floor); BN2 fails, BN3 succeeds.
    const SMALL_LAG_RESPONSE: &str = r#"{"data":{"head_slot":"991","sync_distance":"9","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;
    for bn in [&bn2, &bn3] {
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SMALL_LAG_RESPONSE))
            .mount(bn)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn2)
        .await;
    let parent = [0xabu8; 32];
    let body = produce_json(preparable_data("full", 1, 0, &"ab".repeat(32), false));
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "7000")
                .set_body_string(body),
        )
        .expect(1)
        .mount(&bn3)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri(), &bn3.uri()]);
    manager.check_sync_status().await;

    let result = manager
        .produce_block_v3_for_duty(
            1,
            "0xrandao",
            None,
            None,
            ProduceDuty {
                expected_proposer_index: 0,
                expected_parent_root: Some(parent),
                alternate_parent_root: None,
                parent_closed: false,
                expected_fee_recipient: None,
                expected_consensus_version: ForkName::Deneb,
                shape: ShapeConstraint::Any,
            },
        )
        .await;
    assert!(result.is_ok(), "{result:?}");

    poll_broadcast_health(&manager, |scores| {
        scores[0].error_rate == 1.0 && scores[1].error_rate == 1.0 && scores[2].latency_ms > 0.0
    })
    .await;
}

/// Each of the six topic-gated submission methods respects its broadcast flag:
/// topic on → both BNs receive; topic off → only the primary (query_first).
#[tokio::test]
async fn test_submit_helper_respects_each_broadcast_topic_flag() {
    // -- sync_committee --
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v1/beacon/pool/sync_committees"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.sync_committee = true;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_sync_committee_messages(&[]).await.is_ok());
        poll_received(&bn1, "POST", "/eth/v1/beacon/pool/sync_committees", 1).await;
        poll_received(&bn2, "POST", "/eth/v1/beacon/pool/sync_committees", 1).await;
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&bn2)
            .await;
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.sync_committee = false;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_sync_committee_messages(&[]).await.is_ok());
    }

    // -- subscriptions --
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.subscriptions = true;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_beacon_committee_subscriptions(&[]).await.is_ok());
        poll_received(&bn1, "POST", "/eth/v1/validator/beacon_committee_subscriptions", 1).await;
        poll_received(&bn2, "POST", "/eth/v1/validator/beacon_committee_subscriptions", 1).await;
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&bn2)
            .await;
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.subscriptions = false;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_beacon_committee_subscriptions(&[]).await.is_ok());
    }

    // -- attestations --
    let empty_atts = VersionedAttestation::Electra(vec![]);
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v2/beacon/pool/attestations"))
                .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.attestations = true;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_attestation(&empty_atts).await.is_ok());
        poll_received(&bn1, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
        poll_received(&bn2, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .expect(0)
            .mount(&bn2)
            .await;
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.attestations = false;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_attestation(&empty_atts).await.is_ok());
    }

    // -- payload attestations (shares attestations topic) --
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v1/beacon/pool/payload_attestations"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.attestations = true;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_payload_attestations(&[]).await.is_ok());
        poll_received(&bn1, "POST", "/eth/v1/beacon/pool/payload_attestations", 1).await;
        poll_received(&bn2, "POST", "/eth/v1/beacon/pool/payload_attestations", 1).await;
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/payload_attestations"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/payload_attestations"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&bn2)
            .await;
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.attestations = false;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.submit_payload_attestations(&[]).await.is_ok());
    }

    // -- blocks (publish_block) --
    let signed = sample_signed_block();
    {
        let bn = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .and(MessageBodyObject)
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn)
            .await;
        let manager = BnManager::new(BnManagerConfig::new(vec![bn.uri()])).unwrap();
        assert!(manager.publish_block(&signed, "deneb", None).await.is_ok());
        let requests = bn.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert!(
            body["message"]["body"].is_object(),
            "bare Deneb publish body is an object: {body}"
        );
        assert!(body.get("signed_block").is_none(), "bare block is not block contents");
        let hex_body = serde_json::to_value(&signed).unwrap();
        assert!(hex_body["message"]["body"].is_string(), "in-memory body stays hex");
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v2/beacon/blocks"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.blocks = true;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.publish_block(&signed, "deneb", None).await.is_ok());
        poll_received(&bn1, "POST", "/eth/v2/beacon/blocks", 1).await;
        poll_received(&bn2, "POST", "/eth/v2/beacon/blocks", 1).await;
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&bn2)
            .await;
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.blocks = false;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.publish_block(&signed, "deneb", None).await.is_ok());
    }

    // -- blocks (publish_blinded_block) shares the same topic flag --
    let blinded = sample_signed_blinded_block();
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v1/beacon/blinded_blocks"))
                .and(MessageBodyObject)
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.blocks = true;
        let manager = BnManager::new(config).unwrap();
        let body_before = blinded.message.body.clone();
        assert!(manager.publish_blinded_block(&blinded, "deneb").await.is_ok());
        assert_eq!(blinded.message.body, body_before);
        poll_received(&bn1, "POST", "/eth/v1/beacon/blinded_blocks", 1).await;
        poll_received(&bn2, "POST", "/eth/v1/beacon/blinded_blocks", 1).await;
        let left = bn1.received_requests().await.expect("bn1");
        let right = bn2.received_requests().await.expect("bn2");
        let left_body = blinded_post_body(&left);
        let right_body = blinded_post_body(&right);
        assert_eq!(left_body, right_body, "both nodes receive the one prebuilt JSON body");
        assert!(left_body["message"]["body"].is_object());
        assert!(left_body["message"]["body"]["execution_payload_header"].is_object());
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/blinded_blocks"))
            .and(MessageBodyObject)
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/blinded_blocks"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&bn2)
            .await;
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.blocks = false;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.publish_blinded_block(&blinded, "deneb").await.is_ok());
    }
}

#[tokio::test]
async fn publish_blinded_block_rejects_unsupported_forks_and_invalid_ssz_before_any_post() {
    let bn = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&bn)
        .await;
    let mut config = BnManagerConfig::new(vec![bn.uri()]);
    config.broadcast_topics.blocks = true;
    let manager = BnManager::new(config).unwrap();
    let signed = sample_signed_blinded_block();

    for version in ["phase0", "altair", "bellatrix", "capella", "DENEB", ""] {
        let err = manager.publish_blinded_block(&signed, version).await.expect_err(version);
        match err {
            BeaconError::ParseError(msg) => {
                assert_eq!(
                    msg,
                    format!("JSON blinded block is unsupported for consensus version {version}"),
                    "{version}"
                );
            }
            other => panic!("{version}: {other:?}"),
        }
    }

    let gloas = manager.publish_blinded_block(&signed, "gloas").await.expect_err("gloas");
    match gloas {
        BeaconError::ParseError(msg) => {
            assert_eq!(
                msg,
                "invalid JSON blinded block body: Gloas BeaconBlockBody layout is not supported"
            );
        }
        other => panic!("{other:?}"),
    }

    let mut garbage = signed.clone();
    garbage.message.body = vec![0xbe, 0xef];
    let err = manager.publish_blinded_block(&garbage, "deneb").await.expect_err("bad ssz");
    match err {
        BeaconError::ParseError(msg) => {
            assert!(
                msg.starts_with("invalid JSON blinded block body: invalid SSZ body encoding:"),
                "{msg}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(bn.received_requests().await.expect("requests").is_empty());
}

#[tokio::test]
async fn concurrent_blinded_publishes_keep_each_body() {
    let bn = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .and(MessageBodyObject)
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&bn)
        .await;
    let mut config = BnManagerConfig::new(vec![bn.uri()]);
    config.broadcast_topics.blocks = false;
    let manager = Arc::new(BnManager::new(config).unwrap());
    let deneb = sample_signed_blinded_block();
    let electra = SignedBlindedBeaconBlock {
        message: eth_types::external_vector_electra_blinded_block(),
        signature: vec![0xcc; 96],
    };
    let left = manager.clone();
    let right = manager.clone();
    let deneb_publish = deneb.clone();
    let electra_publish = electra.clone();
    let (first, second) = tokio::join!(
        left.publish_blinded_block(&deneb_publish, "deneb"),
        right.publish_blinded_block(&electra_publish, "electra"),
    );
    assert!(first.is_ok(), "{first:?}");
    assert!(second.is_ok(), "{second:?}");
    assert_eq!(deneb.message.body, deneb_publish.message.body);
    assert_eq!(electra.message.body, electra_publish.message.body);

    let requests = bn.received_requests().await.expect("requests");
    let posts: Vec<serde_json::Value> = requests
        .iter()
        .filter(|req| req.url.path() == "/eth/v1/beacon/blinded_blocks")
        .map(|req| serde_json::from_slice(&req.body).expect("json"))
        .collect();
    assert_eq!(posts.len(), 2);
    let graffiti: Vec<_> = posts
        .iter()
        .map(|post| post["message"]["body"]["graffiti"].as_str().expect("graffiti").to_string())
        .collect();
    let deneb_json = eth_types::SignedBlindedBeaconBlockJson::from_signed_blinded(
        &deneb,
        eth_types::BodyForkLayout::Deneb,
    )
    .expect("deneb")
    .message
    .body;
    let electra_json = eth_types::SignedBlindedBeaconBlockJson::from_signed_blinded(
        &electra,
        eth_types::BodyForkLayout::Electra,
    )
    .expect("electra")
    .message
    .body;
    assert!(graffiti.contains(&deneb_json["graffiti"].as_str().unwrap().to_string()));
    assert!(graffiti.contains(&electra_json["graffiti"].as_str().unwrap().to_string()));
    assert!(posts.iter().all(|post| post["message"]["body"].is_object()));
    assert_ne!(deneb_json["graffiti"], electra_json["graffiti"]);
}

/// A fast 400 partial failure does not win. The slow 200 is kept, so the
/// propagator reports no per-validator failure and none is marked rejected.
#[tokio::test]
async fn submit_attestation_attributed_prefers_a_later_complete_success() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;
    let partial = serde_json::json!({
        "code": 400,
        "message": "some failures",
        "failures": [{ "index": 0, "message": "invalid signature" }]
    });
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(400).set_body_json(partial))
        .expect(1)
        .mount(&bn1)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("[]").set_delay(Duration::from_millis(40)),
        )
        .expect(1)
        .mount(&bn2)
        .await;

    let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
    config.broadcast_topics.attestations = true;
    let manager = Arc::new(BnManager::new(config).unwrap());
    let attestation = VersionedAttestation::Electra(vec![SingleAttestation {
        committee_index: 0,
        attester_index: 7,
        data: AttestationData {
            slot: "1".to_string(),
            index: "0".to_string(),
            beacon_block_root: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            source: Checkpoint {
                epoch: "0".to_string(),
                root: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            },
            target: Checkpoint {
                epoch: "1".to_string(),
                root: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            },
        },
        signature: "0x00".to_string(),
    }]);
    let outcome = Propagator::new(Arc::clone(&manager))
        .propagate_indexed(&attestation)
        .await
        .expect("attributed submit");

    assert_eq!(outcome.reported_by.as_deref(), Some(bn2.uri().as_str()));
    assert_eq!(outcome.success_count, 1);
    assert!(
        outcome.failures.is_empty(),
        "a complete success must not mark a validator rejected: {outcome:?}"
    );
    poll_received(&bn1, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
    poll_received(&bn2, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
}

#[tokio::test]
async fn submit_attestation_attributed_names_the_query_first_bn() {
    let bn1 = MockServer::start().await;
    let bn2 = MockServer::start().await;
    let partial = serde_json::json!({
        "code": 400,
        "message": "some failures",
        "failures": [{ "index": 2, "message": "invalid signature" }]
    });
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(400).set_body_json(partial))
        .expect(1)
        .mount(&bn1)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
        .expect(0)
        .mount(&bn2)
        .await;

    let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
    config.broadcast_topics.attestations = false;
    let manager = BnManager::new(config).unwrap();
    let (reported_by, result) = manager
        .submit_attestation_attributed(&VersionedAttestation::Electra(vec![]))
        .await
        .expect("attributed query-first submit");

    assert_eq!(reported_by, Some(bn1.uri()));
    match result {
        SubmitAttestationResult::PartialFailure { failures } => {
            assert_eq!(failures[0].index, 2);
        }
        other => panic!("expected partial failure from the answering BN, got {other:?}"),
    }
}

// ===================================================================
// ARCH-7k: honour BnRole on broadcast (role yes, tier no)
// ===================================================================

fn role_set(role: BnRole) -> HashSet<BnRole> {
    HashSet::from([role])
}

async fn mount_attestation_publish(server: &MockServer, expect: u64) {
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/pool/attestations"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
        .expect(expect)
        .mount(server)
        .await;
}

/// Capture `tried` recorded on `bn.strategy.broadcast` (creation + later `record`).
async fn with_broadcast_tried<T>(fut: impl std::future::Future<Output = T>) -> (T, Option<u64>) {
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Record};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    #[derive(Clone, Default)]
    struct TriedCap(Arc<std::sync::Mutex<Option<u64>>>);

    struct TriedVisitor<'a>(&'a mut Option<u64>);
    impl Visit for TriedVisitor<'_> {
        fn record_u64(&mut self, field: &Field, value: u64) {
            if field.name() == "tried" {
                *self.0 = Some(value);
            }
        }
        fn record_i64(&mut self, field: &Field, value: i64) {
            if field.name() == "tried" {
                *self.0 = Some(value as u64);
            }
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "tried" {
                if let Ok(v) = format!("{value:?}").parse::<u64>() {
                    *self.0 = Some(v);
                }
            }
        }
    }

    impl<S> Layer<S> for TriedCap
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &tracing::Id, ctx: Context<'_, S>) {
            let Some(span) = ctx.span(id) else {
                return;
            };
            if span.name() != "bn.strategy.broadcast" {
                return;
            }
            if let Ok(mut slot) = self.0.lock() {
                attrs.record(&mut TriedVisitor(&mut slot));
            }
        }

        fn on_record(&self, id: &tracing::Id, values: &Record<'_>, ctx: Context<'_, S>) {
            let Some(span) = ctx.span(id) else {
                return;
            };
            if span.name() != "bn.strategy.broadcast" {
                return;
            }
            if let Ok(mut slot) = self.0.lock() {
                values.record(&mut TriedVisitor(&mut slot));
            }
        }
    }

    let cap = TriedCap::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let result = fut.await;
    let tried = *cap.0.lock().expect("tried cap lock");
    (result, tried)
}

/// RED first (ARCH-7k): three BNs {Attestation}/{Proposal}/{All}; attestation
/// publish must skip the Proposal-only ("block") BN and record `tried = 2`.
#[tokio::test(flavor = "current_thread")]
async fn test_broadcast_reaches_only_the_matching_role() {
    let attestation_bn = MockServer::start().await;
    let block_bn = MockServer::start().await;
    let all_bn = MockServer::start().await;

    mount_attestation_publish(&attestation_bn, 1).await;
    mount_attestation_publish(&block_bn, 0).await;
    mount_attestation_publish(&all_bn, 1).await;

    let mut config = BnManagerConfig::new(vec![attestation_bn.uri(), block_bn.uri(), all_bn.uri()]);
    config.roles =
        vec![role_set(BnRole::Attestation), role_set(BnRole::Proposal), role_set(BnRole::All)];
    let manager = BnManager::new(config).unwrap();

    let empty = VersionedAttestation::Electra(vec![]);
    let (result, tried) = with_broadcast_tried(manager.submit_attestation(&empty)).await;
    assert!(result.is_ok(), "attestation broadcast must succeed: {result:?}");
    assert_eq!(tried, Some(2), "tried must be the role-filtered count, not clients.len()=3");
    poll_received(&attestation_bn, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
    poll_received(&all_bn, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
}

/// Guard on the ARCH-P2-8 narrowing: broadcast is role-filtered, never tier-filtered.
/// A BN below the healthy tier must still receive an already-signed publish.
#[tokio::test]
async fn test_broadcast_is_not_tier_filtered() {
    let synced = MockServer::start().await;
    let unsynced = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
        .mount(&synced)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&unsynced)
        .await;

    mount_attestation_publish(&synced, 1).await;
    mount_attestation_publish(&unsynced, 1).await;

    let manager = make_multi_manager(&[&synced.uri(), &unsynced.uri()]);
    manager.check_sync_status().await;

    {
        let guard = manager.sync_statuses().read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Synced);
        assert_eq!(guard[1].status, BnSyncStatus::Syncing);
        assert!(
            guard[1].tier(&rvc_bn_manager::TierThresholds::default())
                > rvc_bn_manager::HealthTier::Synced,
            "second BN must sit below the healthy tier so a later tier cut would drop it"
        );
    }

    let empty = VersionedAttestation::Electra(vec![]);
    let result = manager.submit_attestation(&empty).await;
    assert!(result.is_ok(), "unsynced BN must still receive the publish: {result:?}");
    poll_received(&synced, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
    poll_received(&unsynced, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
}

/// Pins All-role fallback: no Attestation specialist → All-role BN is used.
/// Off-role-only fleets fail closed: zero publishes, typed `NoEligibleBn`.
#[tokio::test(flavor = "current_thread")]
async fn test_broadcast_falls_back_to_all_role_when_no_bn_matches() {
    let proposal_bn = MockServer::start().await;
    let all_bn = MockServer::start().await;

    mount_attestation_publish(&proposal_bn, 0).await;
    mount_attestation_publish(&all_bn, 1).await;

    let mut config = BnManagerConfig::new(vec![proposal_bn.uri(), all_bn.uri()]);
    config.roles = vec![role_set(BnRole::Proposal), role_set(BnRole::All)];
    let manager = BnManager::new(config).unwrap();

    let empty = VersionedAttestation::Electra(vec![]);
    let (result, tried) = with_broadcast_tried(manager.submit_attestation(&empty)).await;
    assert!(result.is_ok(), "All-role fallback must succeed: {result:?}");
    assert_eq!(tried, Some(1), "All-role fallback must try only the All BN");

    // No All-role BN either: do not fan out off-role; return Err.
    let only_a = MockServer::start().await;
    let only_b = MockServer::start().await;
    mount_attestation_publish(&only_a, 0).await;
    mount_attestation_publish(&only_b, 0).await;
    let mut config = BnManagerConfig::new(vec![only_a.uri(), only_b.uri()]);
    config.roles = vec![role_set(BnRole::Proposal), role_set(BnRole::SyncCommittee)];
    let manager = BnManager::new(config).unwrap();
    let (result, tried) = with_broadcast_tried(manager.submit_attestation(&empty)).await;
    match result {
        Err(BeaconError::NoEligibleBn { operation, role }) => {
            assert_eq!(operation, "submit_attestation");
            assert_eq!(role, "attestation");
        }
        other => panic!("expected NoEligibleBn, got {other:?}"),
    }
    assert_eq!(tried, Some(0), "empty role+All selection must not try any client");
}

/// M2: an unhealthy role-matching BN still receives an already-signed publish.
#[tokio::test]
async fn test_broadcast_is_not_health_score_filtered() {
    let healthy = MockServer::start().await;
    let unhealthy = MockServer::start().await;

    mount_attestation_publish(&healthy, 1).await;
    mount_attestation_publish(&unhealthy, 1).await;

    let manager = make_multi_manager(&[&healthy.uri(), &unhealthy.uri()]);
    {
        let mut guard = manager.health_trackers().write().await;
        for _ in 0..100 {
            guard[1].record_error();
        }
        for _ in 0..10 {
            guard[0].record_success(Duration::from_millis(50));
        }
        assert!(!guard[1].is_healthy(), "second BN must be unhealthy so a score cut would drop it");
        assert!(guard[0].is_healthy());
    }

    let empty = VersionedAttestation::Electra(vec![]);
    let result = manager.submit_attestation(&empty).await;
    assert!(
        result.is_ok(),
        "unhealthy role-matching BN must still receive the publish: {result:?}"
    );
    poll_received(&healthy, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
    poll_received(&unhealthy, "POST", "/eth/v2/beacon/pool/attestations", 1).await;
}

// ===================================================================
// DSR-2.3: rvc_proposer_bn_latency_ms observes proposer BN RPCs
// ===================================================================

fn proposer_bn_latency_count(endpoint: &str) -> u64 {
    RVC_PROPOSER_BN_LATENCY_MS.with_label_values(&[endpoint]).get_sample_count()
}

fn proposer_bn_latency_family_has_samples() -> bool {
    metrics::REGISTRY.gather().iter().any(|mf| {
        mf.name() == "rvc_proposer_bn_latency_ms"
            && mf.get_metric().iter().any(|m| m.get_histogram().get_sample_count() > 0)
    })
}

/// DSR-2.3 / #382: exercising `produce_block_v3` must bump
/// `rvc_proposer_bn_latency_ms` count and leave gatherable histogram samples
/// (not HELP/TYPE-only).
#[tokio::test]
async fn test_produce_block_v3_observes_proposer_bn_latency_ms() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "1000")
                .set_body_string(
                    r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#,
                ),
        )
        .mount(&server)
        .await;

    let endpoint = server.uri();
    let manager = make_manager(&endpoint);

    let count_before = proposer_bn_latency_count(&endpoint);

    manager.produce_block_v3(1, "0xrandao", None, None).await.expect("produce_block_v3");

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let count_after = loop {
        let count_after = proposer_bn_latency_count(&endpoint);
        if count_after > count_before {
            break count_after;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "produce_block_v3 must observe rvc_proposer_bn_latency_ms; before={count_before}, after={count_after}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(
        count_after > count_before,
        "produce_block_v3 must observe rvc_proposer_bn_latency_ms; before={count_before}, after={count_after}"
    );
    assert!(
        proposer_bn_latency_family_has_samples(),
        "rvc_proposer_bn_latency_ms must expose histogram samples on gather (not HELP/TYPE-only)"
    );
}

/// Non-proposer RPCs must not pollute the proposer BN latency histogram.
#[tokio::test]
async fn test_get_genesis_does_not_observe_proposer_bn_latency_ms() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/genesis"))
        .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
        .mount(&server)
        .await;

    let endpoint = server.uri();
    let manager = make_manager(&endpoint);
    let count_before = proposer_bn_latency_count(&endpoint);

    manager.get_genesis().await.expect("get_genesis");

    assert_eq!(
        proposer_bn_latency_count(&endpoint),
        count_before,
        "non-proposer BN RPCs must not observe rvc_proposer_bn_latency_ms"
    );
}

fn shape_duty(shape: ShapeConstraint, parent: Option<[u8; 32]>) -> ProduceDuty {
    ProduceDuty {
        expected_proposer_index: 0,
        expected_parent_root: parent,
        alternate_parent_root: None,
        parent_closed: false,
        expected_fee_recipient: None,
        expected_consensus_version: ForkName::Deneb,
        shape,
    }
}

fn block_document(parent_hex: &str, blinded: bool) -> String {
    let kind = if blinded { "deneb-blinded" } else { "full" };
    produce_json(preparable_data(kind, 1, 0, parent_hex, false))
}

fn http_message(extra_headers: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn block_headers(value: &str, blinded: bool, version: &str) -> String {
    let flag = if blinded { "true" } else { "false" };
    format!(
        "Eth-Consensus-Version: {version}\r\nEth-Execution-Payload-Blinded: {flag}\r\nEth-Execution-Payload-Value: {value}\r\n"
    )
}

/// One beacon node on the test runtime.
///
/// Wiremock's delay sleeps on a private runtime, so a paused test clock cannot
/// release it. This server's sleep is the test clock. The receiver fires once
/// that sleep is registered, which is still at virtual t = 0 when the caller
/// is waiting on a blocking thread. Stepping before that signal would arm the
/// delay in the future and miss the soft deadline.
async fn paused_bn(
    sync_body: String,
    block_delay: Duration,
    block_value: &'static str,
    blinded: bool,
    parent_hex: String,
) -> (String, std::sync::mpsc::Receiver<()>) {
    paused_bn_with(sync_body, block_delay, block_value, blinded, parent_hex, "deneb", None).await
}

/// `body` replaces [`block_document`]. `version` is `Eth-Consensus-Version`.
async fn paused_bn_with(
    sync_body: String,
    block_delay: Duration,
    block_value: &'static str,
    blinded: bool,
    parent_hex: String,
    version: &'static str,
    body: Option<String>,
) -> (String, std::sync::mpsc::Receiver<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (armed_tx, armed_rx) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let sync_body = sync_body.clone();
            let parent_hex = parent_hex.clone();
            let body = body.clone();
            let armed_tx = armed_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut got = 0usize;
                loop {
                    let n = sock.read(&mut buf[got..]).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    got += n;
                    if buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..got]);
                let message = if head.contains("/eth/v1/node/syncing") {
                    http_message("", &sync_body)
                } else {
                    if !block_delay.is_zero() {
                        let sleep = tokio::time::sleep(block_delay);
                        tokio::pin!(sleep);
                        let mut signal = Some(armed_tx);
                        std::future::poll_fn(|cx| {
                            match std::future::Future::poll(sleep.as_mut(), cx) {
                                std::task::Poll::Ready(()) => std::task::Poll::Ready(()),
                                std::task::Poll::Pending => {
                                    if let Some(tx) = signal.take() {
                                        let _ = tx.send(());
                                    }
                                    std::task::Poll::Pending
                                }
                            }
                        })
                        .await;
                    }
                    let body = body.clone().unwrap_or_else(|| block_document(&parent_hex, blinded));
                    http_message(&block_headers(block_value, blinded, version), &body)
                };
                let _ = sock.write_all(&message).await;
            });
        }
    });
    (format!("http://{addr}"), armed_rx)
}

/// Block sleeps are already registered. Step the two arrivals, then the rest
/// of a 3s budget's soft deadline (1.5s). Auto-advance stays off until both
/// receivers fire, so the sleeps are armed at virtual t = 0.
async fn drive_to_soft_deadline(armed: Vec<std::sync::mpsc::Receiver<()>>) {
    tokio::task::spawn_blocking(move || {
        for rx in armed {
            rx.recv().expect("block response armed on the paused clock");
        }
    })
    .await
    .expect("arm wait");
    step_paused(50).await;
    step_paused(1_150).await;
    step_paused(300).await;
}

/// Virtual steps. `sleep` under a paused clock fires each earlier timer first.
/// One `advance` across both arrivals would deliver them together.
async fn step_paused(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Builder-only: a fast local block does not end the wait. The later blinded
/// block is the only candidate, even though the local value is higher.
///
/// Budget 3s, so the soft deadline is 1.5s. The local block is released at
/// 50ms and the blinded block at 1.2s, both before that deadline.
#[tokio::test(flavor = "current_thread")]
async fn builder_only_local_block_does_not_close_the_soft_window() {
    let parent = "00".repeat(32);
    let (local, local_armed) =
        paused_bn("{}".to_string(), Duration::from_millis(50), "9000", false, parent.clone()).await;
    let (blinded, blinded_armed) =
        paused_bn("{}".to_string(), Duration::from_millis(1_200), "1000", true, parent).await;
    tokio::time::pause();
    let manager = manager_with_block_budget(&[&local, &blinded], Duration::from_secs(3));
    let started = tokio::time::Instant::now();
    let duty = shape_duty(ShapeConstraint::BlindedOnly, Some([0u8; 32]));
    let produce = tokio::spawn(async move {
        manager.produce_block_v3_ranked(1, "0xrandao", None, None, Some(duty)).await
    });
    drive_to_soft_deadline(vec![local_armed, blinded_armed]).await;
    let ranked = produce.await.expect("produce task").expect("ranked blocks");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_400) && elapsed <= Duration::from_millis(1_600),
        "soft deadline is 1.5s, returned at {elapsed:?}"
    );
    assert_eq!(ranked.len(), 1, "the local block must not be a candidate");
    assert!(ranked[0].response.is_blinded);
    assert_eq!(ranked[0].response.execution_payload_value.as_deref(), Some("1000"));
}

/// Execution-only: a fast blinded block is a hard reject. The later local
/// block is the only candidate.
#[tokio::test(flavor = "current_thread")]
async fn execution_only_blinded_block_is_a_hard_reject() {
    let parent = "00".repeat(32);
    let (blinded, blinded_armed) =
        paused_bn("{}".to_string(), Duration::from_millis(50), "9000", true, parent.clone()).await;
    let (local, local_armed) =
        paused_bn("{}".to_string(), Duration::from_millis(1_200), "1000", false, parent).await;
    tokio::time::pause();
    let manager = manager_with_block_budget(&[&blinded, &local], Duration::from_secs(3));
    let started = tokio::time::Instant::now();
    let duty = shape_duty(ShapeConstraint::LocalOnly, Some([0u8; 32]));
    let produce = tokio::spawn(async move {
        manager.produce_block_v3_ranked(1, "0xrandao", None, None, Some(duty)).await
    });
    drive_to_soft_deadline(vec![blinded_armed, local_armed]).await;
    let ranked = produce.await.expect("produce task").expect("ranked blocks");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_400) && elapsed <= Duration::from_millis(1_600),
        "soft deadline is 1.5s, returned at {elapsed:?}"
    );
    assert_eq!(ranked.len(), 1, "the blinded block must not be a candidate");
    assert!(!ranked[0].response.is_blinded);
    assert_eq!(ranked[0].response.execution_payload_value.as_deref(), Some("1000"));
}

/// Synced nodes miss the budget. The first fallback is the wrong shape and is
/// not returned. The next fallback, which matches, is.
#[tokio::test(flavor = "current_thread")]
async fn fallback_respects_the_shape_constraint() {
    let parent = "ab".repeat(32);
    let (synced, _) = paused_bn(
        SYNCED_RESPONSE.to_string(),
        Duration::from_secs(30),
        "1111",
        true,
        parent.clone(),
    )
    .await;
    const SMALL_LAG: &str = r#"{"data":{"head_slot":"991","sync_distance":"9","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;
    let (wrong, _) =
        paused_bn(SMALL_LAG.to_string(), Duration::ZERO, "9000", false, parent.clone()).await;
    let (right, _) = paused_bn(SMALL_LAG.to_string(), Duration::ZERO, "1000", true, parent).await;
    let manager = manager_with_block_budget(&[&synced, &wrong, &right], Duration::from_millis(400));
    manager.check_sync_status().await;
    let details = manager.sync_statuses().read().await.clone();
    let summary: Vec<_> = details.iter().map(|d| (d.status, d.sync_distance)).collect();
    assert!(matches!(details[0].status, BnSyncStatus::Synced), "sync {summary:?}");
    assert_eq!(details[1].sync_distance, Some(9), "sync {summary:?}");
    assert_eq!(details[2].sync_distance, Some(9), "sync {summary:?}");
    tokio::time::pause();
    let duty = shape_duty(ShapeConstraint::BlindedOnly, Some([0xab; 32]));
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        let result = manager.produce_block_v3_ranked(1, "0xrandao", None, None, Some(duty)).await;
        let _ = done_tx.send(result);
    });
    // 400 ms expires the synced attempt. After that, auto-advance would skip
    // the fallback sockets and jump to the next timer. Waiting on the result
    // from a blocking thread holds auto-advance off, so those accepts finish
    // while the backstop is still open.
    step_paused(400).await;
    let ranked = tokio::task::spawn_blocking(move || done_rx.recv().expect("produce finished"))
        .await
        .expect("blocking wait")
        .expect("fallback block");
    assert_eq!(ranked.len(), 1, "the wrong-shape fallback must not be returned");
    assert!(ranked[0].response.is_blinded);
    assert_eq!(ranked[0].response.execution_payload_value.as_deref(), Some("1000"));
}

fn fixture_raw(kind: &str) -> &'static str {
    match kind {
        "deneb-contents" => {
            include_str!("../../eth-types/tests/fixtures/beacon_api/deneb_block_contents.json")
        }
        "deneb-blinded" => {
            include_str!("../../eth-types/tests/fixtures/beacon_api/deneb_blinded_block_body.json")
        }
        "electra-blinded" => {
            include_str!(
                "../../eth-types/tests/fixtures/beacon_api/electra_blinded_block_body.json"
            )
        }
        other => panic!("unknown fixture {other}"),
    }
}

fn patch_block(block: &mut serde_json::Value, slot: u64, proposer: u64, parent_hex: &str) {
    for (key, value) in [
        ("slot", slot.to_string()),
        ("proposer_index", proposer.to_string()),
        ("parent_root", format!("0x{parent_hex}")),
        ("state_root", format!("0x{}", "22".repeat(32))),
    ] {
        block[key] = serde_json::Value::String(value);
    }
}

/// Produce `data`. `extra_proof` appends one `kzg_proofs` entry on the Deneb contents fixture.
fn preparable_data(
    kind: &str,
    slot: u64,
    proposer: u64,
    parent_hex: &str,
    extra_proof: bool,
) -> serde_json::Value {
    if kind == "full" && !extra_proof {
        let body =
            serde_json::to_value(eth_types::external_vector_deneb_body()).expect("deneb body");
        let mut block = serde_json::json!({ "body": body });
        patch_block(&mut block, slot, proposer, parent_hex);
        return block;
    }
    if kind == "full" {
        let mut doc: serde_json::Value =
            serde_json::from_str(fixture_raw("deneb-contents")).expect("contents");
        let mut data = doc["data"].take();
        patch_block(data.get_mut("block").expect("block"), slot, proposer, parent_hex);
        let proofs = data.get_mut("kzg_proofs").and_then(|v| v.as_array_mut()).expect("proofs");
        let extra = proofs.first().cloned().expect("one proof");
        proofs.push(extra);
        return data;
    }
    let body: serde_json::Value = serde_json::from_str(fixture_raw(kind)).expect("blinded body");
    let mut block = serde_json::json!({ "body": body });
    patch_block(&mut block, slot, proposer, parent_hex);
    block
}

fn produce_json(data: serde_json::Value) -> String {
    serde_json::json!({ "data": data }).to_string()
}

fn any_duty(version: ForkName, parent: Option<[u8; 32]>, fee: Option<[u8; 20]>) -> ProduceDuty {
    ProduceDuty {
        expected_proposer_index: 7,
        expected_parent_root: parent,
        alternate_parent_root: None,
        parent_closed: false,
        expected_fee_recipient: fee,
        expected_consensus_version: version,
        shape: ShapeConstraint::Any,
    }
}

/// Fast `early` is unpreparable. The 1.2s block is the only candidate.
async fn late_preparable(
    early: (String, bool, &'static str),
    late: (String, bool, &'static str),
    duty: ProduceDuty,
) -> Vec<beacon::RankedBlock> {
    let parent = "ab".repeat(32);
    let (bn_a, armed_a) = paused_bn_with(
        "{}".into(),
        Duration::from_millis(50),
        "9000",
        early.1,
        parent.clone(),
        early.2,
        Some(early.0),
    )
    .await;
    let (bn_b, armed_b) = paused_bn_with(
        "{}".into(),
        Duration::from_millis(1_200),
        "1000",
        late.1,
        parent,
        late.2,
        Some(late.0),
    )
    .await;
    tokio::time::pause();
    let manager = manager_with_block_budget(&[&bn_a, &bn_b], Duration::from_secs(3));
    let produce = tokio::spawn(async move {
        manager.produce_block_v3_ranked(1, "0xrandao", None, None, Some(duty)).await
    });
    drive_to_soft_deadline(vec![armed_a, armed_b]).await;
    produce.await.expect("task").expect("late block")
}

/// BN-A's extra KZG proof must not close the soft window. BN-B is the block.
#[tokio::test(flavor = "current_thread")]
async fn unpreparable_kzg_cardinality_does_not_close_the_soft_window() {
    let parent = "ab".repeat(32);
    let ranked = late_preparable(
        (produce_json(preparable_data("full", 1, 7, &parent, true)), false, "deneb"),
        (produce_json(preparable_data("full", 1, 7, &parent, false)), false, "deneb"),
        any_duty(ForkName::Deneb, Some([0xab; 32]), None),
    )
    .await;
    assert_eq!(ranked.len(), 1, "the extra-proof block must not be held: {ranked:?}");
    assert_eq!(ranked[0].bn_index, 1);
    assert_eq!(ranked[0].response.execution_payload_value.as_deref(), Some("1000"));
}

/// A Deneb blinded body advertised as Fulu fails layout and must not win the window.
#[tokio::test(flavor = "current_thread")]
async fn blinded_deneb_body_under_fulu_does_not_close_the_soft_window() {
    let parent = "ab".repeat(32);
    let ranked = late_preparable(
        (produce_json(preparable_data("deneb-blinded", 1, 7, &parent, false)), true, "fulu"),
        (produce_json(preparable_data("electra-blinded", 1, 7, &parent, false)), true, "fulu"),
        any_duty(ForkName::Fulu, Some([0xab; 32]), None),
    )
    .await;
    assert_eq!(ranked.len(), 1, "the deneb body must not be held");
    assert!(ranked[0].response.is_blinded);
    assert_eq!(ranked[0].response.execution_payload_value.as_deref(), Some("1000"));
}

fn syncing_body(distance: u64, optimistic: bool, el_offline: bool) -> String {
    format!(
        r#"{{"data":{{"head_slot":"1000","sync_distance":"{distance}","is_syncing":true,"is_optimistic":{optimistic},"el_offline":{el_offline}}}}}"#
    )
}

async fn mount_syncing(server: &MockServer, distance: u64, optimistic: bool, el_offline: bool) {
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(syncing_body(distance, optimistic, el_offline)),
        )
        .mount(server)
        .await;
}

async fn mount_produce_times(server: &MockServer, value: &str, times: u64) {
    let parent = "ab".repeat(32);
    let body = produce_json(preparable_data("full", 1, 7, &parent, false));
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(mount_duty_block(value, body))
        .expect(times)
        .mount(server)
        .await;
}

fn unknown_parent_duty() -> ProduceDuty {
    ProduceDuty {
        expected_proposer_index: 7,
        expected_parent_root: None,
        alternate_parent_root: None,
        parent_closed: false,
        expected_fee_recipient: None,
        expected_consensus_version: ForkName::Deneb,
        shape: ShapeConstraint::Any,
    }
}

/// No synced node. The first round still skips large-lag, optimistic, and
/// execution-offline beacon nodes when the parent is unknown. Small lag stays.
#[tokio::test]
async fn initial_round_without_a_synced_node_skips_large_lag_optimistic_and_offline_bns_when_the_parent_is_unknown(
) {
    let small = MockServer::start().await;
    let large = MockServer::start().await;
    let optimistic = MockServer::start().await;
    let offline = MockServer::start().await;
    mount_syncing(&small, 9, false, false).await;
    mount_syncing(&large, 17, false, false).await;
    mount_syncing(&optimistic, 9, true, false).await;
    mount_syncing(&offline, 9, false, true).await;
    mount_produce_times(&small, "7000", 1).await;
    mount_produce_times(&large, "1111", 0).await;
    mount_produce_times(&optimistic, "2222", 0).await;
    mount_produce_times(&offline, "3333", 0).await;

    let manager = manager_with_block_budget(
        &[&small.uri(), &large.uri(), &optimistic.uri(), &offline.uri()],
        Duration::from_secs(3),
    );
    manager.check_sync_status().await;
    let block = manager
        .produce_block_v3_for_duty(1, "0xrandao", None, None, unknown_parent_duty())
        .await
        .expect("the small-lag block");
    assert_eq!(block.execution_payload_value.as_deref(), Some("7000"));
}

/// No node meets the floor. A known parent relaxes to the wider set, so the
/// large-lag block is still produced.
#[tokio::test]
async fn initial_round_relaxes_when_the_parent_is_known_and_no_floor_node_exists() {
    let large = MockServer::start().await;
    mount_syncing(&large, 17, false, false).await;
    mount_produce_times(&large, "7000", 1).await;
    let manager = manager_with_block_budget(&[&large.uri()], Duration::from_secs(3));
    manager.check_sync_status().await;
    let parent = [0xabu8; 32];
    let block = manager
        .produce_block_v3_for_duty(
            1,
            "0xrandao",
            None,
            None,
            any_duty(ForkName::Deneb, Some(parent), None),
        )
        .await
        .expect("known parent relaxes onto the large-lag node");
    assert_eq!(block.execution_payload_value.as_deref(), Some("7000"));
}
