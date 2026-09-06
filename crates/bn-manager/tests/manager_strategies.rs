//! Strategy / multi-BN integration tests for [`rvc_bn_manager::BnManager`] against wiremock.
//!
//! Pure relocation of the wiremock suite formerly inline in `src/manager.rs`
//! (RF6-08 / H1). Unit tests that touch private helpers (`primary_endpoint`,
//! `is_better_block`) remain in `src/manager.rs`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use beacon::{BeaconClient, BeaconClientConfig};
use eth_types::ForkSchedule;
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use rvc_bn_manager::{
    AttestationApi, BeaconError, BeaconNodeClient, BlockProducer, BnManager, BnManagerConfig,
    BnRole, BnSyncDetail, BnSyncStatus, DutiesProvider, LivenessApi, NodeStatusApi,
    OperationTimeouts, PayloadAttestationApi, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SyncCommitteeApi, VersionedAttestation, VersionedSignedAggregateAndProof,
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

    // BN1 returns block with lower value
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "1000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn1)
        .await;

    // BN2 returns block with higher value
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
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.execution_payload_value, Some("5000".to_string()));
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
        .expect(1)
        .mount(&bn1)
        .await;

    // BN2: syncing but block production works
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/syncing"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
        .mount(&bn2)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Eth-Consensus-Version", "deneb")
            .insert_header("Eth-Execution-Payload-Blinded", "false")
            .insert_header("Eth-Execution-Payload-Value", "7000")
            .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
        .expect(1)
        .mount(&bn2)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
    manager.check_sync_status().await;

    // BN1 (synced) fails, should fall back to BN2 (unsynced)
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());
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

    // Both BNs should have health recorded
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
    assert!(
        matches!(&err, BeaconError::OperationTimeout { operation, timeout }
            if operation == "get_attestation_data" && *timeout == Duration::from_millis(100)),
        "expected OperationTimeout, got: {err}"
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

    // BN1 should have error recorded, BN2 should have success
    let health = manager.health_trackers().read().await;
    assert!(health[0].score() < health[1].score());
}

// ===================================================================
// RF4-26: batched health updates + submit() topic dispatch
// ===================================================================

fn sample_signed_block() -> SignedBeaconBlock {
    SignedBeaconBlock {
        message: eth_types::BeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xde, 0xad],
        },
        signature: vec![0xaa; 96],
    }
}

fn sample_signed_blinded_block() -> SignedBlindedBeaconBlock {
    SignedBlindedBeaconBlock {
        message: eth_types::BlindedBeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xbe, 0xef],
        },
        signature: vec![0xbb; 96],
    }
}

/// query_best with N parallel BNs must take the health write lock once for
/// the selection round (not once per result).
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

    manager.health_trackers().reset_write_lock_count();
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());

    let writes = manager.health_trackers().write_lock_count();
    assert_eq!(
        writes, 1,
        "query_best must batch health updates into a single write lock (got {writes})"
    );
}

/// fallback_unsynced also records under one write per fallback round.
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

    // BN2, BN3: unsynced; BN2 fails, BN3 succeeds
    for bn in [&bn2, &bn3] {
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(bn)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .expect(1)
        .mount(&bn2)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "7000")
                .set_body_string(
                    r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#,
                ),
        )
        .expect(1)
        .mount(&bn3)
        .await;

    let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri(), &bn3.uri()]);
    manager.check_sync_status().await;

    manager.health_trackers().reset_write_lock_count();
    let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
    assert!(result.is_ok());

    // 1 write for the failed synced BN (query_best single path) +
    // 1 write for the unsynced fallback round (BN2 err + BN3 ok batched).
    let writes = manager.health_trackers().write_lock_count();
    assert_eq!(writes, 2, "synced fail (1) + batched unsynced fallback (1) expected; got {writes}");
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
        assert!(manager.publish_block(&signed, "deneb").await.is_ok());
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
        assert!(manager.publish_block(&signed, "deneb").await.is_ok());
    }

    // -- blocks (publish_blinded_block) shares the same topic flag --
    let blinded = sample_signed_blinded_block();
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v1/beacon/blinded_blocks"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.blocks = true;
        let manager = BnManager::new(config).unwrap();
        assert!(manager.publish_blinded_block(&blinded, "deneb").await.is_ok());
    }
    {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/blinded_blocks"))
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
}
