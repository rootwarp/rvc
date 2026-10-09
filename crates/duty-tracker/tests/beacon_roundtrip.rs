//! Deliberate integration coverage of the beacon HTTP + DutyTracker pair.
//!
//! Unit tests in `tracker.rs` drive cache logic through
//! `bn_manager::MockBeaconNodeClient` (in-memory). These two cases keep a real
//! `beacon::BeaconClient` against `wiremock` so URL/body contracts for duty
//! endpoints remain exercised (RF6-17 / F103).

use std::sync::Arc;
use std::time::Duration;

use beacon::{BeaconClient, BeaconClientConfig};
use bn_manager::DutiesProvider;
use rvc_duty_tracker::DutyTracker;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup_http_beacon() -> (MockServer, Arc<dyn DutiesProvider>) {
    let mock_server = MockServer::start().await;
    let config = BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(5))
        .with_max_retries(1);
    let client = BeaconClient::new(config).unwrap();
    (mock_server, Arc::new(client) as Arc<dyn DutiesProvider>)
}

/// Attester duties: POST path, request body indices, dependent_root caching.
#[tokio::test]
async fn attester_duties_http_roundtrip() {
    let (mock_server, beacon) = setup_http_beacon().await;
    let validator_indices = vec!["1234".to_string(), "5678".to_string()];

    let response = serde_json::json!({
        "dependent_root": "0xdeproot_http",
        "execution_optimistic": false,
        "data": [
            {
                "pubkey": "0xpubkey_1234",
                "validator_index": "1234",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "25",
                "slot": "320"
            },
            {
                "pubkey": "0xpubkey_5678",
                "validator_index": "5678",
                "committee_index": "2",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "10",
                "slot": "321"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/10"))
        .and(body_json(["1234", "5678"]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = DutyTracker::new(beacon, validator_indices);
    let duties = tracker.fetch_duties_for_epoch(10).await.unwrap();

    assert_eq!(duties.len(), 2);
    assert_eq!(duties[0].slot, "320");
    assert_eq!(duties[1].validator_index, "5678");
    assert!(tracker.is_epoch_cached(10).await);
    assert_eq!(tracker.get_cached_dependent_root(10).await, Some("0xdeproot_http".to_string()));

    let duty = tracker.get_duty(320, 1, 1234).await.unwrap();
    assert_eq!(duty.committee_index, 1);
    assert_eq!(duty.raw.committee_index, "1");
}

/// Proposer + sync-committee duties: GET/POST paths and typed sync pubkey decode.
#[tokio::test]
async fn proposer_and_sync_duties_http_roundtrip() {
    let (mock_server, beacon) = setup_http_beacon().await;
    let validator_indices = vec!["1234".to_string()];

    let proposer = serde_json::json!({
        "dependent_root": "0xproot_http",
        "execution_optimistic": false,
        "data": [{
            "pubkey": "0xpubkey_1234",
            "validator_index": "1234",
            "slot": "320"
        }]
    });
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/duties/proposer/10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&proposer))
        .expect(1)
        .mount(&mock_server)
        .await;

    let sync_pubkey = format!("0x{}", "11".repeat(48));
    let sync = serde_json::json!({
        "execution_optimistic": false,
        "data": [{
            "pubkey": sync_pubkey,
            "validator_index": "1234",
            "validator_sync_committee_indices": ["10", "20"]
        }]
    });
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/sync/10"))
        .and(body_json(["1234"]))
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = DutyTracker::new(beacon, validator_indices);

    let proposers = tracker.fetch_proposer_duties(10).await.unwrap();
    assert_eq!(proposers.len(), 1);
    assert!(tracker.is_proposer_epoch_cached(10).await);
    let duty = tracker.get_proposer_duty(320).await.unwrap();
    assert_eq!(duty.validator_index, 1234);
    assert_eq!(duty.raw.validator_index, "1234");

    let sync_duties = tracker.fetch_sync_committee_duties(10).await.unwrap();
    assert_eq!(sync_duties.len(), 1);
    assert_eq!(sync_duties[0].pubkey, [0x11; 48]);
    assert!(tracker.is_sync_period_cached(10).await);
}
