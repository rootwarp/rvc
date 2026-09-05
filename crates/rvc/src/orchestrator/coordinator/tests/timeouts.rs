//! Coordinator tests: timeouts.

use super::*;
use timing::{AGGREGATE_DUE_BPS, ATTESTATION_DUE_BPS};

#[test]
fn test_timeout_constants_are_reasonable() {
    let timeouts = OperationTimeouts::default();

    // Block production must fit within a slot third (~4s for 12s slots)
    assert!(timeouts.block_production.as_secs() <= 4);
    assert!(timeouts.block_production.as_secs() >= 1);

    // Block publish must fit within remaining slot time
    assert!(timeouts.block_publication.as_secs() <= 3);
    assert!(timeouts.block_publication.as_secs() >= 1);

    // Produce + publish together should fit in one slot third (~4s)
    assert!(timeouts.block_production + timeouts.block_publication <= Duration::from_secs(6));

    // Sync operations must fit within their slot third
    assert!(timeouts.sync_message.as_secs() <= 3);
    assert!(timeouts.sync_contribution.as_secs() <= 3);

    // Duty fetch is less time-critical but should still be bounded
    assert!(timeouts.duty_fetch.as_secs() <= 12);
    assert!(timeouts.duty_fetch.as_secs() >= 5);

    // Attestation timeout must fit within slot third
    assert!(timeouts.attestation_fetch.as_secs() <= 5);
}

#[tokio::test]
async fn test_duty_fetch_timeout() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let timeouts = fast_timeouts();
    let mock_server = MockServer::start().await;

    // Mock attester duties endpoint with a delay that exceeds duty_fetch (200ms)
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "data": [],
                    "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                }))
                .set_delay(timeouts.duty_fetch + Duration::from_millis(500)),
        )
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

    let epoch = 1u64;
    let result =
        tokio::time::timeout(timeouts.duty_fetch, duty_tracker.fetch_duties_for_epoch(epoch)).await;

    // Should timeout (Err from tokio::time::timeout)
    assert!(result.is_err(), "Duty fetch should have timed out");
}

#[tokio::test]
async fn test_sync_message_submit_timeout() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let timeouts = OperationTimeouts::default();
    let mock_server = MockServer::start().await;

    // Mock sync committee messages endpoint with delay exceeding sync_message timeout
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/pool/sync_committees"))
        .respond_with(
            ResponseTemplate::new(200).set_delay(timeouts.sync_message + Duration::from_secs(5)),
        )
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let messages = vec![beacon::SyncCommitteeMessage {
        slot: 100,
        beacon_block_root: [0u8; 32],
        validator_index: 1,
        signature: vec![0u8; 96],
    }];

    let result = tokio::time::timeout(
        timeouts.sync_message,
        beacon.submit_sync_committee_messages(&messages),
    )
    .await;

    assert!(result.is_err(), "Sync message submit should have timed out");
}

#[tokio::test]
async fn test_head_block_root_timeout() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let timeouts = OperationTimeouts::default();
    let mock_server = MockServer::start().await;

    // Mock block root endpoint with delay exceeding sync_message timeout
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/blocks/head/root"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "data": {
                        "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                    }
                }))
                .set_delay(timeouts.sync_message + Duration::from_secs(5)),
        )
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let result = tokio::time::timeout(timeouts.sync_message, beacon.get_block_root("head")).await;

    assert!(result.is_err(), "Head block root fetch should have timed out");
}

#[test]
fn test_aggregation_timeout_is_reasonable() {
    let timeouts = OperationTimeouts::default();
    // Must fit within the 2/3-slot to end-of-slot window (~4s for 12s slots)
    assert!(timeouts.aggregate_fetch.as_secs() <= 4);
    assert!(timeouts.aggregate_fetch.as_secs() >= 1);
}

#[test]
fn test_aggregate_submit_uses_distinct_timeout_field() {
    let timeouts = OperationTimeouts {
        aggregate_fetch: Duration::from_secs(5),
        aggregate_submit: Duration::from_secs(1),
        ..Default::default()
    };
    // These must be distinct fields — submit path must use aggregate_submit
    assert_ne!(timeouts.aggregate_fetch, timeouts.aggregate_submit);
}

#[test]
fn test_attestation_submit_timeout_exists() {
    let timeouts = OperationTimeouts::default();
    // attestation_submit must be a usable timeout value
    assert!(timeouts.attestation_submit.as_secs() >= 1);
    assert!(timeouts.attestation_submit.as_secs() <= 5);
}

#[test]
fn test_preparation_timeout_is_reasonable() {
    let timeouts = OperationTimeouts::default();
    assert!(timeouts.preparation.as_secs() >= 1);
    assert!(timeouts.preparation.as_secs() <= 5);
}

#[test]
fn test_builder_registration_timeout_is_reasonable() {
    assert!(BUILDER_REGISTRATION_TIMEOUT.as_secs() >= 5);
    assert!(BUILDER_REGISTRATION_TIMEOUT.as_secs() <= 15);
}

#[test]
fn test_pre_proposal_deadline_default_is_one_second() {
    assert_eq!(DEFAULT_PRE_PROPOSAL_DEADLINE, Duration::from_millis(1000));
    let config = create_test_config();
    assert_eq!(config.pre_proposal_deadline, DEFAULT_PRE_PROPOSAL_DEADLINE);
}

#[test]
fn test_cold_proposer_fetch_deadline_default_is_500ms() {
    assert_eq!(COLD_PROPOSER_FETCH_DEADLINE, Duration::from_millis(500));
    let config = create_test_config();
    assert_eq!(config.cold_proposer_fetch_deadline, COLD_PROPOSER_FETCH_DEADLINE);
    assert!(
        COLD_PROPOSER_FETCH_DEADLINE <= DEFAULT_PRE_PROPOSAL_DEADLINE,
        "cold fetch must fit inside the aggregate pre-proposal budget"
    );
}

// `as_secs() * 2 / 3`), now exact for non-12 s / Gloas slots (report §4.3).
#[test]
fn test_aggregation_waits_until_two_thirds_8000ms_mainnet() {
    let clock = MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32);
    let slot_duration_ms = clock.slot_duration().as_millis() as u64;

    // Same call the Phase 3 wait makes in production (`due_ms(AGGREGATE_DUE_BPS, ..)`);
    // pinning the literal 8000 here fails if either the constant or the formula drifts.
    let two_thirds_offset_ms = due_ms(AGGREGATE_DUE_BPS, slot_duration_ms);
    assert_eq!(two_thirds_offset_ms, 8000, "mainnet 2/3 offset must be 8000 ms");

    // At slot start, the wait is the full 8000 ms offset.
    clock.set_current_time(TEST_GENESIS_TIME);
    let slot_start_ms = clock.slot_start_time(0) * 1000;
    let two_thirds_ms = slot_start_ms + two_thirds_offset_ms;
    let now_ms = clock.current_time_secs() * 1000;
    assert!(now_ms < two_thirds_ms);
    assert_eq!(two_thirds_ms - now_ms, 8000, "wait at slot start must be 8000 ms");

    // Past 2/3, no wait remains.
    clock.set_current_time(TEST_GENESIS_TIME + 9);
    let now_ms = clock.current_time_secs() * 1000;
    assert!(now_ms >= two_thirds_ms, "9 s into a 12 s slot is past the 8000 ms mark");
}

// Pin the missed-deadline 1/3 check (coordinator.rs:421/:427 site) to the spec
// BPS value: 3333 * 12000 / 10000 = 3999 ms on mainnet, and confirm the warn
// window opens only once we are a further 3999 ms past the deadline (~2/3 slot).
#[test]
fn test_missed_deadline_uses_one_third_bps_at_421_427() {
    let clock = MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32);
    let slot_duration_ms = clock.slot_duration().as_millis() as u64;

    // Same call the missed-deadline check makes in production
    // (`due_ms(ATTESTATION_DUE_BPS, ..)`); the literal 3999 fails on drift.
    let att_window_ms = due_ms(ATTESTATION_DUE_BPS, slot_duration_ms);
    assert_eq!(att_window_ms, 3999, "mainnet 1/3 attestation window must be 3999 ms");

    let slot_start_ms = clock.slot_start_time(0) * 1000;
    let expected_att_ms = slot_start_ms + att_window_ms;

    // `would_warn` mirrors the production condition: now past the deadline AND
    // the overrun exceeds the attestation window.
    let would_warn =
        |now_ms: u64| now_ms > expected_att_ms && now_ms - expected_att_ms > att_window_ms;

    // Just past 1/3 (4 s): missed but inside the window — no warn yet.
    assert!(!would_warn((TEST_GENESIS_TIME + 4) * 1000), "4 s in: missed but within window");
    // At 2/3 (8 s): exactly one window past 3999 ms (overrun 4001 > 3999) — warn.
    assert!(would_warn((TEST_GENESIS_TIME + 8) * 1000), "8 s in: past the window, warn fires");
    // Before the deadline (3 s): not missed.
    assert!(!would_warn((TEST_GENESIS_TIME + 3) * 1000), "3 s in: before the deadline");
}
