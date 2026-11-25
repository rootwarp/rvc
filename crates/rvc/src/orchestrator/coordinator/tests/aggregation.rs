//! Coordinator tests: aggregation flows, bits, and fork-format aggregates.

use super::*;

#[tokio::test]
async fn test_aggregation_no_duties_does_nothing() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, _) = build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    // Mock attester duties to return empty list
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": []
        })))
        .mount(&mock_server)
        .await;

    // Fetch duties (empty) so the epoch is cached
    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    // Should NOT call any aggregation endpoints
    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/validator/aggregate_attestation.*"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

#[tokio::test]
async fn test_aggregation_full_flow_with_mock_beacon() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    // 1. Mock attester duties endpoint — return a duty with a small committee
    //    (committee_length ≤ 16 → modulo=1 → always aggregator)
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // 2. Mock attestation data endpoint
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    // 3. Mock aggregate attestation endpoint
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "aggregation_bits": "0xff01",
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })))
        .mount(&mock_server)
        .await;

    // 4. Mock submit aggregate and proofs endpoint
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Fetch duties first so they're cached
    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    // Run the aggregation dispatch
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;

    // The mock server's expect(1) on submit verifies the request was made
}

#[tokio::test]
async fn test_aggregation_non_aggregator_skips() {
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    // Use committee_length=u64::MAX so is_aggregator is deterministically false
    // modulo = u64::MAX / 16 → probability ~5.4e-18, effectively zero
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "18446744073709551615",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // Should NOT call get_aggregate_attestation or submit
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

#[tokio::test]
async fn test_aggregation_beacon_failure_handled_gracefully() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    // Small committee → always aggregator
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // Attestation data endpoint returns an error
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "message": "Internal server error"
        })))
        .mount(&mock_server)
        .await;

    // Should NOT call submit since attestation data fetch failed
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    // Should not panic; gracefully handle error
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

// -- Fork-aware attestation construction tests (G-1-05) --

fn typed_attester_duty(duty: &AttesterDuty) -> duty_tracker::TypedAttesterDuty {
    duty_tracker::TypedAttesterDuty::try_from(duty).expect("numeric fixture")
}

#[test]
fn test_make_aggregation_bits_first_position() {
    let duty = AttesterDuty {
        pubkey: "0xaabb".to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "4".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: "100".to_string(),
    };
    let bits = utils::make_aggregation_bits(&typed_attester_duty(&duty)).unwrap();
    // committee_length=4, validator_committee_index=0
    // Byte 0: bit 0 set (validator) = 0x01
    // Length bit at position 4 → byte 0, bit 4 = 0x10
    // Combined: 0x11
    assert_eq!(bits, "0x11");
}

#[test]
fn test_make_aggregation_bits_middle_position() {
    let duty = AttesterDuty {
        pubkey: "0xaabb".to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "8".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "3".to_string(),
        slot: "100".to_string(),
    };
    let bits = utils::make_aggregation_bits(&typed_attester_duty(&duty)).unwrap();
    // committee_length=8, validator_committee_index=3
    // Byte 0: bit 3 set = 0x08
    // Length bit at position 8 → byte 1, bit 0 = 0x01
    // Result: [0x08, 0x01]
    assert_eq!(bits, "0x0801");
}

#[test]
fn test_make_aggregation_bits_last_position() {
    let duty = AttesterDuty {
        pubkey: "0xaabb".to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "4".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "3".to_string(),
        slot: "100".to_string(),
    };
    let bits = utils::make_aggregation_bits(&typed_attester_duty(&duty)).unwrap();
    // committee_length=4, validator_committee_index=3
    // Byte 0: bit 3 set = 0x08, length bit at position 4 = 0x10
    // Combined: 0x18
    assert_eq!(bits, "0x18");
}

#[test]
fn test_make_aggregation_bits_zero_committee_length() {
    let duty = AttesterDuty {
        pubkey: "0xaabb".to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "0".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: "100".to_string(),
    };
    assert!(utils::make_aggregation_bits(&typed_attester_duty(&duty)).is_none());
}

#[test]
fn test_make_aggregation_bits_invalid_committee_length() {
    let duty = AttesterDuty {
        pubkey: "0xaabb".to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "not_a_number".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: "100".to_string(),
    };
    assert!(duty_tracker::TypedAttesterDuty::try_from(&duty).is_err());
}

#[test]
fn test_make_aggregation_bits_invalid_validator_committee_index() {
    let duty = AttesterDuty {
        pubkey: "0xaabb".to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "8".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "garbage".to_string(),
        slot: "100".to_string(),
    };
    assert!(duty_tracker::TypedAttesterDuty::try_from(&duty).is_err());
}

// ── Aggregation fork-format tests (Electra/Fulu proofs) ──

#[tokio::test]
async fn test_aggregation_electra_builds_electra_aggregate_and_proof() {
    use wiremock::matchers::{header, method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    // Electra epoch = 50, slot = 50 * 32 = 1600
    let slot = 1600u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    orchestrator.clock.set_slot(slot);

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    // Electra aggregate fetch is /eth/v2 with Eth-Consensus-Version.
    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/aggregate_attestation"))
        .and(header("Eth-Consensus-Version", "electra"))
        .and(query_param("slot", slot.to_string()))
        .and(query_param("committee_index", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "electra")
                .set_body_json(serde_json::json!({
            "version": "electra",
            "data": {
                "aggregation_bits": "0xff01",
                "data": {
                    "slot": slot.to_string(),
                    "index": "0",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "committee_bits": "0x0200000000000000"
            }
        })),
        )
        .mount(&mock_server)
        .await;

    // Electra submit goes to v2 endpoint
    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Pre-Electra submit should NOT be called
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

#[tokio::test]
async fn test_aggregation_pre_electra_unchanged() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    // Pre-Electra: epoch 3, slot 100
    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    // Pre-Electra aggregate (no committee_bits)
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "aggregation_bits": "0xff01",
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })))
        .mount(&mock_server)
        .await;

    // Pre-Electra submit should go to v1 endpoint
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // v2 endpoint should NOT be called
    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

#[tokio::test]
async fn test_aggregation_fulu_dispatches_as_fulu() {
    use wiremock::matchers::{header, method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    // Fulu epoch = 60, slot = 60 * 32 = 1920
    let slot = 1920u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    orchestrator.clock.set_slot(slot);

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    // Fulu aggregate fetch is /eth/v2 with Eth-Consensus-Version.
    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/aggregate_attestation"))
        .and(header("Eth-Consensus-Version", "fulu"))
        .and(query_param("slot", slot.to_string()))
        .and(query_param("committee_index", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "fulu")
                .set_body_json(serde_json::json!({
            "version": "fulu",
            "data": {
                "aggregation_bits": "0xff01",
                "data": {
                    "slot": slot.to_string(),
                    "index": "0",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "committee_bits": "0x0200000000000000"
            }
        })),
        )
        .mount(&mock_server)
        .await;

    // Fulu submit goes to v2 endpoint with Eth-Consensus-Version: fulu
    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .and(header("Eth-Consensus-Version", "fulu"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // v1 endpoint should NOT be called
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

#[tokio::test]
async fn test_aggregation_gloas_dispatches_as_gloas() {
    use wiremock::matchers::{header, method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let mut schedule = (*create_test_fork_schedule()).clone();
    schedule.gloas_fork_epoch = 70;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator_with_schedule(&mock_server.uri(), Arc::new(schedule)).await;

    // Gloas epoch = 70, slot = 70 * 32 = 2240
    let slot = 2240u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    orchestrator.clock.set_slot(slot);

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/aggregate_attestation"))
        .and(header("Eth-Consensus-Version", "gloas"))
        .and(query_param("slot", slot.to_string()))
        .and(query_param("committee_index", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "gloas")
                .set_body_json(serde_json::json!({
            "version": "gloas",
            "data": {
                "aggregation_bits": "0xff01",
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "committee_bits": "0x0200000000000000"
            }
        })),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .and(header("Eth-Consensus-Version", "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

#[tokio::test]
async fn test_aggregation_mismatched_response_logs_warning() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    // Electra epoch = 50, slot = 1600
    let slot = 1600u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    orchestrator.clock.set_slot(slot);

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": {
                    "epoch": (epoch - 1).to_string(),
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                },
                "target": {
                    "epoch": epoch.to_string(),
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    // Electra slot fetches /eth/v2. A 500 is retried, not fallen back to v1,
    // and nothing is submitted.
    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/aggregate_attestation"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    // Neither submit endpoint should be called
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/eth/v2/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    // Should not panic — gracefully handles failure
    orchestrator
        .aggregation_service
        .maybe_produce_aggregations(slot, epoch, crate::orchestrator::aggregation::ample_slot_end())
        .await;
}

// -- W4-E8a2: aggregation through the shared selection-proof cache --

use bn_manager::MockBeaconNodeClient;

use crate::orchestrator::dispatch::{Phase2SignerPermits, SLOT_END_PUBLISH_OVERHANG};
use crate::orchestrator::selection_proofs::test_support::{
    call_bounded, finished_output, join_bounded, wait_until, Gate, ProbeError, YIELD_ROUNDS,
};
use futures::future::BoxFuture;

type MockOrchestrator = DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>;

/// Remote BLS backend that counts each sign and signs with a local key.
#[derive(Clone)]
pub(super) struct CountingRemote {
    local: Arc<LocalSigner>,
    calls: Arc<AtomicUsize>,
    gate: Arc<parking_lot::Mutex<Option<Arc<Gate>>>>,
}

impl CountingRemote {
    fn new(secret: SecretKey) -> Self {
        let mut key_manager = KeyManager::new();
        key_manager.insert(secret);
        Self {
            local: Arc::new(LocalSigner::new(key_manager)),
            calls: Arc::default(),
            gate: Arc::default(),
        }
    }

    /// Each later `sign` counts, then waits on `gate`.
    pub(super) fn hold_on(&self, gate: Arc<Gate>) {
        *self.gate.lock() = Some(gate);
    }

    /// Number of `sign` calls. A call counts when it enters.
    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl crypto::Signer for CountingRemote {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; 48],
    ) -> Result<crypto::Signature, crypto::SigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let gate = self.gate.lock().clone();
        if let Some(gate) = gate {
            gate.pass().await;
        }
        crypto::Signer::sign(self.local.as_ref(), signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        Vec::new()
    }
}

/// An orchestrator over `mock_for(pubkey_hex)` whose one key signs through a [`CountingRemote`].
///
/// The key is registered in the validator store, and the duties of `epoch` are fetched.
pub(super) async fn orchestrator_with_counting_remote_key(
    epoch: u64,
    mock_for: impl FnOnce(&str) -> MockBeaconNodeClient,
) -> (Arc<MockOrchestrator>, CountingRemote, PublicKey) {
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let beacon = Arc::new(mock_for(&pubkey_hex));
    let remote = CountingRemote::new(secret);

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    composite.add_remote_key(pubkey.to_bytes(), Arc::new(remote.clone()));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("in-memory slashing db"));
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let validator_store = create_mock_validator_store();
    validator_store
        .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
        .expect("register the remote key");
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex]));
    duty_tracker.fetch_duties_for_epoch(epoch).await.expect("fetch the attester duties");
    let pubkey_map =
        Arc::new(parking_lot::RwLock::new(HashMap::from([(pubkey.to_bytes(), pubkey.clone())])));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        beacon,
        create_mock_block_beacon(),
        None,
        validator_store,
        create_test_config(),
        pubkey_map,
    ));
    (Arc::new(orchestrator), remote, pubkey)
}

/// In each epoch, one aggregator duty (`committee_length` 8) at the slot offset of `slot`. The
/// aggregate fetch fails, so the aggregation path signs only its selection proof.
pub(super) fn aggregator_duty_mock(pubkey_hex: &str, slot: Slot) -> MockBeaconNodeClient {
    let pubkey_hex = pubkey_hex.to_string();
    let zero_root = format!("0x{}", "00".repeat(32));
    MockBeaconNodeClient::new()
        .with_get_attester_duties(move |epoch, _indices| {
            Ok(beacon::DependentRootResponse {
                dependent_root: zero_root.clone(),
                execution_optimistic: false,
                data: vec![AttesterDuty {
                    pubkey: pubkey_hex.clone(),
                    validator_index: "42".to_string(),
                    committee_index: "1".to_string(),
                    committee_length: "8".to_string(),
                    committees_at_slot: "4".to_string(),
                    validator_committee_index: "0".to_string(),
                    slot: (epoch * SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH).to_string(),
                }],
            })
        })
        .with_get_attestation_data(|queried, _committee| {
            let checkpoint = beacon::Checkpoint {
                epoch: "0".to_string(),
                root: format!("0x{}", "00".repeat(32)),
            };
            Ok(beacon::DataResponse {
                data: beacon::AttestationData {
                    slot: queried.to_string(),
                    index: "1".to_string(),
                    beacon_block_root: format!("0x{}", "11".repeat(32)),
                    source: checkpoint.clone(),
                    target: checkpoint,
                },
            })
        })
        .with_get_aggregate_attestation(|_slot, _root, _index, _fork| {
            Err(beacon::BeaconError::HttpError("no aggregate in this test".into()))
        })
}

/// Runs one aggregation pass for `slot` in a task, joined with a bound.
async fn aggregate_bounded(orchestrator: &Arc<MockOrchestrator>, slot: Slot) -> bool {
    joined(spawn_aggregation(orchestrator, slot)).await
}

/// True only if the task finished within the bound and did not panic.
async fn joined<T>(handle: tokio::task::JoinHandle<T>) -> bool {
    let handles = [handle];
    let _ = join_bounded(&handles).await;
    let [handle] = handles;
    finished_output(handle).await.is_some()
}

fn spawn_aggregation(
    orchestrator: &Arc<MockOrchestrator>,
    slot: Slot,
) -> tokio::task::JoinHandle<()> {
    let orchestrator = Arc::clone(orchestrator);
    tokio::spawn(async move {
        orchestrator
            .aggregation_service
            .maybe_produce_aggregations(
                slot,
                slot / SLOTS_PER_EPOCH,
                crate::orchestrator::aggregation::ample_slot_end(),
            )
            .await
    })
}

/// A second aggregation pass for the same `(slot, key)` reuses the selection proof.
#[tokio::test(flavor = "current_thread")]
async fn aggregation_signs_each_selection_proof_once() {
    let slot = 100;
    let (orchestrator, remote, _pubkey) =
        orchestrator_with_counting_remote_key(slot / SLOTS_PER_EPOCH, |pubkey_hex| {
            aggregator_duty_mock(pubkey_hex, slot)
        })
        .await;

    assert!(aggregate_bounded(&orchestrator, slot).await, "the first pass finishes");
    assert_eq!(remote.calls(), 1, "the first pass signs its selection proof");
    assert!(aggregate_bounded(&orchestrator, slot).await, "the second pass finishes");

    assert_eq!(remote.calls(), 1, "a second pass for the same (slot, key) does not sign again");
}

/// A concurrent pass for the same `(slot, key)` waits for the owner's sign and does not sign.
#[tokio::test(flavor = "current_thread")]
async fn concurrent_aggregation_waits_for_the_selection_proof_owner() {
    let slot = 100;
    let (orchestrator, remote, _pubkey) =
        orchestrator_with_counting_remote_key(slot / SLOTS_PER_EPOCH, |pubkey_hex| {
            aggregator_duty_mock(pubkey_hex, slot)
        })
        .await;
    let gate = Arc::new(Gate::new());
    remote.hold_on(Arc::clone(&gate));
    let cache = &orchestrator.selection_proofs;

    let owner = spawn_aggregation(&orchestrator, slot);
    let owner_entered = wait_until(|| remote.calls() == 1).await;
    let waiter = spawn_aggregation(&orchestrator, slot);
    let waiting = wait_until(|| cache.waiter_registrations() == 1).await;
    let calls_while_held = remote.calls();
    gate.open();
    let (owner_joined, waiter_joined) = (joined(owner).await, joined(waiter).await);

    assert!(owner_entered, "the first pass enters the remote sign");
    assert!(waiting, "the second pass waits for the owner within {YIELD_ROUNDS} rounds");
    assert_eq!(calls_while_held, 1, "the second pass does not sign while the owner is held");
    assert!(owner_joined && waiter_joined, "both passes finish when the owner's sign ends");
    assert_eq!(remote.calls(), 1, "one signature for the (slot, key)");
    assert_eq!((cache.len(), cache.in_flight_len()), (1, 0), "the proof is cached as ready");
}

/// The cache key holds the slot: a pass for another slot signs its own selection proof.
#[tokio::test(flavor = "current_thread")]
async fn aggregation_signs_a_selection_proof_for_each_slot() {
    let (slot, next_slot) = (100, 100 + SLOTS_PER_EPOCH);
    let (orchestrator, remote, _pubkey) =
        orchestrator_with_counting_remote_key(slot / SLOTS_PER_EPOCH, |pubkey_hex| {
            aggregator_duty_mock(pubkey_hex, slot)
        })
        .await;
    orchestrator
        .duty_tracker
        .fetch_duties_for_epoch(next_slot / SLOTS_PER_EPOCH)
        .await
        .expect("fetch the next epoch's duties");

    assert!(aggregate_bounded(&orchestrator, slot).await, "the first slot's pass finishes");
    assert!(aggregate_bounded(&orchestrator, next_slot).await, "the next slot's pass finishes");

    assert_eq!(remote.calls(), 2, "each slot signs its own selection proof");
    assert_eq!(orchestrator.selection_proofs.len(), 2, "one ready proof per slot");
}

/// An owner that times out gives back its permit and its entry. A waiter with a later deadline
/// takes over and signs once.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn timed_out_owner_hands_over_to_a_waiter() {
    let slot = 100;
    let (orchestrator, remote, _pubkey) =
        orchestrator_with_counting_remote_key(slot / SLOTS_PER_EPOCH, |pubkey_hex| {
            aggregator_duty_mock(pubkey_hex, slot)
        })
        .await;
    let gate = Arc::new(Gate::new());
    remote.hold_on(Arc::clone(&gate));
    let permits = Arc::new(Phase2SignerPermits::new(1));
    let cache = &orchestrator.selection_proofs;
    let spawn_until = |slot_end: tokio::time::Instant| {
        let (orchestrator, permits) = (Arc::clone(&orchestrator), Arc::clone(&permits));
        tokio::spawn(async move {
            orchestrator
                .aggregation_service
                .produce_aggregations(slot, slot / SLOTS_PER_EPOCH, slot_end, &permits)
                .await
        })
    };

    let owner_end = tokio::time::Instant::now() + Duration::from_millis(20);
    let owner = spawn_until(owner_end);
    let owner_entered = wait_until(|| remote.calls() == 1).await;
    let waiter = spawn_until(owner_end + Duration::from_secs(10));
    let waiting = wait_until(|| cache.waiter_registrations() == 1).await;
    tokio::time::advance(Duration::from_millis(20) + SLOT_END_PUBLISH_OVERHANG).await;
    let owner_joined = joined(owner).await;
    let took_over = wait_until(|| remote.calls() == 2).await;
    gate.open();
    let waiter_joined = joined(waiter).await;

    assert!(owner_entered && waiting, "the second pass waits for the held owner");
    assert!(owner_joined, "the owner stops at its own sign deadline");
    assert!(took_over, "the waiter takes the returned permit and signs");
    assert!(waiter_joined, "the waiter finishes");
    assert_eq!(remote.calls(), 2, "one sign by the owner, one by the waiter");
    assert_eq!((cache.len(), cache.in_flight_len()), (1, 0), "no entry stays in flight");
}

/// Both concurrent passes publish. The waiter's aggregate carries the owner's proof, and the
/// key signs one selection proof (3 remote signs: 1 selection proof, 2 aggregates).
#[tokio::test(flavor = "current_thread")]
async fn concurrent_passes_publish_the_owner_selection_proof() {
    let slot = 100;
    let submitted =
        Arc::new(parking_lot::Mutex::new(Vec::<beacon::VersionedSignedAggregateAndProof>::new()));
    let capture = Arc::clone(&submitted);
    let (orchestrator, remote, pubkey) =
        orchestrator_with_counting_remote_key(slot / SLOTS_PER_EPOCH, move |pubkey_hex| {
            aggregator_duty_mock(pubkey_hex, slot)
                .with_get_aggregate_attestation(|queried, _root, _index, _fork| {
                    let checkpoint = eth_types::Checkpoint { epoch: 0, root: [0u8; 32] };
                    Ok(beacon::VersionedAggregateAttestation::PreElectra(eth_types::Attestation {
                        aggregation_bits: vec![0xff, 0x01],
                        data: eth_types::AttestationData {
                            slot: queried,
                            index: 1,
                            beacon_block_root: [0x11; 32],
                            source: checkpoint.clone(),
                            target: checkpoint,
                        },
                        signature: vec![0xab; 96],
                    }))
                })
                .with_submit_aggregate_and_proofs(move |proofs| {
                    capture.lock().push(proofs);
                    Ok(())
                })
        })
        .await;
    let gate = Arc::new(Gate::new());
    remote.hold_on(Arc::clone(&gate));
    let cache = &orchestrator.selection_proofs;

    let owner = spawn_aggregation(&orchestrator, slot);
    let owner_entered = wait_until(|| remote.calls() == 1).await;
    let waiter = spawn_aggregation(&orchestrator, slot);
    let waiting = wait_until(|| cache.waiter_registrations() == 1).await;
    gate.open();
    let (owner_joined, waiter_joined) = (joined(owner).await, joined(waiter).await);
    let cached = call_bounded(cache, (slot, pubkey.to_bytes()), || -> BoxFuture<'static, _> {
        Box::pin(async { Err(ProbeError) })
    })
    .await;

    assert!(owner_entered && waiting, "the second pass waits for the owner");
    assert!(owner_joined && waiter_joined, "both passes finish");
    let Some(Ok(cached)) = cached else { panic!("the owner's proof is cached: {cached:?}") };
    let proofs: Vec<Vec<u8>> = submitted
        .lock()
        .iter()
        .flat_map(|batch| match batch {
            beacon::VersionedSignedAggregateAndProof::PreElectra(batch) => batch
                .iter()
                .map(|signed| signed.message.selection_proof.clone())
                .collect::<Vec<_>>(),
            other => panic!("slot {slot} is pre-Electra: {other:?}"),
        })
        .collect();
    assert_eq!(
        proofs,
        vec![cached.to_bytes().to_vec(); 2],
        "both passes publish an aggregate with the owner's exact selection proof"
    );
    assert_eq!(remote.calls(), 3, "one selection proof and two aggregate signs");
}

// -- W4-E8a3: committee subscriptions share the selection-proof cache --

use crate::orchestrator::selection_proofs::test_support::{abort_bounded, Competitor};
use crate::orchestrator::selection_proofs::SelectionProofCache;

const SUBSCRIBED_SLOT: Slot = 100;
const SUBSCRIBED_EPOCH: u64 = SUBSCRIBED_SLOT / SLOTS_PER_EPOCH;

type Posted = Arc<parking_lot::Mutex<Vec<beacon::BeaconCommitteeSubscription>>>;

/// A committee length so large that no proof selects an aggregator (2^-60 odds per proof).
const NO_AGGREGATOR_COMMITTEE: &str = "18446744073709551615";

/// An attester duty for `pubkey_hex` at the slot offset of `slot` in `epoch`.
fn attester_duty(
    pubkey_hex: &str,
    epoch: u64,
    slot: Slot,
    committee_length: String,
) -> AttesterDuty {
    AttesterDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: "42".to_string(),
        committee_index: "1".to_string(),
        committee_length,
        committees_at_slot: "4".to_string(),
        validator_committee_index: "0".to_string(),
        slot: (epoch * SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH).to_string(),
    }
}

fn duties_response(data: Vec<AttesterDuty>) -> beacon::DependentRootResponse<Vec<AttesterDuty>> {
    beacon::DependentRootResponse {
        dependent_root: format!("0x{}", "00".repeat(32)),
        execution_optimistic: false,
        data,
    }
}

/// [`aggregator_duty_mock`] with tracked admission. It records each accepted subscription and
/// counts the aggregate fetches; the aggregate fetch still fails.
fn subscribing_mock(
    pubkey_hex: &str,
    committee: &Arc<parking_lot::Mutex<String>>,
    posted: &Posted,
    aggregate_fetches: &Arc<AtomicUsize>,
    admission: &Arc<parking_lot::Mutex<Option<Arc<std::sync::atomic::AtomicU64>>>>,
) -> MockBeaconNodeClient {
    let (record, fetches) = (Arc::clone(posted), Arc::clone(aggregate_fetches));
    let mock = aggregator_duty_mock(pubkey_hex, SUBSCRIBED_SLOT)
        .with_get_attester_duties({
            let (pubkey_hex, committee) = (pubkey_hex.to_string(), Arc::clone(committee));
            move |epoch, _indices| {
                let length = committee.lock().clone();
                Ok(duties_response(vec![attester_duty(
                    &pubkey_hex,
                    epoch,
                    SUBSCRIBED_SLOT,
                    length,
                )]))
            }
        })
        .with_get_aggregate_attestation(move |_slot, _root, _index, _fork| {
            fetches.fetch_add(1, Ordering::SeqCst);
            Err(beacon::BeaconError::HttpError("no aggregate in this test".into()))
        })
        .with_submit_beacon_committee_subscriptions(move |subscriptions| {
            record.lock().extend(subscriptions);
            Ok(())
        });
    *admission.lock() = Some(mock.track_admission());
    mock
}

/// An orchestrator with one aggregator duty at [`SUBSCRIBED_SLOT`] in each epoch, and the
/// subscriptions that its beacon node accepted. The beacon node tracks its admission, so each
/// subscription sign runs in the production admission scope.
struct Subscribing {
    orchestrator: Arc<MockOrchestrator>,
    remote: CountingRemote,
    pubkey: PublicKey,
    posted: Posted,
    committee: Arc<parking_lot::Mutex<String>>,
    aggregate_fetches: Arc<AtomicUsize>,
    admission: Arc<std::sync::atomic::AtomicU64>,
}

impl Subscribing {
    async fn new() -> Self {
        let posted = Posted::default();
        let committee = Arc::new(parking_lot::Mutex::new("8".to_string()));
        let aggregate_fetches = Arc::new(AtomicUsize::new(0));
        let admission = Arc::new(parking_lot::Mutex::new(None));
        let (orchestrator, remote, pubkey) =
            orchestrator_with_counting_remote_key(SUBSCRIBED_EPOCH, |pubkey_hex| {
                subscribing_mock(pubkey_hex, &committee, &posted, &aggregate_fetches, &admission)
            })
            .await;
        let admission = admission.lock().take().expect("the mock tracks its admission");
        Self { orchestrator, remote, pubkey, posted, committee, aggregate_fetches, admission }
    }

    /// The slot and the aggregator flag of each accepted subscription.
    fn posted_flags(&self) -> Vec<(String, bool)> {
        self.posted.lock().iter().map(|sub| (sub.slot.clone(), sub.is_aggregator)).collect()
    }

    /// Puts `proof` in the cache as the ready proof of the key at [`SUBSCRIBED_SLOT`].
    async fn seed(&self, proof: crypto::Signature) {
        let key = (SUBSCRIBED_SLOT, self.pubkey.to_bytes());
        let sign = move || -> BoxFuture<'static, Result<crypto::Signature, ProbeError>> {
            Box::pin(async move { Ok(proof) })
        };
        let seeded = call_bounded(&self.orchestrator.selection_proofs, key, sign).await;
        assert!(matches!(seeded, Some(Ok(_))), "the cache holds the seeded proof: {seeded:?}");
    }

    fn cache(&self) -> &SelectionProofCache {
        &self.orchestrator.selection_proofs
    }

    /// The slots of the accepted subscriptions that select an aggregator.
    fn aggregator_slots(&self) -> Vec<String> {
        let posted = self.posted.lock();
        posted.iter().filter(|sub| sub.is_aggregator).map(|sub| sub.slot.clone()).collect()
    }

    /// One subscription pass in a task, as a production caller: a sign without an admission
    /// scope fails.
    fn spawn_subscriptions(&self) -> tokio::task::JoinHandle<Result<(), OrchestratorError>> {
        let orchestrator = Arc::clone(&self.orchestrator);
        tokio::spawn(signer::require_beacon_admission_scope(async move {
            orchestrator.duty_management.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await
        }))
    }

    /// One subscription pass in a task, joined with a bound. True only if it returned `Ok`.
    async fn subscribe_bounded(&self) -> bool {
        subscribed(self.spawn_subscriptions()).await
    }

    /// Reports the first signal after the baseline: a new remote sign or a new waiter.
    async fn wait_for_competitor(&self, calls: usize, registrations: usize) -> Competitor {
        for _ in 0..YIELD_ROUNDS {
            if self.remote.calls() > calls {
                return Competitor::Signing;
            }
            if self.cache().waiter_registrations() > registrations {
                return Competitor::Waiting;
            }
            tokio::task::yield_now().await;
        }
        Competitor::Neither
    }
}

/// True only if the subscription task finished within the bound and returned `Ok`.
async fn subscribed(handle: tokio::task::JoinHandle<Result<(), OrchestratorError>>) -> bool {
    let handles = [handle];
    let _ = join_bounded(&handles).await;
    let [handle] = handles;
    matches!(finished_output(handle).await, Some(Ok(())))
}

/// 655-AC3: aggregation reuses the selection proof that the subscription pass signed.
#[tokio::test(flavor = "current_thread")]
async fn test_aggregation_reuses_subscription_selection_proof() {
    let s = Subscribing::new().await;

    assert!(s.subscribe_bounded().await, "the subscription pass sends its POST");
    assert_eq!(s.remote.calls(), 1, "the subscription pass signs in the admission scope");
    assert_eq!(s.aggregator_slots(), ["100"], "the subscription selects the aggregator");
    assert!(aggregate_bounded(&s.orchestrator, SUBSCRIBED_SLOT).await, "the aggregation finishes");

    assert_eq!(s.remote.calls(), 1, "aggregation reuses the subscription's selection proof");
    assert_eq!(
        s.aggregate_fetches.load(Ordering::SeqCst),
        1,
        "aggregation uses the reused proof: it goes on to the aggregate fetch"
    );
}

/// The two services miss one key at once. The subscription pass owns it and aggregation waits.
#[tokio::test(flavor = "current_thread")]
async fn concurrent_subscription_and_aggregation_sign_one_proof() {
    let s = Subscribing::new().await;
    let gate = Arc::new(Gate::new());
    s.remote.hold_on(Arc::clone(&gate));

    let subscriber = s.spawn_subscriptions();
    let owner_entered = wait_until(|| s.remote.calls() == 1).await;
    let registrations = s.cache().waiter_registrations();
    let aggregation = spawn_aggregation(&s.orchestrator, SUBSCRIBED_SLOT);
    let competitor = s.wait_for_competitor(1, registrations).await;
    gate.open();
    let subscriber_done = subscribed(subscriber).await;
    let aggregation_done = joined(aggregation).await;

    assert!(owner_entered, "the subscription pass enters the remote sign");
    assert_eq!(s.remote.calls(), 1, "one signer call for the (slot, key) across both services");
    assert_eq!(competitor, Competitor::Waiting, "aggregation waits for the subscription owner");
    assert!(subscriber_done && aggregation_done, "both passes finish");
    assert_eq!(s.aggregator_slots(), ["100"], "the subscription uses its own proof");
    assert_eq!((s.cache().len(), s.cache().in_flight_len()), (1, 0), "one ready proof");
}

/// The subscription owner is cancelled while aggregation waits. Aggregation takes over and
/// signs. A later subscription pass is a hit.
#[tokio::test(flavor = "current_thread")]
async fn aggregation_takes_over_when_the_subscription_pass_is_cancelled() {
    let s = Subscribing::new().await;
    let gate = Arc::new(Gate::new());
    s.remote.hold_on(Arc::clone(&gate));

    let subscriber = s.spawn_subscriptions();
    let owner_entered = wait_until(|| s.remote.calls() == 1).await;
    let registrations = s.cache().waiter_registrations();
    let aggregation = spawn_aggregation(&s.orchestrator, SUBSCRIBED_SLOT);
    let competitor = s.wait_for_competitor(1, registrations).await;
    let owner_cancelled = abort_bounded(subscriber).await;
    gate.open();
    let aggregation_done = joined(aggregation).await;
    let in_flight_after = s.cache().in_flight_len();
    let calls_after_takeover = s.remote.calls();
    let resubscribed = s.subscribe_bounded().await;

    assert!(owner_entered, "the subscription pass enters the remote sign");
    assert_eq!(competitor, Competitor::Waiting, "aggregation waits for the subscription owner");
    assert!(owner_cancelled, "the subscription pass ends as cancelled");
    assert!(aggregation_done, "aggregation finishes after the take-over");
    assert_eq!(calls_after_takeover, 2, "the cancelled owner's sign and aggregation's sign");
    assert_eq!(in_flight_after, 0, "no entry stays in flight");
    assert!(resubscribed, "the later subscription pass sends its POST");
    assert_eq!(s.remote.calls(), 2, "the later subscription pass is a hit");
    assert_eq!(s.aggregator_slots(), ["100"], "only the later pass posts");
    assert_eq!((s.cache().len(), s.cache().in_flight_len()), (1, 0));
}

/// Subscriptions wait for an aggregation owner and use its proof. A cancelled subscription
/// waiter leaves the owner's entry, and a later pass is a hit.
#[tokio::test(flavor = "current_thread")]
async fn subscription_reuses_the_aggregation_selection_proof() {
    let s = Subscribing::new().await;
    let gate = Arc::new(Gate::new());
    s.remote.hold_on(Arc::clone(&gate));

    let owner = spawn_aggregation(&s.orchestrator, SUBSCRIBED_SLOT);
    let owner_entered = wait_until(|| s.remote.calls() == 1).await;
    let registrations = s.cache().waiter_registrations();
    let dropped = s.spawn_subscriptions();
    let first = s.wait_for_competitor(1, registrations).await;
    let dropped_cancelled = abort_bounded(dropped).await;
    let in_flight_after_drop = s.cache().in_flight_len();
    let registrations = s.cache().waiter_registrations();
    let waiter = s.spawn_subscriptions();
    let second = s.wait_for_competitor(1, registrations).await;
    gate.open();
    let owner_done = joined(owner).await;
    let waiter_done = subscribed(waiter).await;
    let posted_after_wait = s.aggregator_slots();
    let hit = s.subscribe_bounded().await;

    assert!(owner_entered, "aggregation enters the remote sign");
    assert_eq!((first, second), (Competitor::Waiting, Competitor::Waiting), "both passes wait");
    assert!(dropped_cancelled, "the first subscription waiter ends as cancelled");
    assert_eq!(in_flight_after_drop, 1, "a cancelled waiter leaves the owner's entry");
    assert!(owner_done && waiter_done, "the owner and the second waiter finish");
    assert_eq!(posted_after_wait, ["100"], "the waiter posts with the owner's proof");
    assert!(hit, "the third subscription pass sends its POST");
    assert_eq!(s.aggregator_slots(), ["100", "100"], "the ready hit posts with the proof");
    assert_eq!(s.remote.calls(), 1, "one signer call for the (slot, key)");
    assert_eq!((s.cache().len(), s.cache().in_flight_len()), (1, 0));
}

/// A subscription waiter that takes over from a cancelled owner checks the store gate again
/// just before it signs. A key disabled during the wait gets no new sign.
#[tokio::test(flavor = "current_thread")]
async fn subscription_takeover_rechecks_the_store_gate() {
    let s = Subscribing::new().await;
    let gate = Arc::new(Gate::new());
    s.remote.hold_on(Arc::clone(&gate));

    let owner = spawn_aggregation(&s.orchestrator, SUBSCRIBED_SLOT);
    let owner_entered = wait_until(|| s.remote.calls() == 1).await;
    let registrations = s.cache().waiter_registrations();
    let subscriber = s.spawn_subscriptions();
    let competitor = s.wait_for_competitor(1, registrations).await;
    s.orchestrator.validator_store.set_enabled(&s.pubkey.to_bytes(), false);
    let owner_cancelled = abort_bounded(owner).await;
    gate.open();
    let subscriber_done = subscribed(subscriber).await;

    assert!(owner_entered, "aggregation enters the remote sign");
    assert_eq!(competitor, Competitor::Waiting, "the subscription pass waits for the owner");
    assert!(owner_cancelled, "the aggregation owner ends as cancelled");
    assert!(subscriber_done, "the subscription pass finishes with nothing to send");
    assert_eq!(s.remote.calls(), 1, "a key disabled during the wait gets no new sign");
    assert!(s.posted.lock().is_empty(), "no subscription for a disabled key");
    assert_eq!((s.cache().len(), s.cache().in_flight_len()), (0, 0), "no entry stays");
}

/// The runner's first pass of the next epoch evicts the old epoch. An aggregation for a slot of
/// the old epoch then signs nothing.
#[tokio::test(flavor = "current_thread")]
async fn aggregation_below_the_runner_eviction_signs_nothing() {
    let s = Subscribing::new().await;

    s.orchestrator.epoch_boundary.run_pending((SUBSCRIBED_EPOCH + 1) * SLOTS_PER_EPOCH).await;
    let calls_after_pass = s.remote.calls();
    let aggregation_done = aggregate_bounded(&s.orchestrator, SUBSCRIBED_SLOT).await;

    assert_eq!(calls_after_pass, 2, "the pass signs the subscription proofs of E+1 and E+2");
    assert!(aggregation_done, "the aggregation finishes");
    assert_eq!(s.remote.calls(), calls_after_pass, "a slot below the cutoff signs nothing");
    assert_eq!(s.cache().len(), 2, "only the proofs of E+1 and E+2 stay");
}

/// A fixed selection proof: the signature of a fixed key over `fixed proof {tag}`.
fn fixed_proof(tag: u32) -> crypto::Signature {
    let key = SecretKey::from_bytes(&[0x11; 32]).expect("a fixed secret key");
    key.sign(format!("fixed proof {tag}").as_bytes())
}

/// Harper B1 / RSA N3 (#1038 R1, R2): the subscription flag comes from the cached proof and
/// from each pass's own `committee_length`. Two fixed proofs give opposite flags at committee
/// 128, so a substitute for the proof (for example 96 zero bytes) fails one of them. Each one
/// then flips at a second committee length. The proof is a cache hit: no signer call.
#[tokio::test(flavor = "current_thread")]
async fn subscription_recomputes_is_aggregator_for_each_committee_length() {
    let (selects, does_not) = (fixed_proof(16), fixed_proof(0));
    for (proof, other_raw) in [(&selects, u64::MAX), (&does_not, 8)] {
        assert_ne!(
            signer::is_aggregator(128, &proof.to_bytes()),
            signer::is_aggregator(other_raw, &proof.to_bytes()),
            "precondition: the second length flips the flag"
        );
    }
    assert!(signer::is_aggregator(128, &selects.to_bytes()), "precondition: tag 16 selects");
    assert!(!signer::is_aggregator(128, &does_not.to_bytes()), "precondition: tag 0 does not");

    for (proof, other_length) in [(selects, NO_AGGREGATOR_COMMITTEE), (does_not, "8")] {
        let s = Subscribing::new().await;
        let want_first = signer::is_aggregator(128, &proof.to_bytes());
        s.seed(proof).await;
        for length in ["128", other_length] {
            *s.committee.lock() = length.to_string();
            s.orchestrator
                .duty_tracker
                .fetch_duties_for_epoch(SUBSCRIBED_EPOCH)
                .await
                .expect("fetch the duty");
            assert!(s.subscribe_bounded().await, "committee {length}: the pass sends its POST");
        }

        assert_eq!(
            s.posted_flags(),
            [("100".to_string(), want_first), ("100".to_string(), !want_first)],
            "each pass posts the flag of the cached proof at its own committee length"
        );
        assert_eq!(s.remote.calls(), 0, "both passes are cache hits with no signer call");
    }
}

/// RSA N2 (#1038 R1): admission moves while the subscription pass waits for an aggregation
/// owner. After the owner is cancelled, the subscription owns the key, but its last check
/// before the sign refuses the stale admission (RSA B1, #1043 R1): no new backend call and no
/// POST. The pass read its duty before the move. For this reason, it must return
/// `RevokedInFlight` (Harper B1, #1043 R1).
#[tokio::test(flavor = "current_thread")]
async fn subscription_takeover_signs_nothing_after_a_revocation() {
    let s = Subscribing::new().await;
    let gate = Arc::new(Gate::new());
    s.remote.hold_on(Arc::clone(&gate));

    let owner = spawn_aggregation(&s.orchestrator, SUBSCRIBED_SLOT);
    let owner_entered = wait_until(|| s.remote.calls() == 1).await;
    let registrations = s.cache().waiter_registrations();
    let subscriber = s.spawn_subscriptions();
    let competitor = s.wait_for_competitor(1, registrations).await;
    s.admission.fetch_add(1, Ordering::SeqCst);
    let owner_cancelled = abort_bounded(owner).await;
    gate.open();
    let handles = [subscriber];
    let _ = join_bounded(&handles).await;
    let [subscriber] = handles;
    let outcome = finished_output(subscriber).await;

    assert!(owner_entered, "aggregation enters the remote sign");
    assert_eq!(competitor, Competitor::Waiting, "the subscription pass waits for the owner");
    assert!(owner_cancelled, "the aggregation owner ends as cancelled");
    assert!(
        matches!(
            outcome,
            Some(Err(OrchestratorError::Beacon(bn_manager::BeaconError::RevokedInFlight)))
        ),
        "After the revocation, the pass must return RevokedInFlight: {outcome:?}"
    );
    assert_eq!(s.remote.calls(), 1, "a revoked admission gets no new backend call");
    assert!(s.posted.lock().is_empty(), "no subscription after the revocation");
    assert_eq!((s.cache().len(), s.cache().in_flight_len()), (0, 0), "no entry stays");
}

/// RSA N4 (#1038 R1): a duty below the eviction cutoff makes no signer call and no POST, and
/// the call is `Ok`.
#[tokio::test(flavor = "current_thread")]
async fn evicted_subscription_duty_is_skipped_without_a_sign() {
    let s = Subscribing::new().await;
    s.orchestrator.duty_management.evict_selection_proofs_before(SUBSCRIBED_SLOT + 1);

    let done = s.subscribe_bounded().await;

    assert!(done, "an evicted duty is nothing to send");
    assert_eq!(s.remote.calls(), 0, "an evicted duty makes no signer call");
    assert!(s.posted.lock().is_empty(), "an evicted duty sends no subscription");
    assert_eq!(s.cache().len(), 0, "the cache adds no entry");
}

/// Two keys with duties at slots 100 and 101. The key at slot 100 is not in the signer yet, so
/// its sign fails; the key at slot 101 signs through a [`CountingRemote`].
struct TwoKeys {
    orchestrator: Arc<MockOrchestrator>,
    composite: Arc<CompositeSigner>,
    failing: [u8; 48],
    failing_remote: CountingRemote,
    healthy_remote: CountingRemote,
    posted: Posted,
}

impl TwoKeys {
    async fn new() -> Self {
        let (failing_secret, healthy_secret) = (SecretKey::generate(), SecretKey::generate());
        let (failing, healthy) = (failing_secret.public_key(), healthy_secret.public_key());
        let hex = |key: &PublicKey| format!("0x{}", hex::encode(key.to_bytes()));
        let (failing_hex, healthy_hex) = (hex(&failing), hex(&healthy));
        let posted = Posted::default();
        let record = Arc::clone(&posted);
        let duty_hexes = (failing_hex.clone(), healthy_hex.clone());
        let mock = aggregator_duty_mock(&healthy_hex, SUBSCRIBED_SLOT)
            .with_get_attester_duties(move |epoch, _indices| {
                Ok(duties_response(vec![
                    attester_duty(&duty_hexes.0, epoch, SUBSCRIBED_SLOT, "8".into()),
                    attester_duty(&duty_hexes.1, epoch, SUBSCRIBED_SLOT + 1, "8".into()),
                ]))
            })
            .with_submit_beacon_committee_subscriptions(move |subscriptions| {
                record.lock().extend(subscriptions);
                Ok(())
            });
        mock.track_admission();
        let beacon = Arc::new(mock);

        let healthy_remote = CountingRemote::new(healthy_secret);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        composite.add_remote_key(healthy.to_bytes(), Arc::new(healthy_remote.clone()));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("in-memory slashing db"));
        let signer = Arc::new(
            SignerService::new(Arc::clone(&composite), slashing_db)
                .with_enablement(always_enabled()),
        );
        let validator_store = create_mock_validator_store();
        let mut pubkeys = HashMap::new();
        for pubkey in [failing.clone(), healthy] {
            validator_store
                .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
                .expect("register the key");
            pubkeys.insert(pubkey.to_bytes(), pubkey);
        }
        let duty_tracker =
            Arc::new(DutyTracker::new(beacon.clone(), vec![failing_hex, healthy_hex]));
        duty_tracker.fetch_duties_for_epoch(SUBSCRIBED_EPOCH).await.expect("fetch the duties");
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
            clock,
            duty_tracker,
            signer,
            Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            create_test_config(),
            Arc::new(parking_lot::RwLock::new(pubkeys)),
        ));
        Self {
            orchestrator: Arc::new(orchestrator),
            composite,
            failing: failing.to_bytes(),
            failing_remote: CountingRemote::new(failing_secret),
            healthy_remote,
            posted,
        }
    }

    async fn subscribe_bounded(&self) -> bool {
        let orchestrator = Arc::clone(&self.orchestrator);
        subscribed(tokio::spawn(signer::require_beacon_admission_scope(async move {
            orchestrator.duty_management.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await
        })))
        .await
    }

    fn posted_slots(&self) -> Vec<String> {
        self.posted.lock().iter().map(|sub| sub.slot.clone()).collect()
    }
}

/// Harper B3 (#1038 R1): a signer error skips only its own duty. The call is `Ok`, the POST
/// carries the healthy duty, and the failed key leaves no cache entry, so it signs on a retry.
#[tokio::test(flavor = "current_thread")]
async fn a_signer_error_skips_only_its_duty() {
    let k = TwoKeys::new().await;
    let cache = &k.orchestrator.selection_proofs;

    let first = k.subscribe_bounded().await;
    let posted_first = k.posted_slots();
    let entries_first = (cache.len(), cache.in_flight_len());
    k.composite.add_remote_key(k.failing, Arc::new(k.failing_remote.clone()));
    let retry = k.subscribe_bounded().await;

    assert!(first, "a failed sign of one duty does not fail the call");
    assert_eq!(posted_first, ["101"], "the POST carries only the healthy duty");
    assert_eq!(entries_first, (1, 0), "the failed key leaves no cache entry");
    assert!(retry, "the retry sends its POST");
    assert_eq!(k.posted_slots(), ["101", "100", "101"], "the retry carries both duties");
    assert_eq!(k.failing_remote.calls(), 1, "the failed key signs on the retry");
    assert_eq!(k.healthy_remote.calls(), 1, "the healthy key's proof is a hit on the retry");
}
