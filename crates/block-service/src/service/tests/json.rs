//! Live JSON produce/publish. Fixtures are RR-3.5's Beacon-API documents.
//! Assertions read the capture mock, not a second parse of the published body.

use std::sync::Arc;

use super::*;

const DENEB_CONTENTS_JSON: &str =
    include_str!("../../../../eth-types/tests/fixtures/beacon_api/deneb_block_contents.json");
const FULU_CONTENTS_JSON: &str =
    include_str!("../../../../eth-types/tests/fixtures/beacon_api/fulu_block_contents.json");
const ELECTRA_BODY_JSON: &str =
    include_str!("../../../../eth-types/tests/fixtures/beacon_api/electra_block_body.json");
const GLOAS_BODY_JSON: &str =
    include_str!("../../../../eth-types/tests/fixtures/beacon_api/gloas_block_body.json");

fn fixture_doc(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("fixture json")
}

fn decode_hex_list(value: &serde_json::Value) -> Vec<Vec<u8>> {
    value
        .as_array()
        .expect("hex list")
        .iter()
        .map(|item| {
            let text = item.as_str().expect("hex string").trim_start_matches("0x");
            hex::decode(text).expect("hex bytes")
        })
        .collect()
}

fn quoted_u64(value: &serde_json::Value) -> u64 {
    value.as_str().expect("quoted integer").parse().expect("u64")
}

fn contents_response(text: &str) -> ProduceBlockResponse {
    let doc = fixture_doc(text);
    let version = doc["version"].as_str().expect("fixture version").to_string();
    ProduceBlockResponse {
        data: doc["data"].clone(),
        is_blinded: false,
        consensus_version: version,
        execution_payload_value: Some("1".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    }
}

struct JsonHarness {
    service: BlockService<MockSigner, MockBeaconClient>,
    signer: Arc<MockSigner>,
    beacon: Arc<MockBeaconClient>,
}

fn harness(response: ProduceBlockResponse, pubkey: &PublicKey) -> JsonHarness {
    let version = response.consensus_version.clone();
    harness_on(response, pubkey, &test_fork_schedule_for(&version))
}

fn harness_on(
    response: ProduceBlockResponse,
    pubkey: &PublicKey,
    fork: &ForkSchedule,
) -> JsonHarness {
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(pubkey)),
        Arc::new(fork.clone()),
        [0xaa; 32],
    );
    JsonHarness { service, signer, beacon }
}

#[tokio::test]
async fn a_real_beacon_api_json_block_is_produced_signed_and_published() {
    let pubkey = test_pubkey();
    let response = contents_response(DENEB_CONTENTS_JSON);
    let doc = fixture_doc(DENEB_CONTENTS_JSON);
    let slot = quoted_u64(&doc["data"]["block"]["slot"]);
    let proposer = quoted_u64(&doc["data"]["block"]["proposer_index"]);
    let harness = harness(response, &pubkey);

    let sidecars_before = blob_sidecars_published("deneb");
    let result = harness.service.propose_block(slot, &pubkey, proposer, None).await;
    assert!(result.is_ok(), "real JSON block must publish, got {result:?}");
    assert_eq!(harness.signer.block_calls.lock().unwrap().len(), 1, "block must be signed");
    assert_eq!(harness.beacon.publish_contents_calls.lock().unwrap().len(), 1);
    assert!(
        blob_sidecars_published("deneb") > sidecars_before,
        "JSON contents publish increments the counter"
    );
    assert!(
        harness.beacon.publish_calls.lock().unwrap().is_empty(),
        "BlockAndBlobs must not publish a bare block"
    );
}

#[tokio::test]
async fn published_contents_carry_the_original_kzg_proofs_and_blobs() {
    for (label, text) in [("deneb", DENEB_CONTENTS_JSON), ("fulu", FULU_CONTENTS_JSON)] {
        let doc = fixture_doc(text);
        let data = &doc["data"];
        let proofs = decode_hex_list(&data["kzg_proofs"]);
        let blobs = decode_hex_list(&data["blobs"]);
        assert!(!proofs.is_empty() && !blobs.is_empty(), "{label} fixture arrays are non-empty");
        if label == "fulu" {
            assert_eq!(eth_types::CELLS_PER_EXT_BLOB, 128);
            assert_eq!(proofs.len(), blobs.len() * 128, "fulu cell proofs");
        } else {
            assert_eq!(proofs.len(), blobs.len(), "{label} one proof per blob");
        }
        let slot = quoted_u64(&data["block"]["slot"]);
        let proposer = quoted_u64(&data["block"]["proposer_index"]);
        let pubkey = test_pubkey();
        let harness = harness(contents_response(text), &pubkey);
        let sidecars_before = blob_sidecars_published(label);
        let result = harness.service.propose_block(slot, &pubkey, proposer, None).await;
        assert!(result.is_ok(), "{label} publish failed: {result:?}");
        let calls = harness.beacon.publish_contents_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "{label}");
        assert_eq!(calls[0].contents.kzg_proofs, proofs, "{label} kzg_proofs");
        assert_eq!(calls[0].contents.blobs, blobs, "{label} blobs");
        assert!(blob_sidecars_published(label) > sidecars_before, "{label} counter");
    }
}

#[tokio::test]
async fn published_signed_block_body_is_an_object_not_hex() {
    let doc = fixture_doc(DENEB_CONTENTS_JSON);
    let slot = quoted_u64(&doc["data"]["block"]["slot"]);
    let proposer = quoted_u64(&doc["data"]["block"]["proposer_index"]);
    let pubkey = test_pubkey();
    let harness = harness(contents_response(DENEB_CONTENTS_JSON), &pubkey);
    harness.service.propose_block(slot, &pubkey, proposer, None).await.unwrap();

    let calls = harness.beacon.publish_contents_calls.lock().unwrap();
    let wire = serde_json::to_value(&calls[0].contents).expect("serialize recorded contents");
    assert!(
        wire["signed_block"]["message"]["body"].is_object(),
        "signed_block.message.body must be a JSON object, not hex: {wire}"
    );
    assert!(!wire["signed_block"]["message"]["body"].is_string());
}

#[tokio::test]
async fn gloas_json_body_fails_closed_and_publishes_nothing() {
    let gloas_body: serde_json::Value = serde_json::from_str(GLOAS_BODY_JSON).unwrap();
    let data = serde_json::json!({
        "slot": "100",
        "proposer_index": "42",
        "parent_root": format!("0x{}", hex::encode([0x11u8; 32])),
        "state_root": format!("0x{}", hex::encode([0x22u8; 32])),
        "body": gloas_body,
    });
    let response = ProduceBlockResponse {
        data: data.clone(),
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: None,
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    };
    let err = response.parse_full_block().expect_err("gloas JSON body must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("Gloas"), "{msg}");

    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err = harness.service.propose_block(100, &pubkey, 42, None).await.expect_err("no publish");
    assert!(
        matches!(err, BlockServiceError::ConsensusVersionMismatch { .. })
            || matches!(err, BlockServiceError::Parse(_)),
        "{err:?}"
    );
    assert!(harness.signer.block_calls.lock().unwrap().is_empty(), "must not sign");
    assert!(harness.beacon.publish_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_contents_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_ssz_calls.lock().unwrap().is_empty());
    assert_eq!(blob_sidecars_published("gloas"), 0, "Gloas must not increment");
}

fn blob_sidecars_published(fork: &str) -> u64 {
    crate::metrics::RVC_BLOB_SIDECARS_PUBLISHED_TOTAL.with_label_values(&[fork]).get()
}

#[tokio::test]
async fn no_bare_signed_beacon_block_is_published_for_a_block_and_blobs_response() {
    for text in [DENEB_CONTENTS_JSON, FULU_CONTENTS_JSON] {
        let doc = fixture_doc(text);
        let slot = quoted_u64(&doc["data"]["block"]["slot"]);
        let proposer = quoted_u64(&doc["data"]["block"]["proposer_index"]);
        let pubkey = test_pubkey();
        let harness = harness(contents_response(text), &pubkey);
        harness.service.propose_block(slot, &pubkey, proposer, None).await.unwrap();
        assert!(harness.beacon.publish_calls.lock().unwrap().is_empty());
        assert!(harness.beacon.publish_full_calls.lock().unwrap().is_empty());
        assert_eq!(harness.beacon.publish_contents_calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn signing_root_is_unchanged_for_the_same_block() {
    let body: serde_json::Value = serde_json::from_str(ELECTRA_BODY_JSON).expect("electra body");
    let data = serde_json::json!({
        "slot": "3000000",
        "proposer_index": "42",
        "parent_root": format!("0x{}", "11".repeat(32)),
        "state_root": format!("0x{}", "22".repeat(32)),
        "body": body,
    });
    let response = ProduceBlockResponse {
        data,
        is_blinded: false,
        consensus_version: "electra".to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    };
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let result = harness.service.propose_block(3_000_000, &pubkey, 42, None).await.unwrap();
    let expected = hex::decode(eth_types::EXTERNAL_ELECTRA_BLOCK_ROOT_HEX).unwrap();
    assert_eq!(
        result.block_root.as_slice(),
        expected.as_slice(),
        "JSON produce must keep the SEC-6c block root"
    );
    let calls = harness.signer.block_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].block_root.as_slice(), expected.as_slice());
}

const DENEB_BLINDED_BODY_JSON: &str =
    include_str!("../../../../eth-types/tests/fixtures/beacon_api/deneb_blinded_block_body.json");
const ELECTRA_BLINDED_BODY_JSON: &str =
    include_str!("../../../../eth-types/tests/fixtures/beacon_api/electra_blinded_block_body.json");

fn blinded_body(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("blinded body fixture")
}

fn kat_blinded_block(body: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "slot": "3000000",
        "proposer_index": "42",
        "parent_root": format!("0x{}", "11".repeat(32)),
        "state_root": format!("0x{}", "22".repeat(32)),
        "body": body,
    })
}

fn blinded_produce(data: serde_json::Value, version: &str) -> ProduceBlockResponse {
    ProduceBlockResponse {
        data,
        is_blinded: true,
        consensus_version: version.to_string(),
        execution_payload_value: None,
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    }
}

fn electra_block_root() -> Vec<u8> {
    hex::decode(eth_types::EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX).expect("electra block root")
}

fn assert_nothing_signed_or_published(harness: &JsonHarness) {
    assert!(harness.signer.header_calls.lock().unwrap().is_empty(), "header must stay unsigned");
    assert!(harness.signer.block_calls.lock().unwrap().is_empty(), "block must stay unsigned");
    assert!(harness.beacon.publish_blinded_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_blinded_full_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_full_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_contents_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_ssz_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.envelope_publish_calls.lock().unwrap().is_empty());
}

fn assert_one_blinded_publish(harness: &JsonHarness, version: &str, root: &[u8]) {
    assert_eq!(harness.beacon.publish_blinded_calls.lock().unwrap().as_slice(), [version]);
    assert_eq!(harness.beacon.publish_blinded_full_calls.lock().unwrap().len(), 1);
    assert!(harness.beacon.publish_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_contents_calls.lock().unwrap().is_empty());
    assert!(harness.beacon.publish_ssz_calls.lock().unwrap().is_empty());
    let headers = harness.signer.header_calls.lock().unwrap();
    assert_eq!(headers.len(), 1);
    assert!(headers[0].header.is_blinded);
    let calls = harness.signer.block_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].block_root.as_slice(), root);
}

#[tokio::test]
async fn json_blinded_electra_proposal_signs_the_external_block_root() {
    let body = blinded_body(ELECTRA_BLINDED_BODY_JSON);
    let response = blinded_produce(kat_blinded_block(body.clone()), "electra");
    let first = response.parse_blinded_block().expect("first parse");
    let second = response.parse_blinded_block().expect("second parse");
    assert_eq!(first.body, second.body, "a second parse matches the first; nothing is stored");
    assert_eq!(response.data["body"], body);

    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let result =
        harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect("publish");
    let root = electra_block_root();
    assert!(result.is_blinded);
    assert_eq!(result.consensus_version, "electra");
    assert_eq!(result.block_root.as_slice(), root.as_slice());
    assert_one_blinded_publish(&harness, "electra", &root);
    let body_root = hex::encode(harness.signer.header_calls.lock().unwrap()[0].header.body_root);
    assert_eq!(body_root, eth_types::EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX);
    assert!(
        harness.beacon.produce_response.as_ref().expect("response").data["body"].is_object(),
        "stored produce body stays a JSON object"
    );
}

#[tokio::test]
async fn json_blinded_fulu_version_reuses_the_electra_block_root() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), "fulu");
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let result = harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect("fulu");
    let root = electra_block_root();
    assert_eq!(result.block_root.as_slice(), root.as_slice());
    assert_eq!(result.consensus_version, "fulu");
    assert_one_blinded_publish(&harness, "fulu", &root);
    let body_root = hex::encode(harness.signer.header_calls.lock().unwrap()[0].header.body_root);
    assert_eq!(body_root, eth_types::EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX);
}

#[tokio::test]
async fn json_blinded_deneb_proposal_signs_the_external_body_root() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(DENEB_BLINDED_BODY_JSON)), "deneb");
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let result = harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect("deneb");
    assert!(result.is_blinded);
    assert_one_blinded_publish(&harness, "deneb", result.block_root.as_slice());
    let body_root = hex::encode(harness.signer.header_calls.lock().unwrap()[0].header.body_root);
    assert_eq!(body_root, eth_types::EXTERNAL_DENEB_BODY_ROOT_HEX);
    assert_ne!(result.block_root.as_slice(), electra_block_root().as_slice());
}

#[tokio::test]
async fn execution_only_rejects_a_blinded_json_block_before_signing() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), "electra");
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err = harness
        .service
        .propose_block_with_mode(3_000_000, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("execution-only");
    assert!(
        matches!(
            err,
            BlockServiceError::ModeShapeMismatch {
                mode: BlockSelectionMode::ExecutionOnly,
                shape: crate::types::CandidateShape::Blinded,
            }
        ),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "mode execution-only rejects shape blinded");
    assert_nothing_signed_or_published(&harness);
}

#[tokio::test]
async fn builder_only_publishes_a_blinded_json_block() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), "electra");
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let result = harness
        .service
        .propose_block_with_mode(3_000_000, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect("builder-only");
    assert!(result.is_blinded);
    assert_eq!(result.block_root.as_slice(), electra_block_root().as_slice());
    assert_one_blinded_publish(&harness, "electra", result.block_root.as_slice());
}

#[tokio::test]
async fn builder_only_invalid_body_is_parse_not_a_builder_miss() {
    let mut body = blinded_body(ELECTRA_BLINDED_BODY_JSON);
    body.as_object_mut().expect("object").remove("randao_reveal");
    let response = blinded_produce(kat_blinded_block(body), "electra");
    let stored = response.data.clone();
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err = harness
        .service
        .propose_block_with_mode(3_000_000, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("partial body");
    match err {
        BlockServiceError::Parse(msg) => {
            assert!(msg.contains("invalid JSON block body"), "{msg}");
            assert!(msg.contains("randao_reveal"), "{msg}");
        }
        other => panic!("expected Parse, got {other:?}"),
    }
    assert_nothing_signed_or_published(&harness);
    assert_eq!(harness.beacon.produce_response.as_ref().expect("response").data, stored);
}

#[tokio::test]
async fn pre_deneb_versions_are_parse_before_signing() {
    for version in ["phase0", "altair", "bellatrix", "capella"] {
        let response =
            blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), version);
        let pubkey = test_pubkey();
        let harness = harness(response, &pubkey);
        let err =
            harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err(version);
        match err {
            BlockServiceError::Parse(msg) => {
                assert_eq!(
                    msg,
                    format!("JSON block body is unsupported for consensus version {version}"),
                    "{version}"
                );
            }
            other => panic!("{version}: {other:?}"),
        }
        assert_nothing_signed_or_published(&harness);
        assert!(
            harness.beacon.produce_response.as_ref().expect("response").data["body"].is_object()
        );
    }
}

#[tokio::test]
async fn unknown_consensus_versions_mismatch_before_signing() {
    for version in ["DENEB", ""] {
        let response =
            blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), version);
        let pubkey = test_pubkey();
        let harness = harness_on(response, &pubkey, &test_fork_schedule());
        let err =
            harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err(version);
        let BlockServiceError::ConsensusVersionMismatch { expected, got } = err else {
            panic!("{version}: {err:?}");
        };
        assert_eq!(expected, "fulu");
        assert_eq!(got, version);
        assert_nothing_signed_or_published(&harness);
    }
}

#[tokio::test]
async fn gloas_blinded_json_is_dropped_before_the_codec_on_the_proposal_path() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), "gloas");
    match response.parse_blinded_block() {
        Err(beacon::BeaconError::ParseError(msg)) => {
            assert_eq!(
                msg,
                "invalid JSON block body: Gloas BeaconBlockBody layout is not supported"
            );
        }
        other => panic!("codec must fail closed: {other:?}"),
    }
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err = harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err("gloas");
    assert!(
        matches!(err, BlockServiceError::BlindedNotSupportedAtGloas { slot: 3_000_000 }),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "blinded block production is not supported at Gloas (slot 3000000)"
    );
    assert_nothing_signed_or_published(&harness);
}

#[tokio::test]
async fn electra_json_on_a_deneb_header_is_rejected_before_signing() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), "deneb");
    let pubkey = test_pubkey();
    // Slot 3_000_000 is Fulu on the default schedule. The header says Deneb.
    let harness = harness_on(response, &pubkey, &test_fork_schedule());
    let err = harness
        .service
        .propose_block(3_000_000, &pubkey, 42, None)
        .await
        .expect_err("version must match the slot fork");
    let BlockServiceError::ConsensusVersionMismatch { expected, got } = err else {
        panic!("{err:?}");
    };
    assert_eq!(expected, "fulu");
    assert_eq!(got, "deneb");
    assert_nothing_signed_or_published(&harness);
}

#[tokio::test]
async fn deneb_json_as_electra_is_parse_before_signing() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(DENEB_BLINDED_BODY_JSON)), "electra");
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err = harness
        .service
        .propose_block(3_000_000, &pubkey, 42, None)
        .await
        .expect_err("missing requests");
    match err {
        BlockServiceError::Parse(msg) => {
            assert!(msg.contains("invalid JSON block body"), "{msg}");
            assert!(msg.contains("execution_requests"), "{msg}");
        }
        other => panic!("{other:?}"),
    }
    assert_nothing_signed_or_published(&harness);
}

#[tokio::test]
async fn hex_ssz_blinded_body_keeps_the_electra_block_root() {
    let ssz = eth_types::external_vector_blinded_electra_body().as_ssz_bytes();
    let response = blinded_produce(
        kat_blinded_block(serde_json::Value::String(format!("0x{}", hex::encode(&ssz)))),
        "electra",
    );
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let result = harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect("hex");
    let expected = hex::decode(eth_types::EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX)
        .expect("electra block root");
    assert_eq!(result.block_root.as_slice(), expected.as_slice());
    assert_one_blinded_publish(&harness, "electra", &expected);
    assert!(harness.beacon.produce_response.as_ref().expect("response").data["body"].is_string());
}

fn full_produce(data: serde_json::Value, version: &str) -> ProduceBlockResponse {
    ProduceBlockResponse {
        data,
        is_blinded: false,
        consensus_version: version.to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    }
}

/// The fee reader and the decoder share one block object.
#[test]
fn execution_fee_address_uses_one_block_object() {
    let parent = format!("0x{}", "ab".repeat(32));
    let state = format!("0x{}", "00".repeat(32));
    let nested_fee = format!("0x{}", "22".repeat(20));
    let top_fee = format!("0x{}", "11".repeat(20));
    let nested = serde_json::json!({
        "slot": "1",
        "proposer_index": "7",
        "parent_root": parent,
        "state_root": state,
        "body": { "execution_payload": { "fee_recipient": nested_fee } },
    });
    let contents = serde_json::json!({
        "block": nested,
        "kzg_proofs": ["0xab"],
        "blobs": ["0xcd"],
    });
    let got = super::super::execution_fee_address(&full_produce(contents, "deneb"));
    assert_eq!(got, Some([0x22; 20]));

    let hybrid = serde_json::json!({
        "slot": "1",
        "proposer_index": "7",
        "parent_root": parent,
        "state_root": state,
        "body": { "execution_payload": { "fee_recipient": top_fee } },
        "block": nested,
        "kzg_proofs": ["0xab"],
        "blobs": ["0xcd"],
    });
    assert!(super::super::execution_fee_address(&full_produce(hybrid, "deneb")).is_none());
}

/// A blinded document that names two blocks is rejected before signing.
#[tokio::test]
async fn blinded_hybrid_document_signs_nothing() {
    let nested = kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON));
    let mut hybrid = nested.clone();
    hybrid["block"] = nested;
    let response = blinded_produce(hybrid, "electra");
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err =
        harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err("hybrid");
    match err {
        BlockServiceError::Parse(msg) => {
            assert!(msg.contains("both top-level block fields and a nested block"), "{msg}");
        }
        other => panic!("{other:?}"),
    }
    assert_nothing_signed_or_published(&harness);
}

/// A Deneb JSON object body under an Electra header must not be signed.
#[tokio::test]
async fn deneb_object_body_under_electra_header_signs_nothing() {
    let body = eth_types::block_body_json::encode(
        &test_body_ssz_for_version("deneb"),
        eth_types::BodyForkLayout::Deneb,
    )
    .expect("deneb object body");
    assert!(body.is_object());
    let response = full_produce(kat_blinded_block(body), "electra");
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err =
        harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err("object body");
    match err {
        BlockServiceError::Parse(msg) => {
            assert!(msg.contains("invalid JSON block body"), "{msg}");
        }
        other => panic!("{other:?}"),
    }
    assert_nothing_signed_or_published(&harness);
}

/// First Electra slot: a Deneb object body is rejected; an Electra object body is signed.
#[tokio::test]
async fn fork_boundary_slot_uses_the_slot_fork_for_an_object_body() {
    let slot = 50 * SLOTS_PER_EPOCH;
    let pubkey = test_pubkey();
    let fork = test_fork_schedule();

    let deneb = eth_types::block_body_json::encode(
        &test_body_ssz_for_version("deneb"),
        eth_types::BodyForkLayout::Deneb,
    )
    .expect("deneb object body");
    let mut deneb_doc = kat_blinded_block(deneb);
    deneb_doc["slot"] = serde_json::Value::String(slot.to_string());
    let rejected = harness_on(full_produce(deneb_doc, "electra"), &pubkey, &fork);
    let err = rejected.service.propose_block(slot, &pubkey, 42, None).await.expect_err("boundary");
    match err {
        BlockServiceError::Parse(msg) => {
            assert!(msg.contains("invalid JSON block body"), "{msg}");
        }
        other => panic!("{other:?}"),
    }
    assert_nothing_signed_or_published(&rejected);

    let electra = eth_types::block_body_json::encode(
        &test_body_ssz_for_version("electra"),
        eth_types::BodyForkLayout::Electra,
    )
    .expect("electra object body");
    let mut electra_doc = kat_blinded_block(electra);
    electra_doc["slot"] = serde_json::Value::String(slot.to_string());
    let accepted = harness_on(full_produce(electra_doc, "electra"), &pubkey, &fork);
    let result = accepted.service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "matching object body at the Electra boundary must sign: {result:?}");
    assert_eq!(accepted.signer.block_calls.lock().unwrap().len(), 1);
    assert_eq!(accepted.beacon.publish_full_calls.lock().unwrap().len(), 1);
}

/// A Deneb (or Electra) hex body under another fork's header must not be signed.
///
/// Auto-detect would hash the body under the wrong layout and burn the slot.
#[tokio::test]
async fn deneb_hex_full_body_under_electra_or_fulu_signs_nothing() {
    let cases = [("deneb", "electra"), ("deneb", "fulu"), ("electra", "deneb")];
    for (body_fork, header) in cases {
        let ssz = test_body_ssz_for_version(body_fork);
        let body = serde_json::Value::String(format!("0x{}", hex::encode(ssz)));
        let response = full_produce(kat_blinded_block(body), header);
        let pubkey = test_pubkey();
        let harness = harness(response, &pubkey);
        let err =
            harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err(header);
        match err {
            BlockServiceError::Parse(msg) => {
                assert!(
                    msg.contains("invalid block body for tree_hash_root")
                        && msg.contains("invalid SSZ body encoding"),
                    "{body_fork} body under {header} must fail the layout-keyed root: {msg}"
                );
            }
            other => panic!("{body_fork} body under {header}: {other:?}"),
        }
        assert_nothing_signed_or_published(&harness);
        assert!(harness.signer.header_calls.lock().unwrap().is_empty(), "{header}");
        assert!(harness.beacon.publish_calls.lock().unwrap().is_empty(), "{header}");
        assert!(harness.beacon.publish_contents_calls.lock().unwrap().is_empty(), "{header}");
        assert!(harness.beacon.publish_ssz_calls.lock().unwrap().is_empty(), "{header}");
    }
}

#[tokio::test]
async fn deneb_hex_body_under_electra_or_fulu_signs_nothing() {
    let ssz = eth_types::external_vector_blinded_deneb_body().as_ssz_bytes();
    let body = serde_json::Value::String(format!("0x{}", hex::encode(ssz)));
    for version in ["electra", "fulu"] {
        let response = blinded_produce(kat_blinded_block(body.clone()), version);
        let pubkey = test_pubkey();
        let harness = harness(response, &pubkey);
        let err =
            harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err(version);
        match err {
            BlockServiceError::Parse(msg) => {
                assert!(msg.contains("invalid SSZ body encoding"), "{version}: {msg}");
            }
            other => panic!("{version}: {other:?}"),
        }
        assert_nothing_signed_or_published(&harness);
        assert!(harness.signer.header_calls.lock().unwrap().is_empty(), "{version}");
        assert!(harness.beacon.publish_blinded_calls.lock().unwrap().is_empty(), "{version}");
    }
}

#[tokio::test]
async fn short_hex_and_full_payload_bodies_are_parse_before_signing() {
    let full: serde_json::Value = serde_json::from_str(ELECTRA_BODY_JSON).expect("full body");
    let cases = [
        ("short hex", serde_json::Value::String("0x00".to_string()), "invalid SSZ body encoding"),
        ("full payload", full, "invalid JSON block body"),
        ("null", serde_json::Value::Null, "invalid blinded block"),
        ("array", serde_json::Value::Array(vec![]), "invalid blinded block"),
    ];
    for (label, body, needle) in cases {
        let response = blinded_produce(kat_blinded_block(body), "electra");
        let stored = response.data.clone();
        let pubkey = test_pubkey();
        let harness = harness(response, &pubkey);
        let err =
            harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err(label);
        match err {
            BlockServiceError::Parse(msg) => assert!(msg.contains(needle), "{label}: {msg}"),
            other => panic!("{label}: {other:?}"),
        }
        assert_nothing_signed_or_published(&harness);
        assert_eq!(
            harness.beacon.produce_response.as_ref().expect("response").data,
            stored,
            "{label}"
        );
    }
}

#[tokio::test]
async fn short_parent_root_is_rejected_before_signing() {
    let mut data = kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON));
    data["parent_root"] = serde_json::json!("0x11");
    let response = blinded_produce(data, "electra");
    let stored = response.data.clone();
    let pubkey = test_pubkey();
    let harness = harness(response, &pubkey);
    let err =
        harness.service.propose_block(3_000_000, &pubkey, 42, None).await.expect_err("parent");
    match err {
        BlockServiceError::Parse(msg) => {
            assert!(msg.starts_with("invalid blinded block:"), "{msg}")
        }
        other => panic!("{other:?}"),
    }
    assert_nothing_signed_or_published(&harness);
    assert_eq!(harness.beacon.produce_response.as_ref().expect("response").data, stored);
}

#[tokio::test]
async fn parent_and_slot_mismatch_drop_the_duty_before_signing() {
    let response =
        blinded_produce(kat_blinded_block(blinded_body(ELECTRA_BLINDED_BODY_JSON)), "electra");
    let pubkey = test_pubkey();
    let parent_harness = harness(response.clone(), &pubkey);
    let err = parent_harness
        .service
        .propose_block(3_000_000, &pubkey, 42, Some(ExpectedParents::open([0x33; 32], None)))
        .await
        .expect_err("parent");
    assert_eq!(
        err.to_string(),
        format!(
            "parent_root mismatch: expected 0x{}, got 0x{}",
            hex::encode([0x33u8; 32]),
            hex::encode([0x11u8; 32])
        )
    );
    assert_nothing_signed_or_published(&parent_harness);

    let slot_harness = harness(response, &pubkey);
    let err =
        slot_harness.service.propose_block(3_000_001, &pubkey, 42, None).await.expect_err("slot");
    assert_eq!(err.to_string(), "slot mismatch: requested 3000001, got 3000000");
    assert_nothing_signed_or_published(&slot_harness);
}

/// A revoke of the second fence generation during `sign_block_header` is visible
/// in the admission scope. Forgetting `and_generation` leaves `holds` true.
#[tokio::test]
async fn sign_block_header_sees_the_second_admission_generation() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let pubkey = test_pubkey();
    let response = contents_response(DENEB_CONTENTS_JSON);
    let doc = fixture_doc(DENEB_CONTENTS_JSON);
    let slot = quoted_u64(&doc["data"]["block"]["slot"]);
    let proposer = quoted_u64(&doc["data"]["block"]["proposer_index"]);
    let version = response.consensus_version.clone();
    let primary = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let also = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut beacon = MockBeaconClient::from_response(response);
    beacon.revocation = Arc::clone(&primary);
    beacon.also_revocation = Some(Arc::clone(&also));
    let beacon = Arc::new(beacon);
    let signer = Arc::new(MockSigner::new());
    let saw_both = Arc::new(AtomicBool::new(false));
    {
        let primary = Arc::clone(&primary);
        let also = Arc::clone(&also);
        let saw_both = Arc::clone(&saw_both);
        *signer.before_header.lock().unwrap() = Some(Arc::new(move || {
            primary.fetch_add(1, Ordering::Release);
            let primary_drops = signer::testing_beacon_admission_holds() == Some(false);
            primary.fetch_sub(1, Ordering::Release);
            also.fetch_add(1, Ordering::Release);
            let also_drops = signer::testing_beacon_admission_holds() == Some(false);
            saw_both.store(primary_drops && also_drops, Ordering::Release);
            false
        }));
    }
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_for(&version)),
        [0xaa; 32],
    );
    let err = service.propose_block(slot, &pubkey, proposer, None).await.expect_err("refused");
    assert!(saw_both.load(Ordering::Acquire), "both generations must be installed, got {err}");
    assert!(signer.header_calls.lock().unwrap().is_empty(), "no signature is completed");
    assert!(beacon.publish_contents_calls.lock().unwrap().is_empty());
}

/// A parent-capture fence that is already stale must refuse before RANDAO.
#[tokio::test]
async fn stale_parent_capture_fence_signs_no_randao() {
    let pubkey = test_pubkey();
    let response = contents_response(DENEB_CONTENTS_JSON);
    let doc = fixture_doc(DENEB_CONTENTS_JSON);
    let slot = quoted_u64(&doc["data"]["block"]["slot"]);
    let proposer = quoted_u64(&doc["data"]["block"]["proposer_index"]);
    let version = response.consensus_version.clone();
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon,
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_for(&version)),
        [0xaa; 32],
    );
    let err = service
        .propose_block_until(slot, &pubkey, proposer, None, None, &beacon::DutyFence::closed())
        .await
        .expect_err("stale parent capture");
    assert!(err.to_string().contains("admission revoked"), "{err}");
    assert!(
        signer.randao_calls.lock().unwrap().is_empty(),
        "a stale parent-capture fence signs no RANDAO"
    );
}

/// A revoke of the third fence generation during `sign_block_header` is visible
/// in the admission scope. Copying only `also_generation` leaves `holds` true.
#[tokio::test]
async fn sign_block_header_sees_the_third_admission_generation() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let pubkey = test_pubkey();
    let response = contents_response(DENEB_CONTENTS_JSON);
    let doc = fixture_doc(DENEB_CONTENTS_JSON);
    let slot = quoted_u64(&doc["data"]["block"]["slot"]);
    let proposer = quoted_u64(&doc["data"]["block"]["proposer_index"]);
    let version = response.consensus_version.clone();
    let primary = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let also = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let third = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut beacon = MockBeaconClient::from_response(response);
    beacon.revocation = Arc::clone(&primary);
    beacon.also_revocation = Some(Arc::clone(&also));
    beacon.third_revocation = Some(Arc::clone(&third));
    let beacon = Arc::new(beacon);
    let signer = Arc::new(MockSigner::new());
    let saw_third = Arc::new(AtomicBool::new(false));
    {
        let third = Arc::clone(&third);
        let saw_third = Arc::clone(&saw_third);
        *signer.before_header.lock().unwrap() = Some(Arc::new(move || {
            third.fetch_add(1, Ordering::Release);
            let drops = signer::testing_beacon_admission_holds() == Some(false);
            third.fetch_sub(1, Ordering::Release);
            saw_third.store(drops, Ordering::Release);
            false
        }));
    }
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_for(&version)),
        [0xaa; 32],
    );
    let err = service.propose_block(slot, &pubkey, proposer, None).await.expect_err("refused");
    assert!(saw_third.load(Ordering::Acquire), "the third generation must be installed, got {err}");
    assert!(signer.header_calls.lock().unwrap().is_empty(), "no signature is completed");
}

/// The discard inside `sign_and_publish_prepared` must refuse the header.
///
/// The call after produce is index 0. Index 1 is the prepared-candidate
/// discard. Removing that call leaves the generation unmoved and the mock
/// signer completes the header.
#[tokio::test]
async fn prepared_discard_refuses_the_header_when_admission_moves() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let pubkey = test_pubkey();
    let response = contents_response(DENEB_CONTENTS_JSON);
    let doc = fixture_doc(DENEB_CONTENTS_JSON);
    let slot = quoted_u64(&doc["data"]["block"]["slot"]);
    let proposer = quoted_u64(&doc["data"]["block"]["proposer_index"]);
    let version = response.consensus_version.clone();
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_for(&version)),
        [0xaa; 32],
    );
    let revocation = Arc::clone(&beacon.revocation);
    let calls = AtomicUsize::new(0);
    service.set_before_discard(move || {
        if calls.fetch_add(1, Ordering::SeqCst) == 1 {
            revocation.fetch_add(1, Ordering::Release);
        }
    });
    let err = service.propose_block(slot, &pubkey, proposer, None).await.expect_err("discarded");
    assert!(err.to_string().contains("admission revoked"), "{err}");
    assert!(
        signer.header_calls.lock().unwrap().is_empty(),
        "sign_and_publish_prepared must drop the candidate before the header"
    );
}
