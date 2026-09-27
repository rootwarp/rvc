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
    let signer = Arc::new(MockSigner::new());
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(pubkey)),
        Arc::new(test_fork_schedule()),
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

    let result = harness.service.propose_block(slot, &pubkey, proposer, None).await;
    assert!(result.is_ok(), "real JSON block must publish, got {result:?}");
    assert_eq!(harness.signer.block_calls.lock().unwrap().len(), 1, "block must be signed");
    assert_eq!(harness.beacon.publish_contents_calls.lock().unwrap().len(), 1);
    assert_eq!(blob_sidecars_published("deneb"), 1, "JSON contents publish increments the counter");
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
        let result = harness.service.propose_block(slot, &pubkey, proposer, None).await;
        assert!(result.is_ok(), "{label} publish failed: {result:?}");
        let calls = harness.beacon.publish_contents_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "{label}");
        assert_eq!(calls[0].contents.kzg_proofs, proofs, "{label} kzg_proofs");
        assert_eq!(calls[0].contents.blobs, blobs, "{label} blobs");
        assert_eq!(blob_sidecars_published(label), 1, "{label} counter");
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
