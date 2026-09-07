//! Issue 6.20: self-build publish through a BN that did not produce the block.

use std::sync::Arc;

use beacon::{
    HEADER_ETH_BLOB_DATA_INCLUDED, HEADER_ETH_CONSENSUS_VERSION,
    HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, PRODUCE_BLOCK_V4_PATH_PREFIX,
    PUBLISH_EXECUTION_PAYLOAD_ENVELOPES_PATH,
};
use block_service::BlockService;
use bn_manager::{BnManager, BnManagerConfig};
use crypto::SecretKey;
use eth_types::{BeaconBlock, ForkSchedule, SLOTS_PER_EPOCH};
use rvc::beacon_adapter::BeaconBlockAdapter;
use signer::StubValidatorSigner;
use validator_store::{ValidatorConfig, ValidatorStore};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_GLOAS_EPOCH: u64 = 70;

fn near_gloas_fork() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: 10,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch: 30,
        capella_fork_version: [3, 0, 0, 0],
        deneb_fork_epoch: 40,
        deneb_fork_version: [4, 0, 0, 0],
        electra_fork_epoch: 50,
        electra_fork_version: [5, 0, 0, 0],
        fulu_fork_epoch: 60,
        fulu_fork_version: [6, 0, 0, 0],
        gloas_fork_epoch: TEST_GLOAS_EPOCH,
        gloas_fork_version: [7, 0, 0, 0],
    }
}

fn gloas_block(slot: u64) -> BeaconBlock {
    BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body: hex::decode(rvc_gloas::test_fixtures::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ).unwrap(),
    }
}

fn contents_json(slot: u64) -> serde_json::Value {
    let envelope =
        format!("0x{}", rvc_gloas::test_fixtures::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
    serde_json::json!({
        "version": "gloas",
        "data": {
            "block": gloas_block(slot),
            "execution_payload_envelope": envelope,
            "kzg_proofs": ["0xaa"],
            "blobs": ["0xbb"],
        }
    })
}

fn produce_path(slot: u64) -> String {
    format!("{PRODUCE_BLOCK_V4_PATH_PREFIX}/{slot}")
}

#[tokio::test]
async fn test_self_build_publishes_block_and_envelope_through_second_bn() {
    let producer = MockServer::start().await;
    let publisher = MockServer::start().await;
    let slot = TEST_GLOAS_EPOCH * SLOTS_PER_EPOCH;
    let produce_path = produce_path(slot);

    Mock::given(method("POST"))
        .and(path(produce_path.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(HEADER_ETH_CONSENSUS_VERSION, "gloas")
                .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true")
                .set_body_json(contents_json(slot)),
        )
        .expect(1)
        .mount(&producer)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(500).set_body_string("producer has no cache"))
        .expect(1..)
        .mount(&producer)
        .await;
    Mock::given(method("POST"))
        .and(path(PUBLISH_EXECUTION_PAYLOAD_ENVELOPES_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_string("producer has no cache"))
        .expect(1..)
        .mount(&producer)
        .await;

    Mock::given(method("POST"))
        .and(path(produce_path.as_str()))
        .respond_with(ResponseTemplate::new(500).set_body_string("publisher does not produce"))
        .expect(0)
        .mount(&publisher)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&publisher)
        .await;
    Mock::given(method("POST"))
        .and(path(PUBLISH_EXECUTION_PAYLOAD_ENVELOPES_PATH))
        .and(header(HEADER_ETH_BLOB_DATA_INCLUDED, "true"))
        .and(header(HEADER_ETH_CONSENSUS_VERSION, "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&publisher)
        .await;

    let manager = BnManager::new(BnManagerConfig::new(vec![producer.uri(), publisher.uri()]))
        .expect("BnManager");
    let beacon = Arc::new(BeaconBlockAdapter(Arc::new(manager)));
    let pubkey = SecretKey::generate().public_key();
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();
    let service = BlockService::new(
        Arc::new(StubValidatorSigner::new()),
        beacon,
        Arc::new(store),
        Arc::new(near_gloas_fork()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "second-BN self-build must succeed: {result:?}");

    let publisher_reqs = publisher.received_requests().await.unwrap();
    assert!(
        publisher_reqs.iter().any(|r| r.url.path() == "/eth/v2/beacon/blocks"),
        "publisher must receive the block"
    );
    let envelope = publisher_reqs
        .iter()
        .find(|r| r.url.path() == PUBLISH_EXECUTION_PAYLOAD_ENVELOPES_PATH)
        .expect("publisher must receive the envelope");
    assert_eq!(
        envelope.headers.get(HEADER_ETH_BLOB_DATA_INCLUDED).unwrap().to_str().unwrap(),
        "true"
    );
    let body: serde_json::Value = serde_json::from_slice(&envelope.body).unwrap();
    assert_eq!(body["blobs"], serde_json::json!(["0xbb"]));
    assert_eq!(body["kzg_proofs"], serde_json::json!(["0xaa"]));
}
