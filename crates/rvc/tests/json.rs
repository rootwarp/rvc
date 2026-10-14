//! JSON block contents through the production adapter and the BN pool.

use std::sync::Arc;

use block_service::BlockService;
use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};
use crypto::SecretKey;
use eth_types::ForkSchedule;
use rvc::beacon_adapter::BeaconBlockAdapter;
use serde_json::Value;
use signer::StubValidatorSigner;
use validator_store::{BlockSelectionMode, ValidatorStore};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DENEB_CONTENTS_JSON: &str =
    include_str!("../../eth-types/tests/fixtures/beacon_api/deneb_block_contents.json");

fn decode_hex_list(value: &Value) -> Vec<Vec<u8>> {
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

fn quoted_u64(value: &Value) -> u64 {
    value.as_str().expect("quoted integer").parse().expect("u64")
}

fn produce_template() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_string(DENEB_CONTENTS_JSON)
        .insert_header("Content-Type", "application/json")
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Execution-Payload-Value", "1")
}

/// First BN is down. The healthy BN receives the fixture's proof and blob arrays.
#[tokio::test]
async fn contents_publish_through_the_production_adapter_uses_the_bn_pool() {
    let doc: Value = serde_json::from_str(DENEB_CONTENTS_JSON).expect("deneb fixture");
    let data = &doc["data"];
    let proofs = decode_hex_list(&data["kzg_proofs"]);
    let blobs = decode_hex_list(&data["blobs"]);
    assert!(!proofs.is_empty() && !blobs.is_empty());
    let slot = quoted_u64(&data["block"]["slot"]);
    let proposer = quoted_u64(&data["block"]["proposer_index"]);

    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;
    let produce_path = format!("/eth/v3/validator/blocks/{slot}");

    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(ResponseTemplate::new(503).set_body_string("down"))
        .mount(&primary)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(503).set_body_string("down"))
        .mount(&primary)
        .await;
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_template())
        .mount(&secondary)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&secondary)
        .await;

    let mut config = BnManagerConfig::new(vec![primary.uri(), secondary.uri()]);
    config.broadcast_topics.blocks = false;
    let manager = Arc::new(BnManager::new(config).expect("BnManager"));
    let beacon = Arc::new(BeaconBlockAdapter(manager.clone() as Arc<dyn BeaconNodeClient>));
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);
    let service = BlockService::new(
        Arc::new(StubValidatorSigner::new()),
        beacon,
        Arc::new(store),
        Arc::new(ForkSchedule::unscheduled_gloas()),
        [0xaa; 32],
    );
    let pubkey = SecretKey::generate().public_key();

    let result = service.propose_block(slot, &pubkey, proposer, None).await;
    assert!(result.is_ok(), "healthy BN must accept the contents publish: {result:?}");

    let secondary_reqs = secondary.received_requests().await.unwrap();
    let posts: Vec<_> =
        secondary_reqs.iter().filter(|req| req.url.path() == "/eth/v2/beacon/blocks").collect();
    assert_eq!(posts.len(), 1, "healthy BN receives exactly one contents POST");
    let body: Value = serde_json::from_slice(&posts[0].body).expect("json body");
    assert!(
        body["signed_block"]["message"]["body"].is_object(),
        "wire body must be a JSON object: {body}"
    );
    assert_eq!(decode_hex_list(&body["kzg_proofs"]), proofs);
    assert_eq!(decode_hex_list(&body["blobs"]), blobs);
    assert!(body.get("message").is_none(), "must not publish a bare SignedBeaconBlock");

    let trackers = manager.health_trackers().read().await;
    assert_eq!(trackers[0].endpoint(), primary.uri());
    assert!(trackers[0].error_rate() > 0.0, "first BN's failure must be recorded");
}
