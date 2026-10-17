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
    // Fixture payload fee recipient is 0x66…66. The store default is what
    // `propose_block` sends as the expected fee for an unknown pubkey.
    let store = ValidatorStore::new([0x66; 20], 30_000_000);
    store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);
    // The fixture is a Deneb block on slot 3000000. Leave Electra and Fulu
    // unscheduled so that slot's fork is Deneb, matching the response header.
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.electra_fork_epoch = u64::MAX;
    schedule.fulu_fork_epoch = u64::MAX;
    let service = BlockService::new(
        Arc::new(StubValidatorSigner::new()),
        beacon,
        Arc::new(store),
        Arc::new(schedule),
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

const ELECTRA_BLINDED_BODY_JSON: &str =
    include_str!("../../eth-types/tests/fixtures/beacon_api/electra_blinded_block_body.json");

/// `message.body` is a JSON object. A hex string does not match.
struct MessageBodyObject;

impl wiremock::Match for MessageBodyObject {
    fn matches(&self, request: &wiremock::Request) -> bool {
        serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|value| value.pointer("/message/body").cloned())
            .is_some_and(|body| body.is_object())
    }
}

/// JSON blinded Electra proposal. The local store has no remote proposer config.
#[tokio::test]
async fn blinded_electra_json_publishes_once_and_skips_the_full_block_endpoint() {
    let body: Value =
        serde_json::from_str(ELECTRA_BLINDED_BODY_JSON).expect("electra blinded body");
    let slot = 3_000_000u64;
    let proposer = 42u64;
    let envelope = serde_json::json!({
        "version": "electra",
        "data": {
            "slot": "3000000",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "11".repeat(32)),
            "state_root": format!("0x{}", "22".repeat(32)),
            "body": body,
        }
    });

    let bn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/eth/v3/validator/blocks/{slot}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&envelope)
                .insert_header("Content-Type", "application/json")
                .insert_header("Eth-Consensus-Version", "electra")
                .insert_header("Eth-Execution-Payload-Blinded", "true"),
        )
        .expect(1)
        .mount(&bn)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .and(MessageBodyObject)
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&bn)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&bn)
        .await;

    let mut config = BnManagerConfig::new(vec![bn.uri()]);
    config.broadcast_topics.blocks = false;
    let manager = Arc::new(BnManager::new(config).expect("BnManager"));
    let beacon = Arc::new(BeaconBlockAdapter(manager.clone() as Arc<dyn BeaconNodeClient>));
    let store = ValidatorStore::new([0x66; 20], 30_000_000);
    store.set_global_block_selection_mode(BlockSelectionMode::BuilderOnly);
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.fulu_fork_epoch = u64::MAX;
    schedule.gloas_fork_epoch = u64::MAX;
    let service = BlockService::new(
        Arc::new(StubValidatorSigner::new()),
        beacon,
        Arc::new(store),
        Arc::new(schedule),
        [0xaa; 32],
    );
    let pubkey = SecretKey::generate().public_key();

    let result = service.propose_block(slot, &pubkey, proposer, None).await;
    assert!(result.is_ok(), "blinded Electra JSON must publish: {result:?}");
    let result = result.expect("ok");
    assert!(result.is_blinded);
    let expected = hex::decode(eth_types::EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX).expect("kat");
    assert_eq!(result.block_root.as_slice(), expected.as_slice());

    let requests = bn.received_requests().await.expect("requests");
    let blinded: Vec<_> =
        requests.iter().filter(|req| req.url.path() == "/eth/v1/beacon/blinded_blocks").collect();
    let full: Vec<_> =
        requests.iter().filter(|req| req.url.path() == "/eth/v2/beacon/blocks").collect();
    assert_eq!(blinded.len(), 1, "exactly one blinded POST");
    assert!(full.is_empty(), "no full-block POST");
    let wire: Value = serde_json::from_slice(&blinded[0].body).expect("json body");
    assert!(wire["message"]["body"].is_object(), "message.body is a JSON object: {wire}");
    assert!(wire["message"]["body"]["execution_payload_header"].is_object());
    assert!(wire["message"]["body"].get("execution_payload").is_none());
    assert!(wire.get("signed_block").is_none(), "blinded publish is message and signature");
    let version =
        blinded[0].headers.get("eth-consensus-version").and_then(|value| value.to_str().ok());
    assert_eq!(version, Some("electra"));
}
