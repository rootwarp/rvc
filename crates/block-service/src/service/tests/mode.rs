//! Selection mode is enforced on each candidate and on V4 builder entries.
//!
//! Edge cases pinned here:
//! - failed: wrong shape, produce error, every candidate rejected
//! - partial: a later candidate of the right shape is the one signed
//! - duplicate: two wrong shapes sign nothing; two right shapes sign once;
//!   two provider entries with one URL both keep their auth
//! - malformed: garbage JSON and a payload flag that contradicts the body
//!   fail closed with no signature
//! - out of order: a wrong-shape head is skipped; the last error is not
//!   rewritten when it is a slot mismatch
//! - boundaries: boost 0, 1, and `u64::MAX`; store `min_bid` 0 and `i64::MAX`
//! - restart: a failed proposal does not stick, and a fresh breaker sends
//!   builders again

use super::*;
use async_trait::async_trait;
use beacon::{BuilderEntry, BuilderRequestAuth, SignedBuilderRequestAuth};
use std::sync::Arc;
use validator_store::ValidatorStore;

const STORE_MIN_BID_CEILING: u64 = 9_223_372_036_854_775_807;
const STORE_MIN_BID: u64 = 10_000_000;

fn assert_store_min_bid_ceiling() {
    assert_eq!(STORE_MIN_BID_CEILING, i64::MAX as u64);
}

struct FixedBuilderConfig(BuilderConfig);

#[async_trait]
impl BuilderConfigProvider for FixedBuilderConfig {
    async fn builder_config_for(&self, _pubkey: &[u8; 48], _slot: Slot) -> BuilderConfig {
        self.0.clone()
    }
}

fn entry(url: &str, sig_byte: u8, boost: u64, min_bid: u64) -> BuilderEntry {
    BuilderEntry {
        url: url.to_string(),
        auth: SignedBuilderRequestAuth {
            message: BuilderRequestAuth { data: "0xab".to_string(), slot: 2240 },
            signature: format!("0x{}", hex::encode([sig_byte; 96])),
        },
        builder_pubkeys: vec![],
        max_execution_payment: 0,
        min_bid,
        builder_boost_factor: boost,
    }
}

fn provider_with(entries: Vec<BuilderEntry>) -> BuilderConfig {
    BuilderConfig { min_bid: 7, builder_boost_factor: 1, builders: entries }
}

pub(super) fn response_of(client: MockBeaconClient) -> ProduceBlockResponse {
    client.produce_response.expect("configured produce response")
}

fn pre_gloas(
    signer: Arc<MockSigner>,
    beacon: Arc<MockBeaconClient>,
    _pubkey: &PublicKey,
    store: ValidatorStore,
) -> BlockService<MockSigner, MockBeaconClient> {
    BlockService::new(signer, beacon, Arc::new(store), Arc::new(test_fork_schedule()), [0xaa; 32])
}

pub(super) fn gloas(
    signer: Arc<MockSigner>,
    beacon: Arc<MockBeaconClient>,
    _pubkey: &PublicKey,
    store: ValidatorStore,
    breaker: Arc<CircuitBreakerState>,
    provider: Option<BuilderConfig>,
) -> BlockService<MockSigner, MockBeaconClient> {
    let mut service = BlockService::with_circuit_breaker(
        signer,
        beacon,
        Arc::new(store),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
        breaker,
    );
    if let Some(config) = provider {
        service = service.with_builder_config_provider(Arc::new(FixedBuilderConfig(config)));
    }
    service
}

fn store_with(pubkey: &PublicKey, boost: Option<u64>, min_bid: u64) -> ValidatorStore {
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let mut config = validator_store::ValidatorConfig::new(pubkey.to_bytes());
    config.builder_boost_factor = boost;
    store.add_validator(config).expect("validator");
    store.set_global_min_bid(min_bid).expect("min_bid fits toml");
    store
}

pub(super) fn header_signs(signer: &MockSigner) -> usize {
    signer.header_calls.lock().expect("header calls").len()
}

fn envelope_signs(signer: &MockSigner) -> usize {
    signer.envelope_calls.lock().expect("envelope calls").len()
}

pub(super) fn assert_unsigned(signer: &MockSigner, beacon: &MockBeaconClient) {
    assert_eq!(header_signs(signer), 0);
    assert_eq!(signer.block_calls.lock().expect("block calls").len(), 0);
    assert_eq!(envelope_signs(signer), 0);
    assert!(beacon.publish_calls.lock().expect("publish").is_empty());
    assert!(beacon.publish_blinded_calls.lock().expect("blinded publish").is_empty());
    assert!(beacon.publish_ssz_calls.lock().expect("ssz publish").is_empty());
    assert!(beacon.publish_contents_calls.lock().expect("contents publish").is_empty());
    assert!(beacon.publish_full_calls.lock().expect("full publish").is_empty());
    assert!(beacon.publish_blinded_full_calls.lock().expect("blinded full").is_empty());
    assert!(beacon.envelope_publish_calls.lock().expect("envelope publish").is_empty());
}

fn garbage(blinded: bool) -> ProduceBlockResponse {
    ProduceBlockResponse {
        data: serde_json::json!({"slot": "nope"}),
        is_blinded: blinded,
        consensus_version: "deneb".to_string(),
        execution_payload_value: None,
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
        candidate_memo: beacon::CandidateMemo::arc(),
    }
}

fn v4_config(beacon: &MockBeaconClient) -> BuilderConfig {
    beacon.produce_v4_calls.lock().expect("v4 calls")[0].builder_config.clone()
}

/// Builder-only local fallback and execution-only blinded, JSON and SSZ.
#[tokio::test]
async fn test_mode_shape_pre_gloas_rejections_sign_nothing() {
    let cases = [
        (BlockSelectionMode::BuilderOnly, false, false, "unblinded"),
        (BlockSelectionMode::BuilderOnly, false, true, "unblinded"),
        (BlockSelectionMode::ExecutionOnly, true, false, "blinded"),
        (BlockSelectionMode::ExecutionOnly, true, true, "blinded"),
    ];
    for (mode, blinded, ssz, shape) in cases {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = if ssz {
            MockBeaconClient::ssz(slot, 42, blinded)
        } else if blinded {
            MockBeaconClient::blinded(test_blinded_block(slot))
        } else {
            MockBeaconClient::unblinded(test_block(slot))
        };
        let beacon = Arc::new(beacon);
        let signer = Arc::new(MockSigner::new());
        let service =
            pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
        let err =
            service.propose_block_with_mode(slot, &pubkey, mode).await.expect_err("wrong shape");
        assert_unsigned(&signer, &beacon);
        let text = err.to_string();
        assert!(text.contains(shape), "{mode} ssz={ssz}: {text}");
        if mode == BlockSelectionMode::BuilderOnly {
            assert_eq!(
                text,
                format!("builder-only mode: response shape {shape} contradicts builder-only")
            );
            assert!(matches!(err, BlockServiceError::BuilderOnly(_)));
        } else {
            assert_eq!(text, format!("mode {mode} rejects shape {shape}"));
            assert!(matches!(
                err,
                BlockServiceError::ModeShapeMismatch { mode: got, .. } if got == mode
            ));
        }
    }
}

/// Max-profit and builder-always still sign either pre-Gloas shape, once.
#[tokio::test]
async fn test_mode_shape_permissive_modes_sign_both_pre_gloas_shapes() {
    for mode in [BlockSelectionMode::MaxProfit, BlockSelectionMode::BuilderAlways] {
        for blinded in [false, true] {
            let pubkey = test_pubkey();
            let slot = 100;
            let beacon = if blinded {
                MockBeaconClient::blinded(test_blinded_block(slot))
            } else {
                MockBeaconClient::unblinded(test_block(slot))
            };
            let signer = Arc::new(MockSigner::new());
            let service =
                pre_gloas(signer.clone(), Arc::new(beacon), &pubkey, test_validator_store(&pubkey));
            let result = service.propose_block_with_mode(slot, &pubkey, mode).await;
            assert!(result.is_ok(), "{mode} blinded={blinded}: {result:?}");
            assert_eq!(result.expect("signed").is_blinded, blinded);
            assert_eq!(header_signs(&signer), 1, "{mode} blinded={blinded}");
            assert_eq!(envelope_signs(&signer), 0);
        }
    }
}

/// [local, blinded] under builder-only signs the blinded block only.
#[tokio::test]
async fn test_mode_shape_builder_only_skips_local_and_signs_blinded() {
    let slot = 100;
    let mut local = test_block(slot);
    local.state_root = [0x01; 32];
    let mut blinded = test_blinded_block(slot);
    blinded.state_root = [0x02; 32];
    let beacon = Arc::new(MockBeaconClient::unblinded(test_block(1)).with_ranked_responses(vec![
        response_of(MockBeaconClient::unblinded(local)),
        response_of(MockBeaconClient::blinded(blinded)),
    ]));
    let pubkey = test_pubkey();
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
    let result = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect("blinded candidate");
    assert!(result.is_blinded);
    assert_eq!(header_signs(&signer), 1);
    assert_eq!(signer.header_calls.lock().expect("headers")[0].header.state_root, [0x02; 32]);
    assert_eq!(beacon.publish_blinded_full_calls.lock().expect("publish").len(), 1);
    assert!(beacon.publish_full_calls.lock().expect("full").is_empty());
}

/// [blinded, unblinded] under execution-only signs the unblinded block only.
#[tokio::test]
async fn test_mode_shape_execution_only_skips_blinded_and_signs_local() {
    let slot = 100;
    let mut blinded = test_blinded_block(slot);
    blinded.state_root = [0x01; 32];
    let mut local = test_block(slot);
    local.state_root = [0x02; 32];
    let beacon = Arc::new(MockBeaconClient::unblinded(test_block(1)).with_ranked_responses(vec![
        response_of(MockBeaconClient::blinded(blinded)),
        response_of(MockBeaconClient::unblinded(local)),
    ]));
    let pubkey = test_pubkey();
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
    let result = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect("local candidate");
    assert!(!result.is_blinded);
    assert_eq!(header_signs(&signer), 1);
    assert_eq!(signer.header_calls.lock().expect("headers")[0].header.state_root, [0x02; 32]);
    assert_eq!(beacon.publish_full_calls.lock().expect("publish").len(), 1);
    assert!(beacon.publish_blinded_full_calls.lock().expect("blinded").is_empty());
}

/// Two copies of the wrong shape sign nothing. Two copies of the right shape sign once.
#[tokio::test]
async fn test_mode_shape_duplicates_do_not_double_sign() {
    let slot = 100;
    let local = response_of(MockBeaconClient::unblinded(test_block(slot)));
    let blinded = response_of(MockBeaconClient::blinded(test_blinded_block(slot)));

    let beacon = Arc::new(
        MockBeaconClient::unblinded(test_block(1))
            .with_ranked_responses(vec![local.clone(), local]),
    );
    let pubkey = test_pubkey();
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("both local");
    assert_unsigned(&signer, &beacon);
    assert!(matches!(err, BlockServiceError::BuilderOnly(_)));

    let beacon = Arc::new(
        MockBeaconClient::unblinded(test_block(1))
            .with_ranked_responses(vec![blinded.clone(), blinded]),
    );
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
    let result = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect("first blinded");
    assert!(result.is_blinded);
    assert_eq!(header_signs(&signer), 1);
    assert_eq!(beacon.publish_blinded_full_calls.lock().expect("publish").len(), 1);
}

/// The right-shape block is third. The signed header is that block's state root.
#[tokio::test]
async fn test_mode_shape_out_of_order_signs_the_later_matching_parent() {
    let slot = 100;
    let expected: Root = [0x11; 32];
    let mut local = test_block(slot);
    local.parent_root = expected;
    local.state_root = [0x01; 32];
    let mut wrong_parent = test_blinded_block(slot);
    wrong_parent.parent_root = [0x99; 32];
    wrong_parent.state_root = [0x02; 32];
    let mut right = test_blinded_block(slot);
    right.parent_root = expected;
    right.state_root = [0x03; 32];
    let beacon = Arc::new(MockBeaconClient::unblinded(test_block(1)).with_ranked_responses(vec![
        response_of(MockBeaconClient::unblinded(local)),
        response_of(MockBeaconClient::blinded(wrong_parent)),
        response_of(MockBeaconClient::blinded(right)),
    ]));
    let pubkey = test_pubkey();
    let signer = Arc::new(MockSigner::new());
    let store = test_validator_store(&pubkey);
    store.set_global_block_selection_mode(BlockSelectionMode::BuilderOnly);
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, store);
    let result = service
        .propose_block(slot, &pubkey, 42, Some(ExpectedParents::open(expected, None)))
        .await
        .expect("third candidate");
    assert!(result.is_blinded);
    let headers = signer.header_calls.lock().expect("headers");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].header.parent_root, expected);
    assert_eq!(headers[0].header.state_root, [0x03; 32]);
    drop(headers);
    assert_eq!(beacon.publish_blinded_full_calls.lock().expect("publish").len(), 1);
}

fn shape_rejections(mode: &str, shape: &str) -> u64 {
    crate::metrics::RVC_BLOCK_SHAPE_REJECTIONS_TOTAL.with_label_values(&[mode, shape]).get()
}

/// A lone wrong-slot blinded block stays a slot mismatch.
/// A local block anywhere in the list keeps the final error `BuilderOnly`.
#[test]
fn test_mode_shape_builder_only_error_does_not_depend_on_order() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    with_shape_rejection_lock(|| {
        rt.block_on(async {
            let slot = 100;
            let local = response_of(MockBeaconClient::unblinded(test_block(slot)));
            let malformed = garbage(true);
            let expected = "builder-only mode: response shape unblinded contradicts builder-only";
            for (label, responses) in [
                ("local then malformed", vec![local.clone(), malformed.clone()]),
                ("malformed then local", vec![malformed, local]),
            ] {
                let beacon = Arc::new(
                    MockBeaconClient::unblinded(test_block(1)).with_ranked_responses(responses),
                );
                let pubkey = test_pubkey();
                let signer = Arc::new(MockSigner::new());
                let service = pre_gloas(
                    signer.clone(),
                    beacon.clone(),
                    &pubkey,
                    test_validator_store(&pubkey),
                );
                let before = shape_rejections("builder-only", "unblinded");
                let err = service
                    .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
                    .await
                    .expect_err(label);
                assert_unsigned(&signer, &beacon);
                assert_eq!(err.to_string(), expected, "{label}");
                assert!(matches!(err, BlockServiceError::BuilderOnly(_)), "{label}: {err:?}");
                assert_eq!(shape_rejections("builder-only", "unblinded"), before + 1, "{label}");
            }

            let blinded = test_blinded_block(slot + 1);
            let beacon = Arc::new(
                MockBeaconClient::unblinded(test_block(1))
                    .with_ranked_responses(vec![response_of(MockBeaconClient::blinded(blinded))]),
            );
            let pubkey = test_pubkey();
            let signer = Arc::new(MockSigner::new());
            let service =
                pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
            let err = service
                .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
                .await
                .expect_err("wrong slot");
            assert_unsigned(&signer, &beacon);
            assert!(matches!(err, BlockServiceError::SlotMismatch { requested: 100, got: 101 }));
        });
    });
}

/// A blinded flag on garbage JSON is rejected before parse. An allowed garbage body fails closed.
#[tokio::test]
async fn test_mode_shape_malformed_pre_gloas_fails_closed() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = Arc::new(MockBeaconClient::from_response(garbage(true)));
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("garbage blinded");
    assert_unsigned(&signer, &beacon);
    assert_eq!(err.to_string(), "mode execution-only rejects shape blinded");

    let beacon = Arc::new(MockBeaconClient::from_response(garbage(false)));
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect_err("garbage unblinded");
    assert_unsigned(&signer, &beacon);
    assert!(matches!(err, BlockServiceError::Parse(_)), "{err:?}");
}

/// The first proposal is a local block. The second, on the same service, is blinded and is signed once.
#[tokio::test]
async fn test_mode_shape_restart_signs_only_the_later_blinded_proposal() {
    let slot = 100;
    let first = response_of(MockBeaconClient::unblinded(test_block(slot)));
    let beacon = MockBeaconClient::blinded(test_blinded_block(slot));
    beacon.produce_queue.lock().expect("queue").push(first);
    let beacon = Arc::new(beacon);
    let pubkey = test_pubkey();
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));

    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("first proposal is local");
    assert!(matches!(err, BlockServiceError::BuilderOnly(_)));
    assert_eq!(header_signs(&signer), 0);
    assert!(beacon.publish_blinded_full_calls.lock().expect("publish").is_empty());

    let result = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect("second proposal is blinded");
    assert!(result.is_blinded);
    assert_eq!(header_signs(&signer), 1);
    assert_eq!(beacon.publish_blinded_full_calls.lock().expect("publish").len(), 1);
    assert!(beacon.publish_full_calls.lock().expect("full").is_empty());
}

fn gloas_ssz_win(slot: Slot) -> ProduceBlockResponse {
    let ssz_bytes = build_gloas_beacon_block_ssz(
        slot,
        42,
        [0x11; 32],
        [0x22; 32],
        &external_bid_body(slot, [0x11; 32]),
    );
    ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("99999".to_string()),
        is_ssz: true,
        ssz_bytes: Some(ssz_bytes),
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
        candidate_memo: beacon::CandidateMemo::arc(),
    }
}

fn gloas_pair(
    response: ProduceBlockResponse,
) -> (BlockService<MockSigner, MockBeaconClient>, Arc<MockSigner>, Arc<MockBeaconClient>, PublicKey)
{
    let pubkey = test_pubkey();
    let beacon = Arc::new(MockBeaconClient::from_response(response));
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        signer.clone(),
        beacon.clone(),
        &pubkey,
        test_validator_store(&pubkey),
        Arc::new(CircuitBreakerState::new(0, 0)),
        None,
    );
    (service, signer, beacon, pubkey)
}

/// Gloas builder-only rejects a self-build bid. Execution-only rejects an external bid.
#[tokio::test]
async fn test_mode_shape_gloas_rejections_sign_nothing() {
    let slot = test_gloas_slot();
    let cases: Vec<(&str, BlockSelectionMode, ProduceBlockResponse, &str)> = vec![
        (
            "json self-build",
            BlockSelectionMode::BuilderOnly,
            self_build_json_response(slot),
            "self-build",
        ),
        (
            "ssz self-build",
            BlockSelectionMode::BuilderOnly,
            self_build_ssz_response(slot),
            "self-build",
        ),
        (
            "json external bid",
            BlockSelectionMode::ExecutionOnly,
            response_of(gloas_beacon(slot)),
            "external-bid",
        ),
        (
            "ssz external bid",
            BlockSelectionMode::ExecutionOnly,
            gloas_ssz_win(slot),
            "external-bid",
        ),
    ];
    for (label, mode, response, shape) in cases {
        let (service, signer, beacon, pubkey) = gloas_pair(response);
        let err = service.propose_block_with_mode(slot, &pubkey, mode).await.expect_err(label);
        assert_unsigned(&signer, &beacon);
        if mode == BlockSelectionMode::BuilderOnly {
            assert_eq!(
                err.to_string(),
                format!("builder-only mode: response shape {shape} contradicts builder-only"),
                "{label}"
            );
        } else {
            assert_eq!(err.to_string(), format!("mode {mode} rejects shape {shape}"), "{label}");
        }
    }
}

pub(super) fn gloas_beacon(slot: Slot) -> MockBeaconClient {
    MockBeaconClient::unblinded(external_bid_block(slot)).with_consensus_version("gloas")
}

/// A Gloas response flagged blinded is rejected before signing, for either container.
#[tokio::test]
async fn test_mode_shape_gloas_blinded_flag_is_rejected() {
    let slot = test_gloas_slot();
    let mut self_build = self_build_json_response(slot);
    self_build.is_blinded = true;
    let mut external = response_of(gloas_beacon(slot));
    external.is_blinded = true;
    let cases = [
        (BlockSelectionMode::BuilderOnly, self_build),
        (BlockSelectionMode::ExecutionOnly, external),
    ];
    for (mode, response) in cases {
        let (service, signer, beacon, pubkey) = gloas_pair(response);
        let err = service.propose_block_with_mode(slot, &pubkey, mode).await.expect_err("blinded");
        assert_unsigned(&signer, &beacon);
        assert_eq!(
            err.to_string(),
            format!("blinded block production is not supported at Gloas (slot {slot})")
        );
        assert!(
            matches!(err, BlockServiceError::BlindedNotSupportedAtGloas { slot: got } if got == slot)
        );
    }
}

/// The allowed Gloas bid is signed once. The container does not decide the shape.
#[tokio::test]
async fn test_mode_shape_gloas_allowed_shapes_sign_once() {
    let slot = test_gloas_slot();
    let sign_envelope = [
        (BlockSelectionMode::ExecutionOnly, self_build_json_response(slot)),
        (BlockSelectionMode::ExecutionOnly, self_build_ssz_response(slot)),
        (BlockSelectionMode::BuilderAlways, self_build_json_response(slot)),
        (BlockSelectionMode::MaxProfit, self_build_json_response(slot)),
    ];
    for (mode, response) in sign_envelope {
        let (service, signer, beacon, pubkey) = gloas_pair(response);
        let result = service.propose_block_with_mode(slot, &pubkey, mode).await;
        assert!(result.is_ok(), "{mode} self-build: {result:?}");
        let result = result.expect("self-build");
        assert!(!result.is_blinded, "{mode} self-build stays unblinded");
        assert!(!result.builder_path, "{mode} self-build is not a builder path");
        assert_eq!(header_signs(&signer), 1);
        assert_eq!(envelope_signs(&signer), 1);
        assert_eq!(beacon.envelope_publish_calls.lock().expect("envelope").len(), 1);
    }

    let sign_block = [
        (BlockSelectionMode::BuilderOnly, response_of(gloas_beacon(slot))),
        (BlockSelectionMode::BuilderOnly, gloas_ssz_win(slot)),
        (BlockSelectionMode::BuilderAlways, response_of(gloas_beacon(slot))),
        (BlockSelectionMode::MaxProfit, response_of(gloas_beacon(slot))),
    ];
    for (mode, response) in sign_block {
        let (service, signer, beacon, pubkey) = gloas_pair(response);
        let result = service.propose_block_with_mode(slot, &pubkey, mode).await;
        assert!(result.is_ok(), "{mode} builder-win: {result:?}");
        let result = result.expect("builder-win");
        assert!(!result.is_blinded, "{mode} builder-win stays unblinded");
        assert!(result.builder_path, "{mode} external bid is the builder path");
        assert_eq!(header_signs(&signer), 1);
        assert_eq!(envelope_signs(&signer), 0);
        assert!(beacon.envelope_publish_calls.lock().expect("envelope").is_empty());
    }
}

/// A Gloas external-bid publish error is a builder miss. A self-build publish error is not.
#[tokio::test]
async fn test_gloas_publish_failure_counts_only_for_an_external_bid() {
    let slot = test_gloas_slot();
    let pubkey = test_pubkey();
    let external = Arc::new(gloas_beacon(slot).with_publish_error());
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        Arc::clone(&signer),
        Arc::clone(&external),
        &pubkey,
        test_validator_store(&pubkey),
        Arc::new(CircuitBreakerState::new(0, 0)),
        None,
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("external publish");
    assert!(matches!(err, BlockServiceError::BuilderFailure(_)), "{err:?}");
    assert_eq!(header_signs(&signer), 1, "the header is signed once, then publish fails");

    let local = Arc::new(
        MockBeaconClient::from_response(self_build_json_response(slot)).with_publish_error(),
    );
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        Arc::clone(&signer),
        Arc::clone(&local),
        &pubkey,
        test_validator_store(&pubkey),
        Arc::new(CircuitBreakerState::new(0, 0)),
        None,
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("self-build publish");
    assert!(matches!(err, BlockServiceError::Beacon(_)), "{err:?}");
    assert_eq!(header_signs(&signer), 1, "the header is signed once, then publish fails");
}

/// `payload_included` that contradicts the body is a parse error and is not signed.
#[tokio::test]
async fn test_mode_shape_gloas_malformed_payload_flag_fails_closed() {
    let slot = test_gloas_slot();
    let mut win = response_of(gloas_beacon(slot));
    win.payload_included = true;
    let (service, signer, beacon, pubkey) = gloas_pair(win);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("payload flag contradicts BeaconBlock");
    assert_unsigned(&signer, &beacon);
    assert!(matches!(err, BlockServiceError::Parse(_)), "{err:?}");

    let mut contents = self_build_json_response(slot);
    contents.payload_included = false;
    let (service, signer, beacon, pubkey) = gloas_pair(contents);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("payload flag contradicts BlockContents");
    assert_unsigned(&signer, &beacon);
    assert!(matches!(err, BlockServiceError::Parse(_)), "{err:?}");
}

/// Boost 0 clears builders. The allowed self-build is still signed.
#[tokio::test]
async fn test_mode_shape_boost_zero_clears_builders_and_signs_self_build() {
    assert_store_min_bid_ceiling();
    let slot = test_gloas_slot();
    let entries = vec![
        entry("https://a.example", 0x11, u64::MAX, 7),
        entry("https://a.example", 0x22, 0, 9),
        entry("", 0x33, 99, 5),
    ];
    let cases = [
        (BlockSelectionMode::ExecutionOnly, false),
        (BlockSelectionMode::MaxProfit, true),
        (BlockSelectionMode::BuilderAlways, true),
    ];
    for (mode, trip) in cases {
        let pubkey = test_pubkey();
        let beacon = Arc::new(MockBeaconClient::from_response(self_build_json_response(slot)));
        let signer = Arc::new(MockSigner::new());
        let breaker = Arc::new(CircuitBreakerState::new(1, 0));
        if trip {
            breaker.record_miss();
            assert!(breaker.is_tripped());
        }
        let service = gloas(
            signer.clone(),
            beacon.clone(),
            &pubkey,
            store_with(&pubkey, Some(150), STORE_MIN_BID),
            breaker,
            Some(provider_with(entries.clone())),
        );
        let result = service.propose_block_with_mode(slot, &pubkey, mode).await;
        assert!(result.is_ok(), "{mode} trip={trip}: {result:?}");
        assert_eq!(header_signs(&signer), 1, "{mode}");
        assert_eq!(envelope_signs(&signer), 1, "{mode}");
        let config = v4_config(&beacon);
        assert!(config.builders.is_empty(), "{mode} trip={trip}: {:?}", config.builders);
        assert_eq!(config.builder_boost_factor, 0);
        assert_eq!(config.min_bid, STORE_MIN_BID);
    }
}

/// Builder-always entries carry `u64::MAX` and the store ceiling `min_bid`.
#[tokio::test]
async fn test_mode_shape_builder_always_entries_use_max_boost_and_store_min_bid() {
    assert_store_min_bid_ceiling();
    let slot = test_gloas_slot();
    let original = vec![entry("https://a.example", 0x11, 0, 7), entry("", 0x33, u64::MAX, 5)];
    let pubkey = test_pubkey();
    let beacon = Arc::new(MockBeaconClient::from_response(response_of(gloas_beacon(slot))));
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        signer.clone(),
        beacon.clone(),
        &pubkey,
        store_with(&pubkey, Some(1), STORE_MIN_BID_CEILING),
        Arc::new(CircuitBreakerState::new(0, 0)),
        Some(provider_with(original.clone())),
    );
    let result = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways)
        .await
        .expect("builder-win");
    assert!(!result.is_blinded);
    assert_eq!(header_signs(&signer), 1);
    assert_eq!(envelope_signs(&signer), 0);
    let config = v4_config(&beacon);
    assert_eq!(config.builder_boost_factor, u64::MAX);
    assert_eq!(config.min_bid, STORE_MIN_BID_CEILING);
    assert_eq!(config.builders.len(), 2);
    for (got, was) in config.builders.iter().zip(original.iter()) {
        assert_eq!(got.url, was.url);
        assert_eq!(got.auth, was.auth);
        assert_eq!(got.max_execution_payment, 0);
        assert_eq!(got.builder_boost_factor, u64::MAX);
        assert_eq!(got.min_bid, STORE_MIN_BID_CEILING);
    }
}

/// Boost 1 overwrites every entry, including a duplicate URL and an empty URL.
/// An empty builder list stays empty.
#[tokio::test]
async fn test_mode_shape_boost_one_overwrites_every_entry() {
    let slot = test_gloas_slot();
    let original = vec![
        entry("https://a.example", 0x11, u64::MAX, 7),
        entry("https://a.example", 0x22, 0, 9),
        entry("", 0x33, 99, 5),
    ];
    let pubkey = test_pubkey();
    let beacon = Arc::new(MockBeaconClient::from_response(response_of(gloas_beacon(slot))));
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        signer.clone(),
        beacon.clone(),
        &pubkey,
        store_with(&pubkey, Some(1), 0),
        Arc::new(CircuitBreakerState::new(0, 0)),
        Some(provider_with(original.clone())),
    );
    service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect("max-profit builder-win");
    assert_eq!(header_signs(&signer), 1);
    let config = v4_config(&beacon);
    assert_eq!(config.builder_boost_factor, 1);
    assert_eq!(config.min_bid, 0);
    assert_eq!(config.builders.len(), original.len());
    for (got, was) in config.builders.iter().zip(original.iter()) {
        assert_eq!(got.url, was.url);
        assert_eq!(got.auth.signature, was.auth.signature);
        assert_eq!(got.auth.message, was.auth.message);
        assert_eq!(got.builder_boost_factor, 1);
        assert_eq!(got.min_bid, 0);
    }

    let pubkey = test_pubkey();
    let beacon = Arc::new(MockBeaconClient::from_response(response_of(gloas_beacon(slot))));
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        signer,
        beacon.clone(),
        &pubkey,
        store_with(&pubkey, None, 0),
        Arc::new(CircuitBreakerState::new(0, 0)),
        None,
    );
    service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways)
        .await
        .expect("no provider");
    let config = v4_config(&beacon);
    assert!(config.builders.is_empty());
    assert_eq!(config.builder_boost_factor, u64::MAX);
    assert_eq!(config.min_bid, 0);
}

/// A tripped breaker keeps `builders` empty across two proposals.
/// A new service with a fresh breaker sends the entries again.
#[tokio::test]
async fn test_mode_shape_tripped_breaker_stays_empty_until_restart() {
    let slot = test_gloas_slot();
    let entries = vec![entry("https://a.example", 0x11, u64::MAX, 7)];
    let pubkey = test_pubkey();
    let store = store_with(&pubkey, Some(150), STORE_MIN_BID);
    let breaker = Arc::new(CircuitBreakerState::new(1, 0));
    breaker.record_miss();
    let beacon = Arc::new(MockBeaconClient::from_response(self_build_json_response(slot)));
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        signer.clone(),
        beacon.clone(),
        &pubkey,
        store,
        breaker,
        Some(provider_with(entries.clone())),
    );
    for _ in 0..2 {
        service
            .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
            .await
            .expect("self-build while tripped");
    }
    assert_eq!(header_signs(&signer), 2);
    {
        let calls = beacon.produce_v4_calls.lock().expect("v4");
        assert_eq!(calls.len(), 2);
        for call in calls.iter() {
            assert!(call.builder_config.builders.is_empty());
            assert_eq!(call.builder_config.builder_boost_factor, 0);
            assert_eq!(call.builder_config.min_bid, STORE_MIN_BID);
        }
    }

    let beacon = Arc::new(MockBeaconClient::from_response(response_of(gloas_beacon(slot))));
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        signer.clone(),
        beacon.clone(),
        &pubkey,
        store_with(&pubkey, Some(150), STORE_MIN_BID),
        Arc::new(CircuitBreakerState::new(0, 0)),
        Some(provider_with(entries)),
    );
    service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect("fresh breaker");
    assert_eq!(header_signs(&signer), 1);
    let config = v4_config(&beacon);
    assert_eq!(config.builders.len(), 1);
    assert_eq!(config.builders[0].builder_boost_factor, 150);
    assert_eq!(config.builders[0].min_bid, STORE_MIN_BID);
    assert_eq!(config.builders[0].auth.signature, format!("0x{}", hex::encode([0x11u8; 96])));
    assert_eq!(config.builder_boost_factor, 150);
}

/// Execution-only produce failure sends `builders: []` and is not a builder failure.
#[tokio::test]
async fn test_mode_shape_execution_only_produce_failure_fails_closed() {
    let slot = test_gloas_slot();
    let pubkey = test_pubkey();
    let beacon = Arc::new(
        MockBeaconClient::from_response(self_build_json_response(slot)).with_produce_error(),
    );
    let signer = Arc::new(MockSigner::new());
    let service = gloas(
        signer.clone(),
        beacon.clone(),
        &pubkey,
        store_with(&pubkey, Some(150), STORE_MIN_BID),
        Arc::new(CircuitBreakerState::new(0, 0)),
        Some(provider_with(vec![entry("https://a.example", 0x11, u64::MAX, 7)])),
    );
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("produce failed");
    assert_unsigned(&signer, &beacon);
    assert!(matches!(err, BlockServiceError::Beacon(_)), "{err:?}");
    let config = v4_config(&beacon);
    assert!(config.builders.is_empty());
    assert_eq!(config.builder_boost_factor, 0);
    assert_eq!(config.min_bid, STORE_MIN_BID);
}

/// An envelope on an external bid is rejected before signing, in every mode
/// that would otherwise accept that bid.
#[tokio::test]
async fn test_mode_shape_external_bid_wrapped_as_contents_is_rejected() {
    let slot = test_gloas_slot();
    let modes = [
        BlockSelectionMode::BuilderOnly,
        BlockSelectionMode::MaxProfit,
        BlockSelectionMode::BuilderAlways,
    ];
    for mode in modes {
        let mut response = self_build_json_response(slot);
        response.data["block"] =
            serde_json::to_value(external_bid_block(slot)).expect("external block");
        let (service, signer, beacon, pubkey) = gloas_pair(response);
        let err = service
            .propose_block_with_mode(slot, &pubkey, mode)
            .await
            .expect_err("external bid in BlockContents");
        assert_unsigned(&signer, &beacon);
        assert_eq!(
            err.to_string(),
            "parse error: execution payload envelope requires a self-build bid",
            "{mode}"
        );
        assert!(matches!(err, BlockServiceError::Parse(_)), "{mode} {err:?}");
    }
}

/// A self-build bid sent as a bare `BeaconBlock` is still a self-build.
#[tokio::test]
async fn test_mode_shape_self_build_sent_bare_is_rejected() {
    let slot = test_gloas_slot();
    let response = response_of(
        MockBeaconClient::unblinded(self_build_block(slot)).with_consensus_version("gloas"),
    );
    assert!(!response.payload_included);
    let (service, signer, beacon, pubkey) = gloas_pair(response);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("bare self-build");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        "builder-only mode: response shape self-build contradicts builder-only"
    );
    assert!(matches!(err, BlockServiceError::BuilderOnly(_)));
}

/// Envelope `builder_index` and `beacon_block_root` must match the signed block.
#[tokio::test]
async fn test_mode_shape_self_build_envelope_mismatch_is_unsigned() {
    // kat_exempt: error-string only.
    let slot = test_gloas_slot();
    let block = self_build_block(slot);
    let block_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )
    .expect("block root");
    let bound = bound_self_build_envelope(&block);

    let wrong_index = rvc_gloas::envelope_with_binding(&bound, 1, block_root, block.parent_root)
        .expect("index rewrite");
    let mut response = self_build_json_response(slot);
    response.data["execution_payload_envelope"] =
        serde_json::json!(format!("0x{}", hex::encode(&wrong_index)));
    let (service, signer, beacon, pubkey) = gloas_pair(response);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("envelope index");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        "parse error: self-build envelope builder_index 1 does not match bid builder_index 18446744073709551615"
    );

    let wrong_root = rvc_gloas::envelope_with_binding(
        &bound,
        rvc_gloas::BUILDER_INDEX_SELF_BUILD,
        [0xee; 32],
        block.parent_root,
    )
    .expect("root rewrite");
    let mut response = self_build_json_response(slot);
    response.data["execution_payload_envelope"] =
        serde_json::json!(format!("0x{}", hex::encode(&wrong_root)));
    let (service, signer, beacon, pubkey) = gloas_pair(response);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("envelope root");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        format!(
            "parse error: self-build envelope beacon_block_root 0x{} does not match block root 0x{}",
            hex::encode([0xee; 32]),
            hex::encode(block_root)
        )
    );
}

/// A bare self-build is rejected before signing in every mode that allows that shape.
#[tokio::test]
async fn test_mode_shape_bare_self_build_requires_envelope() {
    let slot = test_gloas_slot();
    let modes = [
        BlockSelectionMode::ExecutionOnly,
        BlockSelectionMode::MaxProfit,
        BlockSelectionMode::BuilderAlways,
    ];
    for mode in modes {
        let response = response_of(
            MockBeaconClient::unblinded(self_build_block(slot)).with_consensus_version("gloas"),
        );
        let (service, signer, beacon, pubkey) = gloas_pair(response);
        let err = service
            .propose_block_with_mode(slot, &pubkey, mode)
            .await
            .expect_err("bare self-build");
        assert_unsigned(&signer, &beacon);
        assert_eq!(
            err.to_string(),
            "parse error: self-build bid requires an execution payload envelope",
            "{mode}"
        );
        assert!(matches!(err, BlockServiceError::Parse(_)), "{mode} {err:?}");
    }
}

fn ssz_self_build_with_envelope(slot: Slot, envelope: &[u8]) -> ProduceBlockResponse {
    let parent_root = [0x11; 32];
    let block = eth_types::BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root,
        state_root: [0x22; 32],
        body: self_build_body(slot, parent_root),
    };
    let block_ssz = build_gloas_beacon_block_ssz(
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.state_root,
        &block.body,
    );
    let ssz_bytes = build_gloas_block_contents_ssz(&block_ssz, envelope, &[0xaa], &[0xbb]);
    ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: true,
        ssz_bytes: Some(ssz_bytes),
        payload_included: true,
        builder_url: None,
        consensus_block_value: None,
        candidate_memo: beacon::CandidateMemo::arc(),
    }
}

/// SSZ envelope index and block root are checked before signing, same as JSON.
#[tokio::test]
async fn test_mode_shape_self_build_envelope_mismatch_ssz_is_unsigned() {
    // kat_exempt: error-string only.
    let slot = test_gloas_slot();
    let parent_root = [0x11; 32];
    let block = eth_types::BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root,
        state_root: [0x22; 32],
        body: self_build_body(slot, parent_root),
    };
    let block_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )
    .expect("block root");
    let bound = bound_self_build_envelope(&block);

    let wrong_index = rvc_gloas::envelope_with_binding(&bound, 1, block_root, parent_root)
        .expect("index rewrite");
    let (service, signer, beacon, pubkey) =
        gloas_pair(ssz_self_build_with_envelope(slot, &wrong_index));
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("ssz envelope index");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        "parse error: self-build envelope builder_index 1 does not match bid builder_index 18446744073709551615"
    );

    let wrong_root = rvc_gloas::envelope_with_binding(
        &bound,
        rvc_gloas::BUILDER_INDEX_SELF_BUILD,
        [0xee; 32],
        parent_root,
    )
    .expect("root rewrite");
    let (service, signer, beacon, pubkey) =
        gloas_pair(ssz_self_build_with_envelope(slot, &wrong_root));
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("ssz envelope root");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        format!(
            "parse error: self-build envelope beacon_block_root 0x{} does not match block root 0x{}",
            hex::encode([0xee; 32]),
            hex::encode(block_root)
        )
    );
}

/// Envelope parent must match the block parent before signing.
#[tokio::test]
async fn test_mode_shape_envelope_parent_mismatch_is_unsigned() {
    // kat_exempt: error-string only.
    let slot = test_gloas_slot();
    let block = self_build_block(slot);
    let block_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )
    .expect("block root");
    let bound = bound_self_build_envelope(&block);
    let wrong_parent = rvc_gloas::envelope_with_binding(
        &bound,
        rvc_gloas::BUILDER_INDEX_SELF_BUILD,
        block_root,
        [0xab; 32],
    )
    .expect("parent rewrite");
    let mut response = self_build_json_response(slot);
    response.data["execution_payload_envelope"] =
        serde_json::json!(format!("0x{}", hex::encode(&wrong_parent)));
    let (service, signer, beacon, pubkey) = gloas_pair(response);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly)
        .await
        .expect_err("envelope parent");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        format!(
            "parse error: self-build envelope parent_beacon_block_root 0x{} does not match block parent root 0x{}",
            hex::encode([0xab; 32]),
            hex::encode(block.parent_root)
        )
    );
}

fn ssz_produce(bytes: Vec<u8>, payload_included: bool) -> ProduceBlockResponse {
    ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: true,
        ssz_bytes: Some(bytes),
        payload_included,
        builder_url: None,
        consensus_block_value: None,
        candidate_memo: beacon::CandidateMemo::arc(),
    }
}

/// Bare self-build SSZ (`payload_included` false) is rejected before signing.
#[tokio::test]
async fn test_mode_shape_bare_self_build_ssz_requires_envelope() {
    // kat_exempt: error-string only.
    let slot = test_gloas_slot();
    let block = self_build_block(slot);
    let bytes = build_gloas_beacon_block_ssz(
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.state_root,
        &block.body,
    );
    let modes = [
        BlockSelectionMode::ExecutionOnly,
        BlockSelectionMode::MaxProfit,
        BlockSelectionMode::BuilderAlways,
    ];
    for mode in modes {
        let (service, signer, beacon, pubkey) = gloas_pair(ssz_produce(bytes.clone(), false));
        let err = service.propose_block_with_mode(slot, &pubkey, mode).await.expect_err("bare ssz");
        assert_unsigned(&signer, &beacon);
        assert_eq!(
            err.to_string(),
            "parse error: self-build bid requires an execution payload envelope",
            "{mode}"
        );
    }
}

/// External-bid SSZ wrapped as `BlockContents` is rejected before signing.
#[tokio::test]
async fn test_mode_shape_external_bid_ssz_contents_is_rejected() {
    // kat_exempt: error-string only.
    let slot = test_gloas_slot();
    let block = external_bid_block(slot);
    let block_ssz = build_gloas_beacon_block_ssz(
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.state_root,
        &block.body,
    );
    let contents =
        build_gloas_block_contents_ssz(&block_ssz, &gloas_envelope_ssz(), &[0xaa], &[0xbb]);
    let modes = [
        BlockSelectionMode::BuilderOnly,
        BlockSelectionMode::MaxProfit,
        BlockSelectionMode::BuilderAlways,
    ];
    for mode in modes {
        let (service, signer, beacon, pubkey) = gloas_pair(ssz_produce(contents.clone(), true));
        let err =
            service.propose_block_with_mode(slot, &pubkey, mode).await.expect_err("external ssz");
        assert_unsigned(&signer, &beacon);
        assert_eq!(
            err.to_string(),
            "parse error: execution payload envelope requires a self-build bid",
            "{mode}"
        );
    }
}

/// SSZ envelope parent must match the block parent before signing.
#[tokio::test]
async fn test_mode_shape_envelope_parent_mismatch_ssz_is_unsigned() {
    // kat_exempt: error-string only.
    let slot = test_gloas_slot();
    let parent_root = [0x11; 32];
    let block = eth_types::BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root,
        state_root: [0x22; 32],
        body: self_build_body(slot, parent_root),
    };
    let block_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )
    .expect("block root");
    let bound = bound_self_build_envelope(&block);
    let wrong_parent = rvc_gloas::envelope_with_binding(
        &bound,
        rvc_gloas::BUILDER_INDEX_SELF_BUILD,
        block_root,
        [0xab; 32],
    )
    .expect("parent rewrite");
    let block_ssz = build_gloas_beacon_block_ssz(
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.state_root,
        &block.body,
    );
    let contents = build_gloas_block_contents_ssz(&block_ssz, &wrong_parent, &[0xaa], &[0xbb]);
    let modes = [
        BlockSelectionMode::ExecutionOnly,
        BlockSelectionMode::MaxProfit,
        BlockSelectionMode::BuilderAlways,
    ];
    for mode in modes {
        let (service, signer, beacon, pubkey) = gloas_pair(ssz_produce(contents.clone(), true));
        let err = service
            .propose_block_with_mode(slot, &pubkey, mode)
            .await
            .expect_err("ssz envelope parent");
        assert_unsigned(&signer, &beacon);
        assert_eq!(
            err.to_string(),
            format!(
                "parse error: self-build envelope parent_beacon_block_root 0x{} does not match block parent root 0x{}",
                hex::encode([0xab; 32]),
                hex::encode(parent_root)
            ),
            "{mode}"
        );
    }
}

/// Bid slot and beacon parent are checked on a bare external block, before signing.
#[tokio::test]
async fn test_mode_shape_bid_slot_and_parent_mismatch_are_unsigned() {
    let slot = test_gloas_slot();
    let block = external_bid_block(slot);
    let wrong_slot = rvc_gloas::body_with_bid_binding(&block.body, 1, slot + 1, block.parent_root)
        .expect("slot rewrite");
    let mut shifted = block.clone();
    shifted.body = wrong_slot;
    let response =
        response_of(MockBeaconClient::unblinded(shifted).with_consensus_version("gloas"));
    let (service, signer, beacon, pubkey) = gloas_pair(response);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("bid slot");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        format!("parse error: bid slot {} does not match block slot {slot}", slot + 1)
    );

    let wrong_parent =
        rvc_gloas::body_with_bid_binding(&block.body, 1, slot, [0xab; 32]).expect("parent rewrite");
    let mut shifted = block;
    shifted.body = wrong_parent;
    let response =
        response_of(MockBeaconClient::unblinded(shifted).with_consensus_version("gloas"));
    let (service, signer, beacon, pubkey) = gloas_pair(response);
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect_err("bid parent");
    assert_unsigned(&signer, &beacon);
    assert_eq!(
        err.to_string(),
        format!(
            "parse error: bid parent_block_root 0x{} does not match block parent root 0x{}",
            hex::encode([0xab; 32]),
            hex::encode([1u8; 32])
        )
    );
}

/// A shape rejection is not a publication failure.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_mode_shape_rejection_is_not_logged_as_publication_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = Arc::new(MockBeaconClient::unblinded(test_block(slot)));
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon.clone(), &pubkey, test_validator_store(&pubkey));
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("local");
    assert_unsigned(&signer, &beacon);
    assert!(matches!(err, BlockServiceError::BuilderOnly(_)));
    assert!(logs_contain("Block response rejected before publication"));
    assert!(!logs_contain("Block publication failed"));
}

/// A publish parse error after the header is signed is a publication failure.
#[tokio::test]
#[tracing_test::traced_test]
async fn test_post_sign_parse_is_not_logged_as_rejected_before_publication() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = Arc::new(MockBeaconClient::unblinded(test_block(slot)).with_publish_parse_error());
    let signer = Arc::new(MockSigner::new());
    let service = pre_gloas(signer.clone(), beacon, &pubkey, test_validator_store(&pubkey));
    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit)
        .await
        .expect_err("publish parse");
    assert_eq!(header_signs(&signer), 1);
    assert_eq!(err.to_string(), "beacon error: parse error: publish body");
    assert!(matches!(err, BlockServiceError::Beacon(_)));
    assert!(logs_contain("Block publication failed"));
    assert!(!logs_contain("Block response rejected before publication"));
}

#[test]
fn test_demote_post_sign_relabels_unsigned_variants() {
    let demoted = demote_post_sign(BlockServiceError::Parse("layout".into()));
    assert_eq!(demoted.to_string(), "beacon error: parse error: layout");
    assert!(matches!(demoted, BlockServiceError::Beacon(_)));

    let envelope = demote_post_sign(BlockServiceError::EnvelopeAfterPublish("late".into()));
    assert!(matches!(envelope, BlockServiceError::EnvelopeAfterPublish(_)));

    let beacon = demote_post_sign(BlockServiceError::Beacon("publish failed".into()));
    assert_eq!(beacon.to_string(), "beacon error: publish failed");

    let signer = demote_post_sign(BlockServiceError::Signer("no key".into()));
    assert!(matches!(signer, BlockServiceError::Signer(_)));
}
