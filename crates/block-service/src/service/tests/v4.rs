//! Issue 6.5: ForkName-threaded V4 production dispatch.

use super::*;
use async_trait::async_trait;
use beacon::{BuilderEntry, BuilderRequestAuth, SignedBuilderRequestAuth};
use eth_types::body_tree_hash_root;
use std::sync::Arc;

fn gloas_unblinded(slot: Slot) -> MockBeaconClient {
    MockBeaconClient::unblinded(gloas_block(slot)).with_consensus_version("gloas")
}

fn gloas_ssz_client(slot: Slot) -> MockBeaconClient {
    let body = gloas_body_ssz();
    let body_offset: u32 = 84;
    let mut ssz_bytes = Vec::new();
    ssz_bytes.extend_from_slice(&slot.to_le_bytes());
    ssz_bytes.extend_from_slice(&42u64.to_le_bytes());
    ssz_bytes.extend_from_slice(&[0x11; 32]);
    ssz_bytes.extend_from_slice(&[0x22; 32]);
    ssz_bytes.extend_from_slice(&body_offset.to_le_bytes());
    ssz_bytes.extend_from_slice(&body);
    MockBeaconClient::from_response(ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("99999".to_string()),
        is_ssz: true,
        ssz_bytes: Some(ssz_bytes),
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    })
}

struct FixedBuilderConfig(BuilderConfig);

#[async_trait]
impl BuilderConfigProvider for FixedBuilderConfig {
    async fn builder_config_for(&self, _pubkey: &[u8; 48], _slot: Slot) -> BuilderConfig {
        self.0.clone()
    }
}

fn sample_signed_builder_config() -> BuilderConfig {
    BuilderConfig {
        min_bid: 7,
        builder_boost_factor: 1,
        builders: vec![BuilderEntry {
            url: "https://relay.example".to_string(),
            auth: SignedBuilderRequestAuth {
                message: BuilderRequestAuth { data: "0xab".to_string(), slot: 2240 },
                signature: format!("0x{}", "aa".repeat(96)),
            },
            builder_pubkeys: vec![],
            max_execution_payment: 0,
            min_bid: 7,
            builder_boost_factor: 1,
        }],
    }
}

#[tokio::test]
async fn test_gloas_epoch_calls_produce_block_v4() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let beacon = Arc::new(gloas_unblinded(slot));
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "Gloas proposal must succeed: {result:?}");

    assert!(
        beacon.produce_v3_calls.lock().unwrap().is_empty(),
        "Gloas must not call produce_block_v3"
    );
    let v4 = beacon.produce_v4_calls.lock().unwrap();
    assert_eq!(v4.len(), 1, "Gloas-epoch slot must call produce_block_v4");
    assert_eq!(v4[0].slot, slot);
    assert!(v4[0].randao_reveal.starts_with("0x"));
    assert!(v4[0].graffiti.is_some());
    assert_eq!(v4[0].builder_config.builder_boost_factor, 150);
    assert_eq!(v4[0].builder_config.min_bid, 0);
    assert!(v4[0].builder_config.builders.is_empty());
}

#[tokio::test]
async fn test_fulu_epoch_calls_produce_block_v3() {
    let pubkey = test_pubkey();
    let slot = test_fulu_slot();
    let beacon = Arc::new(MockBeaconClient::unblinded(test_block(slot)));
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "Fulu proposal must succeed: {result:?}");

    assert!(
        beacon.produce_v4_calls.lock().unwrap().is_empty(),
        "Fulu must not call produce_block_v4"
    );
    let v3 = beacon.produce_v3_calls.lock().unwrap();
    assert_eq!(v3.len(), 1, "Fulu-epoch slot must call produce_block_v3");
    assert_eq!(v3[0].slot, slot);
}

#[tokio::test]
async fn test_fulu_slot_gloas_version_unblinded_json_drops_duty_before_hasher() {
    let pubkey = test_pubkey();
    let slot = test_fulu_slot();
    let beacon =
        Arc::new(MockBeaconClient::unblinded(test_block(slot)).with_consensus_version("gloas"));
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("Gloas-versioned unblinded JSON on a Fulu slot must fail closed");
    assert!(
        matches!(
            err,
            BlockServiceError::ConsensusVersionMismatch { ref expected, ref got }
            if expected == "fulu" && got == "gloas"
        ),
        "expected ConsensusVersionMismatch fulu vs gloas, got {err:?}"
    );
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(signer.block_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_ssz_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_fulu_slot_gloas_version_unblinded_ssz_drops_duty_before_hasher() {
    let pubkey = test_pubkey();
    let slot = test_fulu_slot();
    let beacon = Arc::new(MockBeaconClient::ssz_with_version(slot, 42, false, "gloas"));
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("Gloas-versioned unblinded SSZ on a Fulu slot must fail closed");
    assert!(
        matches!(
            err,
            BlockServiceError::ConsensusVersionMismatch { ref expected, ref got }
            if expected == "fulu" && got == "gloas"
        ),
        "expected ConsensusVersionMismatch fulu vs gloas, got {err:?}"
    );
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(signer.block_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_ssz_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_v4_consensus_version_mismatch_drops_duty_before_signer() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let beacon = MockBeaconClient::unblinded(test_block(slot)).with_consensus_version("fulu");
    let signer = MockSigner::new();
    let signer_arc = Arc::new(signer);
    let service = BlockService::new(
        signer_arc.clone(),
        Arc::new(beacon),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("mismatched Eth-Consensus-Version must drop the duty");
    assert!(
        matches!(
            err,
            BlockServiceError::ConsensusVersionMismatch { ref expected, ref got }
            if expected == "gloas" && got == "fulu"
        ),
        "expected ConsensusVersionMismatch gloas vs fulu, got {err:?}"
    );
    assert!(
        signer_arc.header_calls.lock().unwrap().is_empty(),
        "version mismatch must not call sign_block_header"
    );
    assert!(
        signer_arc.block_calls.lock().unwrap().is_empty(),
        "version mismatch must not call sign_block"
    );
}

#[tokio::test]
async fn test_builder_only_circuit_breaker_fails_at_gloas() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let beacon = Arc::new(gloas_unblinded(slot));
    let cb = Arc::new(CircuitBreakerState::new(1, 0));
    cb.record_miss();
    assert!(cb.is_tripped());

    let service = BlockService::with_circuit_breaker(
        Arc::new(MockSigner::new()),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
        cb,
    );

    let err = service
        .propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly)
        .await
        .expect_err("BuilderOnly + tripped breaker must miss at Gloas");
    assert!(matches!(err, BlockServiceError::BuilderOnly(_)), "expected BuilderOnly, got {err:?}");
    assert!(beacon.produce_v3_calls.lock().unwrap().is_empty());
    assert!(
        beacon.produce_v4_calls.lock().unwrap().is_empty(),
        "tripped BuilderOnly must not produce at Gloas"
    );
}

#[tokio::test]
async fn test_gloas_does_not_branch_on_is_blinded() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let mut beacon = gloas_unblinded(slot);
    beacon.produce_response.as_mut().unwrap().is_blinded = true;
    let beacon = Arc::new(beacon);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "Gloas must not drop the duty on is_blinded: {result:?}");
    assert!(!result.unwrap().is_blinded, "Gloas publish path is never blinded");
    assert_eq!(beacon.publish_calls.lock().unwrap().len(), 1);
    assert!(beacon.publish_blinded_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_blinded_full_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_gloas_electra_body_fails_closed_without_signer() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let beacon = MockBeaconClient::unblinded(test_block(slot)).with_consensus_version("gloas");
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        Arc::new(beacon),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("Electra body at Gloas must not Electra-hash");
    assert!(matches!(err, BlockServiceError::Gloas(_)), "expected GloasError, got {err:?}");
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(signer.block_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_gloas_header_uses_island_body_leaf() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let body = gloas_body_ssz();
    assert!(body_tree_hash_root(&body).is_err(), "fixture must not be Electra/Deneb-decodable");
    let expected = rvc_gloas::gloas_body_root(&body).expect("valid Gloas body");
    let expected_hex = rvc_gloas::test_fixtures::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT;
    assert_eq!(hex::encode(expected), expected_hex);

    let block = gloas_block(slot);
    let island_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )
    .expect("valid Gloas body");

    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        Arc::new(gloas_unblinded(slot)),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "Gloas island body must sign: {result:?}");
    let headers = signer.header_calls.lock().unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].header.body_root, expected);
    assert_eq!(headers[0].header.object_root(), island_root);
    assert_eq!(result.unwrap().block_root, island_root);
}

#[tokio::test]
async fn test_gloas_ssz_e2e_signs_with_island_body_leaf() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let body = gloas_body_ssz();
    let expected = rvc_gloas::gloas_body_root(&body).unwrap();
    assert_eq!(hex::encode(expected), rvc_gloas::test_fixtures::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT);

    let beacon = Arc::new(gloas_ssz_client(slot));
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let island_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
        },
        &body,
    )
    .expect("valid Gloas body");

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "Gloas SSZ proposal must succeed: {result:?}");
    assert_eq!(beacon.publish_ssz_calls.lock().unwrap().len(), 1);
    assert!(beacon.publish_calls.lock().unwrap().is_empty());
    let headers = signer.header_calls.lock().unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].header.body_root, expected);
    assert_eq!(headers[0].header.object_root(), island_root);
    assert_eq!(result.unwrap().block_root, island_root);
}

#[tokio::test]
async fn test_v4_builder_config_reuses_provider_auth_and_mode_boost() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let beacon = Arc::new(gloas_unblinded(slot));
    let provided = sample_signed_builder_config();
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    )
    .with_builder_config_provider(Arc::new(FixedBuilderConfig(provided.clone())));

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "{result:?}");
    let captured = &beacon.produce_v4_calls.lock().unwrap()[0].builder_config;
    assert_eq!(captured.builders, provided.builders);
    assert_eq!(captured.builder_boost_factor, 150);
    assert_eq!(captured.min_bid, 0);
}

#[tokio::test]
async fn test_v4_builders_empty_without_provider_even_if_store_has_urls() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let store = test_validator_store(&pubkey);
    store.set_global_builders(vec!["https://relay.example".to_string()]).unwrap();
    let beacon = Arc::new(gloas_unblinded(slot));
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "{result:?}");
    assert!(
        beacon.produce_v4_calls.lock().unwrap()[0].builder_config.builders.is_empty(),
        "must not invent unsigned builder auth"
    );
}

#[test]
fn test_gloas_block_signing_root() {
    use crypto::{compute_domain, compute_signing_root, DOMAIN_BEACON_PROPOSER};

    let ssz = hex::decode(rvc_gloas::test_fixtures::SPEC_GLOAS_BEACON_BLOCK_SSZ).unwrap();
    let (block, _) = beacon::ssz_deser::deserialize_beacon_block_from_ssz(
        &ssz,
        beacon::ssz_deser::SszBlockFormat::BeaconBlock,
    )
    .expect("official BeaconBlock SSZ");
    let (header, block_root) = gloas_header_and_root(&block).expect("valid Gloas body");
    let island_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )
    .expect("valid Gloas body");
    assert_eq!(header.body_root, rvc_gloas::gloas_body_root(&block.body).unwrap());
    assert_eq!(block_root, island_root);
    assert_eq!(header.object_root(), island_root);

    // pyspec argv: --fork-version 0x07000001, zero GVR (gloas_signing_kat provenance).
    let domain = compute_domain(DOMAIN_BEACON_PROPOSER, [0x07, 0x00, 0x00, 0x01], [0u8; 32]);
    let got = compute_signing_root(&block_root, domain);
    assert_eq!(hex::encode(got), rvc_gloas::KAT_GLOAS_BLOCK_SIGNING_ROOT);
}

#[tokio::test]
async fn test_gloas_invalid_body_drops_duty_without_signer_or_publish() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let mut block = gloas_block(slot);
    block.body.truncate(block.body.len() / 2);
    let beacon = Arc::new(MockBeaconClient::unblinded(block).with_consensus_version("gloas"));
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule_with_near_gloas()),
        [0xaa; 32],
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("InvalidBody must drop the duty");
    assert!(
        matches!(err, BlockServiceError::Gloas(rvc_gloas::GloasError::InvalidBody { .. })),
        "expected GloasError::InvalidBody, got {err:?}"
    );
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(signer.block_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_ssz_calls.lock().unwrap().is_empty());
}

#[test]
fn test_gloas_header_helper_uses_island_not_electra_htr() {
    let src = include_str!("../mod.rs");
    let start = src.find("fn gloas_header_and_root").expect("gloas_header_and_root must exist");
    let rest = &src[start + 1..];
    let end = rest.find("\nfn ").expect("helper must be followed by another fn");
    let body = &src[start..start + 1 + end];
    assert!(body.contains("gloas_block_root"), "{body}");
    assert!(body.contains("gloas_body_root"), "{body}");
    assert!(!body.contains("compute_block_root"), "{body}");
    assert!(!body.contains("body_tree_hash_root"), "{body}");
}

#[test]
fn test_gloas_v4_helpers_do_not_read_is_blinded_or_electra_htr() {
    let src = include_str!("../mod.rs");
    for name in ["sign_and_publish_v4", "sign_and_publish_envelope"] {
        let needle = format!("async fn {name}");
        let start = src.find(&needle).unwrap_or_else(|| panic!("{name} must exist"));
        let rest = &src[start..];
        let end = rest.find("\n    async fn ").expect("helper must be followed by another method");
        let body = &rest[..end];
        assert!(!body.contains("is_blinded"), "{name} must not read is_blinded:\n{body}");
        assert!(!body.contains("compute_block_root"), "{name} must not call compute_block_root");
        assert!(!body.contains("body_tree_hash_root"), "{name} must not call body_tree_hash_root");
        assert!(!body.contains("header_from_full"), "{name} must not call header_from_full");
        assert!(!body.contains("parse_full_block"), "{name} must not call parse_full_block");
    }
}
