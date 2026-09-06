//! Propose-path and validation tests for block-service.

use super::*;
use eth_types::{BeaconBlock, BlindedBeaconBlock};
use std::sync::Arc;

#[test]
fn test_compute_block_root_matches_tree_hash() {
    use tree_hash::TreeHash;
    let block = test_block(100);
    let root = compute_block_root(&block).unwrap();
    let expected = block.tree_hash_root();
    assert_eq!(root, expected.0);
}

#[test]
fn test_compute_blinded_block_root_matches_tree_hash() {
    use tree_hash::TreeHash;
    let block = test_blinded_block(200);
    let root = compute_blinded_block_root(&block).unwrap();
    let expected = block.tree_hash_root();
    assert_eq!(root, expected.0);
}

#[test]
fn test_compute_block_root_matches_external_electra_vector() {
    let block = eth_types::external_vector_electra_block();
    let root = compute_block_root(&block).expect("valid external vector body");
    let expected = hex::decode(eth_types::EXTERNAL_ELECTRA_BLOCK_ROOT_HEX).unwrap();
    assert_eq!(
        root.as_slice(),
        expected.as_slice(),
        "compute_block_root must match remerkleable external Electra block root"
    );
}

#[test]
fn test_compute_blinded_block_root_matches_external_vector() {
    let block = eth_types::external_vector_electra_blinded_block();
    let root = compute_blinded_block_root(&block).expect("valid external vector blinded body");
    let expected = hex::decode(eth_types::EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX).unwrap();
    assert_eq!(
        root.as_slice(),
        expected.as_slice(),
        "compute_blinded_block_root must match remerkleable external blinded Electra block root"
    );
}

#[test]
fn test_compute_block_root_matches_external_deneb_vector() {
    let block = eth_types::external_vector_deneb_block();
    let root = compute_block_root(&block).expect("valid Deneb external vector body");
    let expected = hex::decode(eth_types::EXTERNAL_DENEB_BLOCK_ROOT_HEX).unwrap();
    assert_eq!(
        root.as_slice(),
        expected.as_slice(),
        "compute_block_root must match remerkleable external Deneb block root"
    );
}

#[test]
fn test_compute_blinded_block_root_matches_external_deneb_vector() {
    let block = eth_types::external_vector_deneb_blinded_block();
    let root = compute_blinded_block_root(&block).expect("valid Deneb blinded body");
    let expected = hex::decode(eth_types::EXTERNAL_DENEB_BLOCK_ROOT_HEX).unwrap();
    assert_eq!(
        root.as_slice(),
        expected.as_slice(),
        "compute_blinded_block_root must match remerkleable external Deneb block root"
    );
}

#[test]
fn test_malformed_body_returns_error_not_panic() {
    let block = BeaconBlock {
        slot: 1,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
        body: vec![0xde, 0xad],
    };
    let err = compute_block_root(&block).expect_err("malformed body must error");
    assert!(matches!(err, BlockServiceError::Parse(_)), "expected Parse error, got {err:?}");

    let blinded = BlindedBeaconBlock {
        slot: 1,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
        body: vec![0xbe, 0xef],
    };
    let err = compute_blinded_block_root(&blinded).expect_err("malformed blinded body");
    assert!(matches!(err, BlockServiceError::Parse(_)));
}

#[tokio::test]
async fn test_propose_block_unblinded() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();
    let fork = test_fork_schedule();
    let gvr: Root = [0xaa; 32];

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(fork.clone()),
        gvr,
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, slot);
    assert!(!proposal.is_blinded);
    assert_eq!(proposal.consensus_version, "deneb");
    assert_eq!(proposal.value_wei, Some("12345".to_string()));
    assert_ne!(proposal.block_root, [0u8; 32]);

    beacon_arc.assert_last_produce_slot(slot);
    beacon_arc.assert_last_published_block(slot, 42);
    signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    signer_arc.assert_last_sign_block_header(&fork, &gvr);
}

/// D29: two distinct produce answers exist, but sign + publish is single-flight.
///
/// `produce_queue` is drained by both v3 and v4 so 6.5 cannot drop this pin.
/// Slashing-DB row count is covered by signer `reserve_block` tests; here
/// `MockSigner.block_calls` is the stand-in (one sign = one staged row).
#[tokio::test]
async fn test_two_candidates_one_signature_one_publish() {
    let pubkey = test_pubkey();
    let slot = 100;
    let mut block_a = test_block(slot);
    let mut block_b = test_block(slot);
    block_a.parent_root = [0x0a; 32];
    block_b.parent_root = [0x0b; 32];

    let beacon = Arc::new(MockBeaconClient::unblinded_candidates(vec![block_a, block_b]));
    let signer = Arc::new(MockSigner::new());
    let fork = test_fork_schedule();
    let gvr: Root = [0xaa; 32];
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(fork),
        gvr,
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "proposal must succeed on the first candidate: {result:?}");

    let produce_n = beacon.produce_full_calls.lock().unwrap().len();
    let sign_n = signer.block_calls.lock().unwrap().len();
    let header_n = signer.header_calls.lock().unwrap().len();
    let publish_n = beacon.publish_full_calls.lock().unwrap().len();
    assert_eq!(produce_n, 1, "must not re-produce after the first BlockContents");
    assert_eq!(sign_n, 1, "exactly one signature (slashing-DB stand-in: one signed block)");
    assert_eq!(header_n, 1);
    assert_eq!(publish_n, 1, "exactly one block publish");
    beacon.assert_last_published_block(slot, 42);

    let leftover = beacon.produce_queue.lock().unwrap().len();
    assert_eq!(leftover, 1, "second distinct BlockContents must remain unused");
}

/// Issue 2.10: the "Block publication success" info milestone logs the
/// block_root TRUNCATED (0x{first10}...{last8}), never the full 64-hex.
#[tracing_test::traced_test]
#[tokio::test]
// kat_exempt: logging truncation only — asserts publish hex is redacted, not a spec root
async fn test_propose_block_publish_truncates_block_root() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = Arc::new(MockBeaconClient::unblinded(block));
    let fork = test_fork_schedule();
    let gvr: Root = [0xaa; 32];
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon,
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(fork),
        gvr,
    );

    let proposal = service.propose_block(slot, &pubkey, 42, None).await.unwrap();

    let full = hex::encode(proposal.block_root);
    let truncated = format!("0x{}...{}", &full[..10], &full[full.len() - 8..]);
    assert!(logs_contain("Block publication success"), "publish milestone must fire");
    assert!(logs_contain(&truncated), "publish line must show the truncated block_root");
    assert!(!logs_contain(&full), "publish line must NOT show the full block root hex");
}

#[tokio::test]
async fn test_propose_block_blinded() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block);
    let signer = MockSigner::new();
    let fork = test_fork_schedule();
    let gvr: Root = [0xaa; 32];

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(fork.clone()),
        gvr,
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, slot);
    assert!(proposal.is_blinded);
    assert_eq!(proposal.consensus_version, "deneb");
    assert!(proposal.value_wei.is_none());
    assert_ne!(proposal.block_root, [0u8; 32]);

    beacon_arc.assert_last_produce_slot(slot);
    beacon_arc.assert_last_published_blinded_block(slot, 42);
    signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    signer_arc.assert_last_sign_block_header(&fork, &gvr);
}

#[tokio::test]
async fn test_propose_block_blinded_at_gloas_returns_typed_error_without_signer() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block);
    let signer = MockSigner::new();
    let mut fork = test_fork_schedule();
    fork.gloas_fork_epoch = 0;
    let gvr: Root = [0xaa; 32];

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(fork),
        gvr,
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("blinded Gloas must fail closed");
    assert!(
        matches!(err, BlockServiceError::BlindedNotSupportedAtGloas { slot: s } if s == slot),
        "expected BlindedNotSupportedAtGloas, got {err:?}"
    );
    assert!(
        signer_arc.header_calls.lock().unwrap().is_empty(),
        "Gloas blinded must not call sign_block_header"
    );
    assert!(
        signer_arc.block_calls.lock().unwrap().is_empty(),
        "Gloas blinded must not call sign_block"
    );
    assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
    assert!(beacon_arc.publish_blinded_full_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_propose_block_blinded_gloas_version_returns_typed_error_without_signer() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let mut beacon = MockBeaconClient::blinded(block);
    beacon.produce_response.as_mut().unwrap().consensus_version = "gloas".to_string();
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let service = BlockService::new(
        signer_arc.clone(),
        Arc::new(beacon),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("gloas consensus_version blinded must fail closed");
    assert!(
        matches!(err, BlockServiceError::BlindedNotSupportedAtGloas { slot: s } if s == slot),
        "expected BlindedNotSupportedAtGloas, got {err:?}"
    );
    assert!(signer_arc.header_calls.lock().unwrap().is_empty());
    assert!(signer_arc.block_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_propose_block_signing_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new().with_block_error();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, BlockServiceError::Signer(_)));
}

#[tokio::test]
async fn test_propose_block_randao_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new().with_randao_error();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, BlockServiceError::Signer(_)));
}

#[tokio::test]
async fn test_propose_block_beacon_produce_failure() {
    // test_validator_store wires builder_boost_factor = 150, so the
    // default MaxProfit mode sends boost = 150 > 0 to the BN.  After the
    // H-3 fix, a BN error on a builder attempt is tagged BuilderFailure
    // (not Beacon) so that the coordinator can correctly scope
    // circuit-breaker misses.
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block).with_produce_error();
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    // MaxProfit with boost = 150 → BuilderFailure (not Beacon) — H-3.
    assert!(
        matches!(err, BlockServiceError::BuilderFailure(_)),
        "MaxProfit BN error must be BuilderFailure, got {err:?}"
    );
}

#[tokio::test]
async fn test_propose_block_beacon_publish_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block).with_publish_error();
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, BlockServiceError::Beacon(_)));
}

#[tokio::test]
async fn test_propose_block_uses_validator_preferences() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block);

    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        Arc::new(beacon),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    // Verify graffiti + boost via the single capturing mock (full produce capture).
    let last = service.beacon.last_produce_call();
    assert!(last.graffiti.is_some());
    let graffiti_str = last.graffiti.unwrap();
    assert!(graffiti_str.starts_with("0x"));
    // "hello" = 68656c6c6f
    assert!(graffiti_str.contains("68656c6c6f"));
    assert_eq!(last.builder_boost_factor, Some(150));
}

#[tokio::test]
async fn test_propose_block_routes_blinded_to_blinded_endpoint() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block);
    let signer = MockSigner::new();

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(signer),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    assert_eq!(beacon_arc.publish_blinded_calls.lock().unwrap().len(), 1);
    assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
    beacon_arc.assert_last_produce_slot(slot);
    beacon_arc.assert_last_published_blinded_block(slot, 42);
}

#[tokio::test]
async fn test_propose_block_routes_unblinded_to_unblinded_endpoint() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(signer),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    assert_eq!(beacon_arc.publish_calls.lock().unwrap().len(), 1);
    assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
    beacon_arc.assert_last_produce_slot(slot);
    beacon_arc.assert_last_published_block(slot, 42);
}

#[tokio::test]
async fn test_blinded_block_signing_failure_prevents_publish() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block);
    let signer = MockSigner::new().with_block_error();

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(signer),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BlockServiceError::Signer(_)));

    // Verify no publish calls were made
    assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
    assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_blinded_block_publish_failure() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block).with_publish_error();
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BlockServiceError::Beacon(_)));
}

#[tokio::test]
async fn test_blinded_and_unblinded_same_slot_have_different_block_roots() {
    let pubkey = test_pubkey();
    let slot = 100;

    // Propose unblinded block
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block.clone());
    let signer = MockSigner::new();
    let signer_arc = Arc::new(signer);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        Arc::new(beacon),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );
    let unblinded_result = service.propose_block(slot, &pubkey, 42, None).await.unwrap();

    // Propose blinded block at same slot
    let blinded_block = test_blinded_block(slot);
    let beacon2 = MockBeaconClient::blinded(blinded_block.clone());
    let signer2 = MockSigner::new();
    let signer2_arc = Arc::new(signer2);
    let store2 = test_validator_store(&pubkey);
    let service2 = BlockService::new(
        signer2_arc.clone(),
        Arc::new(beacon2),
        Arc::new(store2),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );
    let blinded_result = service2.propose_block(slot, &pubkey, 42, None).await.unwrap();

    // Block roots must differ (slashing protection uses these to detect double proposals)
    assert_ne!(
        unblinded_result.block_root, blinded_result.block_root,
        "blinded and unblinded blocks at same slot must have different roots for slashing protection"
    );

    // Both signers were called with the respective root
    let unblinded_calls = signer_arc.block_calls.lock().unwrap();
    let blinded_calls = signer2_arc.block_calls.lock().unwrap();
    assert_eq!(unblinded_calls.len(), 1);
    assert_eq!(blinded_calls.len(), 1);
    assert_eq!(unblinded_calls[0].block_root, unblinded_result.block_root);
    assert_eq!(blinded_calls[0].block_root, blinded_result.block_root);
}
#[tokio::test]
async fn test_propose_block_unblinded_slot_mismatch_returns_error() {
    let pubkey = test_pubkey();
    let requested_slot = 100;
    let block = test_block(200); // block has slot 200, we request 100
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(requested_slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, BlockServiceError::SlotMismatch { requested: 100, got: 200 }),
        "expected SlotMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn test_propose_block_blinded_slot_mismatch_returns_error() {
    let pubkey = test_pubkey();
    let requested_slot = 100;
    let block = test_blinded_block(300); // block has slot 300, we request 100
    let beacon = MockBeaconClient::blinded(block);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(requested_slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, BlockServiceError::SlotMismatch { requested: 100, got: 300 }),
        "expected SlotMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn test_propose_block_calls_randao_with_correct_epoch() {
    let pubkey = test_pubkey();
    let slot = 320; // epoch = 320/32 = 10
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();
    let fork = test_fork_schedule();
    let gvr: Root = [0xaa; 32];

    let signer_arc = Arc::new(signer);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        Arc::new(beacon),
        Arc::new(store),
        Arc::new(fork.clone()),
        gvr,
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let calls = signer_arc.randao_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], 10); // epoch = 320/32
    drop(calls);

    signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    signer_arc.assert_last_sign_block_header(&fork, &gvr);
}
// --- Issue 3.2: Slot 0 / Epoch boundary block proposal tests (Finding #23) ---

#[tokio::test]
async fn test_propose_block_at_slot_zero() {
    let pubkey = test_pubkey();
    let slot = 0;
    let block = BeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
        body: test_body_ssz(),
    };
    let beacon = MockBeaconClient::unblinded(block);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 1, None).await;

    assert!(result.is_ok(), "slot 0 must not underflow: {:?}", result.err());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, 0);
    assert!(!proposal.is_blinded);
    assert_ne!(proposal.block_root, [0u8; 32]);

    beacon_arc.assert_last_produce_slot(0);
    beacon_arc.assert_last_published_block(0, 1);
}

#[tokio::test]
async fn test_propose_block_at_epoch_boundary() {
    let pubkey = test_pubkey();
    let slot = SLOTS_PER_EPOCH; // slot 32 = first slot of epoch 1
    let block = BeaconBlock {
        slot,
        proposer_index: 5,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body: test_body_ssz(),
    };
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();
    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 5, None).await;

    assert!(result.is_ok(), "epoch boundary slot must work: {:?}", result.err());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, SLOTS_PER_EPOCH);

    beacon_arc.assert_last_produce_slot(SLOTS_PER_EPOCH);
    beacon_arc.assert_last_published_block(SLOTS_PER_EPOCH, 5);

    // RANDAO must use epoch 1
    let randao_calls = signer_arc.randao_calls.lock().unwrap();
    assert_eq!(randao_calls.len(), 1);
    assert_eq!(randao_calls[0], 1, "epoch must be slot/SLOTS_PER_EPOCH = 1");
}

#[tokio::test]
async fn test_propose_block_at_slot_zero_ssz() {
    let pubkey = test_pubkey();
    let slot = 0;
    let beacon = MockBeaconClient::ssz_with_version(slot, 1, false, "capella");
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 1, None).await;

    assert!(result.is_ok(), "SSZ slot 0 must not underflow: {:?}", result.err());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, 0);
    beacon_arc.assert_last_produce_slot(0);
}
// --- Issue 3.3: BlockAndBlobs JSON parse test (Finding #24) ---

#[test]
fn test_block_and_blobs_json_deserialization() {
    use eth_types::BlockContents;

    let json = serde_json::json!({
        "block": {
            "slot": "1000",
            "proposer_index": "42",
            "parent_root": format!("0x{}", hex::encode([0x11u8; 32])),
            "state_root": format!("0x{}", hex::encode([0x22u8; 32])),
            "body": format!("0x{}", hex::encode([0xab; 8])),
        },
        "blob_sidecars": [
            {
                "index": "0",
                "blob": format!("0x{}", hex::encode([0xdd; 128])),
            },
            {
                "index": "1",
                "blob": format!("0x{}", hex::encode([0xee; 128])),
            },
        ]
    });

    let contents: BlockContents = serde_json::from_value(json).unwrap();
    match &contents {
        BlockContents::BlockAndBlobs { block, blob_sidecars } => {
            assert_eq!(block.slot, 1000);
            assert_eq!(block.proposer_index, 42);
            assert_eq!(block.parent_root, [0x11u8; 32]);
            assert_eq!(block.state_root, [0x22u8; 32]);
            assert_eq!(block.body, vec![0xab; 8]);
            assert_eq!(blob_sidecars.len(), 2);
            assert_eq!(blob_sidecars[0].index, 0);
            assert_eq!(blob_sidecars[0].blob, vec![0xdd; 128]);
            assert_eq!(blob_sidecars[1].index, 1);
            assert_eq!(blob_sidecars[1].blob, vec![0xee; 128]);
        }
        BlockContents::Block(_) => {
            panic!("expected BlockAndBlobs variant, got Block");
        }
    }
}

#[test]
fn test_block_and_blobs_json_through_produce_response() {
    let json = serde_json::json!({
        "block": {
            "slot": "500",
            "proposer_index": "10",
            "parent_root": format!("0x{}", hex::encode([0xaa; 32])),
            "state_root": format!("0x{}", hex::encode([0xbb; 32])),
            "body": format!("0x{}", hex::encode([0xde, 0xad])),
        },
        "blob_sidecars": [
            {
                "index": "0",
                "blob": format!("0x{}", hex::encode([0xff; 64])),
            },
        ]
    });

    let response = ProduceBlockResponse {
        data: json,
        is_blinded: false,
        consensus_version: "deneb".to_string(),
        execution_payload_value: Some("99999".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    };

    let contents = response.parse_full_block().unwrap();
    let block = contents.block();
    assert_eq!(block.slot, 500);
    assert_eq!(block.proposer_index, 10);
    match &contents {
        eth_types::BlockContents::BlockAndBlobs { blob_sidecars, .. } => {
            assert_eq!(blob_sidecars.len(), 1);
            assert_eq!(blob_sidecars[0].blob, vec![0xff; 64]);
        }
        _ => panic!("expected BlockAndBlobs"),
    }
}

#[test]
fn test_block_and_blobs_json_empty_sidecars() {
    let json = serde_json::json!({
        "block": {
            "slot": "100",
            "proposer_index": "1",
            "parent_root": format!("0x{}", hex::encode([0u8; 32])),
            "state_root": format!("0x{}", hex::encode([0u8; 32])),
            "body": "0x",
        },
        "blob_sidecars": []
    });

    let contents: eth_types::BlockContents = serde_json::from_value(json).unwrap();
    match &contents {
        eth_types::BlockContents::BlockAndBlobs { blob_sidecars, .. } => {
            assert!(blob_sidecars.is_empty());
        }
        _ => panic!("expected BlockAndBlobs variant even with empty sidecars"),
    }
}
// --- Issue 3.4: Rewrite tautological block root test (Finding #25) ---

#[tokio::test]
async fn test_blinded_and_unblinded_roots_differ_through_production_logic() {
    let pubkey = test_pubkey();
    let slot = 100;

    // Both blocks share the same slot + proposer_index but differ in body.
    // The point: verify production code (compute_block_root / compute_blinded_block_root)
    // produces different roots because tree_hash includes the body field.
    let unblinded_block = BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body: test_body_ssz(),
    };
    let blinded_block = BlindedBeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body: test_blinded_body_ssz(), // different body → different root
    };

    // Exercise the production root computation functions
    let unblinded_root = compute_block_root(&unblinded_block).unwrap();
    let blinded_root = compute_blinded_block_root(&blinded_block).unwrap();

    // Roots differ because body content differs
    assert_ne!(
        unblinded_root, blinded_root,
        "blocks with different bodies at same slot must have different tree_hash roots"
    );

    // Verify roots are non-trivial (not all zeros)
    assert_ne!(unblinded_root, [0u8; 32]);
    assert_ne!(blinded_root, [0u8; 32]);

    // Verify determinism: same input → same root
    assert_eq!(compute_block_root(&unblinded_block).unwrap(), unblinded_root);
    assert_eq!(compute_blinded_block_root(&blinded_block).unwrap(), blinded_root);

    // Now run through the full pipeline and confirm the signer receives these roots
    let beacon_unblinded = MockBeaconClient::unblinded(unblinded_block);
    let signer = MockSigner::new();
    let signer_arc = Arc::new(signer);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        Arc::new(beacon_unblinded),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );
    let result = service.propose_block(slot, &pubkey, 42, None).await.unwrap();
    assert_eq!(result.block_root, unblinded_root, "pipeline must pass tree_hash root to signer");
    let sign_calls = signer_arc.block_calls.lock().unwrap();
    assert_eq!(sign_calls[0].block_root, unblinded_root);
}

#[test]
fn test_block_root_sensitive_to_every_field() {
    let baseline = BeaconBlock {
        slot: 100,
        proposer_index: 42,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body: test_body_ssz(),
    };
    let baseline_root = compute_block_root(&baseline).unwrap();

    // Changing slot
    let mut changed = baseline.clone();
    changed.slot = 101;
    assert_ne!(
        compute_block_root(&changed).unwrap(),
        baseline_root,
        "root must change when slot changes"
    );

    // Changing proposer_index
    let mut changed = baseline.clone();
    changed.proposer_index = 43;
    assert_ne!(
        compute_block_root(&changed).unwrap(),
        baseline_root,
        "root must change when proposer_index changes"
    );

    // Changing parent_root
    let mut changed = baseline.clone();
    changed.parent_root = [99u8; 32];
    assert_ne!(
        compute_block_root(&changed).unwrap(),
        baseline_root,
        "root must change when parent_root changes"
    );

    // Changing state_root
    let mut changed = baseline.clone();
    changed.state_root = [99u8; 32];
    assert_ne!(
        compute_block_root(&changed).unwrap(),
        baseline_root,
        "root must change when state_root changes"
    );

    // Changing body (distinct Electra body SSZ)
    let mut changed = baseline.clone();
    let mut alt = eth_types::external_vector_electra_body();
    alt.graffiti = [0xcd; 32];
    changed.body = alt.as_ssz_bytes();
    assert_ne!(
        compute_block_root(&changed).unwrap(),
        baseline_root,
        "root must change when body changes"
    );
}
// -----------------------------------------------------------------------
// Integration tests: propose_block H-4 validation wiring
// -----------------------------------------------------------------------

/// BN returns block with wrong proposer_index — signer must NOT be called.
#[tokio::test]
async fn test_propose_block_proposer_index_mismatch_drops_duty() {
    let pubkey = test_pubkey();
    let slot = 100;
    // Block has proposer_index = 42; duty expects 99
    let block = test_block(slot); // proposer_index = 42
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    // Duty says expected_proposer_index = 99, but BN returns 42
    let result = service.propose_block(slot, &pubkey, 99, None).await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            BlockServiceError::ProposerIndexMismatch { expected: 99, got: 42 }
        ),
        "expected ProposerIndexMismatch"
    );
    // No signer call must have been made
    assert!(
        signer_arc.block_calls.lock().unwrap().is_empty(),
        "signer must not be called when proposer_index validation fails"
    );
    // No publish call either
    assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
}

/// BN returns block with wrong parent_root — signer must NOT be called.
#[tokio::test]
async fn test_propose_block_parent_root_mismatch_drops_duty() {
    let pubkey = test_pubkey();
    let slot = 100;
    // Block has parent_root = [1u8; 32]; we expect [0xee; 32]
    let block = test_block(slot); // parent_root = [1u8; 32]
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let expected_parent: Root = [0xee; 32];
    let result = service.propose_block(slot, &pubkey, 42, Some(expected_parent)).await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), BlockServiceError::ParentRootMismatch { .. }),
        "expected ParentRootMismatch"
    );
    assert!(
        signer_arc.block_calls.lock().unwrap().is_empty(),
        "signer must not be called when parent_root validation fails"
    );
    assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
}

/// ARCH-3e / H-4: `propose_block` with `expected_parent_root = Some(root of N-1)`
/// rejects a BN block whose parent is a different ancestor. Signer is never called.
#[tokio::test]
async fn test_propose_block_rejects_a_wrong_ancestor_parent() {
    let pubkey = test_pubkey();
    let slot = 100;
    let previous_slot_parent: Root = [0x11; 32];
    let wrong_ancestor: Root = [0x22; 32];

    let mut block = test_block(slot);
    block.parent_root = wrong_ancestor;
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, Some(previous_slot_parent)).await;

    assert!(
        matches!(
            result,
            Err(BlockServiceError::ParentRootMismatch { expected, got })
            if expected == previous_slot_parent && got == wrong_ancestor
        ),
        "wrong-ancestor parent must be ParentRootMismatch, got {result:?}"
    );
    assert!(
        signer_arc.block_calls.lock().unwrap().is_empty(),
        "signer must not be called when parent_root is a wrong ancestor"
    );
    assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
}

/// ARCH-3e / H-4: a block whose parent is the previous-slot root is accepted.
/// Anti-regression for treating slot N's own head as the expected parent.
#[tokio::test]
async fn test_propose_block_accepts_the_previous_slot_parent() {
    let pubkey = test_pubkey();
    let slot = 100;
    let previous_slot_parent: Root = [0x11; 32];

    let mut block = test_block(slot);
    block.parent_root = previous_slot_parent;
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, Some(previous_slot_parent)).await;

    assert!(result.is_ok(), "previous-slot parent must be accepted, got {result:?}");
    assert_eq!(
        signer_arc.block_calls.lock().unwrap().len(),
        1,
        "signer must be called when parent is the previous-slot root"
    );
    beacon_arc.assert_last_published_block(slot, 42);
}

/// Correct proposer_index with None parent_root — proposal proceeds.
#[tokio::test]
async fn test_propose_block_correct_proposer_no_parent_root_succeeds() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot); // proposer_index = 42
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    // Signer WAS called
    assert_eq!(
        signer_arc.block_calls.lock().unwrap().len(),
        1,
        "signer must be called for valid proposal"
    );
    beacon_arc.assert_last_published_block(slot, 42);
}

/// Blinded path: wrong proposer_index — signer must NOT be called.
#[tokio::test]
async fn test_propose_block_blinded_proposer_mismatch_drops_duty() {
    let pubkey = test_pubkey();
    let slot = 200;
    // Blinded block has proposer_index = 42
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block);
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    // Expect proposer 77, BN returns 42
    let result = service.propose_block(slot, &pubkey, 77, None).await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            BlockServiceError::ProposerIndexMismatch { expected: 77, got: 42 }
        ),
        "expected ProposerIndexMismatch on blinded path"
    );
    assert!(
        signer_arc.block_calls.lock().unwrap().is_empty(),
        "signer must not be called when blinded proposer_index validation fails"
    );
    assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
}

// -----------------------------------------------------------------------
// ISSUE-4.3 (L-3): canonical blob KZG commitment binding — regression tests
// -----------------------------------------------------------------------

/// Electra body SSZ with the given `blob_kzg_commitments` (valid for SEC-6c HTR).
fn electra_body_with_kzg_commitments_for_test(commitments: &[[u8; 48]]) -> Vec<u8> {
    let mut body = eth_types::external_vector_electra_body();
    body.blob_kzg_commitments = commitments.to_vec().into();
    body.as_ssz_bytes()
}

/// Build a mock `ProduceBlockResponse` for an Electra `BlockAndBlobs` payload
/// where the body contains `commitments` and the `blob_sidecars` has one entry
/// per commitment. Body is a valid Electra typed container (SEC-6c).
fn block_and_blobs_response(slot: Slot, commitments: &[[u8; 48]]) -> ProduceBlockResponse {
    let body = electra_body_with_kzg_commitments_for_test(commitments);
    let body_hex = format!("0x{}", hex::encode(&body));
    let blob_sidecars: Vec<serde_json::Value> = commitments
        .iter()
        .enumerate()
        .map(|(i, _)| {
            serde_json::json!({
                "index": i.to_string(),
                "blob": format!("0x{}", hex::encode([0u8; 64])),
            })
        })
        .collect();
    let data = serde_json::json!({
        "block": {
            "slot": slot.to_string(),
            "proposer_index": "42",
            "parent_root": format!("0x{}", hex::encode([0x11u8; 32])),
            "state_root": format!("0x{}", hex::encode([0x22u8; 32])),
            "body": body_hex,
        },
        "blob_sidecars": blob_sidecars,
    });
    ProduceBlockResponse {
        data,
        is_blinded: false,
        consensus_version: "electra".to_string(),
        execution_payload_value: Some("12345".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    }
}

/// L-3 (ISSUE-4.3): canonical commitment root must be nonzero for a block
/// with two distinct blob KZG commitments.
#[test]
fn test_l3_kzg_commitment_root_nonzero_for_block_and_blobs() {
    use eth_types::BodyForkLayout;
    let slot = 1000;
    let commitments = [[0xaa; 48], [0xbb; 48]];
    let response = block_and_blobs_response(slot, &commitments);
    let contents = response.parse_full_block().unwrap();
    let root = contents.kzg_commitment_root(BodyForkLayout::Electra).unwrap();
    assert_ne!(root, [0u8; 32], "commitment root must be nonzero for non-empty blobs");
}

/// L-3 (ISSUE-4.3): the canonical commitment root must change when any single
/// byte in any blob KZG commitment in the body is mutated.
#[test]
fn test_l3_kzg_root_changes_on_any_commitment_mutation() {
    use eth_types::BodyForkLayout;
    let slot = 1000;
    let original_commits = [[0xcc; 48], [0xdd; 48]];
    let base_root = {
        let response = block_and_blobs_response(slot, &original_commits);
        response.parse_full_block().unwrap().kzg_commitment_root(BodyForkLayout::Electra).unwrap()
    };

    // Mutate one byte in each commitment and verify the root changes.
    for ci in 0..original_commits.len() {
        let mut mutated = original_commits;
        mutated[ci][0] ^= 0x01;
        let mutated_root = {
            let response = block_and_blobs_response(slot, &mutated);
            response
                .parse_full_block()
                .unwrap()
                .kzg_commitment_root(BodyForkLayout::Electra)
                .unwrap()
        };
        assert_ne!(
            base_root, mutated_root,
            "mutation of commitment[{ci}] must change the canonical root"
        );
    }
}

/// L-3 (ISSUE-4.3): the full propose_block pipeline with a BlockAndBlobs
/// response that has valid kzg_commitments must succeed (the defense-in-depth
/// check is a warning, not a hard error).
#[tokio::test]
async fn test_l3_propose_block_and_blobs_succeeds_with_matching_commitment_count() {
    let pubkey = test_pubkey();
    let slot = 1000;
    let commitments = [[0xee; 48], [0xff; 48]];

    let response = block_and_blobs_response(slot, &commitments);
    let beacon = MockBeaconClient::from_response(response);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "propose_block with valid BlockAndBlobs must succeed, got: {result:?}");
}

/// L-3 (ISSUE-4.3): a mismatch between commitment count in the body and the
/// number of blob sidecars must only warn (not abort signing).
#[tokio::test]
async fn test_l3_propose_block_and_blobs_warns_on_commitment_count_mismatch() {
    let pubkey = test_pubkey();
    let slot = 2000;

    // Body has 2 commitments but blob_sidecars will have 1 entry (mismatch).
    let two_commits = [[0x11; 48], [0x22; 48]];
    let body = electra_body_with_kzg_commitments_for_test(&two_commits);
    let body_hex = format!("0x{}", hex::encode(&body));

    // Only one sidecar despite two commitments in the body.
    let data = serde_json::json!({
        "block": {
            "slot": slot.to_string(),
            "proposer_index": "42",
            "parent_root": format!("0x{}", hex::encode([0x11u8; 32])),
            "state_root": format!("0x{}", hex::encode([0x22u8; 32])),
            "body": body_hex,
        },
        "blob_sidecars": [
            { "index": "0", "blob": format!("0x{}", hex::encode([0u8; 64])) },
        ],
    });
    let response = ProduceBlockResponse {
        data,
        is_blinded: false,
        consensus_version: "electra".to_string(),
        execution_payload_value: Some("99".to_string()),
        is_ssz: false,
        ssz_bytes: None,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    };

    let beacon = MockBeaconClient::from_response(response);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    // Signing must NOT fail — the count mismatch is a warn, not an error.
    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "commitment count mismatch must not abort signing, got: {result:?}");
}

// GREEN (CQ-3.2): formerly RED test for ISSUE-CQ-3.2 (C3).
//
// Before CQ-3.2, `propose_block` performed no proposer_index validation,
// silently accepting a block with any proposer_index.  After CQ-3.2 the
// unvalidated entry point is deleted; the surviving `propose_block` requires
// `expected_proposer_index` and rejects mismatches before calling the signer.
#[tokio::test]
async fn test_propose_block_rejects_mismatched_proposer_index() {
    let pubkey = test_pubkey();
    let slot = 100;
    // BN returns proposer_index = 99; duty expects validator 42.
    let mut block = test_block(slot);
    block.proposer_index = 99;
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    // propose_block now validates: expected = 42, got = 99 → Err.
    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err(), "expected validation rejection but call succeeded");
    assert!(
        matches!(
            result.unwrap_err(),
            BlockServiceError::ProposerIndexMismatch { expected: 42, got: 99 }
        ),
        "expected ProposerIndexMismatch {{ expected: 42, got: 99 }}"
    );
}
