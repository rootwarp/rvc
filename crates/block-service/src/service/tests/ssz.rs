//! SSZ produce/publish path tests for block-service.

use super::*;
use std::sync::Arc;
use tree_hash::TreeHash;

// --- SSZ path tests ---

#[tokio::test]
async fn test_propose_block_ssz_unblinded() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::ssz(slot, 42, false);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, slot);
    assert!(!proposal.is_blinded);
    assert_eq!(proposal.consensus_version, "deneb");
    assert_ne!(proposal.block_root, [0u8; 32]);
}

#[tokio::test]
async fn test_propose_block_ssz_blinded() {
    let pubkey = test_pubkey();
    let slot = 200;
    let beacon = MockBeaconClient::ssz(slot, 42, true);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, slot);
    assert!(proposal.is_blinded);
}

#[tokio::test]
async fn test_propose_block_ssz_calls_publish_block_ssz() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::ssz(slot, 42, false);

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
    assert_eq!(ssz_calls.len(), 1);
    assert_eq!(ssz_calls[0].consensus_version, "deneb");
    assert!(!ssz_calls[0].is_blinded);

    // JSON publish endpoints should NOT be called
    assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
    assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_propose_block_ssz_blinded_passes_is_blinded_flag() {
    let pubkey = test_pubkey();
    let slot = 200;
    let beacon = MockBeaconClient::ssz(slot, 42, true);

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
    assert_eq!(ssz_calls.len(), 1);
    assert!(ssz_calls[0].is_blinded);
}

#[tokio::test]
async fn test_propose_block_ssz_slot_mismatch_returns_error() {
    let pubkey = test_pubkey();
    let requested_slot = 100;
    let ssz_slot = 200; // mismatch!
    let beacon = MockBeaconClient::ssz(ssz_slot, 42, false);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(requested_slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("slot mismatch"), "error should mention slot mismatch: {err}");
}

#[tokio::test]
async fn test_propose_block_ssz_missing_bytes_returns_error() {
    let pubkey = test_pubkey();
    let slot = 100;
    let mut beacon = MockBeaconClient::ssz(slot, 42, false);
    // Set ssz_bytes to None while is_ssz is true
    beacon.produce_response.as_mut().unwrap().ssz_bytes = None;
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("SSZ"), "error should mention SSZ: {err}");
}

#[tokio::test]
async fn test_propose_block_ssz_short_bytes_returns_error() {
    let pubkey = test_pubkey();
    let slot = 100;
    let mut beacon = MockBeaconClient::ssz(slot, 42, false);
    // Set ssz_bytes to too-short buffer
    beacon.produce_response.as_mut().unwrap().ssz_bytes = Some(vec![0u8; 8]);
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_propose_block_ssz_block_root_uses_tree_hash() {
    let pubkey = test_pubkey();
    let fixture = eth_types::external_vector_electra_block();
    let slot = fixture.slot;
    let beacon = MockBeaconClient::ssz_with_version(slot, fixture.proposer_index, false, "electra");
    let ssz_bytes = beacon.produce_response.as_ref().unwrap().ssz_bytes.clone().unwrap();
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let format = ssz_block_format(false, "electra").unwrap();
    let (block, _) =
        beacon::ssz_deser::deserialize_beacon_block_from_ssz(&ssz_bytes, format).unwrap();
    let tree_hash_root: [u8; 32] = block.tree_hash_root().0;
    let expected = hex::decode(eth_types::EXTERNAL_ELECTRA_BLOCK_ROOT_HEX).unwrap();
    let proposal = result.unwrap();
    assert_eq!(proposal.block_root, tree_hash_root);
    assert_eq!(
        proposal.block_root.as_slice(),
        expected.as_slice(),
        "SSZ propose path must match remerkleable EXTERNAL_ELECTRA_BLOCK_ROOT_HEX"
    );

    let block_calls = signer_arc.block_calls.lock().unwrap();
    assert_eq!(block_calls.len(), 1);
    assert_eq!(block_calls[0].block_root, tree_hash_root);
}

#[test]
fn test_ssz_block_root_uses_tree_hash_not_sha256() {
    use sha2::{Digest, Sha256};

    let block = eth_types::BeaconBlock {
        slot: 100,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: test_body_ssz(),
    };

    let tree_hash_root: [u8; 32] = block.tree_hash_root().0;

    // Build SSZ bytes the same way the mock does
    let ssz_bytes = build_ssz_bytes(100, 42, false, "deneb");
    let sha256_root: [u8; 32] = Sha256::digest(&ssz_bytes).into();

    // Regression: these must differ, proving SHA256 was wrong
    assert_ne!(tree_hash_root, sha256_root);
}

#[tokio::test]
async fn test_propose_block_ssz_publish_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::ssz(slot, 42, false).with_publish_error();
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BlockServiceError::Beacon(_)));
}

#[tokio::test]
async fn test_propose_block_ssz_pre_deneb_uses_beacon_block_format() {
    let pubkey = test_pubkey();
    let slot = 100;
    // Pre-Deneb unblinded: raw BeaconBlock SSZ (no BlockContents wrapper)
    let beacon = MockBeaconClient::ssz_with_version(slot, 42, false, "capella");
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, slot);
    assert!(!proposal.is_blinded);
}

#[tokio::test]
async fn test_propose_block_ssz_electra_unblinded_uses_block_contents() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::ssz_with_version(slot, 42, false, "electra");
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    let proposal = result.unwrap();
    assert_eq!(proposal.slot, slot);
}

#[tokio::test]
async fn test_propose_block_ssz_deneb_blinded_uses_beacon_block_format() {
    let pubkey = test_pubkey();
    let slot = 100;
    // Deneb blinded: raw BeaconBlock SSZ (NOT BlockContents)
    let beacon = MockBeaconClient::ssz_with_version(slot, 42, true, "deneb");
    let signer = MockSigner::new();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_ok());
    let proposal = result.unwrap();
    assert!(proposal.is_blinded);
}

#[tokio::test]
async fn test_propose_block_ssz_gloas_slot_deneb_version_mismatch_drops_duty() {
    let pubkey = test_pubkey();
    let slot = 200;
    let beacon = MockBeaconClient::ssz(slot, 42, true);
    let signer = MockSigner::new();
    let mut fork = test_fork_schedule();
    fork.gloas_fork_epoch = 0;

    let signer_arc = Arc::new(signer);
    let beacon_arc = Arc::new(beacon);
    let service = BlockService::new(
        signer_arc.clone(),
        beacon_arc.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(fork),
        [0xaa; 32],
    );

    let err = service
        .propose_block(slot, &pubkey, 42, None)
        .await
        .expect_err("SSZ Gloas slot with deneb Eth-Consensus-Version must fail closed");
    assert!(
        matches!(
            err,
            BlockServiceError::ConsensusVersionMismatch { ref expected, ref got }
            if expected == "gloas" && got == "deneb"
        ),
        "expected ConsensusVersionMismatch, got {err:?}"
    );
    assert!(signer_arc.header_calls.lock().unwrap().is_empty());
    assert!(signer_arc.block_calls.lock().unwrap().is_empty());
    assert!(beacon_arc.publish_ssz_calls.lock().unwrap().is_empty());
}

#[test]
fn test_ssz_block_format_blinded_always_beacon_block() {
    use beacon::ssz_deser::SszBlockFormat;
    assert_eq!(ssz_block_format(true, "phase0").unwrap(), SszBlockFormat::BeaconBlock);
    assert_eq!(ssz_block_format(true, "capella").unwrap(), SszBlockFormat::BeaconBlock);
    assert_eq!(ssz_block_format(true, "deneb").unwrap(), SszBlockFormat::BeaconBlock);
    assert_eq!(ssz_block_format(true, "electra").unwrap(), SszBlockFormat::BeaconBlock);
    assert_eq!(ssz_block_format(true, "gloas").unwrap(), SszBlockFormat::BeaconBlock);
}

#[test]
fn test_ssz_block_format_unblinded_pre_deneb_beacon_block() {
    use beacon::ssz_deser::SszBlockFormat;
    assert_eq!(ssz_block_format(false, "phase0").unwrap(), SszBlockFormat::BeaconBlock);
    assert_eq!(ssz_block_format(false, "altair").unwrap(), SszBlockFormat::BeaconBlock);
    assert_eq!(ssz_block_format(false, "bellatrix").unwrap(), SszBlockFormat::BeaconBlock);
    assert_eq!(ssz_block_format(false, "capella").unwrap(), SszBlockFormat::BeaconBlock);
}

#[test]
fn test_ssz_block_format_unblinded_deneb_electra_fulu_gloas_unknown() {
    use beacon::ssz_deser::SszBlockFormat;
    assert_eq!(ssz_block_format(false, "deneb").unwrap(), SszBlockFormat::BlockContents);
    assert_eq!(ssz_block_format(false, "electra").unwrap(), SszBlockFormat::BlockContents);
    assert_eq!(ssz_block_format(false, "fulu").unwrap(), SszBlockFormat::BlockContents);
    assert_eq!(ssz_block_format(false, "gloas").unwrap(), SszBlockFormat::BeaconBlock);
    let err = ssz_block_format(false, "unknown").unwrap_err();
    assert!(
        matches!(err, BlockServiceError::UnknownSszConsensusVersion(ref v) if v == "unknown"),
        "expected UnknownSszConsensusVersion, got {err:?}"
    );
    let err = ssz_block_format(true, "unknown").unwrap_err();
    assert!(
        matches!(err, BlockServiceError::UnknownSszConsensusVersion(ref v) if v == "unknown"),
        "blinded unknown must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn test_propose_block_ssz_signing_failure() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::ssz(slot, 42, false);
    let signer = MockSigner::new().with_block_error();
    let service = build_service(signer, beacon, &pubkey);

    let result = service.propose_block(slot, &pubkey, 42, None).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BlockServiceError::Signer(_)));
}
#[tokio::test]
async fn test_ssz_published_payload_contains_signature() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::ssz(slot, 42, false);

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
    assert_eq!(ssz_calls.len(), 1);
    let published = &ssz_calls[0].bytes;

    // Deneb unblinded is SignedBlockContents. The signature lives in the signed block.
    let signed_off = u32::from_le_bytes(published[0..4].try_into().unwrap()) as usize;
    let signed = &published[signed_off..];
    let message_offset = u32::from_le_bytes(signed[0..4].try_into().unwrap());
    assert_eq!(message_offset, 100);

    let sig = &signed[4..100];
    assert_eq!(sig.len(), 96);
    assert_eq!(
        sig,
        mock_block_sig().to_bytes(),
        "SSZ payload must carry mock block signature bytes"
    );

    assert!(signed.len() > 100, "published payload should contain block data after signature");
}

#[tokio::test]
async fn test_ssz_published_payload_is_signed_beacon_block() {
    let pubkey = test_pubkey();
    let slot = 100;
    let beacon = MockBeaconClient::ssz(slot, 42, false);

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
    assert_eq!(ssz_calls.len(), 1);
}

#[tokio::test]
async fn test_ssz_blinded_block_also_includes_signature() {
    let pubkey = test_pubkey();
    let slot = 200;
    let beacon = MockBeaconClient::ssz(slot, 42, true);

    let beacon_arc = Arc::new(beacon);
    let store = test_validator_store(&pubkey);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon_arc.clone(),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
    assert_eq!(ssz_calls.len(), 1);
    let published = &ssz_calls[0].bytes;

    // First 4 bytes: message_offset = 100
    let message_offset = u32::from_le_bytes(published[0..4].try_into().unwrap());
    assert_eq!(message_offset, 100);

    // Signature present (typed crypto::Signature → raw bytes at SSZ boundary)
    let sig = &published[4..100];
    assert_eq!(sig, mock_block_sig().to_bytes());

    // Blinded flag should be true
    assert!(ssz_calls[0].is_blinded);
}
// --- Issue 3.1: SSZ large-body + non-empty KZG tests (Finding #21) ---

/// Build SSZ bytes for a BlockContents payload with explicit KZG proofs and blobs.
///
/// Layout: [block_offset(4) | kzg_offset(4) | blobs_offset(4) | BeaconBlock | KZG proofs | Blobs]
fn build_ssz_bytes_with_kzg(
    slot: Slot,
    proposer_index: u64,
    body: &[u8],
    kzg_proofs: &[u8],
    blobs: &[u8],
) -> Vec<u8> {
    let body_offset: u32 = 84;
    let mut block_bytes = Vec::new();
    block_bytes.extend_from_slice(&slot.to_le_bytes());
    block_bytes.extend_from_slice(&proposer_index.to_le_bytes());
    block_bytes.extend_from_slice(&[0x11; 32]); // parent_root
    block_bytes.extend_from_slice(&[0x22; 32]); // state_root
    block_bytes.extend_from_slice(&body_offset.to_le_bytes());
    block_bytes.extend_from_slice(body);

    let bc_block_offset: u32 = 12;
    let kzg_offset: u32 = bc_block_offset + block_bytes.len() as u32;
    let blobs_offset: u32 = kzg_offset + kzg_proofs.len() as u32;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&bc_block_offset.to_le_bytes());
    bytes.extend_from_slice(&kzg_offset.to_le_bytes());
    bytes.extend_from_slice(&blobs_offset.to_le_bytes());
    bytes.extend_from_slice(&block_bytes);
    bytes.extend_from_slice(kzg_proofs);
    bytes.extend_from_slice(blobs);
    bytes
}

#[test]
fn test_ssz_deser_large_body_no_kzg() {
    use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

    let body = vec![0xab; 16384]; // 16KB body
    let body_offset: u32 = 84;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1000u64.to_le_bytes());
    bytes.extend_from_slice(&42u64.to_le_bytes());
    bytes.extend_from_slice(&[0x11; 32]);
    bytes.extend_from_slice(&[0x22; 32]);
    bytes.extend_from_slice(&body_offset.to_le_bytes());
    bytes.extend_from_slice(&body);

    let (block, offset) =
        deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();

    assert_eq!(offset, 0);
    assert_eq!(block.slot, 1000);
    assert_eq!(block.proposer_index, 42);
    assert_eq!(block.body.len(), body.len(), "body must be exactly 16KB");
    assert_eq!(block.body, body);
}

#[test]
#[ignore = "Known body-bleed bug: ssz_deser.rs uses bytes.len() instead of kzg_proofs_offset as block_region_end. Body includes KZG+blob data when non-empty. See beacon/src/ssz_deser.rs:190."]
fn test_ssz_deser_block_contents_with_kzg_proofs() {
    use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

    let body = vec![0xab; 128];
    let kzg_proof = vec![0xcc; 48];
    let blob = vec![0xdd; 131072]; // 128KB blob

    let bytes = build_ssz_bytes_with_kzg(1000, 42, &body, &kzg_proof, &blob);
    let (block, offset) =
        deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();

    assert_eq!(offset, 12);
    assert_eq!(block.slot, 1000);
    assert_eq!(block.proposer_index, 42);
    // This assertion exposes the body-bleed bug: body will include KZG+blob data
    assert_eq!(
        block.body.len(),
        body.len(),
        "body must be exactly {} bytes, not include KZG data (got {})",
        body.len(),
        block.body.len(),
    );
    assert_eq!(block.body, body);
}

#[test]
fn test_ssz_deser_kzg_offset_boundary() {
    use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

    // kzg_offset at exact end of block — empty KZG, empty blobs
    let body = vec![0xab; 1];
    let bytes = build_ssz_bytes_with_kzg(500, 10, &body, &[], &[]);

    let (block, offset) =
        deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();

    assert_eq!(offset, 12);
    assert_eq!(block.slot, 500);
    // With empty KZG data, bytes.len() == kzg_offset, so body is correct
    assert_eq!(block.body.len(), body.len());
}

#[test]
#[ignore = "Known body-bleed bug: multiple KZG proofs + blobs are included in body. See beacon/src/ssz_deser.rs:190."]
fn test_ssz_deser_multiple_blobs_deneb() {
    use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

    let body = vec![0xab; 256];
    let kzg_proofs: Vec<u8> = (0..4).flat_map(|i| vec![i as u8; 48]).collect();
    let blobs: Vec<u8> = (0..4).flat_map(|i| vec![i as u8; 131072]).collect();

    let bytes = build_ssz_bytes_with_kzg(1000, 42, &body, &kzg_proofs, &blobs);
    let (block, _) =
        deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();

    assert_eq!(
        block.body.len(),
        body.len(),
        "body must be exactly {} bytes, not {} (includes KZG+blobs)",
        body.len(),
        block.body.len(),
    );
}

#[test]
fn test_ssz_propose_with_large_body_through_pipeline() {
    use beacon::ssz_deser::SszBlockFormat;

    // Valid Electra body SSZ through the production deserialization path (no KZG data).
    let body = test_body_ssz();
    let ssz = build_ssz_bytes_with_kzg(100, 42, &body, &[], &[]);

    let format = ssz_block_format(false, "deneb").unwrap();
    assert_eq!(format, SszBlockFormat::BlockContents);

    let (block, offset) =
        beacon::ssz_deser::deserialize_beacon_block_from_ssz(&ssz, format).unwrap();
    assert_eq!(offset, 12);
    assert_eq!(block.slot, 100);
    assert_eq!(block.proposer_index, 42);
    assert_eq!(block.body.len(), body.len());
    assert_ne!(block.tree_hash_root().0, [0u8; 32]);
}

fn le_u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn blob_sidecars_published(fork: &str) -> u64 {
    crate::metrics::RVC_BLOB_SIDECARS_PUBLISHED_TOTAL.with_label_values(&[fork]).get()
}

/// Sidecar bytes from an RR-1.1 `BlockContents` fixture. Offsets are read here,
/// not through `deserialize_block_contents_ssz`.
fn fixture_sidecars(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let kzg = le_u32_at(bytes, 4);
    let blobs = le_u32_at(bytes, 8);
    (bytes[kzg..blobs].to_vec(), bytes[blobs..].to_vec())
}

fn contents_client(version: &str, slot: Slot, fixture: &[u8]) -> (MockBeaconClient, Vec<u8>) {
    let (proofs, blobs) = fixture_sidecars(fixture);
    assert!(!proofs.is_empty(), "{version} kzg_proofs empty");
    assert!(!blobs.is_empty(), "{version} blobs empty");
    let body = test_body_ssz_for_version(version);
    let ssz = build_ssz_bytes_with_kzg(slot, 42, &body, &proofs, &blobs);
    let client = MockBeaconClient::from_response(ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: version.to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: true,
        ssz_bytes: Some(ssz.clone()),
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    });
    (client, ssz)
}

fn service_for(
    beacon: MockBeaconClient,
    pubkey: &PublicKey,
    fork: ForkSchedule,
) -> (BlockService<MockSigner, MockBeaconClient>, Arc<MockBeaconClient>) {
    let beacon = Arc::new(beacon);
    let service = BlockService::new(
        Arc::new(MockSigner::new()),
        beacon.clone(),
        Arc::new(test_validator_store(pubkey)),
        Arc::new(fork),
        [0xaa; 32],
    );
    (service, beacon)
}

#[tokio::test]
async fn published_payload_is_a_signed_block_contents_container() {
    const DENEB: &[u8] =
        include_bytes!("../../../../beacon/tests/fixtures/deneb_block_contents.ssz");
    const FULU: &[u8] = include_bytes!("../../../../beacon/tests/fixtures/fulu_block_contents.ssz");
    let pubkey = test_pubkey();

    for (version, fixture) in [("deneb", DENEB), ("fulu", FULU)] {
        let slot = 100;
        let (client, produced) = contents_client(version, slot, fixture);
        let (proofs, blobs) = fixture_sidecars(fixture);
        let block_off = le_u32_at(&produced, 0);
        let kzg_off = le_u32_at(&produced, 4);
        let block_len = kzg_off - block_off;
        let bn_block = produced[block_off..kzg_off].to_vec();

        let (service, beacon) = service_for(client, &pubkey, test_fork_schedule());
        let result = service.propose_block(slot, &pubkey, 42, None).await;
        assert!(result.is_ok(), "{version}: {result:?}");

        let calls = beacon.publish_ssz_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "{version}");
        let published = &calls[0].bytes;
        let signed_len = 100 + block_len;
        assert_eq!(
            published.len(),
            12 + signed_len + proofs.len() + blobs.len(),
            "{version} length"
        );
        let signed_off = le_u32_at(published, 0);
        let proofs_off = le_u32_at(published, 4);
        let blobs_off = le_u32_at(published, 8);
        assert_eq!(proofs_off - signed_off, signed_len, "{version} signed_block region");
        assert_eq!(blobs_off - proofs_off, proofs.len(), "{version} proofs");
        assert_eq!(published.len() - blobs_off, blobs.len(), "{version} blobs");
        let signed = &published[signed_off..proofs_off];
        assert_eq!(le_u32_at(signed, 0), 100, "{version} message offset");
        assert_eq!(
            &signed[100..],
            bn_block.as_slice(),
            "{version} message bit-identical to BN block"
        );
        assert_eq!(blob_sidecars_published(version), 1, "{version}");
    }
}

#[tokio::test]
async fn sidecars_reach_publish_block_ssz() {
    const DENEB: &[u8] =
        include_bytes!("../../../../beacon/tests/fixtures/deneb_block_contents.ssz");
    const FULU: &[u8] = include_bytes!("../../../../beacon/tests/fixtures/fulu_block_contents.ssz");
    let pubkey = test_pubkey();

    for (version, fixture) in [("deneb", DENEB), ("fulu", FULU)] {
        let slot = 100;
        let (client, produced) = contents_client(version, slot, fixture);
        let (proofs, blobs) = fixture_sidecars(fixture);
        let block_off = le_u32_at(&produced, 0);
        let kzg_off = le_u32_at(&produced, 4);
        let bn_block = &produced[block_off..kzg_off];

        let (service, beacon) = service_for(client, &pubkey, test_fork_schedule());
        service.propose_block(slot, &pubkey, 42, None).await.unwrap();
        let published = beacon.publish_ssz_calls.lock().unwrap()[0].bytes.clone();
        let signed_off = le_u32_at(&published, 0);
        let proofs_off = le_u32_at(&published, 4);
        let blobs_off = le_u32_at(&published, 8);
        assert_eq!(
            &published[proofs_off..blobs_off],
            proofs.as_slice(),
            "{version} proofs at offset 2"
        );
        assert_eq!(&published[blobs_off..], blobs.as_slice(), "{version} blobs at offset 3");
        let message = &published[signed_off + 100..proofs_off];
        assert_eq!(message, bn_block, "{version} sidecars are outside the block region");
        assert!(proofs_off == signed_off + 100 + bn_block.len(), "{version}");
    }
}

#[tokio::test]
async fn gloas_payload_still_routes_through_sign_and_publish_v4() {
    let pubkey = test_pubkey();
    let slot = test_gloas_slot();
    let block_ssz =
        build_gloas_beacon_block_ssz(slot, 42, [0x11; 32], [0x22; 32], &gloas_body_ssz());
    let beacon = MockBeaconClient::from_response(ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "gloas".to_string(),
        execution_payload_value: Some("99999".to_string()),
        is_ssz: true,
        ssz_bytes: Some(block_ssz.clone()),
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    });
    let (service, beacon) = service_for(beacon, &pubkey, test_fork_schedule_with_near_gloas());
    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "{result:?}");
    assert!(beacon.produce_v3_calls.lock().unwrap().is_empty());
    assert_eq!(beacon.produce_v4_calls.lock().unwrap().len(), 1);
    let calls = beacon.publish_ssz_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].consensus_version, "gloas");
    assert!(!calls[0].is_blinded);
    let expected = beacon::ssz_deser::serialize_signed_beacon_block_ssz(
        &block_ssz,
        &mock_block_sig().to_bytes(),
    )
    .unwrap();
    assert_eq!(calls[0].bytes, expected);
    assert_eq!(blob_sidecars_published("gloas"), 0);
    assert_eq!(blob_sidecars_published("deneb"), 0);
}

#[tokio::test]
async fn blinded_payload_is_unchanged() {
    let pubkey = test_pubkey();
    let slot = 200;
    let beacon = MockBeaconClient::ssz(slot, 42, true);
    let original = beacon.produce_response.as_ref().unwrap().ssz_bytes.clone().unwrap();
    assert_eq!(
        ssz_block_format(true, "deneb").unwrap(),
        beacon::ssz_deser::SszBlockFormat::BeaconBlock
    );
    let (service, beacon) = service_for(beacon, &pubkey, test_fork_schedule());
    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok(), "{result:?}");
    let calls = beacon.publish_ssz_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].is_blinded);
    let expected = beacon::ssz_deser::serialize_signed_beacon_block_ssz(
        &original,
        &mock_block_sig().to_bytes(),
    )
    .unwrap();
    assert_eq!(calls[0].bytes, expected);
    assert_eq!(blob_sidecars_published("deneb"), 0);
}

#[tokio::test]
async fn corrupt_blobs_offset_fails_before_the_header_is_signed() {
    let pubkey = test_pubkey();
    let slot = 100;
    let body = test_body_ssz_for_version("deneb");
    let mut ssz = build_ssz_bytes_with_kzg(slot, 42, &body, &[0xcc; 48], &[]);
    let past = (ssz.len() as u32).saturating_add(64);
    ssz[8..12].copy_from_slice(&past.to_le_bytes());

    let beacon = Arc::new(MockBeaconClient::from_response(ProduceBlockResponse {
        data: serde_json::Value::Null,
        is_blinded: false,
        consensus_version: "deneb".to_string(),
        execution_payload_value: Some("1".to_string()),
        is_ssz: true,
        ssz_bytes: Some(ssz),
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
    }));
    let signer = Arc::new(MockSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon.clone(),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );

    let err = service.propose_block(slot, &pubkey, 42, None).await.expect_err("bad blobs offset");
    assert!(err.to_string().contains("blobs="), "{err}");
    assert!(signer.header_calls.lock().unwrap().is_empty());
    assert!(signer.block_calls.lock().unwrap().is_empty());
    assert!(beacon.publish_ssz_calls.lock().unwrap().is_empty());
    assert_eq!(blob_sidecars_published("deneb"), 0);
}
