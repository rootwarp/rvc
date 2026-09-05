//! Shared mocks, fixtures, and capture helpers for block-service tests.

use super::*;
use async_trait::async_trait;
use eth_types::{BeaconBlock, BlindedBeaconBlock, SignedBeaconBlock, SignedBlindedBeaconBlock};
use signer::SignerError;
use std::sync::{Arc, Mutex};
use validator_store::ValidatorStore;

// --- Captured call structs ---

#[derive(Debug, Clone)]
pub(crate) struct CapturedProduceCall {
    pub(crate) slot: Slot,
    pub(crate) randao_reveal: String,
    pub(crate) graffiti: Option<String>,
    pub(crate) builder_boost_factor: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct CapturedPublishCall {
    pub(crate) consensus_version: String,
    pub(crate) slot: Slot,
    pub(crate) proposer_index: u64,
    pub(crate) signature_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct CapturedSignBlockCall {
    pub(crate) block_root: Root,
    pub(crate) slot: Slot,
    pub(crate) pubkey: PublicKey,
    pub(crate) fork_schedule: ForkSchedule,
    pub(crate) genesis_validators_root: Root,
}

// --- Mock Signer ---

pub(crate) struct MockSigner {
    pub(crate) fail_randao: bool,
    pub(crate) fail_block: bool,
    pub(crate) randao_calls: Mutex<Vec<u64>>,
    pub(crate) block_calls: Mutex<Vec<CapturedSignBlockCall>>,
}

impl MockSigner {
    pub(crate) fn new() -> Self {
        Self {
            fail_randao: false,
            fail_block: false,
            randao_calls: Mutex::new(Vec::new()),
            block_calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn with_randao_error(mut self) -> Self {
        self.fail_randao = true;
        self
    }

    pub(crate) fn with_block_error(mut self) -> Self {
        self.fail_block = true;
        self
    }

    pub(crate) fn assert_last_sign_block_domain(
        &self,
        expected_fork: &ForkSchedule,
        expected_gvr: &Root,
    ) {
        let calls = self.block_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no sign_block calls captured");
        let last = calls.last().unwrap();
        assert_eq!(last.fork_schedule, *expected_fork, "sign_block fork_schedule mismatch");
        assert_eq!(
            last.genesis_validators_root, *expected_gvr,
            "sign_block genesis_validators_root mismatch"
        );
    }
}

/// Valid-curve mock BLS signature (bytes not stable across calls).
///
/// Uses a fresh key each call — fine when tests only need a non-empty
/// valid `Signature`. Prefer [`mock_block_sig`] / [`mock_randao_sig`] when
/// assertions compare signature bytes across a test.
pub(crate) fn mock_sig(tag: &[u8]) -> crypto::Signature {
    crypto::SecretKey::generate().sign(tag)
}

/// Fixed signatures so SSZ assertions can compare bytes across a test.
pub(crate) fn mock_block_sig() -> crypto::Signature {
    // Use a real key once; bytes are whatever blst produces (not 0xbb fill).
    thread_local! {
        static SIG: crypto::Signature = crypto::SecretKey::generate().sign(b"mock-block");
    }
    SIG.with(|s| s.clone())
}

pub(crate) fn mock_randao_sig() -> crypto::Signature {
    thread_local! {
        static SIG: crypto::Signature = crypto::SecretKey::generate().sign(b"mock-randao");
    }
    SIG.with(|s| s.clone())
}

#[async_trait]
impl ValidatorSigner for MockSigner {
    async fn sign_attestation(
        &self,
        _data: &eth_types::AttestationData,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"attestation"))
    }

    async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        self.block_calls.lock().unwrap().push(CapturedSignBlockCall {
            block_root: *block_root,
            slot,
            pubkey: pubkey.clone(),
            fork_schedule: fork_schedule.clone(),
            genesis_validators_root: *genesis_validators_root,
        });
        if self.fail_block {
            Err(SignerError::KeyNotFound("test".to_string()))
        } else {
            Ok(mock_block_sig())
        }
    }

    async fn sign_randao_reveal(
        &self,
        epoch: u64,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        self.randao_calls.lock().unwrap().push(epoch);
        if self.fail_randao {
            Err(SignerError::KeyNotFound("test".to_string()))
        } else {
            Ok(mock_randao_sig())
        }
    }

    async fn sign_sync_committee_message(
        &self,
        _beacon_block_root: &Root,
        _slot: Slot,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"sync-msg"))
    }

    async fn sign_selection_proof(
        &self,
        _slot: Slot,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"selection"))
    }

    async fn sign_aggregate_and_proof(
        &self,
        _aggregate_and_proof: &eth_types::AggregateAndProof,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"aggregate"))
    }

    async fn sign_electra_aggregate_and_proof(
        &self,
        _aggregate_and_proof: &eth_types::ElectraAggregateAndProof,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"electra-aggregate"))
    }

    async fn sign_voluntary_exit(
        &self,
        _voluntary_exit: &eth_types::VoluntaryExit,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"voluntary-exit"))
    }

    async fn sign_builder_registration(
        &self,
        _registration: &eth_types::ValidatorRegistrationV1,
        _pubkey: &PublicKey,
        _fork_version: [u8; 4],
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"builder-reg"))
    }

    async fn sign_sync_committee_selection_proof(
        &self,
        _slot: Slot,
        _subcommittee_index: u64,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"sync-selection"))
    }

    async fn sign_contribution_and_proof(
        &self,
        _contribution_and_proof: &eth_types::ContributionAndProof,
        _pubkey: &PublicKey,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<crypto::Signature, SignerError> {
        Ok(mock_sig(b"contribution"))
    }
}

// --- Mock Beacon Client ---

pub(crate) struct MockBeaconClient {
    pub(crate) produce_response: Option<ProduceBlockResponse>,
    pub(crate) fail_produce: bool,
    pub(crate) fail_publish: bool,
    pub(crate) publish_calls: Mutex<Vec<String>>,
    pub(crate) publish_blinded_calls: Mutex<Vec<String>>,
    pub(crate) publish_ssz_calls: Mutex<Vec<(Vec<u8>, String, bool)>>,
    pub(crate) produce_full_calls: Mutex<Vec<CapturedProduceCall>>,
    pub(crate) publish_full_calls: Mutex<Vec<CapturedPublishCall>>,
    pub(crate) publish_blinded_full_calls: Mutex<Vec<CapturedPublishCall>>,
}

impl MockBeaconClient {
    pub(crate) fn unblinded(block: BeaconBlock) -> Self {
        let data = serde_json::to_value(&block).unwrap();
        Self {
            produce_response: Some(ProduceBlockResponse {
                data,
                is_blinded: false,
                consensus_version: "deneb".to_string(),
                execution_payload_value: Some("12345".to_string()),
                is_ssz: false,
                ssz_bytes: None,
            }),
            fail_produce: false,
            fail_publish: false,
            publish_calls: Mutex::new(Vec::new()),
            publish_blinded_calls: Mutex::new(Vec::new()),
            publish_ssz_calls: Mutex::new(Vec::new()),
            produce_full_calls: Mutex::new(Vec::new()),
            publish_full_calls: Mutex::new(Vec::new()),
            publish_blinded_full_calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn blinded(block: BlindedBeaconBlock) -> Self {
        let data = serde_json::to_value(&block).unwrap();
        Self {
            produce_response: Some(ProduceBlockResponse {
                data,
                is_blinded: true,
                consensus_version: "deneb".to_string(),
                execution_payload_value: None,
                is_ssz: false,
                ssz_bytes: None,
            }),
            fail_produce: false,
            fail_publish: false,
            publish_calls: Mutex::new(Vec::new()),
            publish_blinded_calls: Mutex::new(Vec::new()),
            publish_ssz_calls: Mutex::new(Vec::new()),
            produce_full_calls: Mutex::new(Vec::new()),
            publish_full_calls: Mutex::new(Vec::new()),
            publish_blinded_full_calls: Mutex::new(Vec::new()),
        }
    }

    /// Create an SSZ mock response.
    ///
    /// - Blinded → raw `BeaconBlock` layout (slot at offset 0).
    /// - Unblinded (deneb) → `BlockContents` layout (3 × 4-byte offsets, then block).
    pub(crate) fn ssz(slot: Slot, proposer_index: u64, is_blinded: bool) -> Self {
        Self::ssz_with_version(slot, proposer_index, is_blinded, "deneb")
    }

    pub(crate) fn ssz_with_version(
        slot: Slot,
        proposer_index: u64,
        is_blinded: bool,
        consensus_version: &str,
    ) -> Self {
        let ssz_bytes = build_ssz_bytes(slot, proposer_index, is_blinded, consensus_version);
        Self {
            produce_response: Some(ProduceBlockResponse {
                data: serde_json::Value::Null,
                is_blinded,
                consensus_version: consensus_version.to_string(),
                execution_payload_value: Some("99999".to_string()),
                is_ssz: true,
                ssz_bytes: Some(ssz_bytes),
            }),
            fail_produce: false,
            fail_publish: false,
            publish_calls: Mutex::new(Vec::new()),
            publish_blinded_calls: Mutex::new(Vec::new()),
            publish_ssz_calls: Mutex::new(Vec::new()),
            produce_full_calls: Mutex::new(Vec::new()),
            publish_full_calls: Mutex::new(Vec::new()),
            publish_blinded_full_calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn with_produce_error(mut self) -> Self {
        self.fail_produce = true;
        self
    }

    pub(crate) fn with_publish_error(mut self) -> Self {
        self.fail_publish = true;
        self
    }

    pub(crate) fn from_response(response: ProduceBlockResponse) -> Self {
        Self {
            produce_response: Some(response),
            fail_produce: false,
            fail_publish: false,
            publish_calls: Mutex::new(Vec::new()),
            publish_blinded_calls: Mutex::new(Vec::new()),
            publish_ssz_calls: Mutex::new(Vec::new()),
            produce_full_calls: Mutex::new(Vec::new()),
            publish_full_calls: Mutex::new(Vec::new()),
            publish_blinded_full_calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn last_produce_call(&self) -> CapturedProduceCall {
        let calls = self.produce_full_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no produce_block_v3 calls captured");
        calls.last().unwrap().clone()
    }

    pub(crate) fn assert_last_produce_slot(&self, expected_slot: Slot) {
        let calls = self.produce_full_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no produce_block_v3 calls captured");
        let last = calls.last().unwrap();
        assert_eq!(
            last.slot, expected_slot,
            "produce_block_v3 slot mismatch: expected {expected_slot}, got {}",
            last.slot
        );
    }

    pub(crate) fn assert_last_published_block(&self, expected_slot: Slot, expected_proposer: u64) {
        let calls = self.publish_full_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no publish_block calls captured");
        let last = calls.last().unwrap();
        assert_eq!(
            last.slot, expected_slot,
            "published block slot mismatch: expected {expected_slot}, got {}",
            last.slot
        );
        assert_eq!(
            last.proposer_index, expected_proposer,
            "published block proposer_index mismatch: expected {expected_proposer}, got {}",
            last.proposer_index
        );
        assert!(!last.signature_bytes.is_empty(), "published block signature must not be empty");
    }

    pub(crate) fn assert_last_published_blinded_block(
        &self,
        expected_slot: Slot,
        expected_proposer: u64,
    ) {
        let calls = self.publish_blinded_full_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no publish_blinded_block calls captured");
        let last = calls.last().unwrap();
        assert_eq!(
            last.slot, expected_slot,
            "published blinded block slot mismatch: expected {expected_slot}, got {}",
            last.slot
        );
        assert_eq!(
            last.proposer_index, expected_proposer,
            "published blinded block proposer_index mismatch: expected {expected_proposer}, got {}",
            last.proposer_index
        );
        assert!(
            !last.signature_bytes.is_empty(),
            "published blinded block signature must not be empty"
        );
    }
}

#[async_trait]
impl BeaconBlockClient for MockBeaconClient {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        self.produce_full_calls.lock().unwrap().push(CapturedProduceCall {
            slot,
            randao_reveal: randao_reveal.to_string(),
            graffiti: graffiti.map(|s| s.to_string()),
            builder_boost_factor,
        });
        if self.fail_produce {
            return Err(BlockServiceError::Beacon("beacon down".to_string()));
        }
        Ok(self.produce_response.clone().unwrap())
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.publish_calls.lock().unwrap().push(consensus_version.to_string());
        self.publish_full_calls.lock().unwrap().push(CapturedPublishCall {
            consensus_version: consensus_version.to_string(),
            slot: signed_block.message.slot,
            proposer_index: signed_block.message.proposer_index,
            signature_bytes: signed_block.signature.clone(),
        });
        if self.fail_publish {
            return Err(BlockServiceError::Beacon("publish failed".to_string()));
        }
        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.publish_blinded_calls.lock().unwrap().push(consensus_version.to_string());
        self.publish_blinded_full_calls.lock().unwrap().push(CapturedPublishCall {
            consensus_version: consensus_version.to_string(),
            slot: signed_block.message.slot,
            proposer_index: signed_block.message.proposer_index,
            signature_bytes: signed_block.signature.clone(),
        });
        if self.fail_publish {
            return Err(BlockServiceError::Beacon("publish failed".to_string()));
        }
        Ok(())
    }

    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BlockServiceError> {
        self.publish_ssz_calls.lock().unwrap().push((
            ssz_bytes.to_vec(),
            consensus_version.to_string(),
            is_blinded,
        ));
        if self.fail_publish {
            return Err(BlockServiceError::Beacon("publish failed".to_string()));
        }
        Ok(())
    }
}
// --- Helpers ---

pub(crate) fn test_fork_schedule() -> ForkSchedule {
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
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [7, 0, 0, 0],
    }
}

pub(crate) fn test_body_ssz() -> Vec<u8> {
    eth_types::external_vector_electra_body().as_ssz_bytes()
}

/// Full body SSZ matching `consensus_version` (typed Deneb vs Electra).
///
/// Required so layout-specific accessors (e.g. blob KZG extract) decode the
/// same schema the BN advertised.
pub(crate) fn test_body_ssz_for_version(consensus_version: &str) -> Vec<u8> {
    match consensus_version {
        "electra" | "fulu" => eth_types::external_vector_electra_body().as_ssz_bytes(),
        _ => eth_types::external_vector_deneb_body().as_ssz_bytes(),
    }
}

pub(crate) fn test_blinded_body_ssz() -> Vec<u8> {
    // Distinct graffiti so full vs blinded roots differ when headers match.
    let mut body = eth_types::external_vector_blinded_electra_body();
    body.graffiti = [0xbe; 32];
    body.as_ssz_bytes()
}

pub(crate) fn test_blinded_body_ssz_for_version(consensus_version: &str) -> Vec<u8> {
    match consensus_version {
        "electra" | "fulu" => {
            let mut body = eth_types::external_vector_blinded_electra_body();
            body.graffiti = [0xbe; 32];
            body.as_ssz_bytes()
        }
        _ => {
            let mut body = eth_types::external_vector_blinded_deneb_body();
            body.graffiti = [0xbe; 32];
            body.as_ssz_bytes()
        }
    }
}

pub(crate) fn test_block(slot: Slot) -> BeaconBlock {
    BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body: test_body_ssz(),
    }
}

pub(crate) fn test_blinded_block(slot: Slot) -> BlindedBeaconBlock {
    BlindedBeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [3u8; 32],
        state_root: [4u8; 32],
        body: test_blinded_body_ssz(),
    }
}

pub(crate) fn test_pubkey() -> PublicKey {
    let secret = crypto::SecretKey::generate();
    secret.public_key()
}

pub(crate) fn test_validator_store(pubkey: &PublicKey) -> ValidatorStore {
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let pk_bytes = pubkey.to_bytes();
    let mut config = validator_store::ValidatorConfig::new(pk_bytes);
    config.builder_boost_factor = 150;
    let mut graffiti = [0u8; 32];
    graffiti[..5].copy_from_slice(b"hello");
    config.graffiti = Some(graffiti);
    store.add_validator(config);
    store
}

pub(crate) fn build_service(
    signer: MockSigner,
    beacon: MockBeaconClient,
    pubkey: &PublicKey,
) -> BlockService<MockSigner, MockBeaconClient> {
    let store = test_validator_store(pubkey);
    BlockService::new(
        Arc::new(signer),
        Arc::new(beacon),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    )
}

pub(crate) fn build_service_with_mode(
    beacon: MockBeaconClient,
    pubkey: &PublicKey,
    circuit_breaker: Arc<CircuitBreakerState>,
) -> BlockService<MockSigner, MockBeaconClient> {
    let store = test_validator_store(pubkey);
    BlockService::with_circuit_breaker(
        Arc::new(MockSigner::new()),
        Arc::new(beacon),
        Arc::new(store),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
        circuit_breaker,
    )
}

/// Build synthetic SSZ bytes matching the expected wire format.
///
/// Body is a valid typed container for `consensus_version` (Deneb or Electra)
/// so `compute_block_root` and layout-specific KZG extract can decode it.
pub(crate) fn build_ssz_bytes(
    slot: Slot,
    proposer_index: u64,
    is_blinded: bool,
    consensus_version: &str,
) -> Vec<u8> {
    let use_block_contents =
        !is_blinded && matches!(consensus_version, "deneb" | "electra" | "fulu");
    let body = if is_blinded {
        test_blinded_body_ssz_for_version(consensus_version)
    } else {
        test_body_ssz_for_version(consensus_version)
    };
    let body_offset: u32 = 84; // fixed portion size

    let mut block_bytes = Vec::new();
    block_bytes.extend_from_slice(&slot.to_le_bytes()); // 8 bytes
    block_bytes.extend_from_slice(&proposer_index.to_le_bytes()); // 8 bytes
    block_bytes.extend_from_slice(&[0x11; 32]); // parent_root
    block_bytes.extend_from_slice(&[0x22; 32]); // state_root
    block_bytes.extend_from_slice(&body_offset.to_le_bytes()); // 4 bytes
    block_bytes.extend_from_slice(&body); // body bytes

    let mut bytes = Vec::new();
    if use_block_contents {
        // BlockContents: 3 × 4-byte offsets, then BeaconBlock at offset 12
        let bc_block_offset: u32 = 12;
        let kzg_offset: u32 = 12 + block_bytes.len() as u32;
        let blobs_offset: u32 = kzg_offset;
        bytes.extend_from_slice(&bc_block_offset.to_le_bytes());
        bytes.extend_from_slice(&kzg_offset.to_le_bytes());
        bytes.extend_from_slice(&blobs_offset.to_le_bytes());
    }
    bytes.extend_from_slice(&block_bytes);
    bytes
}

// --- CapturedCall infrastructure tests ---

#[tokio::test]
pub(crate) async fn test_produce_call_captures_slot_and_args() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    beacon_arc.assert_last_produce_slot(slot);
    let calls = beacon_arc.produce_full_calls.lock().unwrap();
    assert!(calls[0].randao_reveal.starts_with("0x"));
    assert!(calls[0].graffiti.is_some());
    assert_eq!(calls[0].builder_boost_factor, Some(150));
}

#[tokio::test]
pub(crate) async fn test_publish_call_captures_block_fields() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    beacon_arc.assert_last_published_block(slot, 42);
    let calls = beacon_arc.publish_full_calls.lock().unwrap();
    assert_eq!(calls[0].consensus_version, "deneb");
    assert_eq!(calls[0].signature_bytes, mock_block_sig().to_bytes().to_vec());
}

#[tokio::test]
pub(crate) async fn test_publish_blinded_call_captures_block_fields() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block);

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

    beacon_arc.assert_last_published_blinded_block(slot, 42);
    let calls = beacon_arc.publish_blinded_full_calls.lock().unwrap();
    assert_eq!(calls[0].consensus_version, "deneb");
    assert_eq!(calls[0].signature_bytes, mock_block_sig().to_bytes().to_vec());
}

#[tokio::test]
pub(crate) async fn test_sign_block_captures_fork_schedule_and_genesis_root() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
    let beacon = MockBeaconClient::unblinded(block);
    let signer = MockSigner::new();

    let signer_arc = Arc::new(signer);
    let fork = test_fork_schedule();
    let gvr: Root = [0xaa; 32];
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

    signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    let calls = signer_arc.block_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].slot, slot);
    assert_eq!(calls[0].pubkey, pubkey);
}

// --- Assertion helper tests ---

#[tokio::test]
pub(crate) async fn test_assert_last_produce_slot_passes_on_correct_slot() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    beacon_arc.assert_last_produce_slot(slot);
}

#[tokio::test]
#[should_panic(expected = "produce_block_v3 slot mismatch")]
pub(crate) async fn test_assert_last_produce_slot_fails_on_wrong_slot() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    // This should panic: production code sent slot=100, we assert slot+1=101
    beacon_arc.assert_last_produce_slot(slot + 1);
}

#[tokio::test]
pub(crate) async fn test_assert_last_published_block_passes_on_correct_fields() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    beacon_arc.assert_last_published_block(slot, 42);
}

#[tokio::test]
#[should_panic(expected = "published block slot mismatch")]
pub(crate) async fn test_assert_last_published_block_fails_on_wrong_slot() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    beacon_arc.assert_last_published_block(slot + 1, 42);
}

#[tokio::test]
#[should_panic(expected = "published block proposer_index mismatch")]
pub(crate) async fn test_assert_last_published_block_fails_on_wrong_proposer() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    beacon_arc.assert_last_published_block(slot, 99);
}

#[tokio::test]
pub(crate) async fn test_assert_last_published_block_checks_signature() {
    let pubkey = test_pubkey();
    let slot = 100;
    let block = test_block(slot);
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

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    // Verify signature is the mock block signature at the wire boundary
    let calls = beacon_arc.publish_full_calls.lock().unwrap();
    assert!(!calls[0].signature_bytes.is_empty(), "signature must be non-empty");
    assert_eq!(calls[0].signature_bytes, mock_block_sig().to_bytes().to_vec());
}

#[tokio::test]
pub(crate) async fn test_assert_last_published_blinded_block_passes() {
    let pubkey = test_pubkey();
    let slot = 200;
    let block = test_blinded_block(slot);
    let beacon = MockBeaconClient::blinded(block);

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

    beacon_arc.assert_last_published_blinded_block(slot, 42);
}

#[tokio::test]
pub(crate) async fn test_assert_last_sign_block_domain_passes_on_correct_values() {
    let pubkey = test_pubkey();
    let slot = 100;
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

    signer_arc.assert_last_sign_block_domain(&fork, &gvr);
}

#[tokio::test]
#[should_panic(expected = "sign_block fork_schedule mismatch")]
pub(crate) async fn test_assert_last_sign_block_domain_fails_on_wrong_fork() {
    let pubkey = test_pubkey();
    let slot = 100;
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
        Arc::new(fork),
        gvr,
    );

    let result = service.propose_block(slot, &pubkey, 42, None).await;
    assert!(result.is_ok());

    let mut wrong_fork = test_fork_schedule();
    wrong_fork.altair_fork_epoch = 999;
    signer_arc.assert_last_sign_block_domain(&wrong_fork, &gvr);
}

#[tokio::test]
#[should_panic(expected = "sign_block genesis_validators_root mismatch")]
pub(crate) async fn test_assert_last_sign_block_domain_fails_on_wrong_gvr() {
    let pubkey = test_pubkey();
    let slot = 100;
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

    let wrong_gvr: Root = [0xbb; 32];
    signer_arc.assert_last_sign_block_domain(&fork, &wrong_gvr);
}
