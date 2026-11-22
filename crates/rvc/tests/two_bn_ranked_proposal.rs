//! Two beacon nodes, one proposal.
//!
//! A higher-value block on root(N-3) is dropped by BnManager before the
//! candidate walk. The block on an accepted parent is what gets signed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use beacon::HEADER_ETH_CONSENSUS_BLOCK_VALUE;
use block_service::{BlockService, BlockServiceError, ExpectedParents};
use bn_manager::{BnManager, BnManagerConfig};
use crypto::{PublicKey, SecretKey, Signature};
use eth_types::{
    encode_blinded_beacon_block_ssz, AggregateAndProof, AttestationData, BlindedBeaconBlock,
    ContributionAndProof, ElectraAggregateAndProof, Epoch, ForkSchedule, PayloadAttestationData,
    Root, Slot, ValidatorRegistrationV1, VoluntaryExit,
};
use rvc::beacon_adapter::BeaconBlockAdapter;
use signer::{BeaconBlockHeaderFields, SignerError, StubValidatorSigner, ValidatorSigner};
use validator_store::{BlockSelectionMode, ValidatorConfig, ValidatorStore};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SLOT: u64 = 3_000_000;
const PROPOSER: u64 = 42;
const ROOT_N1: Root = [0x11; 32];
const ROOT_N2: Root = [0x22; 32];
const ROOT_N3: Root = [0x33; 32];
const VALUE_A: &str = "70000000000000000";
const VALUE_B: &str = "50000000000000000";
/// Signed blinded SSZ is `[u32 offset = 100][96-byte signature][block]`.
/// `parent_root` is at byte 16 of the block.
const PARENT_OFFSET: usize = 100 + 16;

struct CountingSigner {
    inner: StubValidatorSigner,
    header_signs: AtomicUsize,
}

impl CountingSigner {
    fn new() -> Self {
        Self { inner: StubValidatorSigner::new(), header_signs: AtomicUsize::new(0) }
    }

    fn header_signs(&self) -> usize {
        self.header_signs.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ValidatorSigner for CountingSigner {
    async fn sign_attestation(
        &self,
        data: &AttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner.sign_attestation(data, pubkey, fork_schedule, genesis_validators_root).await
    }

    async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_block(block_root, slot, pubkey, fork_schedule, genesis_validators_root)
            .await
    }

    async fn sign_block_header(
        &self,
        header: &BeaconBlockHeaderFields,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.header_signs.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_block_header(header, pubkey, fork_schedule, genesis_validators_root).await
    }

    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner.sign_randao_reveal(epoch, pubkey, fork_schedule, genesis_validators_root).await
    }

    async fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_sync_committee_message(
                beacon_block_root,
                slot,
                pubkey,
                fork_schedule,
                genesis_validators_root,
            )
            .await
    }

    async fn sign_selection_proof(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner.sign_selection_proof(slot, pubkey, fork_schedule, genesis_validators_root).await
    }

    async fn sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_aggregate_and_proof(
                aggregate_and_proof,
                pubkey,
                fork_schedule,
                genesis_validators_root,
            )
            .await
    }

    async fn sign_electra_aggregate_and_proof(
        &self,
        aggregate_and_proof: &ElectraAggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_electra_aggregate_and_proof(
                aggregate_and_proof,
                pubkey,
                fork_schedule,
                genesis_validators_root,
            )
            .await
    }

    async fn sign_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_voluntary_exit(voluntary_exit, pubkey, fork_schedule, genesis_validators_root)
            .await
    }

    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Signature, SignerError> {
        self.inner.sign_builder_registration(registration, pubkey, fork_version).await
    }

    async fn sign_sync_committee_selection_proof(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_sync_committee_selection_proof(
                slot,
                subcommittee_index,
                pubkey,
                fork_schedule,
                genesis_validators_root,
            )
            .await
    }

    async fn sign_contribution_and_proof(
        &self,
        contribution_and_proof: &ContributionAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_contribution_and_proof(
                contribution_and_proof,
                pubkey,
                fork_schedule,
                genesis_validators_root,
            )
            .await
    }

    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_payload_attestation(data, pubkey, fork_schedule, genesis_validators_root)
            .await
    }

    async fn sign_execution_payload_envelope_root(
        &self,
        object_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_execution_payload_envelope_root(
                object_root,
                slot,
                pubkey,
                fork_schedule,
                genesis_validators_root,
            )
            .await
    }

    async fn sign_aggregate_and_proof_root(
        &self,
        object_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        self.inner
            .sign_aggregate_and_proof_root(
                object_root,
                slot,
                pubkey,
                fork_schedule,
                genesis_validators_root,
            )
            .await
    }
}

fn deneb_schedule() -> ForkSchedule {
    let mut schedule = ForkSchedule::unscheduled_gloas();
    schedule.electra_fork_epoch = u64::MAX;
    schedule.fulu_fork_epoch = u64::MAX;
    schedule
}

fn blinded_on(parent: Root) -> Vec<u8> {
    blinded_with(parent, [0x22; 32])
}

fn blinded_with(parent: Root, state: Root) -> Vec<u8> {
    let mut block: BlindedBeaconBlock = eth_types::external_vector_deneb_blinded_block();
    block.slot = SLOT;
    block.proposer_index = PROPOSER;
    block.parent_root = parent;
    block.state_root = state;
    encode_blinded_beacon_block_ssz(&block, 0)
}

/// Unblinded Deneb `BlockContents`: 3×u32 offsets, then the beacon block, empty sidecars.
fn local_on(parent: Root, state: Root) -> Vec<u8> {
    let mut block = eth_types::external_vector_deneb_block();
    block.slot = SLOT;
    block.proposer_index = PROPOSER;
    block.parent_root = parent;
    block.state_root = state;
    let block_bytes = eth_types::encode_beacon_block_ssz(&block, 0);
    let block_off: u32 = 12;
    let tail = block_off + block_bytes.len() as u32;
    let mut bytes = Vec::with_capacity(12 + block_bytes.len());
    bytes.extend_from_slice(&block_off.to_le_bytes());
    bytes.extend_from_slice(&tail.to_le_bytes());
    bytes.extend_from_slice(&tail.to_le_bytes());
    bytes.extend_from_slice(&block_bytes);
    bytes
}

fn produce_local(bytes: Vec<u8>, execution_value: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Content-Type", "application/octet-stream")
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Execution-Payload-Value", execution_value)
        .insert_header(HEADER_ETH_CONSENSUS_BLOCK_VALUE, "0")
        .set_body_bytes(bytes)
}

fn produce_ssz(bytes: Vec<u8>, execution_value: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Content-Type", "application/octet-stream")
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "true")
        .insert_header("Eth-Execution-Payload-Value", execution_value)
        .insert_header(HEADER_ETH_CONSENSUS_BLOCK_VALUE, "0")
        .set_body_bytes(bytes)
}

/// BN-A's parent is root(N-3). BnManager rejects that parent before the
/// candidate walk, so this test does not show the walk skipping a candidate.
/// BN-B, on root(N-1), is signed and published.
#[tokio::test]
async fn test_higher_value_stale_parent_is_dropped_before_the_walk() {
    let bn_a = MockServer::start().await;
    let bn_b = MockServer::start().await;
    let produce_path = format!("/eth/v3/validator/blocks/{SLOT}");

    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_ssz(blinded_on(ROOT_N3), VALUE_A))
        .expect(1)
        .mount(&bn_a)
        .await;
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_ssz(blinded_on(ROOT_N1), VALUE_B))
        .expect(1)
        .mount(&bn_b)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&bn_a)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&bn_b)
        .await;

    let mut config = BnManagerConfig::new(vec![bn_a.uri(), bn_b.uri()]);
    config.broadcast_topics.blocks = false;
    let manager = BnManager::new(config).expect("BnManager");
    let beacon = Arc::new(BeaconBlockAdapter::new(Arc::new(manager)));
    let pubkey = SecretKey::generate().public_key();
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let mut validator = ValidatorConfig::new(pubkey.to_bytes());
    validator.builder_proposals = true;
    store.add_validator(validator).unwrap();
    let signer = Arc::new(CountingSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon,
        Arc::new(store),
        Arc::new(deneb_schedule()),
        [0xaa; 32],
    );

    let result = service
        .propose_block(
            SLOT,
            &pubkey,
            PROPOSER,
            Some(ExpectedParents { root: ROOT_N1, parent: Some(ROOT_N2), closed: false }),
        )
        .await;
    assert!(result.is_ok(), "BN-B must be proposed: {result:?}");
    assert_eq!(signer.header_signs(), 1, "BN-A must not reach the signer");

    let mut publishes = Vec::new();
    for server in [&bn_a, &bn_b] {
        let reqs = server.received_requests().await.expect("recorded requests");
        publishes.extend(
            reqs.into_iter().filter(|req| req.url.path() == "/eth/v1/beacon/blinded_blocks"),
        );
    }
    assert!(!publishes.is_empty(), "the signed block must be published");
    for req in &publishes {
        assert!(
            req.body.len() >= PARENT_OFFSET + 32,
            "publish body shorter than the parent field: {}",
            req.body.len()
        );
        assert_eq!(&req.body[0..4], &100u32.to_le_bytes(), "signed block offset");
        assert_eq!(&req.body[PARENT_OFFSET..PARENT_OFFSET + 32], &ROOT_N1);
    }
}

const LOCAL_STATE: Root = [0x55; 32];
const BLINDED_STATE: Root = [0x44; 32];
/// `state_root` follows `parent_root` in the block.
const STATE_OFFSET: usize = PARENT_OFFSET + 32;

fn builder_only_service(
    endpoints: Vec<String>,
) -> (BlockService<CountingSigner, BeaconBlockAdapter>, Arc<CountingSigner>, PublicKey) {
    let mut config = BnManagerConfig::new(endpoints);
    config.broadcast_topics.blocks = false;
    let manager = BnManager::new(config).expect("BnManager");
    let beacon = Arc::new(BeaconBlockAdapter::new(Arc::new(manager)));
    let pubkey = SecretKey::generate().public_key();
    let fee = eth_types::external_vector_deneb_body().execution_payload.fee_recipient;
    let store = ValidatorStore::new(fee, 30_000_000);
    store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).expect("validator");
    store.set_global_block_selection_mode(BlockSelectionMode::BuilderOnly);
    let signer = Arc::new(CountingSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon,
        Arc::new(store),
        Arc::new(deneb_schedule()),
        [0xaa; 32],
    );
    (service, signer, pubkey)
}

fn parents() -> Option<ExpectedParents> {
    Some(ExpectedParents { root: ROOT_N1, parent: Some(ROOT_N2), closed: false })
}

/// Builder-only, candidates [local, blinded]: the blinded block is signed.
#[tokio::test]
async fn test_builder_only_signs_blinded_not_the_higher_value_local() {
    let bn_local = MockServer::start().await;
    let bn_blinded = MockServer::start().await;
    let produce_path = format!("/eth/v3/validator/blocks/{SLOT}");

    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_local(local_on(ROOT_N1, LOCAL_STATE), VALUE_A))
        .expect(1)
        .mount(&bn_local)
        .await;
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_ssz(blinded_with(ROOT_N1, BLINDED_STATE), VALUE_B))
        .expect(1)
        .mount(&bn_blinded)
        .await;
    for server in [&bn_local, &bn_blinded] {
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/blinded_blocks"))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
    }

    let (service, signer, pubkey) = builder_only_service(vec![bn_local.uri(), bn_blinded.uri()]);
    let result = service.propose_block(SLOT, &pubkey, PROPOSER, parents()).await;
    assert!(result.is_ok(), "the blinded candidate must be proposed: {result:?}");
    assert!(result.expect("ok").is_blinded);
    assert_eq!(signer.header_signs(), 1);

    let mut blinded_publishes = Vec::new();
    let mut local_publishes = Vec::new();
    for server in [&bn_local, &bn_blinded] {
        let reqs = server.received_requests().await.expect("recorded requests");
        for req in reqs {
            if req.url.path() == "/eth/v1/beacon/blinded_blocks" {
                blinded_publishes.push(req);
            } else if req.url.path() == "/eth/v2/beacon/blocks" {
                local_publishes.push(req);
            }
        }
    }
    assert!(local_publishes.is_empty(), "the local block must not be published");
    assert_eq!(blinded_publishes.len(), 1);
    let body = &blinded_publishes[0].body;
    assert!(body.len() >= STATE_OFFSET + 32, "publish body {}", body.len());
    assert_eq!(&body[PARENT_OFFSET..PARENT_OFFSET + 32], &ROOT_N1);
    assert_eq!(&body[STATE_OFFSET..STATE_OFFSET + 32], &BLINDED_STATE);
}

/// Builder-only, candidate [local] alone: nothing is signed.
#[tokio::test]
async fn test_builder_only_local_alone_signs_nothing() {
    let bn = MockServer::start().await;
    let produce_path = format!("/eth/v3/validator/blocks/{SLOT}");
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_local(local_on(ROOT_N1, LOCAL_STATE), VALUE_A))
        .expect(1)
        .mount(&bn)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&bn)
        .await;

    let (service, signer, pubkey) = builder_only_service(vec![bn.uri()]);
    let err = service
        .propose_block(SLOT, &pubkey, PROPOSER, parents())
        .await
        .expect_err("local fallback is not signed");
    assert_eq!(signer.header_signs(), 0);
    // Collection drops the local block before the sign-time shape error.
    assert_eq!(
        err.to_string(),
        "builder-only mode: builder block production failed: beacon error: produce_block_v3: all candidates rejected: bn 0 shape"
    );
    assert!(matches!(err, BlockServiceError::BuilderOnly(_)));
    let reqs = bn.received_requests().await.expect("recorded requests");
    assert!(reqs.iter().all(|req| req.method.as_str() != "POST"), "nothing published");
}

async fn mount_blinded_publish(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/eth/v1/beacon/blinded_blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

/// The only acceptable block uses the re-org parent. BnManager must have
/// received that parent on the duty, and the signed publish carries it.
#[tokio::test]
async fn test_reorg_parent_block_is_signed_through_bn_manager() {
    let bn_stale = MockServer::start().await;
    let bn_reorg = MockServer::start().await;
    let produce_path = format!("/eth/v3/validator/blocks/{SLOT}");
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_ssz(blinded_on(ROOT_N3), VALUE_A))
        .expect(1)
        .mount(&bn_stale)
        .await;
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_ssz(blinded_on(ROOT_N2), VALUE_B))
        .expect(1)
        .mount(&bn_reorg)
        .await;
    mount_blinded_publish(&bn_stale).await;
    mount_blinded_publish(&bn_reorg).await;

    let mut config = BnManagerConfig::new(vec![bn_stale.uri(), bn_reorg.uri()]);
    config.broadcast_topics.blocks = false;
    let manager = BnManager::new(config).expect("BnManager");
    let beacon = Arc::new(BeaconBlockAdapter::new(Arc::new(manager)));
    let pubkey = SecretKey::generate().public_key();
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let mut validator = ValidatorConfig::new(pubkey.to_bytes());
    validator.builder_proposals = true;
    store.add_validator(validator).unwrap();
    let signer = Arc::new(CountingSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon,
        Arc::new(store),
        Arc::new(deneb_schedule()),
        [0xaa; 32],
    );
    let result = service.propose_block(SLOT, &pubkey, PROPOSER, parents()).await;
    assert!(result.is_ok(), "the re-org parent must be signed: {result:?}");
    assert_eq!(signer.header_signs(), 1);

    let mut publishes = Vec::new();
    for server in [&bn_stale, &bn_reorg] {
        let reqs = server.received_requests().await.expect("recorded requests");
        publishes.extend(
            reqs.into_iter().filter(|req| req.url.path() == "/eth/v1/beacon/blinded_blocks"),
        );
    }
    assert_eq!(publishes.len(), 1, "one blinded publish");
    assert_eq!(&publishes[0].body[PARENT_OFFSET..PARENT_OFFSET + 32], &ROOT_N2);
}

/// A higher-value body that cannot be prepared is not signed.
///
/// The lower blinded block on the primary parent is the one published.
/// This does not isolate BnManager's prepare reject from the later walk:
/// the walk-skip of a candidate the mock still returns is
/// `test_higher_value_unpreparable_candidate_is_skipped_by_the_walk`.
#[tokio::test]
async fn test_higher_value_unpreparable_body_is_not_signed() {
    let bn_bad = MockServer::start().await;
    let bn_good = MockServer::start().await;
    let produce_path = format!("/eth/v3/validator/blocks/{SLOT}");
    let parent = format!("0x{}", hex::encode(ROOT_N1));
    let stub = format!(
        r#"{{"slot":"{SLOT}","proposer_index":"{PROPOSER}","parent_root":"{parent}","state_root":"0x{}","body":{{"execution_payload":{{"fee_recipient":"0x{}"}}}}}}"#,
        "55".repeat(32),
        "00".repeat(20),
    );
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", VALUE_A)
                .insert_header(HEADER_ETH_CONSENSUS_BLOCK_VALUE, "0")
                .set_body_string(stub),
        )
        .expect(1)
        .mount(&bn_bad)
        .await;
    Mock::given(method("GET"))
        .and(path(produce_path.as_str()))
        .respond_with(produce_ssz(blinded_on(ROOT_N1), VALUE_B))
        .expect(1)
        .mount(&bn_good)
        .await;
    mount_blinded_publish(&bn_bad).await;
    mount_blinded_publish(&bn_good).await;

    let mut config = BnManagerConfig::new(vec![bn_bad.uri(), bn_good.uri()]);
    config.broadcast_topics.blocks = false;
    let manager = BnManager::new(config).expect("BnManager");
    let beacon = Arc::new(BeaconBlockAdapter::new(Arc::new(manager)));
    let pubkey = SecretKey::generate().public_key();
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let mut validator = ValidatorConfig::new(pubkey.to_bytes());
    validator.builder_proposals = true;
    store.add_validator(validator).unwrap();
    let signer = Arc::new(CountingSigner::new());
    let service = BlockService::new(
        signer.clone(),
        beacon,
        Arc::new(store),
        Arc::new(deneb_schedule()),
        [0xaa; 32],
    );
    let result = service.propose_block(SLOT, &pubkey, PROPOSER, parents()).await;
    assert!(result.is_ok(), "the preparable block must be signed: {result:?}");
    assert_eq!(signer.header_signs(), 1, "the unpreparable body must not reach the signer");
    // Publish is not pinned to the producing beacon node.
    let mut publishes = Vec::new();
    for server in [&bn_bad, &bn_good] {
        let reqs = server.received_requests().await.expect("recorded requests");
        publishes.extend(
            reqs.into_iter().filter(|req| req.url.path() == "/eth/v1/beacon/blinded_blocks"),
        );
    }
    assert_eq!(publishes.len(), 1, "the blinded block on the primary parent is published");
    assert_eq!(&publishes[0].body[PARENT_OFFSET..PARENT_OFFSET + 32], &ROOT_N1);
}
