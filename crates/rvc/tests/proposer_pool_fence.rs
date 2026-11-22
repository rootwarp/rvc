//! Proposer-pool fence: a revocation in either pool drops the block duty.
//!
//! Synchronisation is a `Notify` plus a condvar. There is no sleep.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use async_trait::async_trait;
use beacon::HEADER_ETH_CONSENSUS_BLOCK_VALUE;
use block_service::{BeaconBlockClient, BlockService};
use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};
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
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const SLOT: u64 = 3_000_000;
const PROPOSER: u64 = 42;
const PARENT: Root = [0x11; 32];
const DENEB_CONTENTS_JSON: &str =
    include_str!("../../eth-types/tests/fixtures/beacon_api/deneb_block_contents.json");

struct CountingSigner {
    inner: StubValidatorSigner,
    header_signs: AtomicUsize,
    randao_signs: AtomicUsize,
    on_randao: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl CountingSigner {
    fn new() -> Self {
        Self {
            inner: StubValidatorSigner::new(),
            header_signs: AtomicUsize::new(0),
            randao_signs: AtomicUsize::new(0),
            on_randao: Mutex::new(None),
        }
    }

    fn set_on_randao(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_randao.lock().unwrap_or_else(|err| err.into_inner()) = Some(Arc::new(hook));
    }

    fn header_signs(&self) -> usize {
        self.header_signs.load(Ordering::SeqCst)
    }

    fn randao_signs(&self) -> usize {
        self.randao_signs.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ValidatorSigner for CountingSigner {
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
        if let Some(hook) = self.on_randao.lock().unwrap_or_else(|err| err.into_inner()).clone() {
            hook();
        }
        self.randao_signs.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_randao_reveal(epoch, pubkey, fork_schedule, genesis_validators_root).await
    }

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

fn blinded_block() -> Vec<u8> {
    let mut block: BlindedBeaconBlock = eth_types::external_vector_deneb_blinded_block();
    block.slot = SLOT;
    block.proposer_index = PROPOSER;
    block.parent_root = PARENT;
    encode_blinded_beacon_block_ssz(&block, 0)
}

fn full_deneb_template() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_string(DENEB_CONTENTS_JSON)
        .insert_header("Content-Type", "application/json")
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "false")
        .insert_header("Eth-Execution-Payload-Value", "1")
}

fn produce_template(bytes: Vec<u8>) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Content-Type", "application/octet-stream")
        .insert_header("Eth-Consensus-Version", "deneb")
        .insert_header("Eth-Execution-Payload-Blinded", "true")
        .insert_header("Eth-Execution-Payload-Value", "1")
        .insert_header(HEADER_ETH_CONSENSUS_BLOCK_VALUE, "0")
        .set_body_bytes(bytes)
}

fn manager(uri: String) -> Arc<BnManager> {
    let mut config = BnManagerConfig::new(vec![uri]);
    config.broadcast_topics.blocks = false;
    Arc::new(BnManager::new(config).expect("manager"))
}

fn service(
    main: Arc<BnManager>,
    proposer: Arc<BnManager>,
    signer: Arc<CountingSigner>,
    pubkey: &PublicKey,
) -> BlockService<CountingSigner, BeaconBlockAdapter> {
    service_with_fee(main, proposer, signer, pubkey, [0u8; 20])
}

fn service_with_fee(
    main: Arc<BnManager>,
    proposer: Arc<BnManager>,
    signer: Arc<CountingSigner>,
    pubkey: &PublicKey,
    fee_recipient: [u8; 20],
) -> BlockService<CountingSigner, BeaconBlockAdapter> {
    let store = ValidatorStore::new(fee_recipient, 30_000_000);
    store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();
    store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);
    let beacon = Arc::new(BeaconBlockAdapter::with_proposer(
        main as Arc<dyn BeaconNodeClient>,
        proposer as Arc<dyn BeaconNodeClient>,
    ));
    BlockService::new(signer, beacon, Arc::new(store), Arc::new(deneb_schedule()), [0xaa; 32])
}

async fn produce_hits(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("requests")
        .iter()
        .filter(|request| request.url.path().starts_with("/eth/v3/validator/blocks/"))
        .count()
}

#[tokio::test]
async fn proposer_candidate_captured_before_revocation_is_not_signed() {
    let main = MockServer::start().await;
    let proposer = MockServer::start().await;
    // Execution-only collection rejects a blinded body. This candidate has to
    // survive that gate so the post-produce fence is what drops it.
    Mock::given(method("GET"))
        .and(path(format!("/eth/v3/validator/blocks/{SLOT}")))
        .respond_with(full_deneb_template())
        .mount(&proposer)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/eth/v3/validator/blocks/{}", SLOT + 1)))
        .respond_with(full_deneb_template())
        .mount(&main)
        .await;
    let main_mgr = manager(main.uri());
    let proposer_mgr = manager(proposer.uri());
    let pubkey = SecretKey::generate().public_key();
    let signer = Arc::new(CountingSigner::new());
    let block =
        service(Arc::clone(&main_mgr), Arc::clone(&proposer_mgr), Arc::clone(&signer), &pubkey);
    let revoke = Arc::clone(&proposer_mgr);
    block.set_after_produce(move || revoke.testing_revoke_admission(0));

    let err = block.propose_block(SLOT, &pubkey, PROPOSER, None).await.expect_err("revoked");
    assert!(err.to_string().contains("admission revoked"), "{err}");
    assert_eq!(signer.header_signs(), 0, "the captured candidate is not signed");
    assert_eq!(produce_hits(&proposer).await, 1);
    assert_eq!(produce_hits(&main).await, 0);

    let _ = block.propose_block(SLOT + 1, &pubkey, PROPOSER, None).await;
    assert_eq!(signer.header_signs(), 0, "the first slot signed nothing");
    assert_eq!(produce_hits(&proposer).await, 1, "the revoked proposer is not asked again");
    assert!(produce_hits(&main).await > 0, "the next slot uses the main pool");
}

#[tokio::test]
async fn late_produce_response_from_a_proposer_node_revoked_in_flight_is_dropped() {
    let main = MockServer::start().await;
    let proposer = MockServer::start().await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    struct HoldProduce {
        entered: Arc<tokio::sync::Notify>,
        pair: Arc<(Mutex<bool>, Condvar)>,
        body: Vec<u8>,
    }
    impl Respond for HoldProduce {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            self.entered.notify_one();
            let (lock, cv) = &*self.pair;
            let mut ready = lock.lock().unwrap_or_else(|err| err.into_inner());
            while !*ready {
                ready = cv.wait(ready).unwrap_or_else(|err| err.into_inner());
            }
            produce_template(self.body.clone())
        }
    }
    Mock::given(method("GET"))
        .and(path(format!("/eth/v3/validator/blocks/{SLOT}")))
        .respond_with(HoldProduce {
            entered: Arc::clone(&entered),
            pair: Arc::clone(&pair),
            body: blinded_block(),
        })
        .mount(&proposer)
        .await;
    let main_mgr = manager(main.uri());
    let proposer_mgr = manager(proposer.uri());
    let pubkey = SecretKey::generate().public_key();
    let signer = Arc::new(CountingSigner::new());
    let block =
        service(Arc::clone(&main_mgr), Arc::clone(&proposer_mgr), Arc::clone(&signer), &pubkey);
    let ranked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&ranked);
    block.set_after_produce(move || flag.store(true, Ordering::SeqCst));

    let propose =
        tokio::spawn(async move { block.propose_block(SLOT, &pubkey, PROPOSER, None).await });
    entered.notified().await;
    proposer_mgr.testing_revoke_admission(0);
    {
        let (lock, cv) = &*pair;
        *lock.lock().unwrap_or_else(|err| err.into_inner()) = true;
        cv.notify_one();
    }
    let err = propose.await.expect("join").expect_err("dropped");
    assert!(err.to_string().contains("admission revoked"), "{err}");
    assert!(!ranked.load(Ordering::SeqCst), "a late proposer block is not ranked");
    assert_eq!(signer.header_signs(), 0, "a late proposer block is not signed");
}

#[tokio::test]
async fn block_duty_with_no_admitted_main_node_signs_no_randao_even_with_an_admitted_proposer_node()
{
    let main = MockServer::start().await;
    let proposer = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/eth/v3/validator/blocks/{SLOT}")))
        .respond_with(produce_template(blinded_block()))
        .mount(&proposer)
        .await;
    let main_mgr = manager(main.uri());
    let proposer_mgr = manager(proposer.uri());
    main_mgr.testing_revoke_admission(0);
    let pubkey = SecretKey::generate().public_key();
    let signer = Arc::new(CountingSigner::new());
    let block =
        service(Arc::clone(&main_mgr), Arc::clone(&proposer_mgr), Arc::clone(&signer), &pubkey);
    let err = block.propose_block(SLOT, &pubkey, PROPOSER, None).await.expect_err("no main node");
    assert!(err.to_string().contains("no admitted beacon node"), "{err}");
    assert_eq!(signer.randao_signs(), 0);
    assert_eq!(signer.header_signs(), 0);
    assert_eq!(produce_hits(&proposer).await, 0, "the admitted proposer is not asked");
}

#[tokio::test]
async fn empty_proposer_pool_uses_the_main_fence() {
    let main = MockServer::start().await;
    let proposer = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/eth/v3/validator/blocks/7"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&main)
        .await;
    let main_mgr = manager(main.uri());
    let proposer_mgr = manager(proposer.uri());
    proposer_mgr.testing_revoke_admission(0);
    let adapter = BeaconBlockAdapter::with_proposer(
        Arc::clone(&main_mgr) as Arc<dyn BeaconNodeClient>,
        Arc::clone(&proposer_mgr) as Arc<dyn BeaconNodeClient>,
    );
    let fence = adapter.duty_fence().expect("main fence");
    assert!(fence.holds());
    let _ = adapter.produce_block_v3(7, "0xrandao", None, None).await;
    assert!(produce_hits(&main).await > 0, "an empty proposer pool uses the main pool");
    assert_eq!(produce_hits(&proposer).await, 0);
    main_mgr.testing_revoke_admission(0);
    assert!(!fence.holds(), "a later main-pool revocation drops that fence");
}

#[tokio::test]
async fn combined_fence_fails_when_either_pool_revokes() {
    let main_mgr = manager("http://127.0.0.1:9".to_string());
    let proposer_mgr = manager("http://127.0.0.1:9".to_string());
    let adapter = BeaconBlockAdapter::with_proposer(
        Arc::clone(&main_mgr) as Arc<dyn BeaconNodeClient>,
        Arc::clone(&proposer_mgr) as Arc<dyn BeaconNodeClient>,
    );
    let from_proposer = adapter.duty_fence().expect("combined");
    proposer_mgr.testing_revoke_admission(0);
    assert!(!from_proposer.holds());
    let from_main = adapter.duty_fence().expect("main only");
    assert!(from_main.holds(), "an empty proposer pool leaves the main fence");
    main_mgr.testing_revoke_admission(0);
    assert!(!from_main.holds());

    let main_mgr = manager("http://127.0.0.1:9".to_string());
    let proposer_mgr = manager("http://127.0.0.1:9".to_string());
    let adapter = BeaconBlockAdapter::with_proposer(
        main_mgr.clone() as Arc<dyn BeaconNodeClient>,
        proposer_mgr as Arc<dyn BeaconNodeClient>,
    );
    let fence = adapter.duty_fence().expect("combined");
    main_mgr.testing_revoke_admission(0);
    assert!(!fence.holds(), "a main-pool revocation drops the combined fence");
}

#[tokio::test]
async fn proposer_granted_after_an_empty_fence_is_not_signed_if_revoked_before_sign() {
    let main = MockServer::start().await;
    let proposer = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/eth/v3/validator/blocks/{SLOT}")))
        .respond_with(full_deneb_template())
        .mount(&proposer)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&proposer)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&main)
        .await;
    let main_mgr = manager(main.uri());
    let proposer_mgr = manager(proposer.uri());
    proposer_mgr.testing_revoke_admission(0);
    let pubkey = SecretKey::generate().public_key();
    let signer = Arc::new(CountingSigner::new());
    let grant = Arc::clone(&proposer_mgr);
    signer.set_on_randao(move || grant.testing_grant_admission(0));
    // The fixture's execution payload pays 0x66…66.
    let block = service_with_fee(
        Arc::clone(&main_mgr),
        Arc::clone(&proposer_mgr),
        Arc::clone(&signer),
        &pubkey,
        [0x66; 20],
    );
    let revoke = Arc::clone(&proposer_mgr);
    block.set_after_produce(move || revoke.testing_revoke_admission(0));

    let result = block.propose_block(SLOT, &pubkey, PROPOSER, None).await;
    assert!(
        produce_hits(&proposer).await > 0,
        "the node granted after the empty fence is asked for a block"
    );
    assert_eq!(
        signer.header_signs(),
        0,
        "revoked proposer candidate was signed, header_signs={}",
        signer.header_signs()
    );
    let err = result.expect_err("revoked before sign");
    assert!(err.to_string().contains("admission revoked"), "{err}");
}
