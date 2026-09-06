//! Issue 4.21: gRPC remote keys sign through `SignerService` via `TypedSigner`.
//!
//! Test names avoid a trailing `_root` (KAT policy).

#![allow(clippy::disallowed_methods)]
#![allow(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use crypto::typed_signer::{SignContext, TypedSigner};
use crypto::{
    signing_root_with_fork_version, CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey,
    Signature, Signer, SigningError, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
};
use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BeaconBlockHeader, Checkpoint,
    ContributionAndProof, ElectraAggregateAndProof, ElectraAttestation, ForkInfo, ForkName,
    ForkSchedule, PayloadAttestationData, ProposerPreferences, Root, Slot,
    SyncCommitteeContribution, ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_APPLICATION_BUILDER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_PROPOSER_PREFERENCES,
    DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT, SLOTS_PER_EPOCH,
};
use grpc_signer::{
    proto::signer_v2::{
        signer_service_server::{SignerService as SignerServiceV2, SignerServiceServer},
        Duty, ForkInfo as ProtoForkInfo, GetStatusRequest, GetStatusResponse,
        ListPublicKeysRequest, ListPublicKeysResponse, SignAggregateAndProofRequest,
        SignAttestationDataRequest, SignBeaconBlockRequest, SignBlindedBeaconBlockRequest,
        SignBlockHeaderRequest, SignBuilderRegistrationRequest, SignContributionAndProofRequest,
        SignRandaoRevealRequest, SignResponse, SignRootRequest,
        SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
        SignVoluntaryExitRequest,
    },
    GrpcRemoteSigner, GrpcRemoteSignerConfig,
};
use prost::Message;
use rvc_signer::{
    always_enabled, BackendKind, BeaconBlockHeaderFields, SignerError, SignerService,
    TimeoutPolicy, ValidatorSigner,
};
use slashing::SlashingDb;
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};

fn phase0_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: u64::MAX,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: u64::MAX,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch: u64::MAX,
        capella_fork_version: [3, 0, 0, 0],
        deneb_fork_epoch: u64::MAX,
        deneb_fork_version: [4, 0, 0, 0],
        electra_fork_epoch: u64::MAX,
        electra_fork_version: [5, 0, 0, 0],
        fulu_fork_epoch: u64::MAX,
        fulu_fork_version: [6, 0, 0, 0],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [7, 0, 0, 0],
    }
}

fn fulu_schedule() -> ForkSchedule {
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

const GVR: Root = [0xab; 32];

fn att_data() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: [0x55; 32],
        source: Checkpoint { epoch: 9, root: [0x66; 32] },
        target: Checkpoint { epoch: 10, root: [0x77; 32] },
    }
}

fn aggregate() -> AggregateAndProof {
    AggregateAndProof {
        aggregator_index: 42,
        aggregate: Attestation {
            aggregation_bits: vec![0xff; 4],
            data: att_data(),
            signature: vec![0xaa; 96],
        },
        selection_proof: vec![0xbb; 96],
    }
}

fn electra_aggregate() -> ElectraAggregateAndProof {
    ElectraAggregateAndProof {
        aggregator_index: 42,
        aggregate: ElectraAttestation {
            aggregation_bits: vec![0xff; 4],
            data: att_data(),
            signature: vec![0xaa; 96],
            committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
        },
        selection_proof: vec![0xbb; 96],
    }
}

fn contribution() -> ContributionAndProof {
    ContributionAndProof {
        aggregator_index: 7,
        contribution: SyncCommitteeContribution {
            slot: 400,
            beacon_block_root: [0x99; 32],
            subcommittee_index: 1,
            aggregation_bits: vec![0x03; 16],
            signature: vec![0xcc; 96],
        },
        selection_proof: vec![0xdd; 96],
    }
}

fn header(slot: Slot) -> BeaconBlockHeaderFields {
    BeaconBlockHeaderFields {
        slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
        body_ssz: Vec::new(),
        is_blinded: false,
    }
}

fn header_with_electra_body(slot: Slot) -> (BeaconBlockHeaderFields, eth_types::BeaconBlock) {
    let body = eth_types::external_vector_electra_body().as_ssz_bytes();
    let body_root = eth_types::body_tree_hash_root(&body).expect("electra body").0;
    let block = eth_types::BeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: body.clone(),
    };
    (
        BeaconBlockHeaderFields {
            slot,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root,
            body_ssz: body,
            is_blinded: false,
        },
        block,
    )
}

fn ptc() -> PayloadAttestationData {
    PayloadAttestationData {
        beacon_block_root: [0x11; 32],
        slot: 1,
        payload_present: true,
        blob_data_available: false,
    }
}

fn prefs() -> ProposerPreferences {
    ProposerPreferences {
        dependent_root: [0x33; 32],
        proposal_slot: 32,
        validator_index: 3,
        fee_recipient: [0x44; 20],
        target_gas_limit: 36_000_000,
    }
}

fn open_db() -> Arc<SlashingDb> {
    Arc::new(SlashingDb::open_in_memory().expect("db"))
}

// ── In-process typed BLS backend (no gRPC wire) ──────────────────────────────

struct LocalBlsTyped {
    sk_bytes: [u8; 32],
    keys: Vec<[u8; 48]>,
}

impl LocalBlsTyped {
    fn new(sk: &SecretKey) -> Self {
        Self { sk_bytes: sk.to_bytes(), keys: vec![sk.public_key().to_bytes()] }
    }

    fn sign_root(&self, root: &Root, pk: &[u8; 48]) -> Result<Signature, SigningError> {
        if !self.keys.contains(pk) {
            return Err(SigningError::KeyNotFound(hex::encode(pk)));
        }
        Ok(SecretKey::from_bytes(&self.sk_bytes).unwrap().sign(root))
    }
}

#[async_trait]
impl TypedSigner for LocalBlsTyped {
    async fn sign_block(
        &self,
        block: &eth_types::BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            block,
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_block_header(
        &self,
        header: &BeaconBlockHeader,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            header,
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_blinded_block(
        &self,
        block: &eth_types::BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            block,
            DOMAIN_BEACON_PROPOSER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            data,
            DOMAIN_BEACON_ATTESTER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            agg,
            DOMAIN_AGGREGATE_AND_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_electra_aggregate_and_proof(
        &self,
        agg: &ElectraAggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            agg,
            DOMAIN_AGGREGATE_AND_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_sync_committee_message(
        &self,
        _slot: Slot,
        beacon_block_root: Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            &beacon_block_root,
            DOMAIN_SYNC_COMMITTEE,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let sel = eth_types::SyncAggregatorSelectionData { slot, subcommittee_index };
        let root = signing_root_with_fork_version(
            &sel,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            c,
            DOMAIN_CONTRIBUTION_AND_PROOF,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            reg,
            DOMAIN_APPLICATION_BUILDER,
            genesis_fork_version,
            [0u8; 32],
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_randao_reveal(
        &self,
        epoch: eth_types::Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            &epoch,
            DOMAIN_RANDAO,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            exit,
            DOMAIN_VOLUNTARY_EXIT,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            data,
            DOMAIN_PTC_ATTESTER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }

    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let root = signing_root_with_fork_version(
            prefs,
            DOMAIN_PROPOSER_PREFERENCES,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        self.sign_root(&root, &ctx.pubkey.to_bytes())
    }
}

struct RecordingTyped {
    inner: LocalBlsTyped,
    seen: Mutex<HashSet<&'static str>>,
}

impl RecordingTyped {
    fn new(sk: &SecretKey) -> Self {
        Self { inner: LocalBlsTyped::new(sk), seen: Mutex::new(HashSet::new()) }
    }

    fn mark(&self, name: &'static str) {
        self.seen.lock().unwrap().insert(name);
    }
}

macro_rules! rec {
    ($self:ident, $name:literal, $call:expr) => {{
        $self.mark($name);
        $call
    }};
}

#[async_trait]
impl TypedSigner for RecordingTyped {
    async fn sign_block(
        &self,
        block: &eth_types::BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_block", self.inner.sign_block(block, ctx).await)
    }
    async fn sign_block_header(
        &self,
        header: &BeaconBlockHeader,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_block_header", self.inner.sign_block_header(header, ctx).await)
    }
    async fn sign_blinded_block(
        &self,
        block: &eth_types::BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_blinded_block", self.inner.sign_blinded_block(block, ctx).await)
    }
    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_attestation", self.inner.sign_attestation(data, ctx).await)
    }
    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_aggregate_and_proof", self.inner.sign_aggregate_and_proof(agg, ctx).await)
    }
    async fn sign_electra_aggregate_and_proof(
        &self,
        agg: &ElectraAggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(
            self,
            "sign_electra_aggregate_and_proof",
            self.inner.sign_electra_aggregate_and_proof(agg, ctx).await
        )
    }
    async fn sign_sync_committee_message(
        &self,
        slot: Slot,
        beacon_block_root: Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(
            self,
            "sign_sync_committee_message",
            self.inner.sign_sync_committee_message(slot, beacon_block_root, ctx).await
        )
    }
    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(
            self,
            "sign_sync_aggregator_selection",
            self.inner.sign_sync_aggregator_selection(slot, subcommittee_index, ctx).await
        )
    }
    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(
            self,
            "sign_contribution_and_proof",
            self.inner.sign_contribution_and_proof(c, ctx).await
        )
    }
    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(
            self,
            "sign_builder_registration",
            self.inner.sign_builder_registration(reg, genesis_fork_version, ctx).await
        )
    }
    async fn sign_randao_reveal(
        &self,
        epoch: eth_types::Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_randao_reveal", self.inner.sign_randao_reveal(epoch, ctx).await)
    }
    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_voluntary_exit", self.inner.sign_voluntary_exit(exit, ctx).await)
    }
    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(self, "sign_payload_attestation", self.inner.sign_payload_attestation(data, ctx).await)
    }
    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        rec!(
            self,
            "sign_proposer_preferences",
            self.inner.sign_proposer_preferences(prefs, ctx).await
        )
    }
}

fn grpc_service(sk: SecretKey, typed: Arc<dyn TypedSigner + Send + Sync>) -> SignerService {
    let pk = sk.public_key().to_bytes();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    composite.add_grpc_remote_signer(vec![pk], typed);
    SignerService::new(composite, open_db()).with_enablement(always_enabled())
}

struct Denied;
impl doppelganger::SigningEnablement for Denied {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

struct HangingTyped {
    sleep: Duration,
}

#[async_trait]
impl TypedSigner for HangingTyped {
    async fn sign_block(
        &self,
        _block: &eth_types::BeaconBlock,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_attestation(
        &self,
        _data: &AttestationData,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        tokio::time::sleep(self.sleep).await;
        Err(SigningError::RemoteSignerError("hang".into()))
    }
    async fn sign_blinded_block(
        &self,
        _block: &eth_types::BlindedBeaconBlock,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_aggregate_and_proof(
        &self,
        _agg: &AggregateAndProof,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_sync_committee_message(
        &self,
        _slot: Slot,
        _beacon_block_root: Root,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_sync_aggregator_selection(
        &self,
        _slot: Slot,
        _subcommittee_index: u64,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_contribution_and_proof(
        &self,
        _c: &ContributionAndProof,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_builder_registration(
        &self,
        _reg: &ValidatorRegistrationV1,
        _genesis_fork_version: [u8; 4],
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_randao_reveal(
        &self,
        _epoch: eth_types::Epoch,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
    async fn sign_voluntary_exit(
        &self,
        _exit: &VoluntaryExit,
        _ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        unreachable!()
    }
}

fn allow_insecure() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| unsafe {
        std::env::set_var(grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR, "true");
    });
}

// ── Capturing in-process v2 signer (legacy RPCs + header) ────────────────────

type Capture = Arc<Mutex<HashMap<String, Vec<u8>>>>;

struct CapturingV2 {
    sk: SecretKey,
    capture: Capture,
}

impl CapturingV2 {
    fn bls_sign(&self, root: &[u8; 32]) -> Vec<u8> {
        self.sk.sign(root).to_bytes().to_vec()
    }

    fn fork(fi: &ProtoForkInfo) -> ([u8; 4], [u8; 32]) {
        let curr: [u8; 4] = fi.current_version.as_slice().try_into().unwrap_or([0u8; 4]);
        let gvr: [u8; 32] = fi.genesis_validators_root.as_slice().try_into().unwrap_or([0u8; 32]);
        (curr, gvr)
    }

    fn record(&self, rpc: &str, bytes: Vec<u8>) {
        self.capture.lock().unwrap().insert(rpc.to_string(), bytes);
    }
}

#[tonic::async_trait]
impl SignerServiceV2 for CapturingV2 {
    async fn sign_beacon_block(
        &self,
        request: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_beacon_block", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let block = eth_types::decode_beacon_block_ssz(&r.block_ssz, r.fork_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let domain = crypto::compute_domain(DOMAIN_BEACON_PROPOSER, curr, gvr);
        let root = crypto::compute_signing_root(&block, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_blinded_beacon_block(
        &self,
        request: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_blinded_beacon_block", r.encode_to_vec());
        Err(Status::unimplemented("unused"))
    }

    async fn sign_attestation_data(
        &self,
        request: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_attestation_data", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let d = r.data.as_ref().ok_or_else(|| Status::invalid_argument("data"))?;
        let src = d.source.as_ref().ok_or_else(|| Status::invalid_argument("source"))?;
        let tgt = d.target.as_ref().ok_or_else(|| Status::invalid_argument("target"))?;
        let data = AttestationData {
            slot: d.slot,
            index: d.index,
            beacon_block_root: d.beacon_block_root.as_slice().try_into().unwrap_or([0; 32]),
            source: Checkpoint {
                epoch: src.epoch,
                root: src.root.as_slice().try_into().unwrap_or([0; 32]),
            },
            target: Checkpoint {
                epoch: tgt.epoch,
                root: tgt.root.as_slice().try_into().unwrap_or([0; 32]),
            },
        };
        let domain = crypto::compute_domain(DOMAIN_BEACON_ATTESTER, curr, gvr);
        let root = crypto::compute_signing_root(&data, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_aggregate_and_proof(
        &self,
        request: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_aggregate_and_proof", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let aggregate = eth_types::decode_attestation_ssz(&r.aggregate_ssz, r.fork_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let agg = AggregateAndProof {
            aggregator_index: r.aggregator_index,
            aggregate,
            selection_proof: r.selection_proof,
        };
        let domain = crypto::compute_domain(DOMAIN_AGGREGATE_AND_PROOF, curr, gvr);
        let root = crypto::compute_signing_root(&agg, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_sync_committee_message(
        &self,
        request: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_sync_committee_message", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let bbr: Root = r.beacon_block_root.as_slice().try_into().unwrap_or([0; 32]);
        let domain = crypto::compute_domain(DOMAIN_SYNC_COMMITTEE, curr, gvr);
        let root = crypto::compute_signing_root(&bbr, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_sync_aggregator_selection_data(
        &self,
        request: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_sync_aggregator_selection_data", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let sel = eth_types::SyncAggregatorSelectionData {
            slot: r.slot,
            subcommittee_index: r.subcommittee_index,
        };
        let domain = crypto::compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, curr, gvr);
        let root = crypto::compute_signing_root(&sel, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_contribution_and_proof(
        &self,
        request: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_contribution_and_proof", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let contribution =
            eth_types::decode_sync_committee_contribution_ssz(&r.contribution_ssz, r.fork_id)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let cap = ContributionAndProof {
            aggregator_index: r.aggregator_index,
            contribution,
            selection_proof: r.selection_proof,
        };
        let domain = crypto::compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, curr, gvr);
        let root = crypto::compute_signing_root(&cap, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_builder_registration(
        &self,
        request: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_builder_registration", r.encode_to_vec());
        let pubkey: [u8; 48] = r.pubkey.clone().try_into().unwrap_or([0; 48]);
        let fee: [u8; 20] = r.fee_recipient.clone().try_into().unwrap_or([0; 20]);
        let reg = ValidatorRegistrationV1 {
            fee_recipient: fee,
            gas_limit: r.gas_limit,
            timestamp: r.timestamp,
            pubkey,
        };
        let gfv: [u8; 4] = if r.genesis_fork_version.is_empty() {
            [0; 4]
        } else {
            r.genesis_fork_version.as_slice().try_into().unwrap_or([0; 4])
        };
        let domain = crypto::compute_domain(DOMAIN_APPLICATION_BUILDER, gfv, [0u8; 32]);
        let root = crypto::compute_signing_root(&reg, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_randao_reveal(
        &self,
        request: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_randao_reveal", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let domain = crypto::compute_domain(DOMAIN_RANDAO, curr, gvr);
        let root = crypto::compute_signing_root(&r.epoch, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_voluntary_exit(
        &self,
        request: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_voluntary_exit", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let exit = VoluntaryExit { epoch: r.epoch, validator_index: r.validator_index };
        let domain = crypto::compute_domain(DOMAIN_VOLUNTARY_EXIT, curr, gvr);
        let root = crypto::compute_signing_root(&exit, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_block_header(
        &self,
        request: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        self.record("sign_block_header", r.encode_to_vec());
        let fi = r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("fork_info"))?;
        let (curr, gvr) = Self::fork(fi);
        let h = r.header.as_ref().ok_or_else(|| Status::invalid_argument("header"))?;
        let header = BeaconBlockHeader {
            slot: h.slot,
            proposer_index: h.proposer_index,
            parent_root: h.parent_root.as_slice().try_into().unwrap_or([0; 32]),
            state_root: h.state_root.as_slice().try_into().unwrap_or([0; 32]),
            body_root: h.body_root.as_slice().try_into().unwrap_or([0; 32]),
        };
        let domain = crypto::compute_domain(DOMAIN_BEACON_PROPOSER, curr, gvr);
        let root = crypto::compute_signing_root(&header, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_root(
        &self,
        _request: Request<SignRootRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("SignRoot"))
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequest>,
    ) -> Result<Response<ListPublicKeysResponse>, Status> {
        Ok(Response::new(ListPublicKeysResponse {
            pubkeys: vec![self.sk.public_key().to_bytes().to_vec()],
        }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        Ok(Response::new(GetStatusResponse { ready: true, backend: "test".into(), key_count: 1 }))
    }
}

async fn start_capturing_server(
    sk_bytes: [u8; 32],
) -> (SocketAddr, Capture, tokio::task::JoinHandle<()>) {
    allow_insecure();
    let capture: Capture = Arc::new(Mutex::new(HashMap::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cap = Arc::clone(&capture);
    let handle = tokio::spawn(async move {
        let svc = CapturingV2 { sk: SecretKey::from_bytes(&sk_bytes).unwrap(), capture: cap };
        tonic::transport::Server::builder()
            .add_service(SignerServiceServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, capture, handle)
}

async fn connect_grpc(addr: SocketAddr) -> GrpcRemoteSigner {
    allow_insecure();
    GrpcRemoteSigner::connect(GrpcRemoteSignerConfig::new(format!("http://{addr}"))).await.unwrap()
}

fn phase0_ctx(pk: PublicKey) -> SignContext {
    SignContext::new(
        pk,
        ForkInfo {
            previous_version: [0, 0, 0, 0],
            current_version: [0, 0, 0, 0],
            genesis_validators_root: GVR,
        },
        ForkName::Phase0,
    )
}

fn grpc_vc(grpc: GrpcRemoteSigner) -> SignerService {
    let keys = grpc.public_keys();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    composite.add_grpc_remote_signer(keys, Arc::new(grpc));
    SignerService::new(composite, open_db()).with_enablement(always_enabled())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_grpc_remote_key_signs_attestation_and_aggregate() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let typed = Arc::new(LocalBlsTyped::new(&sk));
    let svc = grpc_service(sk, typed);
    let schedule = phase0_schedule();

    svc.sign_attestation(&att_data(), &pk, &schedule, &GVR).await.expect("attestation");
    svc.sign_aggregate_and_proof(&aggregate(), &pk, &schedule, &GVR).await.expect("aggregate");
    let hdr = header(100);
    svc.sign_block_header(&hdr, &pk, &schedule, &GVR).await.expect("block header");
}

#[tokio::test]
async fn test_grpc_remote_key_sign_block_without_header_is_local_rejected() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let typed = Arc::new(LocalBlsTyped::new(&sk));
    let svc = grpc_service(sk, typed);
    let err = svc
        .sign_block(&[0x11; 32], 5, &pk, &phase0_schedule(), &GVR)
        .await
        .expect_err("root-only block has no typed object");
    match err {
        SignerError::SigningFailed(msg) => {
            assert!(
                msg.contains("TypedSigner") || msg.contains("raw-root"),
                "expected LocalRejected-mapped message, got {msg}"
            );
        }
        other => panic!("expected SigningFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn test_every_typed_signer_method_reached_from_validator_signer() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let rec = Arc::new(RecordingTyped::new(&sk));
    let svc = grpc_service(sk, rec.clone());
    let schedule = phase0_schedule();
    let gvr = GVR;

    svc.sign_attestation(&att_data(), &pk, &schedule, &gvr).await.unwrap();
    svc.sign_block_header(&header(100), &pk, &schedule, &gvr).await.unwrap();
    svc.sign_randao_reveal(3, &pk, &schedule, &gvr).await.unwrap();
    svc.sign_sync_committee_message(&[0x88; 32], 100, &pk, &schedule, &gvr).await.unwrap();
    svc.sign_aggregate_and_proof(&aggregate(), &pk, &schedule, &gvr).await.unwrap();
    svc.sign_electra_aggregate_and_proof(&electra_aggregate(), &pk, &schedule, &gvr).await.unwrap();
    svc.sign_voluntary_exit(&VoluntaryExit { epoch: 1, validator_index: 0 }, &pk, &schedule, &gvr)
        .await
        .unwrap();
    let reg = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1,
        pubkey: pk.to_bytes(),
    };
    svc.sign_builder_registration(&reg, &pk, [0; 4]).await.unwrap();
    svc.sign_sync_committee_selection_proof(100, 2, &pk, &schedule, &gvr).await.unwrap();
    svc.sign_contribution_and_proof(&contribution(), &pk, &schedule, &gvr).await.unwrap();
    svc.sign_payload_attestation(&ptc(), &pk, &schedule, &gvr).await.unwrap();
    svc.sign_proposer_preferences(&prefs(), &pk, &schedule, &gvr).await.unwrap();

    let seen = rec.seen.lock().unwrap().clone();
    for name in [
        "sign_attestation",
        "sign_block_header",
        "sign_randao_reveal",
        "sign_sync_committee_message",
        "sign_aggregate_and_proof",
        "sign_voluntary_exit",
        "sign_builder_registration",
        "sign_sync_aggregator_selection",
        "sign_contribution_and_proof",
        "sign_payload_attestation",
        "sign_proposer_preferences",
    ] {
        assert!(seen.contains(name), "TypedSigner::{name} was not reached; seen={seen:?}");
    }
}

fn local_bls_backend(sk_bytes: [u8; 32]) -> Arc<dyn Signer> {
    let mut km = KeyManager::new();
    km.insert(SecretKey::from_bytes(&sk_bytes).unwrap());
    Arc::new(LocalSigner::new(km))
}

/// Local / HTTP-remote / gRPC-remote attestation services.
fn attestation_services(
    sk: &SecretKey,
) -> [(BackendKind, BackendKind, TimeoutPolicy, SignerService, Arc<SlashingDb>); 3] {
    let pk = sk.public_key().to_bytes();
    let sk_bytes = sk.to_bytes();
    let mk_local = || {
        let mut km = KeyManager::new();
        km.insert(SecretKey::from_bytes(&sk_bytes).unwrap());
        Arc::new(CompositeSigner::new(LocalSigner::new(km)))
    };
    let mk_http = || {
        let c = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let remote = remote_signer_client::RemoteSigner::new_for_tests(
            remote_signer_client::RemoteSignerConfig::new("https://127.0.0.1:1"),
            vec![pk],
        );
        c.add_remote_key(pk, Arc::new(remote));
        c
    };
    let mk_grpc = || {
        let c = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        c.add_grpc_remote_signer(vec![pk], Arc::new(LocalBlsTyped::new(sk)));
        c
    };
    let local_db = open_db();
    let http_db = open_db();
    let grpc_db = open_db();
    [
        (
            BackendKind::InProcess,
            BackendKind::InProcess,
            TimeoutPolicy::DiscardStagedRow,
            SignerService::new(mk_local(), Arc::clone(&local_db)).with_enablement(always_enabled()),
            local_db,
        ),
        (
            BackendKind::Remote,
            BackendKind::Remote,
            TimeoutPolicy::RetainStagedRow,
            SignerService::new(mk_http(), Arc::clone(&http_db))
                .with_enablement(always_enabled())
                .with_sign_backend(local_bls_backend(sk_bytes)),
            http_db,
        ),
        (
            BackendKind::Unknown, // label: gRPC registry
            BackendKind::Remote,
            TimeoutPolicy::RetainStagedRow,
            SignerService::new(mk_grpc(), Arc::clone(&grpc_db)).with_enablement(always_enabled()),
            grpc_db,
        ),
    ]
}

#[tokio::test]
async fn test_backend_kind_attestation_envelope() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let schedule = phase0_schedule();
    for (label, expected_kind, expected_policy, svc, db) in attestation_services(&sk) {
        assert_eq!(svc.backend_kind(&pk), expected_kind, "{label:?}");
        assert_eq!(svc.timeout_policy_for(&pk), expected_policy, "{label:?}");
        svc.sign_attestation(&att_data(), &pk, &schedule, &GVR)
            .await
            .unwrap_or_else(|e| panic!("{label:?} attestation must succeed: {e:?}"));
        let rows = db.get_attestations(&hex::encode(pk.to_bytes())).unwrap();
        assert_eq!(rows.len(), 1, "{label:?}");
        assert_eq!(rows[0].source_epoch, 9);
        assert_eq!(rows[0].target_epoch, 10);
    }
}

#[tokio::test]
async fn test_grpc_enablement_rejection_writes_no_row() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    composite.add_grpc_remote_signer(vec![pk.to_bytes()], Arc::new(LocalBlsTyped::new(&sk)));
    let db = open_db();
    let svc = SignerService::new(composite, Arc::clone(&db)).with_enablement(Arc::new(Denied));
    let err =
        svc.sign_attestation(&att_data(), &pk, &phase0_schedule(), &GVR).await.expect_err("denied");
    assert!(matches!(err, SignerError::BlockedByDoppelganger));
    assert!(db.get_attestations(&hex::encode(pk.to_bytes())).unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_grpc_timeout_retains_staged_row() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    composite.add_grpc_remote_signer(
        vec![pk.to_bytes()],
        Arc::new(HangingTyped { sleep: Duration::from_millis(400) }),
    );
    let db = open_db();
    let svc = SignerService::new(composite, Arc::clone(&db))
        .with_enablement(always_enabled())
        .with_sign_timeout(Duration::from_millis(50));
    assert_eq!(svc.backend_kind(&pk), BackendKind::Remote);

    let err = svc
        .sign_attestation(&att_data(), &pk, &phase0_schedule(), &GVR)
        .await
        .expect_err("timeout");
    assert!(matches!(err, SignerError::SigningFailed(ref m) if m.contains("timed out")));
    let rows = db.get_attestations(&hex::encode(pk.to_bytes())).unwrap();
    assert_eq!(rows.len(), 1, "gRPC timeout must retain like HTTP remote");
}

#[tokio::test]
async fn test_validator_signer_request_bytes_match_direct_typed_signer() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, capture, _handle) = start_capturing_server(sk.to_bytes()).await;
    let grpc = connect_grpc(addr).await;
    let ctx = phase0_ctx(pk.clone());
    let schedule = phase0_schedule();

    // Direct TypedSigner (grpc-signer's own path).
    TypedSigner::sign_attestation(&grpc, &att_data(), &ctx).await.unwrap();
    let direct_att = capture.lock().unwrap().get("sign_attestation_data").cloned().unwrap();
    capture.lock().unwrap().clear();

    let svc = grpc_vc(grpc);
    svc.sign_attestation(&att_data(), &pk, &schedule, &GVR).await.unwrap();
    let via_vc = capture.lock().unwrap().get("sign_attestation_data").cloned().unwrap();
    assert_eq!(direct_att, via_vc, "attestation request bytes must match grpc-signer");
}

#[tokio::test]
async fn test_aggregate_and_header_request_bytes_match_direct_typed_signer() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, capture, _handle) = start_capturing_server(sk.to_bytes()).await;
    let grpc = connect_grpc(addr).await;
    let ctx = phase0_ctx(pk.clone());
    let schedule = phase0_schedule();

    TypedSigner::sign_aggregate_and_proof(&grpc, &aggregate(), &ctx).await.unwrap();
    let direct_agg = capture.lock().unwrap().get("sign_aggregate_and_proof").cloned().unwrap();
    let (hdr, block) = header_with_electra_body(100);
    TypedSigner::sign_block(&grpc, &block, &ctx).await.unwrap();
    let direct_block = capture.lock().unwrap().get("sign_beacon_block").cloned().unwrap();
    capture.lock().unwrap().clear();

    let svc = grpc_vc(grpc);
    svc.sign_aggregate_and_proof(&aggregate(), &pk, &schedule, &GVR).await.unwrap();
    svc.sign_block_header(&hdr, &pk, &schedule, &GVR).await.unwrap();
    let via_agg = capture.lock().unwrap().get("sign_aggregate_and_proof").cloned().unwrap();
    let via_block = capture.lock().unwrap().get("sign_beacon_block").cloned().unwrap();
    assert_eq!(direct_agg, via_agg);
    assert_eq!(via_block, direct_block, "header with body must speak SignBeaconBlock");
}

#[tokio::test]
async fn test_remaining_duties_request_bytes_match_direct_typed_signer() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, capture, _handle) = start_capturing_server(sk.to_bytes()).await;
    let grpc = connect_grpc(addr).await;
    let ctx = phase0_ctx(pk.clone());
    let schedule = phase0_schedule();
    let exit = VoluntaryExit { epoch: 1, validator_index: 0 };
    let cap = contribution();
    let reg = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 1,
        timestamp: 2,
        pubkey: pk.to_bytes(),
    };

    TypedSigner::sign_randao_reveal(&grpc, 3, &ctx).await.unwrap();
    TypedSigner::sign_sync_committee_message(&grpc, 100, [0x88; 32], &ctx).await.unwrap();
    TypedSigner::sign_sync_aggregator_selection(&grpc, 100, 2, &ctx).await.unwrap();
    TypedSigner::sign_contribution_and_proof(&grpc, &cap, &ctx).await.unwrap();
    TypedSigner::sign_voluntary_exit(&grpc, &exit, &ctx).await.unwrap();
    TypedSigner::sign_builder_registration(&grpc, &reg, [0; 4], &ctx).await.unwrap();
    let mut direct = HashMap::new();
    {
        let cap_map = capture.lock().unwrap();
        for k in [
            "sign_randao_reveal",
            "sign_sync_committee_message",
            "sign_sync_aggregator_selection_data",
            "sign_contribution_and_proof",
            "sign_voluntary_exit",
            "sign_builder_registration",
        ] {
            direct.insert(k, cap_map.get(k).cloned().unwrap());
        }
    }
    capture.lock().unwrap().clear();

    let svc = grpc_vc(grpc);
    svc.sign_randao_reveal(3, &pk, &schedule, &GVR).await.unwrap();
    svc.sign_sync_committee_message(&[0x88; 32], 100, &pk, &schedule, &GVR).await.unwrap();
    svc.sign_sync_committee_selection_proof(100, 2, &pk, &schedule, &GVR).await.unwrap();
    svc.sign_contribution_and_proof(&cap, &pk, &schedule, &GVR).await.unwrap();
    svc.sign_voluntary_exit(&exit, &pk, &schedule, &GVR).await.unwrap();
    svc.sign_builder_registration(&reg, &pk, [0; 4]).await.unwrap();
    let via = capture.lock().unwrap();
    for (k, bytes) in direct {
        assert_eq!(via.get(k).expect(k), &bytes, "{k} request bytes");
    }
}

#[tokio::test]
async fn test_sign_block_header_matches_sign_block_at_fulu_via_local_key() {
    // Local-key identity is also covered in unit tests; this locks Fulu via the
    // same ValidatorSigner surface the gRPC facade uses.
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let db1 = open_db();
    let db2 = open_db();
    let header_svc =
        SignerService::new(Arc::clone(&composite), db1).with_enablement(always_enabled());
    let block_svc = SignerService::new(composite, db2).with_enablement(always_enabled());
    let schedule = fulu_schedule();
    let slot = 60 * SLOTS_PER_EPOCH;
    let hdr = header(slot);
    let block_root = hdr.object_root();
    let a = header_svc.sign_block_header(&hdr, &pk, &schedule, &GVR).await.unwrap();
    let b = block_svc.sign_block(&block_root, slot, &pk, &schedule, &GVR).await.unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
}

struct MemBackend {
    km: KeyManager,
}

#[async_trait]
impl signer_server::backend::SigningBackend for MemBackend {
    async fn sign(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<[u8; 96], signer_server::backend::SigningBackendError> {
        let pk = PublicKey::from_bytes(pubkey)
            .map_err(|_| signer_server::backend::SigningBackendError::KeyNotFound(*pubkey))?;
        let sk = self
            .km
            .get_secret_key(&pk)
            .ok_or(signer_server::backend::SigningBackendError::KeyNotFound(*pubkey))?;
        Ok(sk.sign(signing_root).to_bytes())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
    }
}

#[tokio::test]
async fn test_in_process_signer_server_attestation_via_facade() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    let backend = Arc::new(MemBackend { km });
    let db = open_db();
    let impl_svc =
        signer_server::service::SignerServiceImpl::new_v2(backend, "test".to_string(), db);

    allow_insecure();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(signer_server::SignerServiceServerV2::new(impl_svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let grpc = connect_grpc(addr).await;
    let svc = grpc_vc(grpc);
    svc.sign_attestation(&att_data(), &pk, &phase0_schedule(), &GVR)
        .await
        .expect("legacy attestation RPC through in-process signer-server");
}

fn gloas_schedule() -> ForkSchedule {
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
        gloas_fork_epoch: 70,
        gloas_fork_version: [7, 0, 0, 0],
    }
}

#[tokio::test]
async fn test_gloas_vc_path_reaches_in_process_signer_server() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    let backend = Arc::new(MemBackend { km });
    let db = open_db();
    let impl_svc =
        signer_server::service::SignerServiceImpl::new_v2(backend, "test".to_string(), db);

    allow_insecure();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(signer_server::SignerServiceServerV2::new(impl_svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let grpc = connect_grpc(addr).await;
    let gloas_ctx = SignContext::new(
        pk.clone(),
        ForkInfo {
            previous_version: [6, 0, 0, 0],
            current_version: [7, 0, 0, 0],
            genesis_validators_root: GVR,
        },
        ForkName::Gloas,
    );
    let env_err = grpc
        .sign_root([0x11; 32], Duty::ExecutionPayloadEnvelope as i32, &gloas_ctx)
        .await
        .expect_err("envelope UNIMPLEMENTED until P6");
    match env_err {
        SigningError::SignerLacksGloasSupport { rpc, details } => {
            assert_eq!(rpc, "SignRoot");
            assert!(
                details.contains("EXECUTION_PAYLOAD_ENVELOPE") || details.contains("6.19"),
                "{details}"
            );
        }
        other => panic!("expected SignerLacksGloasSupport for envelope, got {other:?}"),
    }
    let auth_err = grpc
        .sign_root([0x11; 32], Duty::BuilderRequestAuth as i32, &gloas_ctx)
        .await
        .expect_err("request-auth UNIMPLEMENTED until P6");
    match auth_err {
        SigningError::SignerLacksGloasSupport { rpc, details } => {
            assert_eq!(rpc, "SignRoot");
            assert!(
                details.contains("BUILDER_REQUEST_AUTH") || details.contains("6.16"),
                "{details}"
            );
        }
        other => panic!("expected SignerLacksGloasSupport for request-auth, got {other:?}"),
    }

    let svc = grpc_vc(grpc);
    let schedule = gloas_schedule();
    let slot = 70 * SLOTS_PER_EPOCH;
    let hdr = header(slot);
    svc.sign_block_header(&hdr, &pk, &schedule, &GVR)
        .await
        .expect("Gloas block header through in-process signer-server");

    let mut agg = aggregate();
    agg.aggregate.data.slot = slot;
    svc.sign_aggregate_and_proof(&agg, &pk, &schedule, &GVR)
        .await
        .expect("Gloas aggregate through in-process signer-server");

    let ptc_msg = PayloadAttestationData {
        beacon_block_root: [0x11; 32],
        slot,
        payload_present: true,
        blob_data_available: false,
    };
    svc.sign_payload_attestation(&ptc_msg, &pk, &schedule, &GVR)
        .await
        .expect("Gloas PTC through in-process signer-server");

    let mut prefs_msg = prefs();
    prefs_msg.proposal_slot = slot;
    svc.sign_proposer_preferences(&prefs_msg, &pk, &schedule, &GVR)
        .await
        .expect("Gloas proposer preferences through in-process signer-server");

    let mut electra = electra_aggregate();
    electra.aggregate.data.slot = slot;
    let gloas_version = [7, 0, 0, 0];
    let electra_sr =
        signing_root_with_fork_version(&electra, DOMAIN_AGGREGATE_AND_PROOF, gloas_version, GVR);
    let stripped = AggregateAndProof {
        aggregator_index: electra.aggregator_index,
        aggregate: Attestation {
            aggregation_bits: electra.aggregate.aggregation_bits.clone(),
            data: electra.aggregate.data.clone(),
            signature: electra.aggregate.signature.clone(),
        },
        selection_proof: electra.selection_proof.clone(),
    };
    let stripped_sr =
        signing_root_with_fork_version(&stripped, DOMAIN_AGGREGATE_AND_PROOF, gloas_version, GVR);
    assert_ne!(
        electra_sr, stripped_sr,
        "committee_bits must participate in the Gloas Electra aggregate object root"
    );
    let sig = svc
        .sign_electra_aggregate_and_proof(&electra, &pk, &schedule, &GVR)
        .await
        .expect("Gloas Electra aggregate through in-process signer-server");
    assert!(sig.verify(&pk, &electra_sr).is_ok());
    assert!(
        sig.verify(&pk, &stripped_sr).is_err(),
        "must not sign the committee_bits-stripped pre-Electra root"
    );
}

#[tokio::test]
async fn test_gloas_header_with_body_ssz_selects_sign_block_header() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, capture, _handle) = start_capturing_server(sk.to_bytes()).await;
    let grpc = connect_grpc(addr).await;
    let svc = grpc_vc(grpc);
    let schedule = gloas_schedule();
    let slot = 70 * SLOTS_PER_EPOCH;
    let (hdr, _) = header_with_electra_body(slot);
    assert!(!hdr.body_ssz.is_empty(), "production fills body_ssz");
    svc.sign_block_header(&hdr, &pk, &schedule, &GVR).await.expect("Gloas header with body_ssz");
    let captured = capture.lock().unwrap();
    assert!(
        captured.contains_key("sign_block_header"),
        "Gloas populated body_ssz must still select SignBlockHeader"
    );
    assert!(
        !captured.contains_key("sign_beacon_block"),
        "body_ssz must not go to SignBeaconBlock at Gloas"
    );
    let bytes = captured.get("sign_block_header").expect("header RPC");
    let req = SignBlockHeaderRequest::decode(bytes.as_slice()).expect("decode header request");
    assert_eq!(req.fork_id, 7);
    let header = req.header.expect("header leaves");
    assert_eq!(header.body_root, hdr.body_root.to_vec());
    assert!(
        !bytes.windows(hdr.body_ssz.len()).any(|w| w == hdr.body_ssz.as_slice()),
        "body_ssz must not appear on the SignBlockHeader wire"
    );
}
