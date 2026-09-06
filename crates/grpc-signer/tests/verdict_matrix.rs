//! 4.20c per-duty Gloas verdict matrix, fork routing, and new-client/old-server.
//!
//! Test names avoid a trailing `_root` (KAT policy).

#![allow(clippy::disallowed_methods)]
#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use crypto::typed_signer::{SignContext, TypedSigner};
use crypto::{
    compute_domain, compute_signing_root, SecretKey, DOMAIN_BEACON_ATTESTER, DOMAIN_RANDAO,
};
use eth_types::{
    decode_attestation_ssz, decode_beacon_block_ssz, decode_blinded_beacon_block_ssz,
    decode_sync_committee_contribution_ssz, encode_attestation_ssz, encode_beacon_block_ssz,
    encode_blinded_beacon_block_ssz, encode_sync_committee_contribution_ssz, AggregateAndProof,
    Attestation, AttestationData, BeaconBlock, BeaconBlockHeader, BlindedBeaconBlock,
    BuilderRequestAuth, Checkpoint, ContributionAndProof, ElectraAggregateAndProof,
    ElectraAttestation, ForkInfo, ForkName, ForkSchedule, PayloadAttestationData,
    ProposerPreferences, SyncAggregatorSelectionData, SyncCommitteeContribution,
    ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_BUILDER_REQUEST_AUTH, DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
use prost::Message;
use rvc_grpc_signer::{
    proto::signer_v2::{
        signer_service_client::SignerServiceClient,
        signer_service_server::{
            SignerService as SignerServiceV2, SignerServiceServer as SignerServiceServerV2,
        },
        Duty, ForkInfo as ProtoForkInfo, GetStatusRequest as GetStatusRequestV2,
        GetStatusResponse as GetStatusResponseV2, ListPublicKeysRequest as ListPublicKeysRequestV2,
        ListPublicKeysResponse as ListPublicKeysResponseV2, SignAggregateAndProofRequest,
        SignAttestationDataRequest, SignBeaconBlockRequest, SignBlindedBeaconBlockRequest,
        SignBlockHeaderRequest, SignBuilderRegistrationRequest, SignContributionAndProofRequest,
        SignRandaoRevealRequest, SignResponse, SignRootRequest,
        SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
        SignVoluntaryExitRequest,
    },
    GrpcRemoteSigner, GrpcRemoteSignerConfig,
};
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};

type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

fn allow_insecure_for_tests() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| unsafe {
        std::env::set_var(rvc_grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR, "true");
    });
}

fn insecure_grpc_config(addr: SocketAddr) -> GrpcRemoteSignerConfig {
    allow_insecure_for_tests();
    GrpcRemoteSignerConfig::new(format!("http://{addr}"))
}

fn gvr() -> [u8; 32] {
    [0xab; 32]
}

fn fulu_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: [0x05, 0, 0, 0],
        current_version: [0x06, 0, 0, 0],
        genesis_validators_root: gvr(),
    }
}

fn gloas_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: [0x06, 0, 0, 0],
        current_version: [0x07, 0, 0, 0],
        genesis_validators_root: gvr(),
    }
}

fn fulu_ctx(pk: crypto::PublicKey) -> SignContext {
    SignContext::new(pk, fulu_fork_info(), ForkName::Fulu)
}

fn gloas_ctx(pk: crypto::PublicKey) -> SignContext {
    SignContext::new(pk, gloas_fork_info(), ForkName::Gloas)
}

fn far_future_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: 0,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: 0,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch: 0,
        capella_fork_version: [3, 0, 0, 0],
        deneb_fork_epoch: 0,
        deneb_fork_version: [4, 0, 0, 0],
        electra_fork_epoch: 0,
        electra_fork_version: [5, 0, 0, 0],
        fulu_fork_epoch: 0,
        fulu_fork_version: [6, 0, 0, 0],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [7, 0, 0, 0],
    }
}

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

fn full_block() -> BeaconBlock {
    BeaconBlock {
        slot: 100,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    }
}

fn blinded_block() -> BlindedBeaconBlock {
    BlindedBeaconBlock {
        slot: 200,
        proposer_index: 2,
        parent_root: [0x33; 32],
        state_root: [0x44; 32],
        body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
    }
}

fn header() -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: 100,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
    }
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

fn auth() -> BuilderRequestAuth {
    BuilderRequestAuth::new(hex::decode("1234567890abcdef").unwrap(), 1).unwrap()
}

fn proto_fork(ctx: &SignContext) -> ProtoForkInfo {
    ProtoForkInfo {
        previous_version: ctx.fork_info.previous_version.to_vec(),
        current_version: ctx.fork_info.current_version.to_vec(),
        epoch: 0,
        genesis_validators_root: ctx.fork_info.genesis_validators_root.to_vec(),
    }
}

// ── Signing mock ──────────────────────────────────────────────────────────────

struct SigningV2 {
    sk: SecretKey,
}

impl SigningV2 {
    fn bls_sign(&self, root: &[u8; 32]) -> Vec<u8> {
        self.sk.sign(root).to_bytes().to_vec()
    }

    fn extract_fork(fi: &ProtoForkInfo) -> ([u8; 4], [u8; 32]) {
        let curr: [u8; 4] = fi.current_version.as_slice().try_into().unwrap_or([0u8; 4]);
        let gvr: [u8; 32] = fi.genesis_validators_root.as_slice().try_into().unwrap_or([0u8; 32]);
        (curr, gvr)
    }
}

struct RecordingV2 {
    inner: SigningV2,
    calls: Calls,
    /// When true, Gloas RPCs return `UNIMPLEMENTED` (old-server double).
    legacy_only: bool,
}

impl RecordingV2 {
    fn record(&self, name: &str, bytes: Vec<u8>) {
        self.calls.lock().unwrap().push((name.to_string(), bytes));
    }

    fn names(calls: &Calls) -> Vec<String> {
        calls.lock().unwrap().iter().map(|(n, _)| n.clone()).collect()
    }

    fn bytes(calls: &Calls, name: &str) -> Vec<u8> {
        calls
            .lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.clone())
            .unwrap_or_else(|| panic!("missing recorded RPC {name}"))
    }
}

macro_rules! delegate_sign {
    ($self:ident, $name:literal, $request:ident, $method:ident) => {{
        let inner = $request.into_inner();
        $self.record($name, inner.encode_to_vec());
        $self.inner.$method(Request::new(inner)).await
    }};
}

#[tonic::async_trait]
impl SignerServiceV2 for SigningV2 {
    async fn sign_beacon_block(
        &self,
        request: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let block = decode_beacon_block_ssz(&r.block_ssz, r.fork_id)
            .map_err(|e| Status::invalid_argument(format!("SSZ decode: {e}")))?;
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, curr, gvr);
        let root = compute_signing_root(&block, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_blinded_beacon_block(
        &self,
        request: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let block = decode_blinded_beacon_block_ssz(&r.block_ssz, r.fork_id)
            .map_err(|e| Status::invalid_argument(format!("SSZ decode: {e}")))?;
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, curr, gvr);
        let root = compute_signing_root(&block, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_attestation_data(
        &self,
        request: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let proto_data = r.data.as_ref().ok_or_else(|| Status::invalid_argument("missing data"))?;
        let src =
            proto_data.source.as_ref().ok_or_else(|| Status::invalid_argument("missing source"))?;
        let tgt =
            proto_data.target.as_ref().ok_or_else(|| Status::invalid_argument("missing target"))?;
        let data = AttestationData {
            slot: proto_data.slot,
            index: proto_data.index,
            beacon_block_root: proto_data
                .beacon_block_root
                .as_slice()
                .try_into()
                .unwrap_or([0; 32]),
            source: Checkpoint {
                epoch: src.epoch,
                root: src.root.as_slice().try_into().unwrap_or([0; 32]),
            },
            target: Checkpoint {
                epoch: tgt.epoch,
                root: tgt.root.as_slice().try_into().unwrap_or([0; 32]),
            },
        };
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, curr, gvr);
        let root = compute_signing_root(&data, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_aggregate_and_proof(
        &self,
        request: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let aggregate = decode_attestation_ssz(&r.aggregate_ssz, r.fork_id)
            .map_err(|e| Status::invalid_argument(format!("SSZ decode: {e}")))?;
        let agg = AggregateAndProof {
            aggregator_index: r.aggregator_index,
            aggregate,
            selection_proof: r.selection_proof,
        };
        let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, curr, gvr);
        let root = compute_signing_root(&agg, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_sync_committee_message(
        &self,
        request: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let bbr: [u8; 32] = r.beacon_block_root.as_slice().try_into().unwrap_or([0; 32]);
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, curr, gvr);
        let root = compute_signing_root(&bbr, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_sync_aggregator_selection_data(
        &self,
        request: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let sel =
            SyncAggregatorSelectionData { slot: r.slot, subcommittee_index: r.subcommittee_index };
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, curr, gvr);
        let root = compute_signing_root(&sel, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_contribution_and_proof(
        &self,
        request: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let contribution = decode_sync_committee_contribution_ssz(&r.contribution_ssz, r.fork_id)
            .map_err(|e| Status::invalid_argument(format!("SSZ decode: {e}")))?;
        let cap = ContributionAndProof {
            aggregator_index: r.aggregator_index,
            contribution,
            selection_proof: r.selection_proof,
        };
        let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, curr, gvr);
        let root = compute_signing_root(&cap, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_builder_registration(
        &self,
        request: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
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
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, gfv, [0u8; 32]);
        let root = compute_signing_root(&reg, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_randao_reveal(
        &self,
        request: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let domain = compute_domain(DOMAIN_RANDAO, curr, gvr);
        let root = compute_signing_root(&r.epoch, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_voluntary_exit(
        &self,
        request: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let exit = VoluntaryExit { epoch: r.epoch, validator_index: r.validator_index };
        let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, curr, gvr);
        let root = compute_signing_root(&exit, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_block_header(
        &self,
        request: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        if r.fork_id == u32::MAX || r.fork_id == 8 {
            return Err(Status::invalid_argument(format!("unknown fork id: {}", r.fork_id)));
        }
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (curr, gvr) = Self::extract_fork(fi);
        let h = r.header.as_ref().ok_or_else(|| Status::invalid_argument("header"))?;
        let header = BeaconBlockHeader {
            slot: h.slot,
            proposer_index: h.proposer_index,
            parent_root: h.parent_root.as_slice().try_into().unwrap_or([0; 32]),
            state_root: h.state_root.as_slice().try_into().unwrap_or([0; 32]),
            body_root: h.body_root.as_slice().try_into().unwrap_or([0; 32]),
        };
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, curr, gvr);
        let root = compute_signing_root(&header, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_root(
        &self,
        request: Request<SignRootRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        if r.fork_id == u32::MAX || r.fork_id == 8 {
            return Err(Status::invalid_argument(format!("unknown fork id: {}", r.fork_id)));
        }
        let duty = Duty::try_from(r.duty)
            .map_err(|_| Status::invalid_argument(format!("unknown duty: {}", r.duty)))?;
        match duty {
            Duty::Unspecified => Err(Status::invalid_argument("duty must not be UNSPECIFIED")),
            Duty::ExecutionPayloadEnvelope => {
                Err(Status::unimplemented("EXECUTION_PAYLOAD_ENVELOPE (issue 6.19)"))
            }
            Duty::BuilderRequestAuth => {
                let object_root: [u8; 32] = r
                    .object_root
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("object_root"))?;
                let domain = compute_domain(DOMAIN_BUILDER_REQUEST_AUTH, [0u8; 4], [0u8; 32]);
                let root = compute_signing_root(&object_root, domain);
                Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
            }
            other => {
                let fi = r
                    .fork_info
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
                let (curr, gvr) = Self::extract_fork(fi);
                let object_root: [u8; 32] = r
                    .object_root
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("object_root"))?;
                let domain_type = match other {
                    Duty::AggregateAndProof => DOMAIN_AGGREGATE_AND_PROOF,
                    Duty::ContributionAndProof => DOMAIN_CONTRIBUTION_AND_PROOF,
                    Duty::PayloadAttestation => DOMAIN_PTC_ATTESTER,
                    Duty::ProposerPreferences => DOMAIN_PROPOSER_PREFERENCES,
                    _ => unreachable!("filtered above"),
                };
                let domain = compute_domain(domain_type, curr, gvr);
                let root = compute_signing_root(&object_root, domain);
                Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
            }
        }
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequestV2>,
    ) -> Result<Response<ListPublicKeysResponseV2>, Status> {
        Ok(Response::new(ListPublicKeysResponseV2 {
            pubkeys: vec![self.sk.public_key().to_bytes().to_vec()],
        }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequestV2>,
    ) -> Result<Response<GetStatusResponseV2>, Status> {
        Ok(Response::new(GetStatusResponseV2 {
            ready: true,
            backend: "verdict-matrix".into(),
            key_count: 1,
        }))
    }
}

#[tonic::async_trait]
impl SignerServiceV2 for RecordingV2 {
    async fn sign_beacon_block(
        &self,
        request: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_beacon_block", request, sign_beacon_block)
    }
    async fn sign_blinded_beacon_block(
        &self,
        request: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_blinded_beacon_block", request, sign_blinded_beacon_block)
    }
    async fn sign_attestation_data(
        &self,
        request: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_attestation_data", request, sign_attestation_data)
    }
    async fn sign_aggregate_and_proof(
        &self,
        request: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_aggregate_and_proof", request, sign_aggregate_and_proof)
    }
    async fn sign_sync_committee_message(
        &self,
        request: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_sync_committee_message", request, sign_sync_committee_message)
    }
    async fn sign_sync_aggregator_selection_data(
        &self,
        request: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(
            self,
            "sign_sync_aggregator_selection_data",
            request,
            sign_sync_aggregator_selection_data
        )
    }
    async fn sign_contribution_and_proof(
        &self,
        request: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_contribution_and_proof", request, sign_contribution_and_proof)
    }
    async fn sign_builder_registration(
        &self,
        request: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_builder_registration", request, sign_builder_registration)
    }
    async fn sign_randao_reveal(
        &self,
        request: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_randao_reveal", request, sign_randao_reveal)
    }
    async fn sign_voluntary_exit(
        &self,
        request: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        delegate_sign!(self, "sign_voluntary_exit", request, sign_voluntary_exit)
    }
    async fn sign_block_header(
        &self,
        request: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let inner = request.into_inner();
        self.record("sign_block_header", inner.encode_to_vec());
        if self.legacy_only {
            return Err(Status::unimplemented("SignBlockHeader"));
        }
        self.inner.sign_block_header(Request::new(inner)).await
    }
    async fn sign_root(
        &self,
        request: Request<SignRootRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let inner = request.into_inner();
        self.record("sign_root", inner.encode_to_vec());
        if self.legacy_only {
            return Err(Status::unimplemented("SignRoot"));
        }
        self.inner.sign_root(Request::new(inner)).await
    }
    async fn list_public_keys(
        &self,
        request: Request<ListPublicKeysRequestV2>,
    ) -> Result<Response<ListPublicKeysResponseV2>, Status> {
        self.inner.list_public_keys(request).await
    }
    async fn get_status(
        &self,
        request: Request<GetStatusRequestV2>,
    ) -> Result<Response<GetStatusResponseV2>, Status> {
        self.inner.get_status(request).await
    }
}

async fn start_recording_server(
    sk: SecretKey,
    legacy_only: bool,
) -> (SocketAddr, Calls, tokio::task::JoinHandle<()>) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = RecordingV2 { inner: SigningV2 { sk }, calls: Arc::clone(&calls), legacy_only };
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SignerServiceServerV2::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, calls, handle)
}

async fn connect(addr: SocketAddr) -> GrpcRemoteSigner {
    GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap()
}

fn assert_legacy_only(names: &[String]) {
    for n in names {
        assert!(
            n != "sign_block_header" && n != "sign_root",
            "far-future / pre-Gloas must not select Gloas RPCs, got {names:?}"
        );
    }
}

fn assert_gloas_wire_fork_id(calls: &Calls) {
    for (name, bytes) in calls.lock().unwrap().iter() {
        match name.as_str() {
            "sign_block_header" => {
                let r = SignBlockHeaderRequest::decode(bytes.as_slice()).unwrap();
                assert_eq!(r.fork_id, 7, "Gloas SignBlockHeader fork_id");
            }
            "sign_root" => {
                let r = SignRootRequest::decode(bytes.as_slice()).unwrap();
                assert_eq!(r.fork_id, 7, "Gloas SignRoot fork_id");
            }
            _ => {}
        }
    }
}

async fn sign_legacy_duties(signer: &GrpcRemoteSigner, ctx: &SignContext, pk_bytes: [u8; 48]) {
    TypedSigner::sign_block(signer, &full_block(), ctx).await.unwrap();
    TypedSigner::sign_blinded_block(signer, &blinded_block(), ctx).await.unwrap();
    TypedSigner::sign_attestation(signer, &att_data(), ctx).await.unwrap();
    TypedSigner::sign_aggregate_and_proof(signer, &aggregate(), ctx).await.unwrap();
    TypedSigner::sign_sync_committee_message(signer, 500, [0x88; 32], ctx).await.unwrap();
    TypedSigner::sign_sync_aggregator_selection(signer, 600, 3, ctx).await.unwrap();
    TypedSigner::sign_contribution_and_proof(signer, &contribution(), ctx).await.unwrap();
    let reg = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1,
        pubkey: pk_bytes,
    };
    TypedSigner::sign_builder_registration(signer, &reg, [0; 4], ctx).await.unwrap();
    TypedSigner::sign_randao_reveal(signer, 42, ctx).await.unwrap();
    TypedSigner::sign_voluntary_exit(
        signer,
        &VoluntaryExit { epoch: 200, validator_index: 99 },
        ctx,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_gloas_verdict_matrix_supported_duties_sign() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, calls, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = gloas_ctx(pk.clone());

    let rows: Vec<(&str, crypto::Signature)> = vec![
        ("attestation", TypedSigner::sign_attestation(&signer, &att_data(), &ctx).await.unwrap()),
        (
            "sync_message",
            TypedSigner::sign_sync_committee_message(&signer, 500, [0x88; 32], &ctx).await.unwrap(),
        ),
        (
            "sync_selection",
            TypedSigner::sign_sync_aggregator_selection(&signer, 600, 3, &ctx).await.unwrap(),
        ),
        ("randao", TypedSigner::sign_randao_reveal(&signer, 42, &ctx).await.unwrap()),
        (
            "voluntary_exit",
            TypedSigner::sign_voluntary_exit(
                &signer,
                &VoluntaryExit { epoch: 200, validator_index: 99 },
                &ctx,
            )
            .await
            .unwrap(),
        ),
        (
            "builder",
            TypedSigner::sign_builder_registration(
                &signer,
                &ValidatorRegistrationV1 {
                    fee_recipient: [0xab; 20],
                    gas_limit: 1,
                    timestamp: 1,
                    pubkey: pk.to_bytes(),
                },
                [0; 4],
                &ctx,
            )
            .await
            .unwrap(),
        ),
        ("header", TypedSigner::sign_block_header(&signer, &header(), &ctx).await.unwrap()),
        (
            "aggregate",
            TypedSigner::sign_aggregate_and_proof(&signer, &aggregate(), &ctx).await.unwrap(),
        ),
        (
            "electra_aggregate",
            TypedSigner::sign_electra_aggregate_and_proof(&signer, &electra_aggregate(), &ctx)
                .await
                .unwrap(),
        ),
        (
            "contribution",
            TypedSigner::sign_contribution_and_proof(&signer, &contribution(), &ctx).await.unwrap(),
        ),
        ("ptc", TypedSigner::sign_payload_attestation(&signer, &ptc(), &ctx).await.unwrap()),
        ("prefs", TypedSigner::sign_proposer_preferences(&signer, &prefs(), &ctx).await.unwrap()),
        (
            "builder_request_auth",
            TypedSigner::sign_builder_request_auth(&signer, &auth(), [0; 4], &ctx).await.unwrap(),
        ),
    ];
    for (name, sig) in &rows {
        assert_eq!(sig.to_bytes().len(), 96, "{name} must produce a 96-byte signature");
    }
    let names = RecordingV2::names(&calls);
    assert!(
        !names.iter().any(|n| n == "sign_beacon_block" || n == "sign_blinded_beacon_block"),
        "Gloas block must not use legacy SSZ RPCs: {names:?}"
    );
    assert!(
        !names
            .iter()
            .any(|n| n == "sign_aggregate_and_proof" || n == "sign_contribution_and_proof"),
        "Gloas aggregate/contribution must not use legacy SSZ RPCs: {names:?}"
    );
    assert!(names.iter().any(|n| n == "sign_block_header"), "block row uses header RPC: {names:?}");
    assert!(names.iter().any(|n| n == "sign_root"), "root-RPC duties selected: {names:?}");
    assert!(
        names.iter().any(|n| n == "sign_attestation_data"),
        "attestation stays on legacy RPC even at Gloas (id 7 ignored server-side)"
    );
    assert_gloas_wire_fork_id(&calls);

    let block_err = TypedSigner::sign_block(&signer, &full_block(), &ctx).await.unwrap_err();
    match block_err {
        crypto::SigningError::LocalRejected(msg) => {
            assert!(msg.contains("sign_block_header"), "{msg}");
        }
        other => panic!("Gloas sign_block must refuse Electra body hash, got {other:?}"),
    }
}

#[tokio::test]
async fn test_fulu_request_bytes_match_legacy_shape() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, calls, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = fulu_ctx(pk.clone());
    sign_legacy_duties(&signer, &ctx, pk.to_bytes()).await;

    let fork_id = ForkName::Fulu.id();
    let block = full_block();
    let expected = SignBeaconBlockRequest {
        pubkey: pk.to_bytes().to_vec(),
        fork_info: Some(proto_fork(&ctx)),
        block_ssz: encode_beacon_block_ssz(&block, fork_id),
        fork_id,
    };
    assert_eq!(RecordingV2::bytes(&calls, "sign_beacon_block"), expected.encode_to_vec());

    let blinded = blinded_block();
    let expected = SignBlindedBeaconBlockRequest {
        pubkey: pk.to_bytes().to_vec(),
        fork_info: Some(proto_fork(&ctx)),
        block_ssz: encode_blinded_beacon_block_ssz(&blinded, fork_id),
        fork_id,
    };
    assert_eq!(RecordingV2::bytes(&calls, "sign_blinded_beacon_block"), expected.encode_to_vec());

    let data = att_data();
    let expected = SignAttestationDataRequest {
        pubkey: pk.to_bytes().to_vec(),
        fork_info: Some(proto_fork(&ctx)),
        data: Some(rvc_grpc_signer::proto::signer_v2::AttestationData {
            slot: data.slot,
            index: data.index,
            beacon_block_root: data.beacon_block_root.to_vec(),
            source: Some(rvc_grpc_signer::proto::signer_v2::Checkpoint {
                epoch: data.source.epoch,
                root: data.source.root.to_vec(),
            }),
            target: Some(rvc_grpc_signer::proto::signer_v2::Checkpoint {
                epoch: data.target.epoch,
                root: data.target.root.to_vec(),
            }),
        }),
        fork_id,
    };
    assert_eq!(RecordingV2::bytes(&calls, "sign_attestation_data"), expected.encode_to_vec());

    let agg = aggregate();
    let expected = SignAggregateAndProofRequest {
        pubkey: pk.to_bytes().to_vec(),
        fork_info: Some(proto_fork(&ctx)),
        aggregator_index: agg.aggregator_index,
        aggregate_ssz: encode_attestation_ssz(&agg.aggregate, fork_id),
        selection_proof: agg.selection_proof.clone(),
        fork_id,
    };
    assert_eq!(RecordingV2::bytes(&calls, "sign_aggregate_and_proof"), expected.encode_to_vec());

    let cap = contribution();
    let expected = SignContributionAndProofRequest {
        pubkey: pk.to_bytes().to_vec(),
        fork_info: Some(proto_fork(&ctx)),
        aggregator_index: cap.aggregator_index,
        contribution_ssz: encode_sync_committee_contribution_ssz(&cap.contribution, fork_id),
        selection_proof: cap.selection_proof.clone(),
        fork_id,
    };
    assert_eq!(RecordingV2::bytes(&calls, "sign_contribution_and_proof"), expected.encode_to_vec());

    let names = RecordingV2::names(&calls);
    assert_legacy_only(&names);
}

#[tokio::test]
async fn test_gloas_block_aggregate_contribution_use_new_rpcs_only() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, calls, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = gloas_ctx(pk);
    TypedSigner::sign_block_header(&signer, &header(), &ctx).await.unwrap();
    TypedSigner::sign_aggregate_and_proof(&signer, &aggregate(), &ctx).await.unwrap();
    TypedSigner::sign_contribution_and_proof(&signer, &contribution(), &ctx).await.unwrap();
    let names = RecordingV2::names(&calls);
    assert_eq!(
        names,
        vec!["sign_block_header".to_string(), "sign_root".to_string(), "sign_root".to_string()]
    );
    assert_gloas_wire_fork_id(&calls);
}

#[tokio::test]
async fn test_gloas_electra_aggregate_keeps_committee_bits() {
    use tree_hash::TreeHash;

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, calls, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = gloas_ctx(pk);
    let electra = electra_aggregate();
    TypedSigner::sign_electra_aggregate_and_proof(&signer, &electra, &ctx).await.unwrap();
    let bytes = RecordingV2::bytes(&calls, "sign_root");
    let req = SignRootRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(req.fork_id, 7);
    assert_eq!(req.object_root, electra.tree_hash_root().0.to_vec());
    let stripped = AggregateAndProof {
        aggregator_index: electra.aggregator_index,
        aggregate: Attestation {
            aggregation_bits: electra.aggregate.aggregation_bits.clone(),
            data: electra.aggregate.data.clone(),
            signature: electra.aggregate.signature.clone(),
        },
        selection_proof: electra.selection_proof.clone(),
    };
    assert_ne!(req.object_root, stripped.tree_hash_root().0.to_vec());
}

#[tokio::test]
async fn test_far_future_gloas_epoch_selects_legacy_rpcs_only() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, calls, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = SignContext::resolve(pk.clone(), fulu_fork_info(), &far_future_schedule())
        .expect("Fulu version must resolve while Gloas is unscheduled");
    assert_eq!(ctx.fork_name, ForkName::Fulu);
    sign_legacy_duties(&signer, &ctx, pk.to_bytes()).await;
    let names = RecordingV2::names(&calls);
    assert_legacy_only(&names);
    assert!(names.iter().any(|n| n == "sign_beacon_block"));
    assert!(names.iter().any(|n| n == "sign_aggregate_and_proof"));
    assert!(names.iter().any(|n| n == "sign_contribution_and_proof"));
    assert!(names.iter().any(|n| n == "sign_blinded_beacon_block"));
}

#[tokio::test]
async fn test_new_client_old_server_gloas_is_typed_no_retry() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, calls, _h) = start_recording_server(sk, true).await;
    let signer = connect(addr).await;
    let fulu = fulu_ctx(pk.clone());
    TypedSigner::sign_attestation(&signer, &att_data(), &fulu).await.unwrap();
    TypedSigner::sign_block(&signer, &full_block(), &fulu).await.unwrap();

    let gloas = gloas_ctx(pk);
    let err = TypedSigner::sign_block_header(&signer, &header(), &gloas).await.unwrap_err();
    match err {
        crypto::SigningError::SignerLacksGloasSupport { rpc, details } => {
            assert_eq!(rpc, "SignBlockHeader");
            assert!(details.contains("SignBlockHeader") || details.contains("unimplemented"));
        }
        other => panic!("expected SignerLacksGloasSupport, got {other:?}"),
    }
    let err =
        TypedSigner::sign_aggregate_and_proof(&signer, &aggregate(), &gloas).await.unwrap_err();
    match err {
        crypto::SigningError::SignerLacksGloasSupport { rpc, .. } => {
            assert_eq!(rpc, "SignRoot");
        }
        other => panic!("expected SignerLacksGloasSupport for aggregate, got {other:?}"),
    }
    let err = TypedSigner::sign_electra_aggregate_and_proof(&signer, &electra_aggregate(), &gloas)
        .await
        .unwrap_err();
    match err {
        crypto::SigningError::SignerLacksGloasSupport { rpc, .. } => {
            assert_eq!(rpc, "SignRoot");
        }
        other => panic!("expected SignerLacksGloasSupport for electra aggregate, got {other:?}"),
    }

    let names = RecordingV2::names(&calls);
    let gloas_block_calls: Vec<_> =
        names.iter().filter(|n| n.as_str() == "sign_block_header").collect();
    assert_eq!(gloas_block_calls.len(), 1, "no retry on legacy after Gloas header RPC: {names:?}");
    let beacon_calls = names.iter().filter(|n| n.as_str() == "sign_beacon_block").count();
    assert_eq!(beacon_calls, 1, "only the pre-Gloas block used SignBeaconBlock: {names:?}");
    assert!(!names.iter().any(|n| n == "sign_aggregate_and_proof"));
    let root_calls = names.iter().filter(|n| n.as_str() == "sign_root").count();
    assert_eq!(root_calls, 2, "aggregate + electra aggregate, no legacy retry: {names:?}");
}

#[tokio::test]
async fn test_unknown_duty_and_fork_id_fail_closed() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, calls, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = gloas_ctx(pk.clone());

    let err = signer.sign_root([0x11; 32], 99, &ctx).await.unwrap_err();
    match err {
        crypto::SigningError::LocalRejected(msg) => {
            assert!(msg.contains("unknown sign type"), "got {msg}");
        }
        other => panic!("expected LocalRejected unknown-duty, got {other:?}"),
    }
    assert!(
        RecordingV2::names(&calls).is_empty(),
        "unknown duty must not send an RPC or produce a signature"
    );

    let mut raw = SignerServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let err = raw
        .sign_root(SignRootRequest {
            pubkey: pk.to_bytes().to_vec(),
            fork_info: Some(proto_fork(&ctx)),
            object_root: vec![0x11; 32],
            duty: Duty::PayloadAttestation as i32,
            fork_id: 8,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("unknown fork id"));
}

#[tokio::test]
async fn test_envelope_unimplemented_until_p6() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = gloas_ctx(pk);
    let err = signer
        .sign_root([0x11; 32], Duty::ExecutionPayloadEnvelope as i32, &ctx)
        .await
        .unwrap_err();
    match err {
        crypto::SigningError::SignerLacksGloasSupport { rpc, details } => {
            assert_eq!(rpc, "SignRoot");
            assert!(
                details.contains("EXECUTION_PAYLOAD_ENVELOPE") || details.contains("6.19"),
                "UNIMPLEMENTED-until-P6, got {details}"
            );
        }
        other => panic!("envelope must surface unimplemented, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ptc_kat_signature_verifies() {
    use rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT;

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _, _h) = start_recording_server(sk, false).await;
    let signer = connect(addr).await;
    let ctx = SignContext::new(
        pk.clone(),
        ForkInfo {
            previous_version: [0x06, 0x00, 0x00, 0x01],
            current_version: [0x07, 0x00, 0x00, 0x01],
            genesis_validators_root: [0u8; 32],
        },
        ForkName::Gloas,
    );
    let sig = TypedSigner::sign_payload_attestation(&signer, &ptc(), &ctx).await.unwrap();
    let kat: [u8; 32] =
        hex::decode(KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT).unwrap().try_into().unwrap();
    assert!(sig.verify(&pk, &kat).is_ok(), "PTC signature must verify over the KAT signing root");
}
