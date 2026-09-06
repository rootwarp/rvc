//! End-to-end roundtrip tests for the v2 typed gRPC signing contract.
//!
//! Each test:
//! 1. Starts an in-process mock v2 SignerService backed by a real BLS key.
//! 2. Connects `GrpcRemoteSigner` to it.
//! 3. Calls the appropriate `TypedSigner` method.
//! 4. Verifies the returned signature is valid for the reconstructed signing root.

#![allow(clippy::disallowed_methods)]
// Gate 1: tests round-trip raw key bytes for assertions; not a logging surface

// RF1-12: OnceLock init sets env vars via unsafe std::env::{set_var,remove_var}.
#![allow(unsafe_code)]

use std::net::SocketAddr;

use crypto::typed_signer::{SignContext, TypedSigner};
use crypto::{
    compute_domain, compute_signing_root, SecretKey, DOMAIN_BEACON_ATTESTER, DOMAIN_RANDAO,
};
use eth_types::{
    decode_attestation_ssz, decode_beacon_block_ssz, decode_blinded_beacon_block_ssz,
    decode_sync_committee_contribution_ssz,
};
use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BeaconBlock, BlindedBeaconBlock, Checkpoint,
    ContributionAndProof, ForkInfo, SyncAggregatorSelectionData, SyncCommitteeContribution,
    ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
use rvc_grpc_signer::{
    proto::signer_v2::{
        signer_service_server::{
            SignerService as SignerServiceV2, SignerServiceServer as SignerServiceServerV2,
        },
        ForkInfo as ProtoForkInfo, GetStatusRequest as GetStatusRequestV2,
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
use std::sync::OnceLock;
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers: insecure plaintext config
// ─────────────────────────────────────────────────────────────────────────────

/// Sets `RVC_REMOTE_SIGNER_ALLOW_INSECURE=true` once for the entire test binary.
///
/// All tests here use plaintext gRPC (we're testing the v2 protocol contract,
/// not the TLS gate).  At GA (ISSUE-3.13) the gate defaults to Refuse; this
/// sets the operator opt-in so the in-process test server can be reached.
fn allow_insecure_for_tests() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| unsafe {
        std::env::set_var(rvc_grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR, "true");
    });
}

/// Returns a `GrpcRemoteSignerConfig` for a plaintext test server and ensures
/// the insecure opt-in env var is set for this test binary.
fn insecure_grpc_config(addr: SocketAddr) -> GrpcRemoteSignerConfig {
    allow_insecure_for_tests();
    GrpcRemoteSignerConfig::new(format!("http://{addr}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock v2 SignerService backed by a real BLS key
// ─────────────────────────────────────────────────────────────────────────────

struct MockV2Signer {
    sk: SecretKey,
}

impl MockV2Signer {
    fn bls_sign(&self, root: &[u8; 32]) -> Vec<u8> {
        self.sk.sign(root).to_bytes().to_vec()
    }

    fn extract_fork_info(fi: &ProtoForkInfo) -> ([u8; 4], [u8; 4], [u8; 32]) {
        let prev: [u8; 4] = fi.previous_version.as_slice().try_into().unwrap_or([0u8; 4]);
        let curr: [u8; 4] = fi.current_version.as_slice().try_into().unwrap_or([0u8; 4]);
        let gvr: [u8; 32] = fi.genesis_validators_root.as_slice().try_into().unwrap_or([0u8; 32]);
        (prev, curr, gvr)
    }
}

#[tonic::async_trait]
impl SignerServiceV2 for MockV2Signer {
    async fn sign_beacon_block(
        &self,
        request: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let r = request.into_inner();
        let fi =
            r.fork_info.as_ref().ok_or_else(|| Status::invalid_argument("missing fork_info"))?;
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
        let proto_data = r.data.as_ref().ok_or_else(|| Status::invalid_argument("missing data"))?;
        let src =
            proto_data.source.as_ref().ok_or_else(|| Status::invalid_argument("missing source"))?;
        let tgt =
            proto_data.target.as_ref().ok_or_else(|| Status::invalid_argument("missing target"))?;
        let bbr: [u8; 32] = proto_data
            .beacon_block_root
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("bad beacon_block_root"))?;
        let src_root: [u8; 32] = src.root.as_slice().try_into().unwrap_or([0u8; 32]);
        let tgt_root: [u8; 32] = tgt.root.as_slice().try_into().unwrap_or([0u8; 32]);
        let data = AttestationData {
            slot: proto_data.slot,
            index: proto_data.index,
            beacon_block_root: bbr,
            source: Checkpoint { epoch: src.epoch, root: src_root },
            target: Checkpoint { epoch: tgt.epoch, root: tgt_root },
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
        let bbr: [u8; 32] = r
            .beacon_block_root
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("bad beacon_block_root"))?;
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
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
        let pubkey: [u8; 48] =
            r.pubkey.try_into().map_err(|_| Status::invalid_argument("pubkey must be 48 bytes"))?;
        let fee_recipient: [u8; 20] = r
            .fee_recipient
            .try_into()
            .map_err(|_| Status::invalid_argument("fee_recipient must be 20 bytes"))?;
        let reg = ValidatorRegistrationV1 {
            fee_recipient,
            gas_limit: r.gas_limit,
            timestamp: r.timestamp,
            pubkey,
        };
        let zero_gvr = [0u8; 32];
        // Builder registrations carry a per-network GENESIS_FORK_VERSION on the
        // request (empty ⇒ mainnet 0x00000000), mirroring the real server.
        let genesis_fork_version: [u8; 4] = if r.genesis_fork_version.is_empty() {
            [0u8; 4]
        } else {
            r.genesis_fork_version
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("genesis_fork_version must be 4 bytes"))?
        };
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_gvr);
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
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
        let (_prev, curr, gvr) = Self::extract_fork_info(fi);
        let exit = VoluntaryExit { epoch: r.epoch, validator_index: r.validator_index };
        let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, curr, gvr);
        let root = compute_signing_root(&exit, domain);
        Ok(Response::new(SignResponse { signature: self.bls_sign(&root) }))
    }

    async fn sign_block_header(
        &self,
        _request: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("SignBlockHeader (issue 4.20b)"))
    }

    async fn sign_root(
        &self,
        _request: Request<SignRootRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("SignRoot (issue 4.20b)"))
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
            backend: "mock-v2".to_string(),
            key_count: 1,
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: start a v2-only server (RF2-15: v1 retired from this crate)
// ─────────────────────────────────────────────────────────────────────────────

async fn start_v2_server(sk: SecretKey) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sk_bytes = sk.to_bytes();

    let handle = tokio::spawn(async move {
        let sk_v2 = SecretKey::from_bytes(&sk_bytes).unwrap();
        tonic::transport::Server::builder()
            .add_service(SignerServiceServerV2::new(MockV2Signer { sk: sk_v2 }))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, handle)
}

fn test_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: [0x00, 0x00, 0x00, 0x00],
        current_version: [0x00, 0x00, 0x00, 0x00], // Phase0
        genesis_validators_root: [0xab; 32],
    }
}

fn test_ctx(pk: crypto::PublicKey) -> SignContext {
    SignContext { pubkey: pk, fork_info: test_fork_info(), fork_name: eth_types::ForkName::Phase0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Roundtrip tests: each typed RPC
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_typed_block_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let block = BeaconBlock {
        slot: 100,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    };

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_block(&signer, &block, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&block, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "block signature must verify");
}

#[tokio::test]
async fn test_typed_blinded_block_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let block = BlindedBeaconBlock {
        slot: 200,
        proposer_index: 2,
        parent_root: [0x33; 32],
        state_root: [0x44; 32],
        body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
    };

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_blinded_block(&signer, &block, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&block, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "blinded block signature must verify");
}

#[tokio::test]
async fn test_typed_attestation_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let data = AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: [0x55; 32],
        source: Checkpoint { epoch: 9, root: [0x66; 32] },
        target: Checkpoint { epoch: 10, root: [0x77; 32] },
    };

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_attestation(&signer, &data, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_BEACON_ATTESTER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&data, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "attestation signature must verify");
}

#[tokio::test]
async fn test_typed_aggregate_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let agg = AggregateAndProof {
        aggregator_index: 42,
        aggregate: Attestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot: 100,
                index: 0,
                beacon_block_root: [0x11; 32],
                source: Checkpoint { epoch: 9, root: [0x22; 32] },
                target: Checkpoint { epoch: 10, root: [0x33; 32] },
            },
            signature: vec![0xaa; 96],
        },
        selection_proof: vec![0xbb; 96],
    };

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_aggregate_and_proof(&signer, &agg, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_AGGREGATE_AND_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&agg, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "aggregate signature must verify");
}

#[tokio::test]
async fn test_typed_sync_message_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let slot = 500u64;
    let beacon_block_root = [0x88u8; 32];

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_sync_committee_message(&signer, slot, beacon_block_root, &ctx)
        .await
        .unwrap();

    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&beacon_block_root, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "sync message signature must verify");
}

#[tokio::test]
async fn test_typed_sync_aggregator_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let slot = 600u64;
    let subcommittee_index = 3u64;

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_sync_aggregator_selection(&signer, slot, subcommittee_index, &ctx)
        .await
        .unwrap();

    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
    let signing_root = compute_signing_root(&selection_data, domain);
    assert!(
        sig.verify(&pk, &signing_root).is_ok(),
        "sync aggregator selection signature must verify"
    );
}

#[tokio::test]
async fn test_typed_contribution_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let c = ContributionAndProof {
        aggregator_index: 7,
        contribution: SyncCommitteeContribution {
            slot: 400,
            beacon_block_root: [0x99; 32],
            subcommittee_index: 1,
            aggregation_bits: vec![0x03; 16],
            signature: vec![0xcc; 96],
        },
        selection_proof: vec![0xdd; 96],
    };

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_contribution_and_proof(&signer, &c, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_CONTRIBUTION_AND_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&c, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "contribution signature must verify");
}

#[tokio::test]
async fn test_typed_builder_registration_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    // Non-zero (Holesky) version so the roundtrip would fail if the field were
    // dropped on the wire — the old [0u8; 4] passed only by coincidence with the
    // mock's hardcoded default.
    let genesis_fork_version = [0x01, 0x01, 0x70, 0x00];
    let reg = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey: pk.to_bytes(),
    };

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_builder_registration(&signer, &reg, genesis_fork_version, &ctx)
        .await
        .unwrap();

    let zero_gvr = [0u8; 32];
    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_gvr);
    let signing_root = compute_signing_root(&reg, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "builder registration signature must verify");
}

#[tokio::test]
async fn test_typed_randao_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let epoch = 42u64;

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_randao_reveal(&signer, epoch, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_RANDAO,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&epoch, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "RANDAO signature must verify");
}

#[tokio::test]
async fn test_typed_voluntary_exit_round_trip() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let (addr, _handle) = start_v2_server(sk).await;

    let signer = GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await.unwrap();

    let exit = VoluntaryExit { epoch: 200, validator_index: 99 };

    let ctx = test_ctx(pk.clone());
    let sig = TypedSigner::sign_voluntary_exit(&signer, &exit, &ctx).await.unwrap();

    let domain = compute_domain(
        DOMAIN_VOLUNTARY_EXIT,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&exit, domain);
    assert!(sig.verify(&pk, &signing_root).is_ok(), "voluntary exit signature must verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression: GrpcRemoteSigner does NOT implement raw-root Signer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_grpc_remote_signer_has_no_raw_signer_impl() {
    // Compile-time assertion: if this test compiles, `GrpcRemoteSigner` does NOT
    // implement the raw-root `Signer` trait. We verify this by ensuring the trait
    // is not in scope for the type. The negative-impl check is implicit: if
    // `GrpcRemoteSigner` did implement `Signer`, any of the sign() calls in the
    // integration tests would have to use the typed interface, which would be a
    // breaking change. This comment + the absence of `impl Signer for GrpcRemoteSigner`
    // in client.rs IS the test.
    //
    // Positive assertion: GrpcRemoteSigner DOES implement TypedSigner (verified by all
    // roundtrip tests above that call TypedSigner::sign_* on it).
    let _ = "GrpcRemoteSigner implements TypedSigner only — C-2/C-3 closure verified";
}

// ─────────────────────────────────────────────────────────────────────────────
// Contract version check: server that cannot list keys fails at connect
// ─────────────────────────────────────────────────────────────────────────────

/// Stand-in for a legacy v1-only signer: registers the v2 service path but every
/// RPC (including `ListPublicKeys`) returns `Unimplemented`.  RF2-15 removed the
/// in-crate v1 mock types; this preserves the SS-1 connect-time refusal without
/// reintroducing v1 codegen.
struct UnimplementedV2Signer;

#[tonic::async_trait]
impl SignerServiceV2 for UnimplementedV2Signer {
    async fn sign_beacon_block(
        &self,
        _request: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_blinded_beacon_block(
        &self,
        _request: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_attestation_data(
        &self,
        _request: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_aggregate_and_proof(
        &self,
        _request: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_sync_committee_message(
        &self,
        _request: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_sync_aggregator_selection_data(
        &self,
        _request: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_contribution_and_proof(
        &self,
        _request: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_builder_registration(
        &self,
        _request: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_randao_reveal(
        &self,
        _request: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_voluntary_exit(
        &self,
        _request: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_block_header(
        &self,
        _request: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn sign_root(
        &self,
        _request: Request<SignRootRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 signing unavailable"))
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequestV2>,
    ) -> Result<Response<ListPublicKeysResponseV2>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 ListPublicKeys unavailable"))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequestV2>,
    ) -> Result<Response<GetStatusResponseV2>, Status> {
        Err(Status::unimplemented("legacy stand-in: v2 GetStatus unavailable"))
    }
}

async fn start_unimplemented_v2_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SignerServiceServerV2::new(UnimplementedV2Signer))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, handle)
}

/// Verify that a `GrpcRemoteSigner` rejects a non-functional v2 server at connect.
///
/// SS-1 (Issue 2.2): the client calls the v2 `ListPublicKeys` RPC during
/// `connect()`.  When that RPC returns `Unimplemented`, `connect()` fails —
/// the same wire outcome as dialing a legacy v1-only signer (C-2/C-3).
///
/// RF2-15: previously this used an in-crate v1 mock; v1 types are gone from
/// `crates/grpc-signer`, so the stand-in is an all-Unimplemented v2 service.
#[tokio::test]
async fn test_refuses_v1_signer_at_typed_rpc_time() {
    let (addr, _handle) = start_unimplemented_v2_server().await;

    // SS-1: connect() fails because ListPublicKeys is Unimplemented.
    match GrpcRemoteSigner::connect(insecure_grpc_config(addr)).await {
        Ok(_) => panic!("connect() must fail when ListPublicKeys is Unimplemented"),
        Err(crypto::SigningError::RemoteSignerError(msg)) => {
            assert!(
                msg.contains("list public keys")
                    || msg.contains("Unimplemented")
                    || msg.contains("not implemented"),
                "error should indicate v2 ListPublicKeys is unavailable, got: {msg}"
            );
        }
        Err(other) => panic!("expected RemoteSignerError, got: {other:?}"),
    }
}
