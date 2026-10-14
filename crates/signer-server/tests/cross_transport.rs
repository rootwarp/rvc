//! Cross-transport signature-equality oracle (builder fork + duty parity).
//!
//! Same duty payload signed through gRPC and HTTP over one shared
//! `Arc<SigningGate>` + backend must yield **byte-identical** BLS signatures.
//! Covers builder registration (prior fork-version divergence), one slashable
//! duty (attestation), and one other non-slashable duty (RANDAO).
//!
//! DVT partial-sign produces share signatures, not full BLS signatures, so it
//! is not compared byte-for-byte here; DVT builds the same `PlanInput` via
//! `plan_sign` (unit tests in `sign_plan`).

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use tonic::Request;
use tower::ServiceExt;

use crypto::{compute_domain, compute_signing_root, KeyManager, PublicKey, SecretKey, Signature};
use eth_types::{
    AggregateAndProof, Attestation, AttestationData, BeaconBlockHeader, BuilderRequestAuth,
    Checkpoint, ContributionAndProof, PayloadAttestationData, ProposerPreferences,
    SyncCommitteeContribution, ValidatorRegistrationV1, DOMAIN_APPLICATION_BUILDER,
    DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_BUILDER_REQUEST_AUTH,
    DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO,
};
use signer_server::backend::{SigningBackend, SigningBackendError};
use signer_server::http_api::{router, AuditCfg, Web3SignerState};
use signer_server::proto::signer_v2::signer_service_server::SignerService as SignerServiceV2;
use signer_server::proto::signer_v2::{
    AttestationData as ProtoAttestationData, BeaconBlockHeader as ProtoBeaconBlockHeader,
    Checkpoint as ProtoCheckpoint, Duty, ForkInfo, SignAttestationDataRequest,
    SignBlockHeaderRequest, SignBuilderRegistrationRequest, SignRandaoRevealRequest,
    SignRootRequest,
};
use signer_server::service::SignerServiceImpl;
use tree_hash::TreeHash;

const GVR: [u8; 32] = [0xab; 32];
const CURRENT_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
const HOLESKY_GENESIS: [u8; 4] = eth_types::NetworkPreset::HOLESKY.genesis_fork_version;
const MAINNET_GENESIS: [u8; 4] = eth_types::NetworkPreset::MAINNET.genesis_fork_version;

// ── Local backend / fixtures ─────────────────────────────────────────────────

struct RealBackend {
    km: Arc<KeyManager>,
}

impl RealBackend {
    fn with_key(sk: SecretKey) -> Self {
        let mut km = KeyManager::new();
        km.insert(sk);
        Self { km: Arc::new(km) }
    }
}

#[async_trait]
impl SigningBackend for RealBackend {
    async fn sign(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<[u8; 96], SigningBackendError> {
        let pk =
            PublicKey::from_bytes(pubkey).map_err(|_| SigningBackendError::KeyNotFound(*pubkey))?;
        let sk = self.km.get_secret_key(&pk).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;
        Ok(sk.sign(signing_root).to_bytes())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
    }
}

fn test_keypair() -> (SecretKey, [u8; 48]) {
    let sk = crypto::eip2333::derive_master_sk(&[0x11u8; 32]).expect("derive master sk");
    let pk = sk.public_key().to_bytes();
    (sk, pk)
}

struct Shared {
    backend: Arc<dyn SigningBackend>,
    gate: Arc<signer::SigningGate>,
    pubkey: [u8; 48],
    sk: SecretKey,
    genesis_fork_version: [u8; 4],
}

fn shared(genesis_fork_version: [u8; 4]) -> Shared {
    // Two independent keypairs with the same seed so we can keep a SecretKey for KAT
    // assertions while also loading an identical key into the backend.
    let (sk, pubkey) = test_keypair();
    let (sk_backend, _) = test_keypair();
    let backend: Arc<dyn SigningBackend> = Arc::new(RealBackend::with_key(sk_backend));
    let db = Arc::new(slashing::SlashingDb::open_in_memory().expect("in-memory slashing DB"));
    let gate = Arc::new(SignerServiceImpl::build_gate(Arc::clone(&backend), db));
    Shared { backend, gate, pubkey, sk, genesis_fork_version }
}

fn grpc_svc(s: &Shared) -> SignerServiceImpl {
    SignerServiceImpl::new_v2_with_gate(
        Arc::clone(&s.backend),
        "basic".to_string(),
        Arc::clone(&s.gate),
    )
    .with_genesis_fork_version(s.genesis_fork_version)
}

fn http_state(s: &Shared) -> Web3SignerState {
    Web3SignerState {
        gate: Arc::clone(&s.gate),
        backend: Arc::clone(&s.backend),
        audit: AuditCfg::default(),
        metrics: Arc::new(signer_server::metrics::SignerMetrics::new()),
        client_cn_allow_list: None,
        genesis_fork_version: s.genesis_fork_version,
    }
}

fn fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: CURRENT_VERSION.to_vec(),
        current_version: CURRENT_VERSION.to_vec(),
        epoch: 0,
        genesis_validators_root: GVR.to_vec(),
    }
}

fn sample_registration(pubkey: [u8; 48]) -> ValidatorRegistrationV1 {
    ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey,
    }
}

fn sample_attestation() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 1, root: [0x22; 32] },
        target: Checkpoint { epoch: 2, root: [0x33; 32] },
    }
}

async fn http_sign(state: Web3SignerState, pubkey: &[u8; 48], body: String) -> Vec<u8> {
    let id = format!("0x{}", hex::encode(pubkey));
    let req = HttpRequest::builder()
        .method("POST")
        .uri(format!("/api/v1/eth2/sign/{id}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "HTTP sign must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let sig_hex = v["signature"].as_str().unwrap().strip_prefix("0x").unwrap();
    hex::decode(sig_hex).unwrap()
}

// ── Builder registration ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_builder_registration_signature_identical_across_transports() {
    // Non-mainnet: the pre-fix divergence (HTTP mainnet-hardcoded vs gRPC request).
    let s = shared(HOLESKY_GENESIS);
    let reg = sample_registration(s.pubkey);

    let grpc_resp = SignerServiceV2::sign_builder_registration(
        &grpc_svc(&s),
        Request::new(SignBuilderRegistrationRequest {
            pubkey: s.pubkey.to_vec(),
            fee_recipient: reg.fee_recipient.to_vec(),
            gas_limit: reg.gas_limit,
            timestamp: reg.timestamp,
            genesis_fork_version: vec![], // use server network config
        }),
    )
    .await
    .expect("gRPC builder registration")
    .into_inner()
    .signature;

    let reg_json = serde_json::to_string(&reg).unwrap();
    let body =
        format!(r#"{{ "type": "VALIDATOR_REGISTRATION", "validator_registration": {reg_json} }}"#);
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;

    assert_eq!(
        grpc_resp, http_sig,
        "gRPC and HTTP builder-registration signatures must be byte-identical on holesky"
    );

    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, HOLESKY_GENESIS, [0u8; 32]);
    let root = compute_signing_root(&reg, domain);
    let pk = PublicKey::from_bytes(&s.pubkey).unwrap();
    let sig = Signature::from_bytes(&grpc_resp).unwrap();
    assert!(sig.verify(&pk, &root).is_ok(), "signature must verify under holesky genesis");
}

#[tokio::test]
async fn test_mainnet_builder_registration_kat_unchanged() {
    let s = shared(MAINNET_GENESIS);
    let reg = sample_registration(s.pubkey);

    let grpc_resp = SignerServiceV2::sign_builder_registration(
        &grpc_svc(&s),
        Request::new(SignBuilderRegistrationRequest {
            pubkey: s.pubkey.to_vec(),
            fee_recipient: reg.fee_recipient.to_vec(),
            gas_limit: reg.gas_limit,
            timestamp: reg.timestamp,
            genesis_fork_version: vec![],
        }),
    )
    .await
    .expect("gRPC mainnet builder")
    .into_inner()
    .signature;

    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, MAINNET_GENESIS, [0u8; 32]);
    let root = compute_signing_root(&reg, domain);
    let expected = s.sk.sign(&root).to_bytes().to_vec();
    assert_eq!(grpc_resp, expected, "mainnet builder KAT must stay unchanged");

    let reg_json = serde_json::to_string(&reg).unwrap();
    let body =
        format!(r#"{{ "type": "VALIDATOR_REGISTRATION", "validator_registration": {reg_json} }}"#);
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;
    assert_eq!(http_sig, expected, "HTTP mainnet builder KAT must match gRPC");
}

// ── Attestation (slashable) ──────────────────────────────────────────────────

#[tokio::test]
async fn test_attestation_signature_identical_across_transports() {
    let s = shared(MAINNET_GENESIS);
    let data = sample_attestation();

    let grpc_resp = SignerServiceV2::sign_attestation_data(
        &grpc_svc(&s),
        Request::new(SignAttestationDataRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(fork_info()),
            data: Some(ProtoAttestationData {
                slot: data.slot,
                index: data.index,
                beacon_block_root: data.beacon_block_root.to_vec(),
                source: Some(ProtoCheckpoint {
                    epoch: data.source.epoch,
                    root: data.source.root.to_vec(),
                }),
                target: Some(ProtoCheckpoint {
                    epoch: data.target.epoch,
                    root: data.target.root.to_vec(),
                }),
            }),
            fork_id: 4,
        }),
    )
    .await
    .expect("gRPC attestation")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{
            "type": "ATTESTATION",
            "fork_info": {{
                "fork": {{
                    "previous_version": "0x04000000",
                    "current_version": "0x04000000",
                    "epoch": "0"
                }},
                "genesis_validators_root": "0x{gvr}"
            }},
            "attestation": {{
                "slot": "{slot}",
                "index": "{index}",
                "beacon_block_root": "0x{bbr}",
                "source": {{ "epoch": "{src_ep}", "root": "0x{src_root}" }},
                "target": {{ "epoch": "{tgt_ep}", "root": "0x{tgt_root}" }}
            }}
        }}"#,
        gvr = hex::encode(GVR),
        slot = data.slot,
        index = data.index,
        bbr = hex::encode(data.beacon_block_root),
        src_ep = data.source.epoch,
        src_root = hex::encode(data.source.root),
        tgt_ep = data.target.epoch,
        tgt_root = hex::encode(data.target.root),
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;

    assert_eq!(grpc_resp, http_sig, "gRPC and HTTP attestation signatures must be byte-identical");

    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, CURRENT_VERSION, GVR);
    let root = compute_signing_root(&data, domain);
    let pk = PublicKey::from_bytes(&s.pubkey).unwrap();
    assert!(Signature::from_bytes(&grpc_resp).unwrap().verify(&pk, &root).is_ok());
}

// ── RANDAO (non-slashable) ───────────────────────────────────────────────────

#[tokio::test]
async fn test_randao_signature_identical_across_transports() {
    let s = shared(MAINNET_GENESIS);
    let epoch: u64 = 42;

    let grpc_resp = SignerServiceV2::sign_randao_reveal(
        &grpc_svc(&s),
        Request::new(SignRandaoRevealRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(fork_info()),
            epoch,
            fork_id: 4,
        }),
    )
    .await
    .expect("gRPC randao")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{
            "type": "RANDAO_REVEAL",
            "fork_info": {{
                "fork": {{
                    "previous_version": "0x04000000",
                    "current_version": "0x04000000",
                    "epoch": "0"
                }},
                "genesis_validators_root": "0x{gvr}"
            }},
            "randao_reveal": {{ "epoch": "{epoch}" }}
        }}"#,
        gvr = hex::encode(GVR),
        epoch = epoch,
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;

    assert_eq!(grpc_resp, http_sig, "gRPC and HTTP RANDAO signatures must be byte-identical");

    let domain = compute_domain(DOMAIN_RANDAO, CURRENT_VERSION, GVR);
    let root = compute_signing_root(&epoch, domain);
    let pk = PublicKey::from_bytes(&s.pubkey).unwrap();
    assert!(Signature::from_bytes(&grpc_resp).unwrap().verify(&pk, &root).is_ok());
}

fn gloas_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: vec![0x07, 0x00, 0x00, 0x00],
        current_version: vec![0x07, 0x00, 0x00, 0x01],
        epoch: 0,
        genesis_validators_root: vec![0x00; 32],
    }
}

fn gloas_http_fork_info() -> String {
    format!(
        r#"{{ "fork": {{ "previous_version": "0x07000000",
                         "current_version": "0x07000001",
                         "epoch": "0" }},
              "genesis_validators_root": "0x{gvr}" }}"#,
        gvr = "00".repeat(32),
    )
}

fn deneb_http_fork_info() -> String {
    format!(
        r#"{{ "fork": {{ "previous_version": "0x04000000",
                         "current_version": "0x04000000",
                         "epoch": "0" }},
              "genesis_validators_root": "0x{gvr}" }}"#,
        gvr = hex::encode(GVR),
    )
}

// ── Block header (slashable; gRPC SignBlockHeader vs HTTP BLOCK_V2) ──────────

#[tokio::test]
async fn test_block_header_signature_identical_across_transports() {
    let s = shared(MAINNET_GENESIS);
    let header = BeaconBlockHeader {
        slot: 3_000_000,
        proposer_index: 12_345,
        parent_root: [0xaa; 32],
        state_root: [0xbb; 32],
        body_root: [0xcc; 32],
    };

    let grpc_resp = SignerServiceV2::sign_block_header(
        &grpc_svc(&s),
        Request::new(SignBlockHeaderRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(fork_info()),
            header: Some(ProtoBeaconBlockHeader {
                slot: header.slot,
                proposer_index: header.proposer_index,
                parent_root: header.parent_root.to_vec(),
                state_root: header.state_root.to_vec(),
                body_root: header.body_root.to_vec(),
            }),
            fork_id: 4,
        }),
    )
    .await
    .expect("gRPC block header")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{ "type": "BLOCK_V2",
              "fork_info": {fi},
              "beacon_block": {{ "version": "DENEB",
                                 "block_header": {{ "slot": "{slot}",
                                                    "proposer_index": "{idx}",
                                                    "parent_root": "0x{p}",
                                                    "state_root": "0x{st}",
                                                    "body_root": "0x{b}" }} }} }}"#,
        fi = deneb_http_fork_info(),
        slot = header.slot,
        idx = header.proposer_index,
        p = hex::encode(header.parent_root),
        st = hex::encode(header.state_root),
        b = hex::encode(header.body_root),
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;
    assert_eq!(grpc_resp, http_sig, "gRPC header and HTTP BLOCK_V2 must match");

    let domain = compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_VERSION, GVR);
    let root = compute_signing_root(&header, domain);
    let pk = PublicKey::from_bytes(&s.pubkey).unwrap();
    assert!(Signature::from_bytes(&grpc_resp).unwrap().verify(&pk, &root).is_ok());
}

// ── Aggregate / contribution via SignRoot vs HTTP ────────────────────────────

#[tokio::test]
async fn test_aggregate_and_proof_root_rpc_matches_http() {
    let s = shared(MAINNET_GENESIS);
    let agg = AggregateAndProof {
        aggregator_index: 1,
        aggregate: Attestation {
            aggregation_bits: vec![0x01],
            data: sample_attestation(),
            signature: vec![0xAB; 96],
        },
        selection_proof: vec![0xCD; 96],
    };
    let object_root = agg.try_tree_hash_root().expect("aggregate htr").0;

    let grpc_resp = SignerServiceV2::sign_root(
        &grpc_svc(&s),
        Request::new(SignRootRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(fork_info()),
            object_root: object_root.to_vec(),
            duty: Duty::AggregateAndProof as i32,
            fork_id: 4,
        }),
    )
    .await
    .expect("gRPC SignRoot aggregate")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{ "type": "AGGREGATE_AND_PROOF", "fork_info": {fi}, "aggregate_and_proof": {payload} }}"#,
        fi = deneb_http_fork_info(),
        payload = serde_json::to_string(&agg).unwrap(),
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;
    assert_eq!(grpc_resp, http_sig, "gRPC SignRoot aggregate must match HTTP");
}

#[tokio::test]
async fn test_contribution_and_proof_root_rpc_matches_http() {
    let s = shared(MAINNET_GENESIS);
    let cap = ContributionAndProof {
        aggregator_index: 1,
        contribution: SyncCommitteeContribution {
            slot: 5,
            beacon_block_root: [0x11; 32],
            subcommittee_index: 0,
            aggregation_bits: vec![0u8; 16],
            signature: vec![0xAB; 96],
        },
        selection_proof: vec![0xCD; 96],
    };
    let object_root = cap.tree_hash_root().0;

    let grpc_resp = SignerServiceV2::sign_root(
        &grpc_svc(&s),
        Request::new(SignRootRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(fork_info()),
            object_root: object_root.to_vec(),
            duty: Duty::ContributionAndProof as i32,
            fork_id: 4,
        }),
    )
    .await
    .expect("gRPC SignRoot contribution")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{ "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", "fork_info": {fi}, "contribution_and_proof": {payload} }}"#,
        fi = deneb_http_fork_info(),
        payload = serde_json::to_string(&cap).unwrap(),
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;
    assert_eq!(grpc_resp, http_sig, "gRPC SignRoot contribution must match HTTP");
}

// ── Payload attestation (gRPC SignRoot vs HTTP PAYLOAD_ATTESTATION) ──────────

#[tokio::test]
async fn test_payload_attestation_plan_identical_across_transports() {
    let s = shared(MAINNET_GENESIS);
    let data = PayloadAttestationData {
        beacon_block_root: [0x11; 32],
        slot: 1,
        payload_present: true,
        blob_data_available: false,
    };
    let object_root = data.tree_hash_root().0;
    assert_eq!(
        hex::encode(object_root),
        rvc_spec_vectors::spec_kat::SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT
    );

    let grpc_resp = SignerServiceV2::sign_root(
        &grpc_svc(&s),
        Request::new(SignRootRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(gloas_fork_info()),
            object_root: object_root.to_vec(),
            duty: Duty::PayloadAttestation as i32,
            fork_id: 7,
        }),
    )
    .await
    .expect("gRPC SignRoot payload attestation")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{ "type": "PAYLOAD_ATTESTATION",
              "fork_info": {fi},
              "payload_attestation": {{ "version": "GLOAS", "data": {data} }} }}"#,
        fi = gloas_http_fork_info(),
        data = serde_json::to_string(&data).unwrap(),
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;
    assert_eq!(grpc_resp, http_sig, "gRPC SignRoot PTC must match HTTP");

    let kat: [u8; 32] =
        hex::decode(rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT)
            .expect("kat hex")
            .try_into()
            .expect("32-byte kat");
    let expected = s.sk.sign(&kat).to_bytes().to_vec();
    assert_eq!(grpc_resp, expected, "PTC signature must be over KAT_GLOAS_* signing root");
    let domain = compute_domain(DOMAIN_PTC_ATTESTER, [0x07, 0x00, 0x00, 0x01], [0u8; 32]);
    assert_eq!(compute_signing_root(&object_root, domain), kat);
}

// ── Proposer preferences (gRPC SignRoot vs HTTP PROPOSER_PREFERENCES) ────────

#[tokio::test]
async fn test_proposer_preferences_plan_identical_across_transports() {
    let s = shared(MAINNET_GENESIS);
    let data = ProposerPreferences {
        dependent_root: [0x33; 32],
        proposal_slot: 32,
        validator_index: 3,
        fee_recipient: [0x44; 20],
        target_gas_limit: 36_000_000,
    };
    let object_root = data.tree_hash_root().0;
    assert_eq!(
        hex::encode(object_root),
        rvc_spec_vectors::spec_kat::SPEC_GLOAS_PROPOSERPREFERENCES_ROOT
    );

    let grpc_resp = SignerServiceV2::sign_root(
        &grpc_svc(&s),
        Request::new(SignRootRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(gloas_fork_info()),
            object_root: object_root.to_vec(),
            duty: Duty::ProposerPreferences as i32,
            fork_id: 7,
        }),
    )
    .await
    .expect("gRPC SignRoot proposer preferences")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{ "type": "PROPOSER_PREFERENCES",
              "fork_info": {fi},
              "proposer_preferences": {{ "version": "GLOAS", "data": {data} }} }}"#,
        fi = gloas_http_fork_info(),
        data = serde_json::to_string(&data).unwrap(),
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;
    assert_eq!(grpc_resp, http_sig, "gRPC SignRoot proposer preferences must match HTTP");

    let kat: [u8; 32] =
        hex::decode(rvc_spec_vectors::spec_kat::KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT)
            .expect("kat hex")
            .try_into()
            .expect("32-byte kat");
    let expected = s.sk.sign(&kat).to_bytes().to_vec();
    assert_eq!(grpc_resp, expected);
    let domain = compute_domain(DOMAIN_PROPOSER_PREFERENCES, [0x07, 0x00, 0x00, 0x01], [0u8; 32]);
    assert_eq!(compute_signing_root(&object_root, domain), kat);
}

// ── Builder request auth (gRPC SignRoot vs HTTP BUILDER_REQUEST_AUTH) ────────

#[tokio::test]
async fn test_builder_request_auth_plan_identical_across_transports() {
    let s = shared(MAINNET_GENESIS);
    let data = BuilderRequestAuth::new(hex::decode("1234567890abcdef").unwrap(), 1).unwrap();
    let object_root = data.tree_hash_root().0;
    assert_eq!(
        hex::encode(object_root),
        rvc_spec_vectors::builder_request_auth_kat::SPEC_GLOAS_BUILDERREQUESTAUTH_ROOT
    );

    let grpc_resp = SignerServiceV2::sign_root(
        &grpc_svc(&s),
        Request::new(SignRootRequest {
            pubkey: s.pubkey.to_vec(),
            fork_info: Some(gloas_fork_info()),
            object_root: object_root.to_vec(),
            duty: Duty::BuilderRequestAuth as i32,
            fork_id: 7,
        }),
    )
    .await
    .expect("gRPC SignRoot builder request auth")
    .into_inner()
    .signature;

    let body = format!(
        r#"{{ "type": "BUILDER_REQUEST_AUTH",
              "builder_request_auth": {{ "version": "GLOAS", "data": {data} }} }}"#,
        data = serde_json::to_string(&data).unwrap(),
    );
    let http_sig = http_sign(http_state(&s), &s.pubkey, body).await;
    assert_eq!(grpc_resp, http_sig, "gRPC SignRoot BUILDER_REQUEST_AUTH must match HTTP");

    let kat: [u8; 32] = hex::decode(
        rvc_spec_vectors::builder_request_auth_kat::KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT,
    )
    .expect("kat hex")
    .try_into()
    .expect("32-byte kat");
    let expected = s.sk.sign(&kat).to_bytes().to_vec();
    assert_eq!(grpc_resp, expected);
    let domain = compute_domain(DOMAIN_BUILDER_REQUEST_AUTH, MAINNET_GENESIS, [0u8; 32]);
    assert_eq!(compute_signing_root(&object_root, domain), kat);
}
