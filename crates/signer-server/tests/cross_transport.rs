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
    AttestationData, Checkpoint, ValidatorRegistrationV1, DOMAIN_APPLICATION_BUILDER,
    DOMAIN_BEACON_ATTESTER, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO,
};
use signer_server::backend::{SigningBackend, SigningBackendError};
use signer_server::http_api::{router, AuditCfg, Web3SignerState};
use signer_server::proto::signer_v2::signer_service_server::SignerService as SignerServiceV2;
use signer_server::proto::signer_v2::{
    AttestationData as ProtoAttestationData, Checkpoint as ProtoCheckpoint, ForkInfo,
    SignAttestationDataRequest, SignBuilderRegistrationRequest, SignRandaoRevealRequest,
};
use signer_server::service::SignerServiceImpl;

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

// ── Payload attestation (non-slashable; HTTP-only until 4.20b) ───────────────
//
// No v2 SignerService RPC yet (4.20b) and no Web3Signer PAYLOAD_ATTESTATION
// type yet (4.9b). Future transports build the same PlanInput::PayloadAttestation
// (object_root + fork_version + gvr) and dispatch through the shared gate.

#[tokio::test]
async fn test_payload_attestation_plan_identical_across_transports() {
    let s = shared(MAINNET_GENESIS);
    let object_root: [u8; 32] =
        hex::decode(rvc_spec_vectors::spec_kat::SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT)
            .expect("spec object root hex")
            .try_into()
            .expect("32-byte object root");
    let fork_version = [0x07, 0x00, 0x00, 0x01];
    let gvr = [0u8; 32];
    // Same object_root + fork + gvr every transport will hand to plan_sign (4.9b / 4.20b).
    let domain = compute_domain(DOMAIN_PTC_ATTESTER, fork_version, gvr);
    let root = compute_signing_root(&object_root, domain);
    assert_eq!(
        hex::encode(root),
        rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT,
        "shared object_root + DOMAIN_PTC_ATTESTER must match the 4.0 KAT"
    );

    let pk = PublicKey::from_bytes(&s.pubkey).unwrap();
    let sig =
        s.gate.sign_payload_attestation(&pk, root).await.expect("shared-gate payload attestation");
    assert!(Signature::from_bytes(&sig).unwrap().verify(&pk, &root).is_ok());
}
