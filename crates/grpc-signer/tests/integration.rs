#![allow(clippy::disallowed_methods)]
// Gate 1: tests round-trip raw key bytes for assertions; not a logging surface

// RF1-12: Tests must set/clear env vars via unsafe std::env::{set_var,remove_var}.
#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use crypto::typed_signer::{SignContext, TypedSigner};
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey, Signer, SigningError};
use eth_types::{BeaconBlock, ForkInfo};
use rvc_grpc_signer::{
    GrpcRemoteSigner, GrpcRemoteSignerConfig, SignerServiceServerV2, SignerServiceV2,
};
use rvc_test_support::TestPki;
use tokio::net::TcpListener;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::{Request, Response, Status};

// V2 proto types needed for the mock implementation
use rvc_grpc_signer::proto::signer_v2::{
    GetStatusRequest as GetStatusRequestV2, GetStatusResponse as GetStatusResponseV2,
    ListPublicKeysRequest as ListPublicKeysRequestV2,
    ListPublicKeysResponse as ListPublicKeysResponseV2, SignAggregateAndProofRequest,
    SignAttestationDataRequest, SignBeaconBlockRequest, SignBlindedBeaconBlockRequest,
    SignBlockHeaderRequest, SignBuilderRegistrationRequest, SignContributionAndProofRequest,
    SignRandaoRevealRequest, SignResponse as SignResponseV2, SignRootRequest,
    SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
    SignVoluntaryExitRequest,
};

// ---------------------------------------------------------------------------
// Test signing backend — implements gRPC v2 SignerService
// ---------------------------------------------------------------------------
//
// SS-1 (Issue 2.2): the live listener only serves the v2 SignerService.
// The mock therefore implements SignerServiceV2.  Only list_public_keys and
// get_status return real data; signing methods return Unimplemented because
// the connect path only calls list_public_keys.

struct TestSignerServiceV2 {
    secret_keys: Vec<SecretKey>,
    backend_name: String,
}

impl TestSignerServiceV2 {
    fn new(secret_keys: Vec<SecretKey>) -> Self {
        Self { secret_keys, backend_name: "basic".to_string() }
    }
}

#[tonic::async_trait]
impl SignerServiceV2 for TestSignerServiceV2 {
    // ── Informational RPCs (functional) ─────────────────────────────────────

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequestV2>,
    ) -> Result<Response<ListPublicKeysResponseV2>, Status> {
        let pubkeys: Vec<Vec<u8>> =
            self.secret_keys.iter().map(|sk| sk.public_key().to_bytes().to_vec()).collect();
        Ok(Response::new(ListPublicKeysResponseV2 { pubkeys }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequestV2>,
    ) -> Result<Response<GetStatusResponseV2>, Status> {
        Ok(Response::new(GetStatusResponseV2 {
            ready: true,
            backend: self.backend_name.clone(),
            key_count: self.secret_keys.len() as u32,
        }))
    }

    // ── Signing RPCs — Unimplemented in the test mock ────────────────────────
    // The integration tests only exercise the connect path (list_public_keys)
    // and the client-side key-not-found guard (no RPC sent).  Full signing
    // round-trips are covered by the rvc-signer-server integration tests.

    async fn sign_beacon_block(
        &self,
        _request: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_beacon_block not implemented"))
    }

    async fn sign_blinded_beacon_block(
        &self,
        _request: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_blinded_beacon_block not implemented"))
    }

    async fn sign_attestation_data(
        &self,
        _request: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_attestation_data not implemented"))
    }

    async fn sign_aggregate_and_proof(
        &self,
        _request: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_aggregate_and_proof not implemented"))
    }

    async fn sign_randao_reveal(
        &self,
        _request: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_randao_reveal not implemented"))
    }

    async fn sign_sync_committee_message(
        &self,
        _request: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_sync_committee_message not implemented"))
    }

    async fn sign_sync_aggregator_selection_data(
        &self,
        _request: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_sync_aggregator_selection_data not implemented"))
    }

    async fn sign_contribution_and_proof(
        &self,
        _request: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_contribution_and_proof not implemented"))
    }

    async fn sign_builder_registration(
        &self,
        _request: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_builder_registration not implemented"))
    }

    async fn sign_voluntary_exit(
        &self,
        _request: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_voluntary_exit not implemented"))
    }

    async fn sign_block_header(
        &self,
        _request: Request<SignBlockHeaderRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_block_header not implemented"))
    }

    async fn sign_root(
        &self,
        _request: Request<SignRootRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("test mock: sign_root not implemented"))
    }
}

// ---------------------------------------------------------------------------
// Server helpers — serve only the v2 SignerService (matching production)
// ---------------------------------------------------------------------------

async fn start_mtls_server(
    service: TestSignerServiceV2,
    pki: &TestPki,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    rvc_test_support::start_mtls_server(pki, move |mut server| {
        server.add_service(SignerServiceServerV2::new(service))
    })
    .await
}

async fn start_plaintext_server(
    service: TestSignerServiceV2,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SignerServiceServerV2::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, handle)
}

fn create_mtls_config(addr: SocketAddr, pki: &TestPki) -> GrpcRemoteSignerConfig {
    GrpcRemoteSignerConfig::new(format!("https://localhost:{}", addr.port())).with_tls(
        pki.client_cert_pem.clone(),
        pki.client_key_pem.clone(),
        pki.ca_cert_pem.clone(),
    )
}

// ---------------------------------------------------------------------------
// Sign context helper
// ---------------------------------------------------------------------------

fn test_sign_ctx(pk: crypto::PublicKey) -> SignContext {
    SignContext {
        pubkey: pk,
        fork_info: ForkInfo {
            previous_version: [0x00, 0x00, 0x00, 0x00],
            current_version: [0x00, 0x00, 0x00, 0x00], // Phase0
            genesis_validators_root: [0xaa; 32],
        },
        fork_name: eth_types::ForkName::Phase0,
    }
}

// ---------------------------------------------------------------------------
// 1. Happy path E2E: mTLS server → GrpcRemoteSigner client → connect verifies keys
//    Confirms that GrpcRemoteSigner::connect() uses the v2 list_public_keys RPC.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_connect_and_list_keys_with_mtls() {
    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();

    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    // GrpcRemoteSigner caches keys at connect time via v2 ListPublicKeys
    let keys = signer.public_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], pk_bytes);
}

// ---------------------------------------------------------------------------
// 2. mTLS rejection: client without cert → connection refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mtls_rejects_client_without_cert() {
    let sk = SecretKey::generate();
    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk]), &pki).await;

    // Connect with only CA cert (no client identity) — should fail
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(&pki.ca_cert_pem));

    let result = Channel::from_shared(format!("https://localhost:{}", addr.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await;

    match result {
        // Connection may succeed initially but fail on first RPC
        Ok(channel) => {
            use rvc_grpc_signer::SignerServiceClientV2;
            let mut client = SignerServiceClientV2::new(channel);
            let result = client.list_public_keys(ListPublicKeysRequestV2 {}).await;
            assert!(result.is_err(), "RPC should fail without client certificate");
        }
        Err(_) => {
            // Connection-level rejection is also acceptable
        }
    }
}

#[tokio::test]
async fn test_mtls_rejects_client_with_wrong_ca() {
    let sk = SecretKey::generate();
    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk]), &pki).await;

    // Generate a completely separate PKI (different CA)
    let rogue_pki = TestPki::new();

    let config = create_mtls_config(addr, &rogue_pki);
    let result = GrpcRemoteSigner::connect(config).await;

    assert!(result.is_err(), "Connection with wrong CA should be rejected");
}

// ---------------------------------------------------------------------------
// 3. Unknown key: TypedSigner returns KeyNotFound for unknown pubkey
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_unknown_key_returns_key_not_found() {
    let sk = SecretKey::generate();
    let unknown_sk = SecretKey::generate();
    let unknown_pk = unknown_sk.public_key();

    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    // sign_block should reject unknown pubkey before even sending the request
    let block = BeaconBlock {
        slot: 1,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
        body: vec![],
    };
    let unknown_pk_bytes = unknown_pk.to_bytes();
    let ctx = test_sign_ctx(unknown_pk);
    let result = TypedSigner::sign_block(&signer, &block, &ctx).await;
    match result.unwrap_err() {
        SigningError::KeyNotFound(pk_hex) => {
            assert_eq!(pk_hex, hex::encode(unknown_pk_bytes));
        }
        other => panic!("expected KeyNotFound, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. ListPublicKeys: returns all loaded keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_public_keys_returns_all() {
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();
    let pk1 = sk1.public_key().to_bytes();
    let pk2 = sk2.public_key().to_bytes();

    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk1, sk2]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    let keys = signer.public_keys();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&pk1));
    assert!(keys.contains(&pk2));
}

// ---------------------------------------------------------------------------
// 5. GetStatus: returns ready with correct backend/count (via v2 raw client)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_status_via_raw_client() {
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();

    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk1, sk2]), &pki).await;

    // Use raw v2 gRPC client to call GetStatus
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .identity(Identity::from_pem(&pki.client_cert_pem, &pki.client_key_pem))
        .ca_certificate(Certificate::from_pem(&pki.ca_cert_pem));

    let channel = Channel::from_shared(format!("https://localhost:{}", addr.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();

    use rvc_grpc_signer::SignerServiceClientV2;
    let mut client = SignerServiceClientV2::new(channel);

    let resp = client.get_status(GetStatusRequestV2 {}).await.unwrap().into_inner();
    assert!(resp.ready);
    assert_eq!(resp.backend, "basic");
    assert_eq!(resp.key_count, 2);
}

// ---------------------------------------------------------------------------
// 6. CompositeSigner routing: gRPC signer key registered via CompositeSigner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_composite_signer_registers_grpc_remote_keys() {
    let grpc_sk = SecretKey::generate();
    let grpc_pk = grpc_sk.public_key();
    let grpc_pk_bytes = grpc_pk.to_bytes();

    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![grpc_sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let grpc_signer = GrpcRemoteSigner::connect(config).await.unwrap();
    let grpc_pubkeys = grpc_signer.public_keys();

    // Build CompositeSigner with empty local signer
    let composite = CompositeSigner::new(LocalSigner::new(KeyManager::new()));
    composite.add_grpc_remote_signer(grpc_pubkeys, Arc::new(grpc_signer));

    // Verify public_keys includes the gRPC remote key
    let keys = composite.public_keys();
    assert!(keys.contains(&grpc_pk_bytes));
    // has_grpc_remote returns true for this key
    assert!(composite.has_grpc_remote(&grpc_pk_bytes));
    // get_grpc_remote returns a TypedSigner
    assert!(composite.get_grpc_remote(&grpc_pk_bytes).is_some());
}

#[tokio::test]
async fn test_composite_signer_grpc_remote_takes_priority_over_local_in_key_list() {
    // Generate key; reconstruct a second copy from raw bytes for the local signer
    let sk = SecretKey::generate();
    let sk_bytes = sk.to_bytes();
    let pk_bytes = sk.public_key().to_bytes();

    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let grpc_signer = GrpcRemoteSigner::connect(config).await.unwrap();
    let grpc_pubkeys = grpc_signer.public_keys();

    let local_sk = SecretKey::from_bytes(&sk_bytes).unwrap();
    let mut km = KeyManager::new();
    km.insert(local_sk);
    let composite = CompositeSigner::new(LocalSigner::new(km));
    composite.add_grpc_remote_signer(grpc_pubkeys, Arc::new(grpc_signer));

    // Key appears only once (deduplication)
    let keys = composite.public_keys();
    assert_eq!(keys.iter().filter(|k| **k == pk_bytes).count(), 1);
}

// ---------------------------------------------------------------------------
// Additional: plaintext E2E (no TLS) to verify basic wiring
// ---------------------------------------------------------------------------

/// Idempotent process-lifetime opt-in to the insecure remote-signer env var.
/// Used by the plaintext E2E test below.  Panic-safe: a panic during
/// `connect()` cannot leave the var set "leaked" because there is no paired
/// remove (this binary has no Refuse-path tests, so the var staying set for
/// the binary lifetime is the desired behavior — see review note).
fn allow_insecure_for_tests() {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        unsafe { std::env::set_var(rvc_grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR, "true") };
    });
}

#[tokio::test]
async fn test_e2e_plaintext_connect_lists_keys() {
    // GA (ISSUE-3.13) default mode is Refuse; we explicitly opt in for the
    // plaintext path.  Use the OnceLock helper instead of a raw set/remove
    // sandwich so a panic in `connect()` cannot leave the gate disabled for
    // siblings (review MF-1: panic-unsafe set_var/remove_var).
    allow_insecure_for_tests();

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();

    let (addr, _handle) = start_plaintext_server(TestSignerServiceV2::new(vec![sk])).await;

    let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    // GrpcRemoteSigner has v2 ListPublicKeys working
    assert_eq!(signer.public_keys().len(), 1);
    assert_eq!(signer.public_keys()[0], pk_bytes);
}

// ---------------------------------------------------------------------------
// Multiple keys: connect with multiple keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_multiple_keys_mtls() {
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();
    let sk3 = SecretKey::generate();
    let pk1_bytes = sk1.public_key().to_bytes();
    let pk2_bytes = sk2.public_key().to_bytes();
    let pk3_bytes = sk3.public_key().to_bytes();

    let pki = TestPki::new();
    let (addr, _handle) =
        start_mtls_server(TestSignerServiceV2::new(vec![sk1, sk2, sk3]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    assert_eq!(signer.public_keys().len(), 3);
    assert!(signer.public_keys().contains(&pk1_bytes));
    assert!(signer.public_keys().contains(&pk2_bytes));
    assert!(signer.public_keys().contains(&pk3_bytes));
}

#[tokio::test]
async fn test_connect_strips_trailing_slash() {
    let sk = SecretKey::generate();
    let pki = TestPki::new();
    let (addr, _handle) = start_mtls_server(TestSignerServiceV2::new(vec![sk]), &pki).await;

    let config = GrpcRemoteSignerConfig::new(format!("https://localhost:{}/", addr.port()))
        .with_tls(pki.client_cert_pem.clone(), pki.client_key_pem.clone(), pki.ca_cert_pem.clone());
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();
    assert!(!signer.url().ends_with('/'));
}
