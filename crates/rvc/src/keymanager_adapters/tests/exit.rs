use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use crypto::{Signature, Signer, SigningError, PUBLIC_KEY_BYTES_LEN};
use eth_types::Root;

struct CountingBackend {
    inner: Arc<dyn Signer>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Signer for CountingBackend {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.inner.public_keys()
    }
}

fn exit_signer_counting(
    composite: Arc<CompositeSigner>,
    slashing_db: Arc<SlashingDb>,
    enablement: Arc<dyn doppelganger::SigningEnablement>,
) -> (Arc<SignerService>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CountingBackend {
        inner: Arc::clone(&composite) as Arc<dyn Signer>,
        calls: Arc::clone(&calls),
    });
    let (signer, _registry) = crate::config::ServiceBuilder::new(crate::config::Config::default())
        .build_signer(composite, slashing_db, enablement);
    let signer = match Arc::try_unwrap(signer) {
        Ok(signer) => signer,
        Err(_) => panic!("the test owns the only SignerService"),
    };
    (Arc::new(signer.with_sign_backend(backend)), calls)
}

fn schedule_with_capella(capella_fork_epoch: u64) -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: 10,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch,
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

async fn assert_no_post(server: &wiremock::MockServer) {
    let requests = server.received_requests().await.expect("requests");
    assert!(
        requests.iter().all(|request| request.method.as_str() != "POST"),
        "exit must not POST, requests={requests:?}"
    );
}

// --- VoluntaryExitManagerAdapter tests ---

fn create_exit_adapter(beacon_url: &str, secret_key: SecretKey) -> VoluntaryExitManagerAdapter {
    let beacon_config = beacon::BeaconClientConfig::new(beacon_url);
    let beacon_client: Arc<dyn bn_manager::BeaconNodeClient> =
        Arc::new(BeaconClient::new(beacon_config).expect("test beacon client"));

    let key_manager = crypto::KeyManager::new();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    composite.add_local_key(secret_key);

    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let fork_schedule = Arc::new(ForkSchedule {
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
    });

    let genesis_validators_root = [0xaa; 32];

    VoluntaryExitManagerAdapter::new(
        beacon_client,
        signer,
        fork_schedule,
        genesis_validators_root,
        0,
        eth_types::SLOT_DURATION_MS,
    )
}

#[test]
fn test_exit_adapter_struct_construction() {
    let sk = SecretKey::generate();
    let _adapter = create_exit_adapter("http://localhost:5052", sk);
}

#[tokio::test]
async fn test_exit_adapter_validator_not_found() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .mount(&mock_server)
        .await;

    let sk = SecretKey::generate();
    let pubkey = sk.public_key().to_bytes();
    let adapter = create_exit_adapter(&mock_server.uri(), sk);

    let result = adapter.sign_voluntary_exit(&pubkey, Some(100)).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        ApiError::NotFound(msg) => assert!(msg.contains("not found")),
        other => panic!("expected NotFound, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_exit_adapter_sign_with_explicit_epoch() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let sk = SecretKey::generate();
    let pubkey_bytes = sk.public_key().to_bytes();
    let pubkey_hex = pubkey_hex(pubkey_bytes);

    Mock::given(method("GET"))
        .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "index": "42",
                "status": "active_ongoing",
                "validator": {
                    "pubkey": pubkey_hex,
                    "withdrawal_credentials": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "effective_balance": "32000000000",
                    "slashed": false,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": "0",
                    "exit_epoch": "18446744073709551615",
                    "withdrawable_epoch": "18446744073709551615"
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let adapter = create_exit_adapter(&mock_server.uri(), sk);

    let result = adapter.sign_voluntary_exit(&pubkey_bytes, Some(100)).await;
    assert!(result.is_ok());

    let signed = result.unwrap();
    assert_eq!(signed.message.epoch, 100);
    assert_eq!(signed.message.validator_index, 42);
    assert_eq!(signed.signature.len(), 96);
}

#[tokio::test]
async fn test_exit_adapter_refuses_a_pending_forward_window_key() {
    use doppelganger::{ForwardWindowStatus, ValidatorLivenessData, CLOSED_EPOCH_SLOT};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let sk = SecretKey::generate();
    let pubkey_bytes = sk.public_key().to_bytes();
    let pubkey_hex = pubkey_hex(pubkey_bytes);
    let pk = crypto::PublicKey::from_bytes(&pubkey_bytes).expect("pubkey");

    Mock::given(method("GET"))
        .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "index": "42",
                "status": "active_ongoing",
                "validator": { "pubkey": pubkey_hex }
            }]
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
    let beacon_client: Arc<dyn bn_manager::BeaconNodeClient> =
        Arc::new(BeaconClient::new(beacon_config).expect("test beacon client"));

    let key_manager = crypto::KeyManager::new();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    composite.add_local_key(sk);

    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::clone(&slashing_db) as _;
    let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xaa; 32]));
    machine.register_for_import(&pk, 10);
    assert_eq!(machine.status(&pk), ForwardWindowStatus::Pending);

    let (signer, calls) = exit_signer_counting(
        composite,
        slashing_db,
        Arc::clone(&machine) as Arc<dyn SigningEnablement>,
    );
    let adapter = VoluntaryExitManagerAdapter::new(
        beacon_client,
        signer,
        Arc::new(schedule_with_capella(30)),
        [0xaa; 32],
        0,
        eth_types::SLOT_DURATION_MS,
    );

    let blocked = adapter.sign_voluntary_exit(&pubkey_bytes, Some(100)).await;
    match blocked {
        Err(ApiError::Internal(msg)) => {
            assert!(
                msg.to_lowercase().contains("doppelganger"),
                "expected the keymanager doppelganger error, got: {msg}"
            );
        }
        other => panic!("expected doppelganger Internal, got: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "Pending must not reach BLS");
    assert_no_post(&mock_server).await;

    let index = hex::encode(pk.to_bytes());
    for epoch in 11..16 {
        let missing = machine.observe_liveness(
            epoch,
            &[ValidatorLivenessData { index: index.clone(), is_live: false }],
            epoch + 1,
            CLOSED_EPOCH_SLOT,
        );
        assert!(missing.is_empty(), "epoch {epoch} left keys unobserved: {missing:?}");
        if machine.status(&pk) == ForwardWindowStatus::Safe {
            break;
        }
    }
    assert_eq!(machine.status(&pk), ForwardWindowStatus::Safe);

    let signed =
        adapter.sign_voluntary_exit(&pubkey_bytes, Some(100)).await.expect("safe key signs");
    assert_eq!(signed.message.epoch, 100);
    assert_eq!(signed.message.validator_index, 42);
    assert_eq!(signed.signature.len(), 96);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "Safe reaches BLS once");
    assert_no_post(&mock_server).await;
}

#[tokio::test]
async fn test_exit_adapter_refuses_a_detected_forward_window_key() {
    use doppelganger::{ForwardWindowStatus, ValidatorLivenessData, CLOSED_EPOCH_SLOT};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let sk = SecretKey::generate();
    let pubkey_bytes = sk.public_key().to_bytes();
    let pubkey_hex = pubkey_hex(pubkey_bytes);
    let pk = crypto::PublicKey::from_bytes(&pubkey_bytes).expect("pubkey");

    Mock::given(method("GET"))
        .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "index": "42",
                "status": "active_ongoing",
                "validator": { "pubkey": pubkey_hex }
            }]
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
    let beacon_client: Arc<dyn bn_manager::BeaconNodeClient> =
        Arc::new(BeaconClient::new(beacon_config).expect("test beacon client"));

    let key_manager = crypto::KeyManager::new();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    composite.add_local_key(sk);

    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::clone(&slashing_db) as _;
    let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xaa; 32]));
    machine.register_for_import(&pk, 10);
    let index = hex::encode(pk.to_bytes());
    let missing = machine.observe_liveness(
        11,
        &[ValidatorLivenessData { index, is_live: true }],
        12,
        CLOSED_EPOCH_SLOT,
    );
    assert!(missing.is_empty(), "live sample must be observed: {missing:?}");
    assert_eq!(machine.status(&pk), ForwardWindowStatus::Detected);

    let (signer, calls) = exit_signer_counting(
        composite,
        slashing_db,
        Arc::clone(&machine) as Arc<dyn SigningEnablement>,
    );
    let adapter = VoluntaryExitManagerAdapter::new(
        beacon_client,
        signer,
        Arc::new(schedule_with_capella(30)),
        [0xaa; 32],
        0,
        eth_types::SLOT_DURATION_MS,
    );

    let blocked = adapter.sign_voluntary_exit(&pubkey_bytes, Some(100)).await;
    match blocked {
        Err(ApiError::Internal(msg)) => {
            assert!(
                msg.to_lowercase().contains("doppelganger"),
                "expected the keymanager doppelganger error, got: {msg}"
            );
        }
        other => panic!("expected doppelganger Internal, got: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "Detected must not reach BLS");
    assert_no_post(&mock_server).await;
}

#[tokio::test]
async fn test_exit_adapter_beacon_unreachable() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key().to_bytes();
    let adapter = create_exit_adapter("http://127.0.0.1:1", sk);

    let result = adapter.sign_voluntary_exit(&pubkey, Some(100)).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        ApiError::Internal(msg) => assert!(msg.contains("beacon node error")),
        other => panic!("expected Internal, got: {:?}", other),
    }
}

async fn mount_exit_validator(server: &wiremock::MockServer, pubkey_hex: &str) {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("GET"))
        .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "index": "42",
                "status": "active_ongoing",
                "validator": { "pubkey": pubkey_hex }
            }]
        })))
        .mount(server)
        .await;
}

fn counting_adapter(
    server: &wiremock::MockServer,
    secret_key: SecretKey,
    capella_fork_epoch: u64,
) -> (VoluntaryExitManagerAdapter, Arc<AtomicUsize>) {
    let beacon_config = beacon::BeaconClientConfig::new(server.uri());
    let beacon_client: Arc<dyn bn_manager::BeaconNodeClient> =
        Arc::new(BeaconClient::new(beacon_config).expect("test beacon client"));
    let key_manager = crypto::KeyManager::new();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    composite.add_local_key(secret_key);
    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
    let (signer, calls) = exit_signer_counting(composite, slashing_db, signer::always_enabled());
    let adapter = VoluntaryExitManagerAdapter::new(
        beacon_client,
        signer,
        Arc::new(schedule_with_capella(capella_fork_epoch)),
        [0xaa; 32],
        0,
        eth_types::SLOT_DURATION_MS,
    );
    (adapter, calls)
}

fn assert_bad_request_names_epochs(err: ApiError, epoch: u64, capella_fork_epoch: u64) {
    match err {
        ApiError::BadRequest(msg) => {
            assert!(msg.contains(&epoch.to_string()), "{msg}");
            assert!(msg.contains(&capella_fork_epoch.to_string()), "{msg}");
            let status = ApiError::BadRequest(msg).into_response().status();
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        other => panic!("expected BadRequest, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_exit_adapter_rejects_a_pre_capella_exit_epoch() {
    let server = wiremock::MockServer::start().await;
    let sk = SecretKey::generate();
    let pubkey = sk.public_key().to_bytes();
    mount_exit_validator(&server, &pubkey_hex(pubkey)).await;
    let (adapter, calls) = counting_adapter(&server, sk, 30);
    let err = adapter.sign_voluntary_exit(&pubkey, Some(25)).await.expect_err("epoch 25");
    assert_bad_request_names_epochs(err, 25, 30);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(server.received_requests().await.expect("requests").len(), 0);
}

#[tokio::test]
async fn test_exit_adapter_signs_at_the_capella_fork_epoch() {
    let server = wiremock::MockServer::start().await;
    let sk = SecretKey::generate();
    let pubkey = sk.public_key().to_bytes();
    mount_exit_validator(&server, &pubkey_hex(pubkey)).await;
    let (adapter, calls) = counting_adapter(&server, sk, 30);
    let signed = adapter.sign_voluntary_exit(&pubkey, Some(30)).await.expect("Capella epoch signs");
    assert_eq!(signed.message.epoch, 30);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_exit_adapter_rejects_every_explicit_epoch_when_capella_is_unscheduled() {
    let server = wiremock::MockServer::start().await;
    let sk = SecretKey::generate();
    let pubkey = sk.public_key().to_bytes();
    mount_exit_validator(&server, &pubkey_hex(pubkey)).await;
    let (adapter, calls) = counting_adapter(&server, sk, u64::MAX);
    for epoch in [25_u64, u64::MAX] {
        let err = adapter
            .sign_voluntary_exit(&pubkey, Some(epoch))
            .await
            .expect_err("unscheduled Capella");
        assert_bad_request_names_epochs(err, epoch, u64::MAX);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(server.received_requests().await.expect("requests").len(), 0);
}
