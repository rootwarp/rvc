use super::*;

// --- VoluntaryExitManagerAdapter tests ---

fn create_exit_adapter(beacon_url: &str, secret_key: SecretKey) -> VoluntaryExitManagerAdapter {
    let beacon_config = beacon::BeaconClientConfig::new(beacon_url);
    let beacon_client = Arc::new(BeaconClient::new(beacon_config).expect("test beacon client"));

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

    VoluntaryExitManagerAdapter::new(beacon_client, signer, fork_schedule, genesis_validators_root)
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
