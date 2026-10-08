use super::*;

// --- Full lifecycle: adapters wired into KeymanagerServer ---

fn build_test_server() -> keymanager_api::KeymanagerServer {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 100));

    let keystore_mgr = Arc::new(test_keystore_adapter(dir.keep(), composite.clone()).0);
    let slashing_prot =
        Arc::new(SlashingProtectionAdapter::new_in_free_window(slashing_db, [0u8; 32]));
    let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
    let doppelganger_mon = Arc::new(DoppelgangerDisabledMonitor::new());
    let remote_key_mgr = Arc::new(test_remote_adapter(composite, None).0);
    let config_mgr = Arc::new(ValidatorConfigManagerAdapter::new(validator_store));

    let token = "deadbeef".repeat(8);
    let addr = "127.0.0.1:0".parse().unwrap();

    keymanager_api::KeymanagerServer::new(
        keymanager_api::KeymanagerDeps {
            keystore_manager: keystore_mgr,
            slashing_protection: slashing_prot,
            validator_manager: validator_mgr,
            doppelganger_monitor: doppelganger_mon,
            remote_key_manager: remote_key_mgr,
            config_manager: config_mgr,
            exit_manager: None,
            signing_quiesce: None,
        },
        keymanager_api::KeymanagerSettings {
            token,
            addr,
            cors_origins: vec![],
            body_limit: keymanager_api::DEFAULT_BODY_LIMIT,
            allow_insecure_remote_signer: true,
            attesting_enabled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            doppelganger_window: std::time::Duration::ZERO,
        },
    )
}

#[test]
fn test_keymanager_server_builds_with_adapters() {
    let _server = build_test_server();
}

#[test]
fn test_keymanager_server_router_builds() {
    let server = build_test_server();
    let _router = server.router();
}

#[tokio::test]
async fn test_keymanager_server_list_keystores_requires_auth() {
    use tower::ServiceExt;

    let server = build_test_server();
    let router = server.router();

    // Request without auth token should be rejected
    let request = axum::http::Request::builder()
        .uri("/eth/v1/keystores")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_keymanager_server_list_keystores_empty() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let server = build_test_server();
    let router = server.router();
    let token = "deadbeef".repeat(8);

    let request = axum::http::Request::builder()
        .uri("/eth/v1/keystores")
        .header("Authorization", format!("Bearer {}", token))
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_keymanager_server_list_remote_keys_empty() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let server = build_test_server();
    let router = server.router();
    let token = "deadbeef".repeat(8);

    let request = axum::http::Request::builder()
        .uri("/eth/v1/remotekeys")
        .header("Authorization", format!("Bearer {}", token))
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_keymanager_server_import_remote_key_lifecycle() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 100));

    let keystore_mgr = Arc::new(test_keystore_adapter(dir.keep(), composite.clone()).0);
    let slashing_prot =
        Arc::new(SlashingProtectionAdapter::new_in_free_window(slashing_db, [0u8; 32]));
    let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
    let doppelganger_mon = Arc::new(DoppelgangerDisabledMonitor::new());
    let remote_key_mgr = Arc::new(test_remote_adapter(composite.clone(), None).0);
    let config_mgr = Arc::new(ValidatorConfigManagerAdapter::new(validator_store));

    let token = "deadbeef".repeat(8);
    let addr = "127.0.0.1:0".parse().unwrap();

    let server = keymanager_api::KeymanagerServer::new(
        keymanager_api::KeymanagerDeps {
            keystore_manager: keystore_mgr,
            slashing_protection: slashing_prot,
            validator_manager: validator_mgr,
            doppelganger_monitor: doppelganger_mon,
            remote_key_manager: remote_key_mgr,
            config_manager: config_mgr,
            exit_manager: None,
            signing_quiesce: None,
        },
        keymanager_api::KeymanagerSettings {
            token: token.clone(),
            addr,
            cors_origins: vec![],
            body_limit: keymanager_api::DEFAULT_BODY_LIMIT,
            allow_insecure_remote_signer: true,
            attesting_enabled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            doppelganger_window: std::time::Duration::ZERO,
        },
    );

    // 1. Import a remote key
    let pk = test_pubkey(42);
    let pk_hex = pubkey_hex(pk);
    // ISSUE-4.9 / L-9: import_remote_keys re-resolves the host via DNS
    // and validates against the private/reserved deny-list. Use a public
    // IP literal so this test does not depend on a CI DNS resolver.
    let import_body = serde_json::json!({
        "remote_keys": [{
            "pubkey": pk_hex,
            "url": "https://8.8.8.8:9000"
        }]
    });

    let router = server.router();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/eth/v1/remotekeys")
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(import_body.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let statuses = json["data"].as_array().unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0]["status"], "imported");

    // 2. Verify composite signer has the key
    assert!(composite.public_keys().contains(&pk));

    // 3. List remote keys - should contain the imported key
    let router = server.router();
    let request = axum::http::Request::builder()
        .uri("/eth/v1/remotekeys")
        .header("Authorization", format!("Bearer {}", token))
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys = json["data"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["pubkey"], pk_hex);

    // 4. Delete the remote key
    let delete_body = serde_json::json!({
        "pubkeys": [pk_hex]
    });

    let router = server.router();
    let request = axum::http::Request::builder()
        .method("DELETE")
        .uri("/eth/v1/remotekeys")
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(delete_body.to_string()))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let statuses = json["data"].as_array().unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0]["status"], "deleted");

    // 5. Verify composite signer no longer has the key
    assert!(!composite.public_keys().contains(&pk));
}
