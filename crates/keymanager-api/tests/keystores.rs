//! Router tests: `/eth/v1/keystores` and related slashing/import behavior.

mod common;

use std::sync::Arc;

use axum::extract::{Json, State};
use axum::http::HeaderMap;
use common::*;
use http_body_util::BodyExt;
use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::import_keystores;
use rvc_keymanager_api::traits::{DoppelgangerMonitor, KeystoreManager};
use rvc_keymanager_api::types::{
    DeleteKeystoreResult, DeleteKeystoresResponse, DeleteStatus, ImportKeystoreResult,
    ImportKeystoresRequest, ImportKeystoresResponse, ImportStatus, ListKeystoresResponse,
};
use tower::ServiceExt;

fn auth_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    headers
}

fn mk_request() -> ImportKeystoresRequest {
    ImportKeystoresRequest {
        keystores: vec![mock_keystore_json(1)],
        passwords: vec!["pw".to_string()],
        slashing_protection: None,
    }
}

// --- GET /eth/v1/keystores tests ---

#[tokio::test]
async fn test_list_keystores_empty() {
    let app = TestApp::new();
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ListKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert!(resp.data.is_empty());
}

#[tokio::test]
async fn test_list_keystores_with_validators() {
    let app = TestApp::with_keys(vec![test_pubkey(1), test_pubkey(2)]);

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ListKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 2);
    assert_eq!(resp.data[0].validating_pubkey, format!("0x{}", test_pubkey_hex(1)));
    assert_eq!(resp.data[1].validating_pubkey, format!("0x{}", test_pubkey_hex(2)));
    assert!(!resp.data[0].readonly);
    assert!(!resp.data[1].readonly);
}

// --- POST /eth/v1/keystores tests ---

#[tokio::test]
async fn test_import_single_keystore() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "keystores": [mock_keystore_json(1)],
        "passwords": ["password1"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, ImportStatus::Imported);

    assert!(app.keystore_manager.has_key(&test_pubkey(1)));

    let validators = app.validator_manager.validators.lock();
    assert_eq!(validators.len(), 1);
    assert!(!validators[0].1); // disabled for doppelganger

    let monitored = app.doppelganger_monitor.monitored.lock();
    assert_eq!(monitored.len(), 1);
}

#[tokio::test]
async fn test_import_multiple_keystores() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "keystores": [mock_keystore_json(1), mock_keystore_json(2)],
        "passwords": ["password1", "password2"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 2);
    assert_eq!(resp.data[0].status, ImportStatus::Imported);
    assert_eq!(resp.data[1].status, ImportStatus::Imported);
}

#[tokio::test]
async fn test_import_duplicate_keystore() {
    let app = TestApp::with_keys(vec![test_pubkey(1)]);
    let request_body = serde_json::json!({
        "keystores": [mock_keystore_json(1)],
        "passwords": ["password1"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, ImportStatus::Duplicate);
}

#[tokio::test]
async fn test_import_with_slashing_protection() {
    let mock_slashing = Arc::new(MockSlashingProtection::new());
    let mut app = TestApp::new();
    app.slashing_protection = mock_slashing.clone();
    let slashing_data = serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "data": []
    })
    .to_string();

    let request_body = serde_json::json!({
        "keystores": [mock_keystore_json(1)],
        "passwords": ["password1"],
        "slashing_protection": slashing_data
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let imported = mock_slashing.imported.lock();
    assert_eq!(imported.len(), 1);
}

#[tokio::test]
async fn test_import_mismatched_lengths() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "keystores": [mock_keystore_json(1), mock_keystore_json(2)],
        "passwords": ["password1"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_invalid_keystore_json() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "keystores": ["not valid json"],
        "passwords": ["password1"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, ImportStatus::Error);
}

#[tokio::test]
async fn test_import_keystores_rate_limit_kicks_in_at_eleventh_call() {
    let state = TestApp::new().app_state();
    for i in 1..=IMPORT_KEYSTORES_MAX_PER_WINDOW {
        let r = import_keystores(State(state.clone()), auth_headers("token-A"), Json(mk_request()))
            .await;
        assert!(r.is_ok(), "call #{i} for token-A must be allowed (under quota)");
    }
    let r =
        import_keystores(State(state.clone()), auth_headers("token-A"), Json(mk_request())).await;
    match r {
        Err(ApiError::RateLimited { retry_after_secs }) => {
            assert!(retry_after_secs >= 1, "Retry-After must be at least 1s");
            assert!(retry_after_secs <= 60, "Retry-After cannot exceed window");
        }
        other => panic!("11th call must be rate-limited, got {:?}", other.is_ok()),
    }
}

#[tokio::test]
async fn test_import_keystores_rate_limit_isolated_per_token() {
    let state = TestApp::new().app_state();
    for _ in 0..IMPORT_KEYSTORES_MAX_PER_WINDOW {
        let r = import_keystores(State(state.clone()), auth_headers("token-A"), Json(mk_request()))
            .await;
        assert!(r.is_ok());
    }
    // Token-A is now rate-limited.
    let r =
        import_keystores(State(state.clone()), auth_headers("token-A"), Json(mk_request())).await;
    assert!(matches!(r, Err(ApiError::RateLimited { .. })));

    // Token-B has its own quota.
    let r =
        import_keystores(State(state.clone()), auth_headers("token-B"), Json(mk_request())).await;
    assert!(r.is_ok(), "token-B must have an independent quota");
}

#[tokio::test]
async fn test_import_keystores_no_auth_header_skips_rate_limit() {
    // Without a Bearer token the rate-limiter is bypassed; auth
    // middleware (`bearer_auth`) is the primary gate in production.
    let state = TestApp::new().app_state();
    for _ in 0..(IMPORT_KEYSTORES_MAX_PER_WINDOW + 5) {
        let r = import_keystores(State(state.clone()), HeaderMap::new(), Json(mk_request())).await;
        assert!(r.is_ok(), "no-token requests must not be rate-limited");
    }
}

// --- DELETE /eth/v1/keystores tests ---

#[tokio::test]
async fn test_delete_existing_keystore() {
    let app = TestApp::with_keys(vec![test_pubkey(1)]);
    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
    assert!(!app.keystore_manager.has_key(&test_pubkey(1)));
}

#[tokio::test]
async fn test_delete_nonexistent_keystore() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(99))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteStatus::NotFound);
}

#[tokio::test]
async fn test_delete_returns_slashing_export() {
    let app = TestApp::with_keys(vec![test_pubkey(1)]);
    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
    let export: serde_json::Value = serde_json::from_str(&resp.slashing_protection).unwrap();
    assert_eq!(export["data"].as_array().unwrap().len(), 1);
    assert_eq!(export["data"][0]["pubkey"], format!("0x{}", test_pubkey_hex(1)));
}

#[tokio::test]
async fn test_delete_unknown_pubkey_returns_one_empty_record() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(99))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
    let export: serde_json::Value = serde_json::from_str(&resp.slashing_protection).unwrap();
    let data = export["data"].as_array().unwrap();
    assert_eq!(data.len(), 1, "an unknown key is an empty record, not a missing document");
    assert_eq!(data[0]["pubkey"], format!("0x{}", test_pubkey_hex(99)));
    assert!(data[0]["signed_attestations"].as_array().unwrap().is_empty());
    assert!(data[0]["signed_blocks"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_invalid_pubkey_hex() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "pubkeys": ["not_valid_hex!"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteStatus::Error);
}

// --- Finding #1 & #2: Slashing import must happen FIRST and failure is a hard error ---

#[tokio::test]
async fn test_import_slashing_failure_returns_error_no_keys_imported() {
    let app = TestApp::with_failing_slashing();
    let slashing_data = serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "data": []
    })
    .to_string();

    let request_body = serde_json::json!({
        "keystores": [mock_keystore_json(1)],
        "passwords": ["password1"],
        "slashing_protection": slashing_data
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Must return an error status, NOT 200
    assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    // No keys should have been imported
    assert!(!app.keystore_manager.has_key(&test_pubkey(1)));

    // No validators should have been added
    let validators = app.validator_manager.validators.lock();
    assert!(validators.is_empty());

    // No doppelganger monitoring started
    let monitored = app.doppelganger_monitor.monitored.lock();
    assert!(monitored.is_empty());
}

#[tokio::test]
async fn test_import_without_slashing_data_succeeds() {
    // When no slashing_protection is provided, import should still work
    let app = TestApp::with_failing_slashing();
    let request_body = serde_json::json!({
        "keystores": [mock_keystore_json(1)],
        "passwords": ["password1"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert!(app.keystore_manager.has_key(&test_pubkey(1)));
}

// --- Finding #3: message field should be omitted when empty ---

#[test]
fn test_import_success_result_omits_empty_message() {
    let result = ImportKeystoreResult { status: ImportStatus::Imported, message: String::new() };
    let json = serde_json::to_value(&result).unwrap();
    assert!(
        json.get("message").is_none(),
        "success result should not have 'message' key, got: {json}"
    );
}

#[test]
fn test_delete_success_result_omits_empty_message() {
    let result = DeleteKeystoreResult { status: DeleteStatus::Deleted, message: String::new() };
    let json = serde_json::to_value(&result).unwrap();
    assert!(
        json.get("message").is_none(),
        "success result should not have 'message' key, got: {json}"
    );
}

#[test]
fn test_error_result_includes_message() {
    let result = ImportKeystoreResult {
        status: ImportStatus::Error,
        message: "something went wrong".into(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["message"], "something went wrong");
}

// --- Finding #4: Delete must export slashing BEFORE deleting keystores ---

#[tokio::test]
async fn test_delete_exports_slashing_before_deletion() {
    // Uses key-aware slashing mock that only returns data for keys
    // that still exist in the keystore manager
    let app = TestApp::with_key_aware_slashing(vec![test_pubkey(1)]);
    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();

    // Key should be deleted
    assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
    assert!(!app.keystore_manager.has_key(&test_pubkey(1)));

    // Slashing export should contain the deleted key's data
    // (only possible if export happened BEFORE deletion)
    let export: serde_json::Value = serde_json::from_str(&resp.slashing_protection).unwrap();
    assert_eq!(
        export["data"].as_array().unwrap().len(),
        1,
        "export should contain data for the deleted key (export must happen before delete)"
    );
}

// --- Finding #5: Delete must call stop_monitoring ---

#[tokio::test]
async fn test_delete_calls_stop_monitoring() {
    let app = TestApp::with_keys(vec![test_pubkey(1), test_pubkey(2)]);
    // Pre-populate monitoring
    app.doppelganger_monitor.start_monitoring(test_pubkey(1));
    app.doppelganger_monitor.start_monitoring(test_pubkey(2));

    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Key 1 should no longer be monitored, key 2 should remain
    let monitored = app.doppelganger_monitor.monitored.lock();
    assert_eq!(monitored.len(), 1);
    assert_eq!(monitored[0], test_pubkey(2));
}
