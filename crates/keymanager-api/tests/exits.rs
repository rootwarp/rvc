//! Router tests: voluntary exit, prepare_exit, fee recipient, gas limit, graffiti.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use http_body_util::BodyExt;
use rvc_keymanager_api::types::VoluntaryExitResponse;
use tower::ServiceExt;

fn authed_get(token: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

fn authed_post(token: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

fn authed_post_json(
    token: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

fn authed_delete(token: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

#[tokio::test]
async fn test_get_fee_recipient_returns_value() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let addr = [0xABu8; 20];
    mock.fee_recipients.lock().insert(pk, addr);

    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["ethaddress"], format!("0x{}", hex::encode(addr)));
}

#[tokio::test]
async fn test_get_fee_recipient_unknown_pubkey_404() {
    let mock = MockValidatorConfigManager::new();
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_set_fee_recipient_valid_202() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
    let body = serde_json::json!({"ethaddress": "0xAbcF8e0d4e9587369b2301D0790347320302cc09"});
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_set_fee_recipient_zero_address_400() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
    let body = serde_json::json!({"ethaddress": "0x0000000000000000000000000000000000000000"});
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_delete_fee_recipient_204() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_fee_recipient_unknown_pubkey_404() {
    let mock = MockValidatorConfigManager::new();
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- Gas limit handler tests ---

#[tokio::test]
async fn test_get_gas_limit_returns_value() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    mock.gas_limits.lock().insert(pk, 30_000_000);

    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["gas_limit"], "30000000");
}

#[tokio::test]
async fn test_get_gas_limit_unknown_pubkey_404() {
    let mock = MockValidatorConfigManager::new();
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_set_gas_limit_valid_202() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
    let body = serde_json::json!({"gas_limit": "30000000"});
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_set_gas_limit_non_numeric_400() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
    let body = serde_json::json!({"gas_limit": "not_a_number"});
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_set_gas_limit_above_i64_max_400() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
    let above = (i64::MAX as u64).saturating_add(1).to_string();
    let body = serde_json::json!({"gas_limit": above});
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_delete_gas_limit_204() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_gas_limit_unknown_pubkey_404() {
    let mock = MockValidatorConfigManager::new();
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- Graffiti handler tests ---

#[tokio::test]
async fn test_get_graffiti_returns_value() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    mock.graffiti.lock().insert(pk, "hello world".to_string());

    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["graffiti"], "hello world");
}

#[tokio::test]
async fn test_get_graffiti_unknown_pubkey_404() {
    let mock = MockValidatorConfigManager::new();
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_set_graffiti_valid_202() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
    let body = serde_json::json!({"graffiti": "my graffiti"});
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_set_graffiti_too_long_400() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
    let body = serde_json::json!({"graffiti": "a]".repeat(17)}); // 34 bytes > 32
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_delete_graffiti_204() {
    let pk = test_pubkey(1);
    let mock = MockValidatorConfigManager::with_validator(pk);
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_graffiti_unknown_pubkey_404() {
    let mock = MockValidatorConfigManager::new();
    let router = TestApp::with_config_manager(mock).router();
    let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_voluntary_exit_with_explicit_epoch() {
    let pk = test_pubkey(1);
    let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let uri = format!("/eth/v1/validator/0x{}/voluntary_exit?epoch=300000", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
    let resp: VoluntaryExitResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp.data.message.epoch, 300000);
    assert_eq!(resp.data.message.validator_index, 42);
}

#[tokio::test]
async fn test_voluntary_exit_without_epoch_auto_detect() {
    let pk = test_pubkey(1);
    let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let uri = format!("/eth/v1/validator/0x{}/voluntary_exit", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
    let resp: VoluntaryExitResponse = serde_json::from_slice(&body_bytes).unwrap();
    // Mock returns epoch=100 when None is passed
    assert_eq!(resp.data.message.epoch, 100);
}

#[tokio::test]
async fn test_voluntary_exit_invalid_epoch_400() {
    let pk = test_pubkey(1);
    let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let uri = format!("/eth/v1/validator/0x{}/voluntary_exit?epoch=abc", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_voluntary_exit_unknown_pubkey_404() {
    let mock = Arc::new(MockVoluntaryExitManager::new());
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let uri = format!("/eth/v1/validator/0x{}/voluntary_exit", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_voluntary_exit_no_exit_manager_500() {
    let router = TestApp::new().with_exit_manager(None).router();

    let uri = format!("/eth/v1/validator/0x{}/voluntary_exit", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_prepare_exit_returns_signed_exit() {
    let pk = test_pubkey(1);
    let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let uri = format!("/rvc/v1/validator/0x{}/prepare_exit?epoch=300000", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
    let resp: VoluntaryExitResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp.data.message.epoch, 300000);
    assert_eq!(resp.data.message.validator_index, 42);
}

#[tokio::test]
async fn test_prepare_exit_unknown_pubkey_404() {
    let mock = Arc::new(MockVoluntaryExitManager::new());
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let uri = format!("/rvc/v1/validator/0x{}/prepare_exit", test_pubkey_hex(99));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_prepare_exit_no_exit_manager_500() {
    let router = TestApp::new().with_exit_manager(None).router();

    let uri = format!("/rvc/v1/validator/0x{}/prepare_exit", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_prepare_exit_invalid_epoch_400() {
    let pk = test_pubkey(1);
    let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let uri = format!("/rvc/v1/validator/0x{}/prepare_exit?epoch=abc", test_pubkey_hex(1));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_both_exit_routes_return_identical_response_for_same_input() {
    let pk = test_pubkey(1);
    let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let router = TestApp::new().with_exit_manager(Some(mock)).router();

    let hex = test_pubkey_hex(1);
    let eth_uri = format!("/eth/v1/validator/0x{hex}/voluntary_exit?epoch=300000");
    let rvc_uri = format!("/rvc/v1/validator/0x{hex}/prepare_exit?epoch=300000");

    let eth_resp = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&eth_uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let rvc_resp = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&rvc_uri)
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(eth_resp.status(), StatusCode::OK);
    assert_eq!(rvc_resp.status(), StatusCode::OK);

    let eth_bytes = BodyExt::collect(eth_resp.into_body()).await.unwrap().to_bytes();
    let rvc_bytes = BodyExt::collect(rvc_resp.into_body()).await.unwrap().to_bytes();
    let eth: VoluntaryExitResponse = serde_json::from_slice(&eth_bytes).unwrap();
    let rvc: VoluntaryExitResponse = serde_json::from_slice(&rvc_bytes).unwrap();

    assert_eq!(eth.data.message.epoch, rvc.data.message.epoch);
    assert_eq!(eth.data.message.validator_index, rvc.data.message.validator_index);
    assert_eq!(eth.data.signature, rvc.data.signature);
    assert_eq!(eth_bytes, rvc_bytes);
}

#[test]
fn test_exit_route_docs_match_openapi_description() {
    let openapi = include_str!("../../../docs/keymanager-api.openapi.yaml");
    assert!(
        openapi.contains("/eth/v1/validator/{pubkey}/voluntary_exit"),
        "OpenAPI must document the eth voluntary_exit path"
    );
    assert!(
        openapi.contains("/rvc/v1/validator/{pubkey}/prepare_exit"),
        "OpenAPI must document the rvc prepare_exit path"
    );
    // Both routes: API signs only; does not submit.
    assert!(
        openapi.contains("does not submit") || openapi.contains("does **not** submit"),
        "OpenAPI must state the API does not submit exits"
    );
    assert!(
        openapi.contains("Identical signing path and response shape"),
        "OpenAPI must document identical signing path for both routes"
    );
    // Intent-driven log framing remains documented.
    assert!(
        openapi.contains("WARN")
            || openapi.contains("WARN-level")
            || openapi.contains("log level differs (WARN")
    );
    assert!(openapi.contains("INFO"));
}

// --- Issue 4.1: Fee recipient integration tests ---

#[tokio::test]
async fn test_fee_recipient_lifecycle() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");
    let eth_addr = "0xAbcF8e0d4e9587369b2301D0790347320302cc09";

    // POST: set fee recipient → 202
    let resp = router
        .clone()
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "ethaddress": eth_addr })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // GET: verify it was set → 200
    let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["data"]["ethaddress"].as_str().unwrap().to_lowercase(),
        eth_addr.to_lowercase()
    );

    // DELETE: remove fee recipient → 204
    let resp = router.clone().oneshot(authed_delete(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET: verify it returns 404 after deletion
    let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_fee_recipient_unknown_pubkey() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let unknown_hex = format!("0x{}", test_pubkey_hex(99));
    let uri = format!("/eth/v1/validator/{unknown_hex}/feerecipient");

    let resp = router.oneshot(authed_get(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_fee_recipient_invalid_address() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");

    let resp = router
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "ethaddress": "0xinvalid" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fee_recipient_zero_address() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");

    let resp = router
        .oneshot(authed_post_json(
            &token,
            &uri,
            serde_json::json!({ "ethaddress": "0x0000000000000000000000000000000000000000" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- Issue 4.2: Gas limit + graffiti integration tests ---

#[tokio::test]
async fn test_gas_limit_lifecycle() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/gas_limit");

    // POST: set gas limit → 202
    let resp = router
        .clone()
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "gas_limit": "30000000" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // GET: verify → 200
    let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["gas_limit"], "30000000");

    // DELETE → 204
    let resp = router.clone().oneshot(authed_delete(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET: verify 404 after deletion
    let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_gas_limit_string_encoding() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/gas_limit");

    router
        .clone()
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "gas_limit": "30000000" })))
        .await
        .unwrap();

    let resp = router.oneshot(authed_get(&token, &uri)).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["data"]["gas_limit"].is_string(), "gas_limit must be a JSON string, not number");
    assert_eq!(json["data"]["gas_limit"].as_str().unwrap(), "30000000");
}

#[tokio::test]
async fn test_gas_limit_invalid_value() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/gas_limit");

    let resp = router
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "gas_limit": "not_a_number" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_graffiti_lifecycle() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/graffiti");

    // POST: set graffiti → 202
    let resp = router
        .clone()
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "graffiti": "hello world" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // GET: verify → 200
    let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["graffiti"], "hello world");

    // DELETE → 204
    let resp = router.clone().oneshot(authed_delete(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET: after delete returns empty default
    let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["graffiti"], "");
}

#[tokio::test]
async fn test_graffiti_max_length() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/graffiti");

    // 33 bytes → 400
    let resp = router
        .clone()
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "graffiti": "a".repeat(33) })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 32 bytes → 202
    let resp = router
        .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "graffiti": "a".repeat(32) })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

// --- Issue 4.3: Voluntary exit integration tests ---

#[tokio::test]
async fn test_voluntary_exit_with_epoch_integration() {
    let pk = test_pubkey(1);
    let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(Some(exit_mgr))
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit?epoch=300000");

    let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["message"]["epoch"], "300000");
}

#[tokio::test]
async fn test_voluntary_exit_auto_epoch_integration() {
    let pk = test_pubkey(1);
    let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(Some(exit_mgr))
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit");

    let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Mock defaults to epoch 100 when not specified
    assert_eq!(json["data"]["message"]["epoch"], "100");
}

#[tokio::test]
async fn test_voluntary_exit_invalid_epoch_integration() {
    let pk = test_pubkey(1);
    let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(Some(exit_mgr))
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit?epoch=abc");

    let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_voluntary_exit_unknown_pubkey_integration() {
    let pk = test_pubkey(1);
    let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(Some(exit_mgr))
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let unknown_hex = format!("0x{}", test_pubkey_hex(99));
    let uri = format!("/eth/v1/validator/{unknown_hex}/voluntary_exit");

    let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_voluntary_exit_no_manager_integration() {
    let pk = test_pubkey(1);
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit");

    let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_voluntary_exit_response_schema() {
    let pk = test_pubkey(1);
    let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let (router, token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(Some(exit_mgr))
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit?epoch=300000");

    let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // epoch and validator_index must be strings per Eth2 spec
    assert!(json["data"]["message"]["epoch"].is_string(), "epoch must be a string");
    assert!(
        json["data"]["message"]["validator_index"].is_string(),
        "validator_index must be a string"
    );

    // signature must be 0x-prefixed hex
    let sig = json["data"]["signature"].as_str().expect("signature must be a string");
    assert!(sig.starts_with("0x"), "signature must start with 0x");
    assert!(hex::decode(sig.strip_prefix("0x").unwrap()).is_ok(), "signature must be valid hex");
}
