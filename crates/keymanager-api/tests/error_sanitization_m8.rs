//! Integration tests for M-8: keymanager-api error sanitization.
//!
//! Verifies that verbose internal error details are never echoed to API clients.
//! Full error chains are logged server-side (with a request ID); the client only
//! receives a stable, generic message.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use async_trait::async_trait;
use axum::routing::{get, post};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::{
    import_keystores, import_remote_keys, list_keystores, AppState,
};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, DoppelgangerMonitor, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection,
    SlashingProtectionError, ValidatorConfigManager, ValidatorManager,
};

// ── Verbose error string that must never reach the client ──────────────────
const VERBOSE_ERROR: &str =
    "INTERNAL_SECRET: file=/var/secrets/keystore.db syscall=open errno=ENOMEM detail=heap_alloc_failed_0xdeadbeef";

// ── Minimal mock implementations ──────────────────────────────────────────

struct SimpleKeystoreManager;

#[async_trait]
impl KeystoreManager for SimpleKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        vec![]
    }
    fn has_key(&self, _: &Pubkey) -> bool {
        false
    }
    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Ok([1u8; 48])
    }
    fn delete_keystore(&self, _: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        Ok(false)
    }
}

/// Always returns a verbose I/O error from `import_keystore`.
struct VerboseFailingKeystoreManager;

#[async_trait]
impl KeystoreManager for VerboseFailingKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        vec![]
    }
    fn has_key(&self, _: &Pubkey) -> bool {
        false
    }
    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Err(ImportKeystoreError::Io(VERBOSE_ERROR.to_string()))
    }
    fn delete_keystore(&self, _: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        Ok(false)
    }
}

struct SimpleSlashingProtection;

#[async_trait]
impl SlashingProtection for SimpleSlashingProtection {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }
    fn export_interchange(&self, _: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        Ok(r#"{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"data":[]}"#.to_string())
    }
}

/// Always returns a verbose error from `import_interchange`.
struct VerboseFailingSlashingProtection;

#[async_trait]
impl SlashingProtection for VerboseFailingSlashingProtection {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Err(SlashingProtectionError::Backend(VERBOSE_ERROR.to_string()))
    }
    fn export_interchange(&self, _: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        Err(SlashingProtectionError::Backend(VERBOSE_ERROR.to_string()))
    }
}

struct NoopValidatorManager;

impl ValidatorManager for NoopValidatorManager {
    fn add_validator(&self, _: Pubkey, _: bool) {}
    fn remove_validator(&self, _: &Pubkey) -> bool {
        false
    }
    fn set_validator_enabled(&self, _: &Pubkey, _: bool) {}
}

struct NoopDoppelgangerMonitor;

impl DoppelgangerMonitor for NoopDoppelgangerMonitor {
    fn start_monitoring(&self, _: Pubkey) {}
    fn stop_monitoring(&self, _: &Pubkey) {}
    fn is_doppelganger_safe(&self, _: &Pubkey) -> bool {
        true
    }
}

struct SimpleRemoteKeyManager;

impl RemoteKeyManager for SimpleRemoteKeyManager {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        vec![]
    }
    fn has_remote_key(&self, _: &Pubkey) -> bool {
        false
    }
    fn import_remote_key(&self, _: Pubkey, _: String) -> Result<(), ImportRemoteKeyError> {
        Ok(())
    }
    fn delete_remote_key(&self, _: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        Ok(false)
    }
}

/// Always returns a verbose `Other` error from `import_remote_key`.
struct VerboseFailingRemoteKeyManager;

impl RemoteKeyManager for VerboseFailingRemoteKeyManager {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        vec![]
    }
    fn has_remote_key(&self, _: &Pubkey) -> bool {
        false
    }
    fn import_remote_key(&self, _: Pubkey, _: String) -> Result<(), ImportRemoteKeyError> {
        Err(ImportRemoteKeyError::Backend(VERBOSE_ERROR.to_string()))
    }
    fn delete_remote_key(&self, _: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        Ok(false)
    }
}

struct NoopConfigManager;

impl ValidatorConfigManager for NoopConfigManager {
    fn get_fee_recipient(&self, _: &Pubkey) -> Result<[u8; 20], ApiError> {
        Err(ApiError::NotFound("not found".into()))
    }
    fn set_fee_recipient(&self, _: &Pubkey, _: [u8; 20]) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_fee_recipient(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
    fn get_gas_limit(&self, _: &Pubkey) -> Result<u64, ApiError> {
        Err(ApiError::NotFound("not found".into()))
    }
    fn set_gas_limit(&self, _: &Pubkey, _: u64) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_gas_limit(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
    fn get_graffiti(&self, _: &Pubkey) -> Result<String, ApiError> {
        Ok(String::new())
    }
    fn set_graffiti(&self, _: &Pubkey, _: &str) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_graffiti(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
}

// ── Test helpers ───────────────────────────────────────────────────────────

fn pubkey_hex(seed: u8) -> String {
    hex::encode([seed; 48])
}

fn keystore_json(seed: u8) -> String {
    serde_json::json!({ "pubkey": pubkey_hex(seed) }).to_string()
}

fn make_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/eth/v1/keystores", get(list_keystores).post(import_keystores))
        .route("/eth/v1/remotekeys", post(import_remote_keys))
        .with_state(state)
}

fn post_request(uri: &str, body: String) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

// ── Spot 1: slashing-protection import failure ─────────────────────────────

/// Spot 1 — when slashing-protection import fails, the HTTP 500 body must NOT
/// contain the verbose internal error string; only a generic message is sent.
#[tokio::test]
async fn test_internal_error_sanitized() {
    let state = Arc::new(AppState {
        keystore_manager: Arc::new(SimpleKeystoreManager),
        slashing_protection: Arc::new(VerboseFailingSlashingProtection),
        validator_manager: Arc::new(NoopValidatorManager),
        doppelganger: Arc::new(rvc_keymanager_api::DoppelgangerLifecycle::new(
            std::time::Duration::ZERO,
            Arc::new(NoopDoppelgangerMonitor),
            Arc::new(NoopValidatorManager),
        )),
        remote_key_manager: Arc::new(SimpleRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: true,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let slashing_data = r#"{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"data":[]}"#;
    let body = serde_json::json!({
        "keystores": [keystore_json(1)],
        "passwords": ["pass"],
        "slashing_protection": slashing_data
    })
    .to_string();

    let response =
        make_router(state).oneshot(post_request("/eth/v1/keystores", body)).await.unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "expected 500 when slashing import fails"
    );

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = json["message"].as_str().unwrap_or("");

    assert!(
        !msg.contains(VERBOSE_ERROR),
        "spot 1: verbose internal error was leaked to API client — message: {msg}"
    );
    assert!(
        msg.contains("internal error"),
        "spot 1: expected a generic 'internal error' message, got: {msg}"
    );
}

// ── Spot 2: keystore import per-item error ─────────────────────────────────

/// Spot 2 — when a single keystore import fails with an internal error, the
/// per-item `message` in the 200 response must NOT contain verbose internals.
#[tokio::test]
async fn test_keystore_import_item_error_sanitized() {
    let state = Arc::new(AppState {
        keystore_manager: Arc::new(VerboseFailingKeystoreManager),
        slashing_protection: Arc::new(SimpleSlashingProtection),
        validator_manager: Arc::new(NoopValidatorManager),
        doppelganger: Arc::new(rvc_keymanager_api::DoppelgangerLifecycle::new(
            std::time::Duration::ZERO,
            Arc::new(NoopDoppelgangerMonitor),
            Arc::new(NoopValidatorManager),
        )),
        remote_key_manager: Arc::new(SimpleRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: true,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let body = serde_json::json!({
        "keystores": [keystore_json(2)],
        "passwords": ["pass"]
    })
    .to_string();

    let response =
        make_router(state).oneshot(post_request("/eth/v1/keystores", body)).await.unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = json["data"][0]["message"].as_str().unwrap_or("");

    assert!(
        !msg.contains(VERBOSE_ERROR),
        "spot 2: verbose internal error was leaked to API client — message: {msg}"
    );
    assert!(
        !msg.is_empty(),
        "spot 2: error result must have a non-empty message for clients to surface"
    );
    // The request_id is the sole correlation primitive between this client
    // message and the server's error log chain — without it operators cannot
    // map a user complaint back to a specific failure.
    assert!(
        msg.contains("request_id="),
        "spot 2: request_id correlator missing from client message — got: {msg}"
    );
    assert!(msg.contains("key error"), "spot 2: expected generic 'key error' prefix — got: {msg}");
}

// ── Spot 3: remote-key import per-item error ───────────────────────────────

/// Spot 3 — when a remote-key import fails with an internal `Other` error, the
/// per-item `message` in the 200 response must NOT contain verbose internals.
#[tokio::test]
async fn test_remote_key_import_item_error_sanitized() {
    let state = Arc::new(AppState {
        keystore_manager: Arc::new(SimpleKeystoreManager),
        slashing_protection: Arc::new(SimpleSlashingProtection),
        validator_manager: Arc::new(NoopValidatorManager),
        doppelganger: Arc::new(rvc_keymanager_api::DoppelgangerLifecycle::new(
            std::time::Duration::ZERO,
            Arc::new(NoopDoppelgangerMonitor),
            Arc::new(NoopValidatorManager),
        )),
        remote_key_manager: Arc::new(VerboseFailingRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: true,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let pubkey_str = format!("0x{}", pubkey_hex(3));
    let body = serde_json::json!({
        "remote_keys": [{
            "pubkey": pubkey_str,
            "url": "https://8.8.8.8:9000"
        }]
    })
    .to_string();

    let response =
        make_router(state).oneshot(post_request("/eth/v1/remotekeys", body)).await.unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = json["data"][0]["message"].as_str().unwrap_or("");

    assert!(
        !msg.contains(VERBOSE_ERROR),
        "spot 3: verbose internal error was leaked to API client — message: {msg}"
    );
    assert!(
        !msg.is_empty(),
        "spot 3: error result must have a non-empty message for clients to surface"
    );
    assert!(
        msg.contains("request_id="),
        "spot 3: request_id correlator missing from client message — got: {msg}"
    );
    assert!(msg.contains("key error"), "spot 3: expected generic 'key error' prefix — got: {msg}");
}
