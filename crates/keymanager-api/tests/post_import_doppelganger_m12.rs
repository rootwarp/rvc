//! Integration tests for M-12: post-import doppelganger window.
//!
//! Verifies that:
//!   - After `POST /eth/v1/keystores`, imported keys are NOT immediately
//!     attesting-enabled; they are held in the doppelganger window.
//!   - Once the window elapses, `doppelganger_safe` flips to `true` and
//!     the validator is enabled in the validator store.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::routing::get;
use axum::Router;
use common::PendingSetMonitor;
use http_body_util::BodyExt;
use tower::ServiceExt;

use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::{import_keystores, list_keystores, AppState};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, ImportKeystoreError, ImportRemoteKeyError,
    KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection, SlashingProtectionError,
    ValidatorConfigManager, ValidatorManager,
};

// ── Mock implementations ─────────────────────────────────────────────────────

/// Keystore manager that remembers which keys it has imported.
struct TrackingKeystoreManager {
    keys: Mutex<Vec<Pubkey>>,
}

impl TrackingKeystoreManager {
    fn new() -> Self {
        Self { keys: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl KeystoreManager for TrackingKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.lock().unwrap().clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.lock().unwrap().contains(pubkey)
    }

    async fn import_keystore(
        &self,
        keystore_json: &str,
        _password: &str,
    ) -> Result<Pubkey, ImportKeystoreError> {
        let v: serde_json::Value = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        let hex = v["pubkey"]
            .as_str()
            .ok_or_else(|| ImportKeystoreError::InvalidKeystore("missing pubkey".into()))?;
        let bytes =
            hex::decode(hex).map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        if bytes.len() != 48 {
            return Err(ImportKeystoreError::InvalidKeystore("pubkey must be 48 bytes".into()));
        }
        let mut pk = [0u8; 48];
        pk.copy_from_slice(&bytes);
        let mut keys = self.keys.lock().unwrap();
        if keys.contains(&pk) {
            return Err(ImportKeystoreError::Duplicate);
        }
        keys.push(pk);
        Ok(pk)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let mut keys = self.keys.lock().unwrap();
        if let Some(pos) = keys.iter().position(|k| k == pubkey) {
            keys.remove(pos);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct NoopSlashingProtection;
#[async_trait]
impl SlashingProtection for NoopSlashingProtection {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }
    fn export_interchange(&self, _: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        Ok(String::new())
    }
}

/// Spy validator manager that records which validators are enabled.
struct SpyValidatorManager {
    state: Mutex<HashMap<Pubkey, bool>>,
}

impl SpyValidatorManager {
    fn new() -> Self {
        Self { state: Mutex::new(HashMap::new()) }
    }

    fn is_enabled(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().get(pubkey).copied().unwrap_or(false)
    }
}

impl ValidatorManager for SpyValidatorManager {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        self.state.lock().unwrap().insert(pubkey, enabled);
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().remove(pubkey).is_some()
    }

    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
        if let Some(v) = self.state.lock().unwrap().get_mut(pubkey) {
            *v = enabled;
        }
    }
}

struct NoopRemoteKeyManager;
impl RemoteKeyManager for NoopRemoteKeyManager {
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// One epoch = 32 slots × 12 s/slot = 384 s.
/// The default doppelganger window is 2 epochs = 768 s.
const DOPPELGANGER_WINDOW: Duration = Duration::from_secs(2 * 32 * 12);

/// One slot duration for advancing mock time.
const ONE_SLOT: Duration = Duration::from_secs(12);

fn test_pubkey() -> Pubkey {
    let mut pk = [0u8; 48];
    pk[0] = 0x42;
    pk
}

fn keystore_json_for(pubkey: &Pubkey) -> String {
    serde_json::json!({ "pubkey": hex::encode(pubkey) }).to_string()
}

fn make_state(
    vm: Arc<SpyValidatorManager>,
    monitor: Arc<PendingSetMonitor>,
    window: Duration,
) -> Arc<AppState> {
    Arc::new(AppState {
        keystore_manager: Arc::new(TrackingKeystoreManager::new()),
        slashing_protection: Arc::new(NoopSlashingProtection),
        validator_manager: Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        doppelganger: Arc::new(rvc_keymanager_api::DoppelgangerLifecycle::new(
            window,
            monitor,
            Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        )),
        remote_key_manager: Arc::new(NoopRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    })
}

fn make_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/eth/v1/keystores", get(list_keystores).post(import_keystores))
        .with_state(state)
}

fn import_request(pubkey: &Pubkey) -> axum::http::Request<axum::body::Body> {
    let body = serde_json::json!({
        "keystores": [keystore_json_for(pubkey)],
        "passwords": ["test_password"]
    })
    .to_string();
    axum::http::Request::builder()
        .method("POST")
        .uri("/eth/v1/keystores")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn list_request() -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("GET")
        .uri("/eth/v1/keystores")
        .body(axum::body::Body::empty())
        .unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// After import, advancing one slot (< full window) must NOT flip the key to
/// doppelganger-safe or attesting-enabled.
#[tokio::test]
async fn test_imported_key_runs_doppelganger() {
    tokio::time::pause();

    let pubkey = test_pubkey();
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(PendingSetMonitor::new());
    let state = make_state(vm.clone(), monitor, DOPPELGANGER_WINDOW);
    let app = make_router(state);

    // POST import the keystore
    let resp = app.clone().oneshot(import_request(&pubkey)).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK, "import should succeed");

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["data"][0]["status"], "imported");

    // Advance one slot — still inside the window
    tokio::time::advance(ONE_SLOT).await;

    // GET keystores: doppelganger_safe must be false
    let resp = app.clone().oneshot(list_request()).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let entries = body["data"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "should have one key");
    assert_eq!(
        entries[0]["doppelganger_safe"],
        false,
        "key must NOT be doppelganger-safe after only one slot (window = {} s, elapsed ≈ {} s)",
        DOPPELGANGER_WINDOW.as_secs(),
        ONE_SLOT.as_secs(),
    );

    // Validator must still be disabled (background task has not fired yet)
    assert!(
        !vm.is_enabled(&pubkey),
        "validator must NOT be attesting-enabled while still in doppelganger window"
    );
}

/// Advancing past the full doppelganger window must flip `doppelganger_safe`
/// to `true` and enable the validator for attestation.
#[tokio::test]
async fn test_imported_key_attesting_after_window() {
    tokio::time::pause();

    let pubkey = test_pubkey();
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(PendingSetMonitor::new());
    let state = make_state(vm.clone(), monitor, DOPPELGANGER_WINDOW);
    let app = make_router(state);

    // POST import the keystore
    let resp = app.clone().oneshot(import_request(&pubkey)).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK, "import should succeed");

    // Advance past the full doppelganger window
    tokio::time::advance(DOPPELGANGER_WINDOW + Duration::from_secs(1)).await;

    // Yield control so the background task (tokio::spawn) can run
    tokio::task::yield_now().await;

    // GET keystores: doppelganger_safe must now be true
    let resp = app.clone().oneshot(list_request()).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let entries = body["data"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "should have one key");
    assert_eq!(
        entries[0]["doppelganger_safe"], true,
        "key must be doppelganger-safe after the window has elapsed"
    );

    // Validator must now be enabled (background task fired and called set_validator_enabled)
    assert!(
        vm.is_enabled(&pubkey),
        "validator must be attesting-enabled after doppelganger window elapses"
    );
}
