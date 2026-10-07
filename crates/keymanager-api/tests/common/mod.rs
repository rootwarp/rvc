//! Shared TestApp harness and trait doubles for keymanager-api router tests.
//!
//! Each top-level `tests/*.rs` file is a separate crate; fixtures live here so
//! keystores / remotekeys / exits / auth suites share one harness.
//!
//! Router construction always goes through [`KeymanagerServer::router`] — tests
//! must not rebuild routes by hand.

#![allow(dead_code)]

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Request};
use axum::Router;
use http_body_util::BodyExt;
use parking_lot::Mutex;
use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::AppState;
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, DoppelgangerMonitor, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection,
    ValidatorConfigManager, ValidatorManager, VoluntaryExitManager,
};
use rvc_keymanager_api::{KeymanagerDeps, KeymanagerServer, KeymanagerSettings};
use tower::ServiceExt;

/// Default bearer token used by [`TestApp`].
pub const DEFAULT_TEST_TOKEN: &str = "test_token";

/// Spec rate-limit: max `import_keystores` calls per token per 60s window.
/// Mirrors private `IMPORT_KEYSTORES_MAX_PER_WINDOW` in handlers.
pub const IMPORT_KEYSTORES_MAX_PER_WINDOW: usize = 10;

// --- Mock implementations ---

pub struct MockKeystoreManager {
    pub keys: Mutex<Vec<Pubkey>>,
}

impl MockKeystoreManager {
    pub fn new() -> Self {
        Self { keys: Mutex::new(Vec::new()) }
    }

    pub fn with_keys(keys: Vec<Pubkey>) -> Self {
        Self { keys: Mutex::new(keys) }
    }
}

#[async_trait]
impl KeystoreManager for MockKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.lock().clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.lock().contains(pubkey)
    }

    async fn import_keystore(
        &self,
        keystore_json: &str,
        _password: &str,
    ) -> Result<Pubkey, ImportKeystoreError> {
        let parsed: serde_json::Value = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        let pubkey_hex = parsed["pubkey"]
            .as_str()
            .ok_or_else(|| ImportKeystoreError::InvalidKeystore("missing pubkey".into()))?;
        let bytes = hex::decode(pubkey_hex)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        if bytes.len() != 48 {
            return Err(ImportKeystoreError::InvalidKeystore("invalid pubkey length".into()));
        }
        let mut pubkey = [0u8; 48];
        pubkey.copy_from_slice(&bytes);

        let mut keys = self.keys.lock();
        if keys.contains(&pubkey) {
            return Err(ImportKeystoreError::Duplicate);
        }
        keys.push(pubkey);
        Ok(pubkey)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let mut keys = self.keys.lock();
        if let Some(pos) = keys.iter().position(|k| k == pubkey) {
            keys.remove(pos);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct MockSlashingProtection {
    pub imported: Mutex<Vec<String>>,
}

impl MockSlashingProtection {
    pub fn new() -> Self {
        Self { imported: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl SlashingProtection for MockSlashingProtection {
    async fn import_interchange(
        &self,
        interchange_json: &str,
    ) -> Result<(), rvc_keymanager_api::traits::SlashingProtectionError> {
        self.imported.lock().push(interchange_json.to_string());
        Ok(())
    }

    fn export_interchange(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<String, rvc_keymanager_api::traits::SlashingProtectionError> {
        let data: Vec<serde_json::Value> = pubkeys
            .iter()
            .map(|pk| {
                serde_json::json!({
                    "pubkey": format!("0x{}", hex::encode(pk)),
                    "signed_blocks": [],
                    "signed_attestations": []
                })
            })
            .collect();
        Ok(serde_json::json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": data
        })
        .to_string())
    }
}

pub struct MockValidatorManager {
    pub validators: Mutex<Vec<(Pubkey, bool)>>,
}

impl MockValidatorManager {
    pub fn new() -> Self {
        Self { validators: Mutex::new(Vec::new()) }
    }
}

impl ValidatorManager for MockValidatorManager {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        self.validators.lock().push((pubkey, enabled));
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        let mut validators = self.validators.lock();
        if let Some(pos) = validators.iter().position(|(pk, _)| pk == pubkey) {
            validators.remove(pos);
            true
        } else {
            false
        }
    }

    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
        let mut validators = self.validators.lock();
        if let Some((_, e)) = validators.iter_mut().find(|(pk, _)| pk == pubkey) {
            *e = enabled;
        }
    }
}

pub struct MockDoppelgangerMonitor {
    pub monitored: Mutex<Vec<Pubkey>>,
}

impl MockDoppelgangerMonitor {
    pub fn new() -> Self {
        Self { monitored: Mutex::new(Vec::new()) }
    }
}

impl DoppelgangerMonitor for MockDoppelgangerMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        self.monitored.lock().push(pubkey);
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        let mut monitored = self.monitored.lock();
        if let Some(pos) = monitored.iter().position(|pk| pk == pubkey) {
            monitored.remove(pos);
        }
    }

    fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool {
        true
    }
}

/// Test double: unsafe while `start_monitoring` is outstanding.
///
/// Replaces the retired time-based gate in M-12 / KM-2 tests. `cancel_monitoring`
/// inherits the prune-pending default.
pub struct PendingSetMonitor {
    pending: Mutex<Vec<Pubkey>>,
}

impl PendingSetMonitor {
    pub fn new() -> Self {
        Self { pending: Mutex::new(Vec::new()) }
    }
}

impl DoppelgangerMonitor for PendingSetMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        self.pending.lock().push(pubkey);
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        let mut pending = self.pending.lock();
        if let Some(pos) = pending.iter().position(|pk| pk == pubkey) {
            pending.remove(pos);
        }
    }

    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
        !self.pending.lock().contains(pubkey)
    }
}

pub struct MockRemoteKeyManager {
    pub keys: Mutex<Vec<(Pubkey, String)>>,
}

impl MockRemoteKeyManager {
    pub fn new() -> Self {
        Self { keys: Mutex::new(Vec::new()) }
    }

    pub fn with_keys(keys: Vec<(Pubkey, String)>) -> Self {
        Self { keys: Mutex::new(keys) }
    }
}

impl RemoteKeyManager for MockRemoteKeyManager {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        self.keys.lock().clone()
    }

    fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.lock().iter().any(|(pk, _)| pk == pubkey)
    }

    fn import_remote_key(&self, pubkey: Pubkey, url: String) -> Result<(), ImportRemoteKeyError> {
        let mut keys = self.keys.lock();
        if keys.iter().any(|(pk, _)| *pk == pubkey) {
            return Err(ImportRemoteKeyError::Duplicate);
        }
        keys.push((pubkey, url));
        Ok(())
    }

    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        let mut keys = self.keys.lock();
        if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
            keys.remove(pos);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct MockValidatorConfigManager {
    pub fee_recipients: Mutex<std::collections::HashMap<Pubkey, [u8; 20]>>,
    pub gas_limits: Mutex<std::collections::HashMap<Pubkey, u64>>,
    pub graffiti: Mutex<std::collections::HashMap<Pubkey, String>>,
    pub known_pubkeys: Mutex<Vec<Pubkey>>,
}

impl MockValidatorConfigManager {
    pub fn new() -> Self {
        Self {
            fee_recipients: Mutex::new(std::collections::HashMap::new()),
            gas_limits: Mutex::new(std::collections::HashMap::new()),
            graffiti: Mutex::new(std::collections::HashMap::new()),
            known_pubkeys: Mutex::new(Vec::new()),
        }
    }

    pub fn with_validator(pubkey: Pubkey) -> Self {
        let m = Self::new();
        m.known_pubkeys.lock().push(pubkey);
        m
    }
}

impl ValidatorConfigManager for MockValidatorConfigManager {
    fn get_fee_recipient(&self, pubkey: &Pubkey) -> Result<[u8; 20], ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.fee_recipients
            .lock()
            .get(pubkey)
            .copied()
            .ok_or_else(|| ApiError::NotFound("fee recipient not set".into()))
    }

    fn set_fee_recipient(&self, pubkey: &Pubkey, address: [u8; 20]) -> Result<(), ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.fee_recipients.lock().insert(*pubkey, address);
        Ok(())
    }

    fn delete_fee_recipient(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.fee_recipients.lock().remove(pubkey);
        Ok(())
    }

    fn get_gas_limit(&self, pubkey: &Pubkey) -> Result<u64, ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.gas_limits
            .lock()
            .get(pubkey)
            .copied()
            .ok_or_else(|| ApiError::NotFound("gas limit not set".into()))
    }

    fn set_gas_limit(&self, pubkey: &Pubkey, limit: u64) -> Result<(), ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.gas_limits.lock().insert(*pubkey, limit);
        Ok(())
    }

    fn delete_gas_limit(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.gas_limits.lock().remove(pubkey);
        Ok(())
    }

    fn get_graffiti(&self, pubkey: &Pubkey) -> Result<String, ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        Ok(self.graffiti.lock().get(pubkey).cloned().unwrap_or_default())
    }

    fn set_graffiti(&self, pubkey: &Pubkey, graffiti: &str) -> Result<(), ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.graffiti.lock().insert(*pubkey, graffiti.to_string());
        Ok(())
    }

    fn delete_graffiti(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound("validator not found".into()));
        }
        self.graffiti.lock().remove(pubkey);
        Ok(())
    }
}

pub struct FailingSlashingProtection;

#[async_trait]
impl SlashingProtection for FailingSlashingProtection {
    async fn import_interchange(
        &self,
        _interchange_json: &str,
    ) -> Result<(), rvc_keymanager_api::traits::SlashingProtectionError> {
        Err(rvc_keymanager_api::traits::SlashingProtectionError::Backend(
            "slashing DB corrupted".into(),
        ))
    }

    fn export_interchange(
        &self,
        _pubkeys: &[Pubkey],
    ) -> Result<String, rvc_keymanager_api::traits::SlashingProtectionError> {
        Err(rvc_keymanager_api::traits::SlashingProtectionError::Backend("export failed".into()))
    }
}

/// Mock that checks key existence in a shared KeystoreManager at export time.
pub struct KeyAwareSlashingProtection {
    pub keystore_manager: Arc<MockKeystoreManager>,
}

#[async_trait]
impl SlashingProtection for KeyAwareSlashingProtection {
    async fn import_interchange(
        &self,
        _interchange_json: &str,
    ) -> Result<(), rvc_keymanager_api::traits::SlashingProtectionError> {
        Ok(())
    }

    fn export_interchange(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<String, rvc_keymanager_api::traits::SlashingProtectionError> {
        let existing: Vec<&Pubkey> =
            pubkeys.iter().filter(|pk| self.keystore_manager.has_key(pk)).collect();
        let data: Vec<serde_json::Value> = existing
            .iter()
            .map(|pk| {
                serde_json::json!({
                    "pubkey": format!("0x{}", hex::encode(pk)),
                    "signed_blocks": [],
                    "signed_attestations": []
                })
            })
            .collect();
        Ok(serde_json::json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": data
        })
        .to_string())
    }
}

pub struct MockVoluntaryExitManager {
    pub known_pubkeys: Mutex<Vec<Pubkey>>,
}

impl MockVoluntaryExitManager {
    pub fn new() -> Self {
        Self { known_pubkeys: Mutex::new(Vec::new()) }
    }

    pub fn with_validator(pubkey: Pubkey) -> Self {
        let m = Self::new();
        m.known_pubkeys.lock().push(pubkey);
        m
    }
}

#[async_trait::async_trait]
impl VoluntaryExitManager for MockVoluntaryExitManager {
    async fn sign_voluntary_exit(
        &self,
        pubkey: &Pubkey,
        epoch: Option<u64>,
    ) -> Result<eth_types::SignedVoluntaryExit, ApiError> {
        if !self.known_pubkeys.lock().contains(pubkey) {
            return Err(ApiError::NotFound(format!(
                "validator 0x{} not found",
                hex::encode(pubkey)
            )));
        }
        let epoch = epoch.unwrap_or(100);
        Ok(eth_types::SignedVoluntaryExit {
            message: eth_types::VoluntaryExit { epoch, validator_index: 42 },
            signature: vec![0xaa; 96],
        })
    }
}

// --- Helpers ---

pub fn test_pubkey(id: u8) -> Pubkey {
    let mut pk = [0u8; 48];
    pk[0] = id;
    pk
}

pub fn test_pubkey_hex(id: u8) -> String {
    hex::encode(test_pubkey(id))
}

pub fn mock_keystore_json(id: u8) -> String {
    serde_json::json!({ "pubkey": test_pubkey_hex(id) }).to_string()
}

/// Shared router harness built via [`KeymanagerServer::router`].
pub struct TestApp {
    pub keystore_manager: Arc<MockKeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<MockValidatorManager>,
    pub doppelganger_monitor: Arc<MockDoppelgangerMonitor>,
    pub remote_key_manager: Arc<MockRemoteKeyManager>,
    pub config_manager: Arc<MockValidatorConfigManager>,
    pub exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
    pub token: String,
    pub body_limit: usize,
    pub cors_origins: Vec<String>,
    pub allow_insecure_remote_signer: bool,
    pub attesting_enabled: Arc<AtomicBool>,
}

impl Default for TestApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TestApp {
    pub fn new() -> Self {
        Self {
            keystore_manager: Arc::new(MockKeystoreManager::new()),
            slashing_protection: Arc::new(MockSlashingProtection::new()),
            validator_manager: Arc::new(MockValidatorManager::new()),
            doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
            remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
            config_manager: Arc::new(MockValidatorConfigManager::new()),
            exit_manager: None,
            token: DEFAULT_TEST_TOKEN.to_string(),
            body_limit: 10 * 1024 * 1024,
            cors_origins: Vec::new(),
            allow_insecure_remote_signer: true,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn with_keys(keys: Vec<Pubkey>) -> Self {
        let mut app = Self::new();
        app.keystore_manager = Arc::new(MockKeystoreManager::with_keys(keys));
        app
    }

    pub fn with_remote_keys(keys: Vec<(Pubkey, String)>) -> Self {
        let mut app = Self::new();
        app.remote_key_manager = Arc::new(MockRemoteKeyManager::with_keys(keys));
        app
    }

    pub fn with_failing_slashing() -> Self {
        let mut app = Self::new();
        app.slashing_protection = Arc::new(FailingSlashingProtection);
        app
    }

    pub fn with_key_aware_slashing(keys: Vec<Pubkey>) -> Self {
        let keystore_manager = Arc::new(MockKeystoreManager::with_keys(keys));
        let mut app = Self::new();
        app.slashing_protection =
            Arc::new(KeyAwareSlashingProtection { keystore_manager: keystore_manager.clone() });
        app.keystore_manager = keystore_manager;
        app
    }

    pub fn with_config_manager(config_manager: MockValidatorConfigManager) -> Self {
        let mut app = Self::new();
        app.config_manager = Arc::new(config_manager);
        app
    }

    pub fn with_exit_manager(self, exit_manager: Option<Arc<dyn VoluntaryExitManager>>) -> Self {
        let mut app = self;
        app.exit_manager = exit_manager;
        app
    }

    pub fn with_token(self, token: impl Into<String>) -> Self {
        let mut app = self;
        app.token = token.into();
        app
    }

    pub fn with_body_limit(self, body_limit: usize) -> Self {
        let mut app = self;
        app.body_limit = body_limit;
        app
    }

    pub fn with_cors_origins(self, cors_origins: Vec<String>) -> Self {
        let mut app = self;
        app.cors_origins = cors_origins;
        app
    }

    pub fn with_allow_insecure_remote_signer(self, allow: bool) -> Self {
        let mut app = self;
        app.allow_insecure_remote_signer = allow;
        app
    }

    fn deps(&self) -> KeymanagerDeps {
        KeymanagerDeps {
            keystore_manager: self.keystore_manager.clone(),
            slashing_protection: self.slashing_protection.clone(),
            validator_manager: self.validator_manager.clone(),
            doppelganger_monitor: self.doppelganger_monitor.clone(),
            remote_key_manager: self.remote_key_manager.clone(),
            config_manager: self.config_manager.clone(),
            exit_manager: self.exit_manager.clone(),
            signing_quiesce: None,
        }
    }

    fn settings(&self) -> KeymanagerSettings {
        KeymanagerSettings {
            token: self.token.clone(),
            addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: self.cors_origins.clone(),
            body_limit: self.body_limit,
            allow_insecure_remote_signer: self.allow_insecure_remote_signer,
            attesting_enabled: self.attesting_enabled.clone(),
            doppelganger_window: Duration::ZERO,
        }
    }

    pub fn server(&self) -> KeymanagerServer {
        KeymanagerServer::new(self.deps(), self.settings())
    }

    /// Production router via [`KeymanagerServer::router`] (auth + cors + body limit).
    pub fn router(&self) -> Router {
        self.server().router()
    }

    /// Shared [`AppState`] for handler-level tests that need stable rate-limit maps.
    pub fn app_state(&self) -> Arc<AppState> {
        let validator_manager: Arc<dyn ValidatorManager> = self.validator_manager.clone();
        Arc::new(AppState {
            keystore_manager: self.keystore_manager.clone(),
            slashing_protection: self.slashing_protection.clone(),
            validator_manager: Arc::clone(&validator_manager),
            doppelganger: Arc::new(rvc_keymanager_api::DoppelgangerLifecycle::new(
                Duration::ZERO,
                self.doppelganger_monitor.clone(),
                Arc::clone(&validator_manager),
            )),
            remote_key_manager: self.remote_key_manager.clone(),
            config_manager: self.config_manager.clone(),
            exit_manager: self.exit_manager.clone(),
            allow_insecure_remote_signer: self.allow_insecure_remote_signer,
            attesting_enabled: self.attesting_enabled.clone(),
            last_set_attesting_enabled: std::sync::Mutex::new(None),
            import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        headers
    }

    pub fn authed_get(&self, uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.token))
            .body(Body::empty())
            .unwrap()
    }

    pub fn authed_post(&self, uri: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.token))
            .body(Body::empty())
            .unwrap()
    }

    pub fn authed_post_json(&self, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    pub fn authed_delete(&self, uri: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.token))
            .body(Body::empty())
            .unwrap()
    }

    pub fn authed_delete_json(&self, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    pub fn unauthenticated(&self, method: &str, uri: &str) -> Request<Body> {
        Request::builder().method(method).uri(uri).body(Body::empty()).unwrap()
    }

    pub fn unauthenticated_json(
        &self,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    pub async fn oneshot(&self, req: Request<Body>) -> axum::http::Response<Body> {
        self.router().oneshot(req).await.unwrap()
    }

    pub async fn body_bytes(response: axum::http::Response<Body>) -> axum::body::Bytes {
        BodyExt::collect(response.into_body()).await.unwrap().to_bytes()
    }
}
