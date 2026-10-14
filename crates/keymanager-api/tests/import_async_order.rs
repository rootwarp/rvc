//! RR2-08: `import_keystores` awaits interchange to completion, then keystores.
//!
//! The interchange mock yields. A handler that polled `import_keystore` during
//! that yield (for example via `join!`) would record a keystore event first.

mod common;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Json, State};
use axum::http::HeaderMap;
use common::{
    MockDoppelgangerMonitor, MockRemoteKeyManager, MockValidatorConfigManager, MockValidatorManager,
};
use rvc_keymanager_api::handlers::{import_keystores, AppState};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, ImportKeystoreError, KeystoreManager, Pubkey, SlashingProtection,
    SlashingProtectionError, ValidatorManager,
};
use rvc_keymanager_api::types::{ImportKeystoresRequest, ImportStatus};
use rvc_keymanager_api::DoppelgangerLifecycle;

/// Records interchange and keystore calls so the handler's order is observable.
struct OrderProbe {
    events: Mutex<Vec<&'static str>>,
}

impl OrderProbe {
    fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl KeystoreManager for OrderProbe {
    fn list_keys(&self) -> Vec<Pubkey> {
        Vec::new()
    }

    fn has_key(&self, _: &Pubkey) -> bool {
        false
    }

    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        self.events.lock().expect("events").push("keystore");
        Ok([1u8; 48])
    }

    fn delete_keystore(&self, _: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        Ok(false)
    }
}

#[async_trait]
impl SlashingProtection for OrderProbe {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        self.events.lock().expect("events").push("interchange_start");
        tokio::task::yield_now().await;
        let events = self.events.lock().expect("events");
        assert!(
            !events.contains(&"keystore"),
            "import_keystore began before import_interchange finished: {events:?}"
        );
        drop(events);
        self.events.lock().expect("events").push("interchange_done");
        Ok(())
    }

    fn export_interchange(&self, _: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        Ok("{}".into())
    }
}

#[tokio::test]
async fn import_handler_is_async_across_both_imports() {
    let probe = Arc::new(OrderProbe::new());
    let validator_manager = Arc::new(MockValidatorManager::new());
    let validator_manager_dyn: Arc<dyn ValidatorManager> = validator_manager;
    let state = Arc::new(AppState {
        keystore_manager: Arc::clone(&probe) as Arc<dyn KeystoreManager>,
        slashing_protection: Arc::clone(&probe) as Arc<dyn SlashingProtection>,
        validator_manager: Arc::clone(&validator_manager_dyn),
        doppelganger: Arc::new(DoppelgangerLifecycle::new(
            Duration::ZERO,
            Arc::new(MockDoppelgangerMonitor::new()),
            validator_manager_dyn,
        )),
        remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
        config_manager: Arc::new(MockValidatorConfigManager::new()),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    });

    let request = ImportKeystoresRequest {
        keystores: vec!["keystore".into()],
        passwords: vec!["password".into()],
        slashing_protection: Some("interchange".into()),
    };

    let Json(resp) =
        import_keystores(State(state), HeaderMap::new(), Json(request)).await.expect("import");
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, ImportStatus::Imported);
    assert_eq!(
        probe.events.lock().expect("events").as_slice(),
        ["interchange_start", "interchange_done", "keystore"]
    );
}
