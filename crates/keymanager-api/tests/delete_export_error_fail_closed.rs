//! Integration test — KM-1: DELETE `/eth/v1/keystores` must fail CLOSED when
//! slashing-protection export fails.
//!
//! # Spec-correct (fail-closed) behavior verified here
//!
//! When `SlashingProtection::export_interchange` returns `Err`, the handler
//! MUST:
//!   1. Return `ApiError::Internal` (HTTP 500) — NOT `Ok`.
//!   2. NOT delete any keystores (keys remain present after the call).
//!   3. NOT produce an empty-interchange success response (covered by #1).
//!
//! # Schema-agnostic design
//!
//! All assertions are driven through the `SlashingProtection` trait interface
//! (`pubkeys in → Result<String, SlashingProtectionError> out`).  The test does NOT inspect any
//! on-disk SQLite layout, column names, or file paths.  This means it passes
//! against both the current slashing-DB schema and any future schema revision
//! (e.g., the v2 schema added by Issue 2.4).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Json, State};
use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::{delete_keystores, AppState};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DoppelgangerMonitor, ImportKeystoreError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, SlashingProtectionError, ValidatorConfigManager,
    ValidatorManager,
};
use rvc_keymanager_api::types::{DeleteKeystoresRequest, DeleteKeystoresResponse, DeleteStatus};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns a deterministic 48-byte pubkey seeded by `id`.
fn test_pubkey(id: u8) -> Pubkey {
    let mut pk = [0u8; 48];
    pk[0] = id;
    pk
}

fn test_pubkey_hex(id: u8) -> String {
    format!("0x{}", hex::encode(test_pubkey(id)))
}

fn make_state(
    keystore_manager: Arc<dyn KeystoreManager>,
    slashing_protection: Arc<dyn SlashingProtection>,
) -> Arc<AppState> {
    Arc::new(AppState {
        keystore_manager,
        slashing_protection,
        validator_manager: Arc::new(NoopValidatorManager),
        doppelganger: Arc::new(rvc_keymanager_api::DoppelgangerLifecycle::new(
            std::time::Duration::ZERO,
            Arc::new(NoopDoppelgangerMonitor),
            Arc::new(NoopValidatorManager),
        )),
        remote_key_manager: Arc::new(NoopRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    })
}

// ── Mock: slashing-protection that always fails export ────────────────────────

/// A `SlashingProtection` implementation whose `export_interchange` always
/// returns `Err`.  Used to simulate a corrupt or unavailable slashing DB.
struct FailingExport;

#[async_trait]
impl SlashingProtection for FailingExport {
    async fn import_interchange(
        &self,
        _interchange_json: &str,
    ) -> Result<(), SlashingProtectionError> {
        Ok(())
    }

    fn export_interchange(&self, _pubkeys: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        Err(SlashingProtectionError::Backend("boom: slashing DB unavailable".into()))
    }
}

// ── Mock: slashing-protection returning per-key history ───────────────────────

/// Returns a deterministic interchange covering exactly the pubkeys passed in.
/// Keys whose id is even get one attestation record; odd keys get none (to
/// exercise the completeness / empty-record path in the adapter).
struct RecordingExport;

#[async_trait]
impl SlashingProtection for RecordingExport {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }

    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        let data: Vec<serde_json::Value> = pubkeys
            .iter()
            .map(|pk| {
                let has_history = pk[0] % 2 == 0;
                let attestations = if has_history {
                    serde_json::json!([{"source_epoch":"1","target_epoch":"2"}])
                } else {
                    serde_json::json!([])
                };
                serde_json::json!({
                    "pubkey": format!("0x{}", hex::encode(pk)),
                    "signed_blocks": [],
                    "signed_attestations": attestations
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

// ── Mock: keystore manager that tracks deletion attempts ──────────────────────

/// A `KeystoreManager` that:
///   * Reports the registered pubkeys as present via `has_key`.
///   * Counts how many times `delete_keystore` is invoked.
///   * Succeeds if `delete_keystore` is called (so the test isolates the
///     handler's abort logic, not a downstream deletion error).
struct CountingKeystoreManager {
    keys: Vec<Pubkey>,
    delete_call_count: AtomicU32,
}

impl CountingKeystoreManager {
    fn with_keys(keys: Vec<Pubkey>) -> Self {
        Self { keys, delete_call_count: AtomicU32::new(0) }
    }

    fn delete_call_count(&self) -> u32 {
        self.delete_call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeystoreManager for CountingKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.contains(pubkey)
    }

    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        unimplemented!("not exercised in this test")
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        if self.keys.contains(pubkey) {
            self.delete_call_count.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ── Minimal no-op mocks for the remaining AppState fields ────────────────────

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

struct NoopRemoteKeyManager;
impl RemoteKeyManager for NoopRemoteKeyManager {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        vec![]
    }
    fn has_remote_key(&self, _: &Pubkey) -> bool {
        false
    }
    fn import_remote_key(
        &self,
        _: Pubkey,
        _: String,
    ) -> Result<(), rvc_keymanager_api::traits::ImportRemoteKeyError> {
        unimplemented!()
    }
    fn delete_remote_key(
        &self,
        _: &Pubkey,
    ) -> Result<bool, rvc_keymanager_api::traits::DeleteRemoteKeyError> {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

/// KM-1: when `export_interchange` returns `Err`, `delete_keystores` must:
///   1. Return `Err(ApiError::Internal(_))` — not swallow the error and return
///      `Ok` with an empty interchange.
///   2. Not invoke `delete_keystore` on any keystore (fail before the
///      deletion loop).
///
/// On the un-patched code this test fails because the handler uses
/// `unwrap_or_else(|e| empty_interchange())`, proceeds to delete all
/// keystores, and returns `Ok` with an empty interchange.
#[tokio::test]
async fn test_delete_keystores_export_error_fails_closed_no_deletion() {
    let known_key = test_pubkey(42);
    let keystore_manager = Arc::new(CountingKeystoreManager::with_keys(vec![known_key]));

    let state = make_state(keystore_manager.clone(), Arc::new(FailingExport));

    let request = DeleteKeystoresRequest { pubkeys: vec![test_pubkey_hex(42)] };

    let result = delete_keystores(State(state.clone()), Json(request)).await;

    // Assertion 1: the handler must return Err(ApiError::Internal(_)) — HTTP 500.
    // On the bug-affected code this is Ok(...) with an empty interchange.
    match &result {
        Err(ApiError::Internal(_)) => {} // correct fail-closed behavior
        Ok(_) => panic!(
            "KM-1 BUG: handler returned Ok (success) when export failed; \
             expected Err(ApiError::Internal). Keys would have been deleted \
             with an empty slashing-protection interchange — double-sign hazard."
        ),
        Err(other) => panic!("expected ApiError::Internal, got {other:?}"),
    }

    // Assertion 2: no keystore must have been deleted.
    // The fix aborts before the deletion loop, so delete_call_count stays 0.
    let delete_calls = keystore_manager.delete_call_count();
    assert_eq!(
        delete_calls, 0,
        "KM-1 BUG: delete_keystore was called {delete_calls} time(s) even though \
         slashing-protection export failed — keys must NOT be deleted when export errors."
    );

    // Assertion 3: the key must still be present (covered by counting mock above,
    // but assert explicitly for clarity).
    assert!(
        keystore_manager.has_key(&known_key),
        "KM-1 BUG: key was removed from the keystore despite a failed export"
    );

    // Note: assertion on "no empty interchange in response body" is covered by
    // assertion 1 — a 500 Err result has no success body at all.
}

/// Mixed-pubkey DELETE: one existing key with history, one existing key without
/// history, one not-found, one invalid hex.
///
/// Verifies:
///   - Per-item statuses: Deleted, Deleted, NotFound, Error.
///   - The returned interchange contains a record for BOTH existing keys
///     (the clean key as an empty signed_attestations/signed_blocks record),
///     confirming the KM-1(a) completeness requirement.
///   - Happy-path: returns Ok (200), not an error.
#[tokio::test]
async fn test_delete_keystores_mixed_request_per_item_statuses_and_interchange_completeness() {
    // pk(2): existing, even id → has attestation history in RecordingExport
    // pk(3): existing, odd id → no history, but gets an explicit empty record
    let key_with_history = test_pubkey(2);
    let key_clean = test_pubkey(3);

    let keystore_manager =
        Arc::new(CountingKeystoreManager::with_keys(vec![key_with_history, key_clean]));

    let state = make_state(keystore_manager.clone(), Arc::new(RecordingExport));

    let request = DeleteKeystoresRequest {
        pubkeys: vec![
            test_pubkey_hex(2),            // existing, with history
            test_pubkey_hex(3),            // existing, clean (no history)
            test_pubkey_hex(99),           // not in keystore → NotFound
            "0xinvalid_hex!!".to_string(), // malformed → Error
        ],
    };

    let result = delete_keystores(State(state), Json(request)).await;

    let Json(DeleteKeystoresResponse { data, slashing_protection }) =
        result.expect("mixed DELETE must succeed when export succeeds");

    // Per-item statuses
    assert_eq!(data.len(), 4);
    assert_eq!(data[0].status, DeleteStatus::Deleted, "key_with_history should be Deleted");
    assert_eq!(data[1].status, DeleteStatus::Deleted, "key_clean should be Deleted");
    assert_eq!(data[2].status, DeleteStatus::NotFound, "non-existent key should be NotFound");
    assert_eq!(data[3].status, DeleteStatus::Error, "malformed pubkey should be Error");

    // Interchange completeness: both existing keys must have a record.
    let export: serde_json::Value =
        serde_json::from_str(&slashing_protection).expect("interchange must be valid JSON");
    let export_data = export["data"].as_array().expect("interchange data must be an array");

    let exported_keys: std::collections::HashSet<&str> =
        export_data.iter().filter_map(|r| r["pubkey"].as_str()).collect();

    let hex_with_history = test_pubkey_hex(2);
    let hex_clean = test_pubkey_hex(3);

    assert!(
        exported_keys.contains(hex_with_history.as_str()),
        "interchange must contain record for key_with_history ({hex_with_history})"
    );
    assert!(
        exported_keys.contains(hex_clean.as_str()),
        "interchange must contain record for key_clean ({hex_clean}) — KM-1(a) completeness"
    );

    // The key_with_history record should have attestation data.
    let history_record = export_data
        .iter()
        .find(|r| r["pubkey"].as_str() == Some(&hex_with_history))
        .expect("history record must be present");
    assert!(
        !history_record["signed_attestations"].as_array().unwrap().is_empty(),
        "key_with_history must have signed_attestations in the interchange"
    );

    // The key_clean record may be present with empty arrays (completeness guarantee).
    let clean_record = export_data
        .iter()
        .find(|r| r["pubkey"].as_str() == Some(&hex_clean))
        .expect("clean record must be present");
    assert!(
        clean_record["signed_attestations"].as_array().unwrap().is_empty(),
        "key_clean must have an empty signed_attestations list"
    );
    assert!(
        clean_record["signed_blocks"].as_array().unwrap().is_empty(),
        "key_clean must have an empty signed_blocks list"
    );

    // Both keys were actually deleted.
    assert_eq!(
        keystore_manager.delete_call_count(),
        2,
        "exactly the two existing keys should have been deleted"
    );
}

/// Happy-path confirmation: a successful export still yields a 200 with the
/// real interchange (no regression from the fail-closed change).
#[tokio::test]
async fn test_delete_keystores_happy_path_returns_real_interchange() {
    let key = test_pubkey(2); // even → has attestation history in RecordingExport
    let keystore_manager = Arc::new(CountingKeystoreManager::with_keys(vec![key]));

    let state = make_state(keystore_manager.clone(), Arc::new(RecordingExport));

    let request = DeleteKeystoresRequest { pubkeys: vec![test_pubkey_hex(2)] };

    let result = delete_keystores(State(state), Json(request)).await;

    let Json(DeleteKeystoresResponse { data, slashing_protection }) =
        result.expect("happy-path DELETE must succeed");

    assert_eq!(data.len(), 1);
    assert_eq!(data[0].status, DeleteStatus::Deleted);

    let export: serde_json::Value =
        serde_json::from_str(&slashing_protection).expect("interchange must be valid JSON");
    let export_data = export["data"].as_array().expect("data must be array");

    assert_eq!(export_data.len(), 1, "interchange must contain one record");
    assert_eq!(
        export_data[0]["pubkey"].as_str().unwrap(),
        test_pubkey_hex(2),
        "interchange pubkey must match the deleted key"
    );
    assert!(
        !export_data[0]["signed_attestations"].as_array().unwrap().is_empty(),
        "real interchange must carry the key's attestation history"
    );

    assert_eq!(keystore_manager.delete_call_count(), 1, "the key must have been deleted");
}
