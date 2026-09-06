//! Regression tests for ISSUE-3.11 M-12 post-import doppelganger window.
//!
//! These tests verify the public-API surface of the M-12 fix:
//!
//! 1. `ValidatorStore::is_signing_enabled` blocks newly imported validators
//!    that are still inside their doppelganger window (enabled=false).
//! 2. The doppelganger monitor and `ValidatorStore` together represent the
//!    combined enablement state: a validator is safe to sign only when both
//!    - the monitor reports `is_doppelganger_safe` = true, AND
//!    - the validator store's enabled flag is true (`is_signing_enabled` = true).
//! 3. `scan_and_rearm_gate` re-arms the monitor after restart for recently-imported
//!    keys (Critical #2 fix).

use std::sync::{Arc, Mutex};

use keymanager_api::traits::{DoppelgangerMonitor, Pubkey};
use rvc::keymanager_adapters::scan_and_rearm_gate;
use validator_store::{ValidatorConfig, ValidatorStore};

fn test_pk(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

/// Probe for `scan_and_rearm_gate`: records `start_monitoring` calls.
/// Always-safe so it matches the production opt-out monitor.
struct RecordingMonitor {
    started: Mutex<Vec<Pubkey>>,
}

impl RecordingMonitor {
    fn new() -> Self {
        Self { started: Mutex::new(Vec::new()) }
    }

    fn started(&self) -> Vec<Pubkey> {
        self.started.lock().unwrap().clone()
    }
}

impl DoppelgangerMonitor for RecordingMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        self.started.lock().unwrap().push(pubkey);
    }

    fn stop_monitoring(&self, _pubkey: &Pubkey) {}

    fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool {
        true
    }
}

// ── Critical #1: ValidatorStore gate integration ─────────────────────────────

/// A newly imported validator (enabled=false) must be blocked from attesting.
#[test]
fn test_newly_imported_validator_blocked() {
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let pk = test_pk(1);

    let mut config = ValidatorConfig::new(pk);
    config.enabled = false;
    store.add_validator(config).unwrap();

    assert!(
        !store.is_signing_enabled(&pk),
        "validator must be blocked while inside doppelganger window"
    );
}

/// After the background task flips enabled=true, the validator must be permitted.
#[test]
fn test_validator_enabled_after_window() {
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let pk = test_pk(2);

    let mut config = ValidatorConfig::new(pk);
    config.enabled = false;
    store.add_validator(config).unwrap();

    // Simulate window expiring: background task calls set_enabled(true)
    store.set_enabled(&pk, true);

    assert!(
        store.is_signing_enabled(&pk),
        "validator must be enabled after the doppelganger window expires"
    );
}

/// D-3 (Issue 2.11): a pubkey not tracked by the store is fail-closed — it must
/// default to disabled. Keystore-loaded keys are never silently blocked because
/// startup registers them in the store (see
/// `ServiceBuilder::register_loaded_validators`); only a genuinely-unknown
/// pubkey reaches this default.
#[test]
fn test_untracked_validator_defaults_to_disabled() {
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    let unknown_pk = test_pk(99);

    assert!(
        !store.is_signing_enabled(&unknown_pk),
        "validators not tracked by the store must fail closed (default disabled)"
    );
}

// ── Critical #2: Restart does not bypass the window ─────────────────────────

/// After a restart, `scan_and_rearm_gate` must re-arm the monitor for any key
/// whose sidecar shows the window has not yet elapsed.
#[test]
fn test_scan_rearms_gate_for_recent_import() {
    let dir = tempfile::TempDir::new().unwrap();
    let pk: [u8; 48] = [0x42u8; 48];
    let window_secs = 768u64;

    // Simulate sidecar written at import time = now (well within window)
    let now_unix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let meta_path = dir.path().join(format!("0x{}.import_meta.json", hex::encode(pk)));
    std::fs::write(&meta_path, format!("{{\"imported_unix_seconds\":{}}}", now_unix)).unwrap();

    let monitor = Arc::new(RecordingMonitor::new());
    assert!(monitor.is_doppelganger_safe(&pk));
    assert!(monitor.started().is_empty());

    scan_and_rearm_gate(dir.path(), monitor.as_ref(), window_secs);

    assert_eq!(monitor.started(), vec![pk], "recent import must be re-armed after restart");
    assert!(monitor.is_doppelganger_safe(&pk), "recording probe stays always-safe");
}

/// `scan_and_rearm_gate` must NOT re-arm keys whose window has fully elapsed.
#[test]
fn test_scan_skips_expired_import() {
    let dir = tempfile::TempDir::new().unwrap();
    let pk: [u8; 48] = [0x43u8; 48];
    let window_secs = 768u64;

    // Sidecar with timestamp = now − window − 1 s (expired)
    let old_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(window_secs + 1);
    let meta_path = dir.path().join(format!("0x{}.import_meta.json", hex::encode(pk)));
    std::fs::write(&meta_path, format!("{{\"imported_unix_seconds\":{}}}", old_unix)).unwrap();

    let monitor = Arc::new(RecordingMonitor::new());

    scan_and_rearm_gate(dir.path(), monitor.as_ref(), window_secs);

    assert!(monitor.started().is_empty(), "expired key must NOT be re-armed after restart");
    assert!(monitor.is_doppelganger_safe(&pk), "expired key must remain safe (not re-armed)");
}
