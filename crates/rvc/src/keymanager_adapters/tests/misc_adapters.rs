use super::*;

// --- SlashingProtectionAdapter tests ---

#[test]
fn test_slashing_adapter_import_invalid_json() {
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = SlashingProtectionAdapter::new_in_free_window(db, [0u8; 32]);
    let result = block_on(adapter.import_interchange("not valid json"));
    assert!(result.is_err());
}

#[test]
fn test_slashing_adapter_import_valid() {
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = SlashingProtectionAdapter::new_in_free_window(db, [0u8; 32]);
    let interchange = serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "data": []
    });
    let result = block_on(adapter.import_interchange(&interchange.to_string()));
    assert!(result.is_ok());
}

#[test]
fn test_slashing_adapter_export_empty() {
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = SlashingProtectionAdapter::new_in_free_window(db, [0u8; 32]);
    let result = block_on(adapter.export_interchange(&[]));
    assert!(result.is_ok());
    let export: serde_json::Value = serde_json::from_str(&result.unwrap().json).unwrap();
    assert!(export["data"].as_array().unwrap().is_empty());
}

// --- ValidatorManagerAdapter tests ---

#[test]
fn test_validator_manager_adapter_add_remove() {
    let store = Arc::new(ValidatorStore::new([0u8; 20], 100));
    let adapter = ValidatorManagerAdapter::new(store.clone());
    adapter.add_validator(test_pubkey(1), true).unwrap();

    // Verify the validator was actually added to the store
    assert!(store.get_config(&test_pubkey(1)).is_some());

    // Remove and verify
    assert!(adapter.remove_validator(&test_pubkey(1)).unwrap());
    assert!(store.get_config(&test_pubkey(1)).is_none());

    // Removing non-existent returns false
    assert!(!adapter.remove_validator(&test_pubkey(99)).unwrap());
}

#[test]
fn test_validator_manager_remove_persists_under_save_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let adapter = ValidatorManagerAdapter::new(store.clone());
    let pk = test_pubkey(1);
    adapter.add_validator(pk, true).unwrap();
    assert!(ValidatorStore::load_from_config(&path).unwrap().has_validator(&pk));
    assert!(adapter.remove_validator(&pk).unwrap());
    assert!(!store.has_validator(&pk));
    assert!(!ValidatorStore::load_from_config(&path).unwrap().has_validator(&pk));
}

/// The doppelganger window re-enable must reach the validators file.
/// A restart otherwise reloads `enabled = false` and the key stays offline.
#[test]
fn test_reenable_persists_before_it_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let pk = test_pubkey(1);
    let mut disabled = validator_store::ValidatorConfig::new(pk);
    disabled.enabled = false;
    store.add_validator(disabled).unwrap();
    let adapter = ValidatorManagerAdapter::new(store.clone());
    adapter.set_validator_enabled(&pk, true).unwrap();
    assert!(store.is_signing_enabled(&pk));
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    assert!(
        disk.is_signing_enabled(&pk),
        "re-enable must be durable; a restart would otherwise stay disabled"
    );
}

/// A failed validators-file write must not look like "validator not found".
#[test]
fn test_remove_validator_surfaces_a_persist_failure() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("gone");
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let adapter = ValidatorManagerAdapter::new(Arc::clone(&store));
    let pk = test_pubkey(7);
    adapter.add_validator(pk, true).expect("import persists");
    std::fs::remove_dir_all(&parent).unwrap();
    let err = adapter
        .remove_validator(&pk)
        .expect_err("a failed config removal is an error, not not-found");
    assert!(!err.is_empty());
    assert!(store.has_validator(&pk), "failed remove must keep the live validator");
}

// --- DoppelgangerDisabledMonitor tests ---

#[test]
fn test_doppelganger_adapter_start_stop() {
    let adapter = DoppelgangerDisabledMonitor::new();
    adapter.start_monitoring(test_pubkey(1));
    adapter.stop_monitoring(&test_pubkey(1));
}

// --- SEC-2b: ForwardWindowMonitor (keymanager import → machine) ---

/// Keymanager import path registers the key with ForwardWindowMachine so
/// the production signing enablement gate applies to API-imported keys.
#[test]
fn test_keymanager_imported_key_registers_with_machine() {
    use doppelganger::ForwardWindowStatus;

    struct NoPrior;
    impl slashing::SlashingDbReader for NoPrior {
        fn last_signed_attestation(
            &self,
            _pubkey: &str,
            _gvr: &Root,
        ) -> Option<slashing::TargetEpoch> {
            None
        }
    }

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_bytes = pk.to_bytes();

    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPrior);
    let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xabu8; 32]));
    let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 42);
    let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);

    // Before import registration: unmonitored → not safe.
    assert!(!monitor.is_doppelganger_safe(&pk_bytes));
    assert_eq!(machine.status(&pk), ForwardWindowStatus::Unmonitored);

    // Import handler calls start_monitoring → register_for_import at epoch 42.
    monitor.start_monitoring(pk_bytes);

    assert_eq!(
        machine.status(&pk),
        ForwardWindowStatus::Pending,
        "imported key must be Pending on the ForwardWindowMachine"
    );
    assert!(
        !monitor.is_doppelganger_safe(&pk_bytes),
        "imported key must not be signing-safe until the window elapses"
    );
    assert!(!machine.is_signing_enabled(&pk));

    // M-12 window elapsed: stop_monitoring must NOT cancel machine state.
    monitor.stop_monitoring(&pk_bytes);
    assert_eq!(
        machine.status(&pk),
        ForwardWindowStatus::Pending,
        "stop_monitoring (M-12 elapsed) must leave machine Pending"
    );

    // DELETE path: cancel_monitoring drops state for re-import freshness.
    monitor.cancel_monitoring(&pk_bytes);
    assert_eq!(machine.status(&pk), ForwardWindowStatus::Unmonitored);
}

/// Import path never applies epoch-0 Safe bypass (SEC-2b Finding 2).
#[test]
fn test_keymanager_import_epoch0_stays_pending() {
    use doppelganger::ForwardWindowStatus;

    struct NoPrior;
    impl slashing::SlashingDbReader for NoPrior {
        fn last_signed_attestation(
            &self,
            _pubkey: &str,
            _gvr: &Root,
        ) -> Option<slashing::TargetEpoch> {
            None
        }
    }

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_bytes = pk.to_bytes();

    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPrior);
    let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xacu8; 32]));
    let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 0);
    let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);

    monitor.start_monitoring(pk_bytes);
    assert_eq!(
        machine.status(&pk),
        ForwardWindowStatus::Pending,
        "import at epoch 0 must stay Pending (no pre-genesis Safe bypass on import path)"
    );
    assert!(!monitor.is_doppelganger_safe(&pk_bytes));
}

/// Import + recent slashing history must NOT Safe-skip (interchange hazard).
#[test]
fn test_import_with_recent_history_stays_pending() {
    use doppelganger::ForwardWindowStatus;

    struct RecentPrior;
    impl slashing::SlashingDbReader for RecentPrior {
        fn last_signed_attestation(
            &self,
            _pubkey: &str,
            _gvr: &Root,
        ) -> Option<slashing::TargetEpoch> {
            Some(98) // recent relative to epoch 100, monitoring=2
        }
    }

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_bytes = pk.to_bytes();
    let gvr = [0xadu8; 32];

    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(RecentPrior);
    let machine = Arc::new(ForwardWindowMachine::new(reader, 2, gvr));
    // Boot-style register WOULD safe-skip:
    machine.register(&pk, 100);
    assert_eq!(
        machine.status(&pk),
        ForwardWindowStatus::Safe,
        "control: boot register with recent history is Safe"
    );
    machine.cancel(&pk);

    let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 100);
    let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);
    monitor.start_monitoring(pk_bytes);
    assert_eq!(
        machine.status(&pk),
        ForwardWindowStatus::Pending,
        "import must not Safe-skip even with recent interchange history"
    );
    assert!(!machine.is_signing_enabled(&pk));
}
