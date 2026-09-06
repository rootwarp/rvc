use super::*;

// --- ValidatorConfigManagerAdapter tests ---

fn create_config_adapter_with_store() -> (ValidatorConfigManagerAdapter, Arc<ValidatorStore>) {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("validators.toml");
    std::fs::write(
        &config_path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
    // Keep TempDir alive by leaking it — tests are short-lived
    std::mem::forget(dir);
    let adapter = ValidatorConfigManagerAdapter::new(store.clone());
    (adapter, store)
}

fn add_test_validator(store: &ValidatorStore, id: u8) -> Pubkey {
    let pk = test_pubkey(id);
    store.add_validator(validator_store::ValidatorConfig::new(pk)).unwrap();
    pk
}

#[test]
fn test_config_adapter_unknown_pubkey_returns_not_found() {
    let (adapter, _store) = create_config_adapter_with_store();
    let pk = test_pubkey(99);

    assert!(matches!(adapter.get_fee_recipient(&pk), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.get_gas_limit(&pk), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.get_graffiti(&pk), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.set_fee_recipient(&pk, [0u8; 20]), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.set_gas_limit(&pk, 100), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.set_graffiti(&pk, "test"), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.delete_fee_recipient(&pk), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.delete_gas_limit(&pk), Err(ApiError::NotFound(_))));
    assert!(matches!(adapter.delete_graffiti(&pk), Err(ApiError::NotFound(_))));
}

#[test]
fn test_config_adapter_get_fee_recipient_returns_default() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    let fee = adapter.get_fee_recipient(&pk).unwrap();
    // Default from config: 0x0000000000000000000000000000000000000001
    let mut expected = [0u8; 20];
    expected[19] = 1;
    assert_eq!(fee, expected);
}

#[test]
fn test_config_adapter_fee_recipient_set_get_roundtrip() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    let new_fee = [0xABu8; 20];
    adapter.set_fee_recipient(&pk, new_fee).unwrap();

    let got = adapter.get_fee_recipient(&pk).unwrap();
    assert_eq!(got, new_fee);
}

#[test]
fn test_config_adapter_fee_recipient_delete_resets_to_default() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    let new_fee = [0xABu8; 20];
    adapter.set_fee_recipient(&pk, new_fee).unwrap();
    adapter.delete_fee_recipient(&pk).unwrap();

    let got = adapter.get_fee_recipient(&pk).unwrap();
    // Should be back to default
    let mut expected = [0u8; 20];
    expected[19] = 1;
    assert_eq!(got, expected);
}

#[test]
fn test_config_adapter_get_gas_limit_returns_default() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    let limit = adapter.get_gas_limit(&pk).unwrap();
    assert_eq!(limit, 30_000_000);
}

#[test]
fn test_config_adapter_gas_limit_set_get_roundtrip() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    adapter.set_gas_limit(&pk, 50_000_000).unwrap();
    let got = adapter.get_gas_limit(&pk).unwrap();
    assert_eq!(got, 50_000_000);
}

#[test]
fn test_config_adapter_gas_limit_delete_resets_to_default() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    adapter.set_gas_limit(&pk, 50_000_000).unwrap();
    adapter.delete_gas_limit(&pk).unwrap();
    let got = adapter.get_gas_limit(&pk).unwrap();
    assert_eq!(got, 30_000_000);
}

#[test]
fn test_config_adapter_get_graffiti_returns_empty_when_none() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    let graffiti = adapter.get_graffiti(&pk).unwrap();
    assert_eq!(graffiti, "");
}

#[test]
fn test_config_adapter_graffiti_set_get_roundtrip() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    adapter.set_graffiti(&pk, "hello world").unwrap();
    let got = adapter.get_graffiti(&pk).unwrap();
    assert_eq!(got, "hello world");
}

#[test]
fn test_config_adapter_graffiti_delete_resets_to_default() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    adapter.set_graffiti(&pk, "hello").unwrap();
    adapter.delete_graffiti(&pk).unwrap();
    let got = adapter.get_graffiti(&pk).unwrap();
    assert_eq!(got, "");
}

#[test]
fn test_config_adapter_save_persists_to_file() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("validators.toml");
    std::fs::write(
        &config_path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
    let adapter = ValidatorConfigManagerAdapter::new(store.clone());

    let pk = test_pubkey(1);
    store.add_validator(validator_store::ValidatorConfig::new(pk)).unwrap();

    let fee = [0xFFu8; 20];
    adapter.set_fee_recipient(&pk, fee).unwrap();

    // Reload from disk and verify
    let store2 = ValidatorStore::load_from_config(&config_path).unwrap();
    let loaded_fee = store2.effective_fee_recipient(&pk);
    assert_eq!(loaded_fee, fee);
}

#[test]
fn test_config_adapter_graffiti_truncates_long_input() {
    let (adapter, store) = create_config_adapter_with_store();
    let pk = add_test_validator(&store, 1);

    let long_graffiti = "a".repeat(64);
    adapter.set_graffiti(&pk, &long_graffiti).unwrap();
    let got = adapter.get_graffiti(&pk).unwrap();
    assert_eq!(got.len(), 32);
    assert_eq!(got, "a".repeat(32));
}

// --- Issue 4.4: Config persistence integration tests ---

fn create_persistence_adapter(
    dir: &std::path::Path,
) -> (ValidatorConfigManagerAdapter, std::path::PathBuf) {
    let config_path = dir.join("validators.toml");
    let pubkey_hex = pubkey_hex(test_pubkey(1));
    let toml = format!(
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"{}\"\n",
        pubkey_hex,
    );
    std::fs::write(&config_path, &toml).unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
    let adapter = ValidatorConfigManagerAdapter::new(store);
    (adapter, config_path)
}

#[test]
fn test_config_persistence_fee_recipient() {
    let dir = TempDir::new().unwrap();
    let (adapter, config_path) = create_persistence_adapter(dir.path());
    let pk = test_pubkey(1);

    let fee = [0xABu8; 20];
    adapter.set_fee_recipient(&pk, fee).unwrap();

    let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
    assert_eq!(reloaded.effective_fee_recipient(&pk), fee);
}

#[test]
fn test_config_persistence_gas_limit() {
    let dir = TempDir::new().unwrap();
    let (adapter, config_path) = create_persistence_adapter(dir.path());
    let pk = test_pubkey(1);

    adapter.set_gas_limit(&pk, 50_000_000).unwrap();

    let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
    assert_eq!(reloaded.effective_gas_limit(&pk), 50_000_000);
}

#[test]
fn test_config_persistence_graffiti() {
    let dir = TempDir::new().unwrap();
    let (adapter, config_path) = create_persistence_adapter(dir.path());
    let pk = test_pubkey(1);

    adapter.set_graffiti(&pk, "persist me").unwrap();

    let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
    let graffiti = reloaded.effective_graffiti(&pk).unwrap();
    let end = graffiti.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let s = std::str::from_utf8(&graffiti[..end]).unwrap();
    assert_eq!(s, "persist me");
}

#[test]
fn test_config_persistence_delete_reverts() {
    let dir = TempDir::new().unwrap();
    let (adapter, config_path) = create_persistence_adapter(dir.path());
    let pk = test_pubkey(1);

    adapter.set_fee_recipient(&pk, [0xBBu8; 20]).unwrap();
    adapter.delete_fee_recipient(&pk).unwrap();

    let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
    let mut expected_default = [0u8; 20];
    expected_default[19] = 1;
    assert_eq!(reloaded.effective_fee_recipient(&pk), expected_default);

    adapter.set_gas_limit(&pk, 99_000_000).unwrap();
    adapter.delete_gas_limit(&pk).unwrap();

    let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
    assert_eq!(reloaded.effective_gas_limit(&pk), 30_000_000);

    adapter.set_graffiti(&pk, "temporary").unwrap();
    adapter.delete_graffiti(&pk).unwrap();

    let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
    assert!(reloaded.effective_graffiti(&pk).is_none());
}

#[test]
fn test_config_persistence_concurrent_writes() {
    use std::thread;

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("validators.toml");
    let mut toml = String::from(
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n",
    );
    for i in 0..10u8 {
        let pk_hex = pubkey_hex(test_pubkey(i));
        toml.push_str(&format!("[[validators]]\npubkey = \"{}\"\n\n", pk_hex));
    }
    std::fs::write(&config_path, &toml).unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
    let adapter = Arc::new(ValidatorConfigManagerAdapter::new(store));

    let mut handles = vec![];
    for i in 0..10u8 {
        let adapter = adapter.clone();
        handles.push(thread::spawn(move || {
            let pk = test_pubkey(i);
            let mut fr = [0u8; 20];
            fr[0] = i;
            adapter.set_fee_recipient(&pk, fr).unwrap();
            adapter.set_gas_limit(&pk, 30_000_000 + i as u64 * 1_000_000).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
    for i in 0..10u8 {
        let pk = test_pubkey(i);
        let fr = reloaded.effective_fee_recipient(&pk);
        assert_eq!(fr[0], i);
        // Gas limit should be one of the written values for this validator
        let gl = reloaded.effective_gas_limit(&pk);
        assert_eq!(gl, 30_000_000 + i as u64 * 1_000_000);
    }
}
