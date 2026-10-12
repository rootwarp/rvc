use super::*;

// --- KeystoreManagerAdapter tests ---

#[test]
fn test_keystore_manager_adapter_empty_list() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    assert!(adapter.list_keys().is_empty());
}

#[test]
fn test_keystore_manager_adapter_has_key_false() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    assert!(!adapter.has_key(&test_pubkey(1)));
}

#[test]
fn test_keystore_manager_adapter_delete_nonexistent() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    assert!(!adapter.delete_keystore(&test_pubkey(1)).unwrap());
}

#[test]
fn delete_refuses_a_local_key_absent_from_the_armed_export() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), Arc::clone(&composite));
    let secret = SecretKey::generate();
    let pk = secret.public_key().to_bytes();
    let members = adapter.membership_for_delete(&[]);
    adapter.begin_delete_export(&members);
    composite.add_local_key(secret);
    let err = adapter.delete_keystore(&pk).expect_err("outside the export");
    assert!(matches!(err, keymanager_api::traits::DeleteKeystoreError::Io(_)));
    assert!(adapter.has_key(&pk), "admitted key is not removed");
    adapter.end_delete_export(&members);
    assert!(adapter.delete_keystore(&pk).unwrap(), "unarmed delete still removes");
    assert!(!adapter.has_key(&pk));
}

#[test]
fn test_keystore_manager_adapter_import_invalid_json() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    let result = block_on(adapter.import_keystore("not valid json", "password"));
    assert!(matches!(result, Err(ImportKeystoreError::InvalidKeystore(_))));
}

// --- Keystore import with real secret key ---

#[test]
fn test_keystore_manager_tracks_imported_key_in_composite_signer() {
    let composite = create_empty_composite_signer();
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

    let sk = SecretKey::generate();
    let pk_bytes = sk.public_key().to_bytes();

    // Manually add key (simulating what would happen with a real keystore)
    composite.add_local_key(sk);
    adapter.tracked_keys.lock().push(pk_bytes);

    assert!(adapter.has_key(&pk_bytes));
    assert!(composite.public_keys().contains(&pk_bytes));

    // Delete
    let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
    assert!(deleted);
    assert!(!adapter.has_key(&pk_bytes));
    assert!(!composite.public_keys().contains(&pk_bytes));
}

/// A failed admission must not leave a boot-loadable keystore or sidecar.
#[test]
fn failed_admit_leaves_no_keystore_json() {
    use secrecy::SecretString;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));

    let validators_dir = TempDir::new().unwrap();
    let parent = validators_dir.path().join("gone");
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    std::fs::remove_dir_all(&parent).unwrap();

    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password));
    assert!(err.is_err(), "import must fail when the validators file cannot be written");

    let names: Vec<String> = std::fs::read_dir(keystore_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json") || n.contains("import_meta"))
        .collect();
    assert!(
        names.is_empty(),
        "failed import must not leave a keystore or sidecar, found {names:?}"
    );

    let mut passwords = std::collections::HashMap::new();
    passwords.insert("*".to_string(), SecretString::from(password.to_string()));
    match crypto::KeyManager::load_from_directory(keystore_dir.path(), &passwords) {
        Ok(km) => assert!(!km.contains(&pk), "boot must not load a key whose import failed"),
        Err(crypto::KeyManagerError::NoKeystoreFiles) => {}
        Err(e) => panic!("boot load failed unexpectedly: {e}"),
    }
}

/// A duplicate import must not leave a boot-loadable `0x<pk>.json`.
#[test]
fn duplicate_import_leaves_no_boot_loadable_keystore() {
    use secrecy::SecretString;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    // In the map, but not a local signer key. The pre-rename map check reports
    // duplicate before the staged partials are published.
    pubkey_map.write().insert(pk, sk.public_key().clone());

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "duplicate import must be reported as duplicate, got {err:?}"
    );

    let live_json: Vec<String> = std::fs::read_dir(keystore_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json") && !n.ends_with(".partial") && !n.contains("import_meta"))
        .collect();
    assert!(
        live_json.is_empty(),
        "a duplicate import must not leave a live keystore json, found {live_json:?}"
    );

    let mut passwords = std::collections::HashMap::new();
    passwords.insert("*".to_string(), SecretString::from(password.to_string()));
    match crypto::KeyManager::load_from_directory(keystore_dir.path(), &passwords) {
        Ok(km) => assert!(!km.contains(&pk), "boot must not load a duplicate import"),
        Err(crypto::KeyManagerError::NoKeystoreFiles) => {}
        Err(e) => panic!("boot load failed unexpectedly: {e}"),
    }
}

/// The final `*.json` is durable before admit publishes the signer.
#[test]
fn keystore_files_are_durable_before_the_signer_is_live() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let final_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let saw_file = Arc::new(AtomicBool::new(false));
    let saw_signer = Arc::new(AtomicBool::new(false));
    let flag_file = Arc::clone(&saw_file);
    let flag_signer = Arc::clone(&saw_signer);
    let composite_hook = Arc::clone(&composite);
    adapter.set_before_admit_hook(Arc::new(move || {
        flag_file.store(final_json.exists(), std::sync::atomic::Ordering::SeqCst);
        flag_signer.store(composite_hook.has_local_key(&pk), std::sync::atomic::Ordering::SeqCst);
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    block_on(adapter.import_keystore(&json, password)).expect("import");
    assert!(
        saw_file.load(std::sync::atomic::Ordering::SeqCst),
        "the keystore json must be durable before admit publishes the signer"
    );
    assert!(
        !saw_signer.load(std::sync::atomic::Ordering::SeqCst),
        "the signer must not hold the key before the keystore commit"
    );
}

/// A crash at `before_admit` must not leave a boot-visible keystore over an enabled row.
#[test]
fn windowed_import_keeps_the_keystore_partial_until_the_hold_is_durable() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let pk_hex = pubkey_hex(pk);
    std::fs::write(
        &path,
        format!(
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"{pk_hex}\"\nenabled = true\n"
        ),
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let final_json = keystore_dir.path().join(format!("{pk_hex}.json"));
    let partial = keystore_dir.path().join(format!("{pk_hex}.json.partial"));
    let path_hook = path.clone();
    let saw = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_hook = std::sync::Arc::clone(&saw);
    adapter.set_before_admit_hook(std::sync::Arc::new(move || {
        let json_live = final_json.exists();
        let partial_live = partial.exists();
        let disk = ValidatorStore::load_from_config(&path_hook).expect("reload");
        let held = !disk.is_signing_enabled(&pk)
            && disk.get_config(&pk).and_then(|cfg| cfg.doppelganger_hold_until).is_some();
        saw_hook.store(!json_live && partial_live && held, std::sync::atomic::Ordering::SeqCst);
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    block_on(adapter.import_keystore(&json, password)).expect("import");
    assert!(
        saw.load(std::sync::atomic::Ordering::SeqCst),
        "the keystore must stay .partial until the disabled hold is durable"
    );
    assert!(
        keystore_dir.path().join(format!("{pk_hex}.json")).exists(),
        "a finished import publishes the keystore json"
    );
    assert!(!store.is_signing_enabled(&pk));
}

/// The persisted hold deadline is sampled after the staged keystore bytes are written.
#[test]
fn hold_deadline_is_sampled_after_keystore_io() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let seen_hook = std::sync::Arc::clone(&seen);
    adapter.set_during_blocking_hook(std::sync::Arc::new(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        seen_hook.store(now, std::sync::atomic::Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    block_on(adapter.import_keystore(&json, password)).expect("import");
    let disk = ValidatorStore::load_from_config(&path).expect("reload");
    let deadline =
        disk.get_config(&pk).and_then(|cfg| cfg.doppelganger_hold_until).expect("hold written");
    let seen_at = seen.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        deadline >= seen_at.saturating_add(31),
        "the hold deadline must be taken after keystore io, deadline {deadline} seen {seen_at}"
    );
}

/// A failed import unpublishes the key before it deletes the keystore files.
#[test]
fn rollback_revokes_before_discarding_keystore_files() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let signer_at_discard = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&signer_at_discard);
    let composite_hook = Arc::clone(&composite);
    adapter.set_before_discard_hook(Arc::new(move || {
        flag.store(composite_hook.has_local_key(&pk), std::sync::atomic::Ordering::SeqCst);
    }));
    adapter.fail_after_admit();

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password));
    assert!(err.is_err(), "directory sync fault must fail the import");
    assert!(
        !signer_at_discard.load(std::sync::atomic::Ordering::SeqCst),
        "revoke must drop the signer before the keystore files are discarded"
    );
}

/// A crash while `*.json` is still boot-visible must not find the hold row already gone.
///
/// `register_loaded_validators` enables a loaded key that has no row.
#[test]
fn failed_import_keeps_the_hold_row_until_the_keystore_json_is_unlinked() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let crash_safe = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&crash_safe);
    let path_hook = path.clone();
    let json_hook = json_path.clone();
    let composite_hook = Arc::clone(&composite);
    adapter.set_before_discard_hook(Arc::new(move || {
        let disk = ValidatorStore::load_from_config(&path_hook).expect("reload");
        let disabled_row = disk.has_validator(&pk) && !disk.is_signing_enabled(&pk);
        flag.store(
            json_hook.exists() && disabled_row && !composite_hook.has_local_key(&pk),
            std::sync::atomic::Ordering::SeqCst,
        );
    }));
    adapter.fail_after_admit();

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    assert!(block_on(adapter.import_keystore(&json, password)).is_err());
    assert!(
        crash_safe.load(std::sync::atomic::Ordering::SeqCst),
        "a crash before unlink must keep a disabled row while the keystore json is boot-visible"
    );
    assert!(!json_path.exists(), "a finished rollback unlinks the keystore json");
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    assert!(
        !disk.has_validator(&pk),
        "the hold row is removed only after the keystore json is gone"
    );
}

/// An unlink that does not stick leaves a plain disabled row, not a hold.
#[test]
fn failed_unlink_keeps_a_disabled_tombstone() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let locked_dir = keystore_dir.path().to_path_buf();
    adapter.set_before_discard_hook(Arc::new(move || {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&locked_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked_dir, perms).unwrap();
    }));
    adapter.fail_after_admit();

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    assert!(block_on(adapter.import_keystore(&json, password)).is_err());

    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(keystore_dir.path()).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(keystore_dir.path(), perms).unwrap();

    assert!(json_path.exists(), "a failed unlink must leave the keystore json");
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    assert!(disk.has_validator(&pk), "a failed unlink must keep a validators row");
    assert!(!disk.is_signing_enabled(&pk), "the tombstone row must be disabled");
    assert!(
        disk.get_config(&pk).unwrap().doppelganger_hold_until.is_none(),
        "the tombstone must not be a hold boot can re-enable"
    );
}

/// Metadata or directory sync failing after the `*.json` rename must not drop the hold first.
#[test]
fn publish_failure_after_rename_keeps_the_hold_until_the_json_is_unlinked() {
    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        store,
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(admissions);
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));
    adapter.fail_after_keystore_rename();

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let json_path = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    let crash_safe = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&crash_safe);
    let path_hook = path.clone();
    let json_hook = json_path.clone();
    adapter.set_before_discard_hook(Arc::new(move || {
        let disk = ValidatorStore::load_from_config(&path_hook).expect("reload");
        let disabled_row = disk.has_validator(&pk) && !disk.is_signing_enabled(&pk);
        flag.store(json_hook.exists() && disabled_row, std::sync::atomic::Ordering::SeqCst);
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    assert!(block_on(adapter.import_keystore(&json, password)).is_err());
    assert!(
        crash_safe.load(std::sync::atomic::Ordering::SeqCst),
        "a crash after the json rename must keep the disabled hold while the keystore is boot-visible"
    );
    assert!(!json_path.exists(), "a finished publish rollback unlinks the keystore json");
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    assert!(
        !disk.has_validator(&pk),
        "the hold row is removed only after the keystore json is gone"
    );
}

/// A refresh that wins the same pubkey must keep its signer after this import's AlreadyPresent.
#[test]
fn already_present_import_does_not_unpublish_a_concurrent_refresh() {
    use doppelganger::ForwardWindowStatus;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let db: Arc<dyn slashing::SlashingDbReader> =
        Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    let machine = Arc::new(ForwardWindowMachine::new(db, 2, [0xabu8; 32]));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        Some(Arc::clone(&machine)),
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(Arc::clone(&admissions));
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let public = sk.public_key();
    // Test-only: recreate the same key for the refresh admit. Never log these bytes.
    #[allow(clippy::disallowed_methods)]
    let secret_bytes = sk.to_bytes();
    let refresh = Arc::clone(&admissions);
    adapter.set_before_admit_hook(Arc::new(move || {
        let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");
        refresh
            .admit(secret, crate::key_admission::AdmissionSource::RawSecret)
            .expect("refresh admit");
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "a lost race must be a duplicate, got {err:?}"
    );
    assert!(composite.has_local_key(&pk), "the refresh admission must still be signing");
    assert!(pubkey_map.read().contains_key(&pk), "the refresh map entry must stay");
    assert!(
        store.has_validator(&pk),
        "the rollback must not remove the row the refresh admitted over"
    );
    assert_ne!(
        machine.status(&public),
        ForwardWindowStatus::Unmonitored,
        "the refresh forward window must stay"
    );
    let live_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    assert!(!live_json.exists(), "this import must not leave a live keystore json");
}

/// A refresh paused after its map insert, before `notify`, still owns the signer and the hold.
#[test]
fn already_present_import_leaves_a_midflight_refresh_hold() {
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(Arc::clone(&admissions));
    let window_secs = 30u64;
    adapter.set_doppelganger_window(Duration::from_secs(window_secs));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    // Test-only: recreate the same key for the refresh admit. Never log these bytes.
    #[allow(clippy::disallowed_methods)]
    let secret_bytes = sk.to_bytes();

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Arc::new(std::sync::Mutex::new(Some(entered_tx)));
    let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    let release_on_drop = ReleaseOnDrop(Arc::new(std::sync::Mutex::new(Some(release_tx.clone()))));
    admissions.pause_once_after_map_insert(move || {
        if let Some(tx) = entered_tx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
        if let Some(rx) = release_rx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = rx.recv();
        }
    });

    let refresh = Arc::clone(&admissions);
    let entered_rx = Arc::new(std::sync::Mutex::new(Some(entered_rx)));
    let refresh_thread = Arc::new(std::sync::Mutex::new(None));
    let thread_slot = Arc::clone(&refresh_thread);
    adapter.set_before_admit_hook(Arc::new(move || {
        let refresh = Arc::clone(&refresh);
        let handle = std::thread::spawn(move || {
            let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");
            refresh
                .admit(secret, crate::key_admission::AdmissionSource::RawSecret)
                .expect("refresh admit");
        });
        *thread_slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        let rx = entered_rx.lock().unwrap_or_else(|p| p.into_inner()).take();
        rx.expect("pause channel")
            .recv_timeout(Duration::from_secs(10))
            .expect("refresh paused after the map insert");
    }));

    let started = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "a lost race must be a duplicate, got {err:?}"
    );

    let paused =
        store.get_config(&pk).expect("the hold row must survive while the refresh is paused");
    let hold = paused.doppelganger_hold_until.expect("the import hold must still be stored");
    assert!(!paused.enabled, "the held row must stay disabled while the refresh is paused");
    assert!(
        composite.has_local_key(&pk),
        "the refresh signer must already be installed before its generation bump"
    );

    release_on_drop.0.lock().unwrap_or_else(|p| p.into_inner()).take();
    release_tx.send(()).expect("release the refresh");
    let handle =
        refresh_thread.lock().unwrap_or_else(|p| p.into_inner()).take().expect("refresh thread");
    handle.join().expect("refresh admit finishes");

    let finished = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    assert!(composite.has_local_key(&pk), "the refresh signer must stay enabled");
    assert!(pubkey_map.read().contains_key(&pk), "the refresh map entry must stay");
    let cfg = store.get_config(&pk).expect("the refresh must end with a row");
    assert_eq!(cfg.doppelganger_hold_until, Some(hold), "the refresh must keep the import hold");
    assert!(!cfg.enabled, "a correct hold leaves the row disabled");
    assert!(hold >= started.saturating_add(window_secs));
    assert!(hold <= finished.saturating_add(window_secs));
    let disk = ValidatorStore::load_from_config(&path).unwrap();
    let disk_cfg = disk.get_config(&pk).expect("the hold must be durable");
    assert_eq!(disk_cfg.doppelganger_hold_until, Some(hold));
    assert!(!disk_cfg.enabled);
    let live_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    assert!(!live_json.exists(), "AlreadyPresent must not publish this import's keystore");
}

/// A zero-window import that loses the race after rename must not leave a boot-loadable keystore.
///
/// The refresh inserts its signer and map, then its validators-row write fails and
/// it rolls that signer back. Both admissions failed, so boot must not load the key.
#[test]
fn late_already_present_with_a_failed_refresh_row_is_not_boot_loadable() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use std::time::Duration;

    use secrecy::SecretString;

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = adapter.with_admission_service(Arc::clone(&admissions));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    // Test-only: recreate the same key for the refresh admit. Never log these bytes.
    #[allow(clippy::disallowed_methods)]
    let secret_bytes = sk.to_bytes();

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Arc::new(std::sync::Mutex::new(Some(entered_tx)));
    let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    let release_on_drop = ReleaseOnDrop(Arc::new(std::sync::Mutex::new(Some(release_tx.clone()))));
    let locked_validators = validators_dir.path().to_path_buf();
    let _restore_validators = RestoreDirPerms(locked_validators.clone());
    admissions.pause_once_after_map_insert(move || {
        let mut perms = std::fs::metadata(&locked_validators).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked_validators, perms).unwrap();
        if let Some(tx) = entered_tx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
        if let Some(rx) = release_rx.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = rx.recv();
        }
    });

    let refresh = Arc::clone(&admissions);
    let entered_rx = Arc::new(std::sync::Mutex::new(Some(entered_rx)));
    let refresh_thread = Arc::new(std::sync::Mutex::new(None));
    let thread_slot = Arc::clone(&refresh_thread);
    adapter.set_before_admit_hook(Arc::new(move || {
        let refresh = Arc::clone(&refresh);
        let handle = std::thread::spawn(move || {
            let secret = SecretKey::from_bytes(&secret_bytes).expect("secret");
            refresh.admit(secret, crate::key_admission::AdmissionSource::RawSecret)
        });
        *thread_slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        let rx = entered_rx.lock().unwrap_or_else(|p| p.into_inner()).take();
        rx.expect("pause channel")
            .recv_timeout(Duration::from_secs(10))
            .expect("refresh paused after the map insert");
    }));

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    let err = block_on(adapter.import_keystore(&json, password)).expect_err("duplicate");
    assert!(
        matches!(err, ImportKeystoreError::Duplicate),
        "a lost race after rename must be a duplicate, got {err:?}"
    );

    release_on_drop.0.lock().unwrap_or_else(|p| p.into_inner()).take();
    release_tx.send(()).expect("release the refresh");
    let handle =
        refresh_thread.lock().unwrap_or_else(|p| p.into_inner()).take().expect("refresh thread");
    let refresh_result = handle.join().expect("refresh thread");
    assert!(refresh_result.is_err(), "the refresh row write must fail, got {refresh_result:?}");
    assert!(!composite.has_local_key(&pk), "a failed refresh must roll its signer back");
    assert!(!pubkey_map.read().contains_key(&pk), "a failed refresh must roll its map entry back");

    let live_json = keystore_dir.path().join(format!("{}.json", pubkey_hex(pk)));
    assert!(!live_json.exists(), "this import's renamed keystore must not stay boot-visible");
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("*".to_string(), SecretString::from(password.to_string()));
    match crypto::KeyManager::load_from_directory(keystore_dir.path(), &passwords) {
        Ok(km) => assert!(!km.contains(&pk), "boot must not load a key both admissions failed"),
        Err(crypto::KeyManagerError::NoKeystoreFiles) => {}
        Err(e) => panic!("boot load failed unexpectedly: {e}"),
    }
}

/// Sends the refresh-release token if the test fails while the admit is paused.
struct ReleaseOnDrop(Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

/// The tombstone disable listener must not take `state_lock` while import holds `tracked_keys`.
///
/// DELETE takes `state_lock` and then `tracked_keys`. A listener that runs under
/// `tracked_keys` deadlocks with that DELETE. The timeout is the failure mode.
#[test]
fn tombstone_disable_does_not_deadlock_with_delete() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use std::time::Instant;

    use keymanager_api::lifecycle::ConfigTouch;
    use keymanager_api::traits::ValidatorManager;
    use keymanager_api::{DoppelgangerLifecycle, ImportKind};

    let composite = create_empty_composite_signer();
    let keystore_dir = TempDir::new().unwrap();
    let (adapter, pubkey_map, _rx) =
        test_keystore_adapter(keystore_dir.path().to_path_buf(), Arc::clone(&composite));
    let validators_dir = TempDir::new().unwrap();
    let path = validators_dir.path().join("validators.toml");
    std::fs::write(
        &path,
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
    )
    .unwrap();
    let store = Arc::new(ValidatorStore::load_from_config(&path).unwrap());
    let (tx, _rx2) = watch::channel(0u64);
    let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
        keystore_dir.path().join(".rvc.deleted_keys"),
    ));
    let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
        pubkey_map,
        tx,
        Arc::clone(&composite),
        Arc::clone(&store),
        denylist,
        None,
        Arc::new(MonotonicEpochClock::new(0)),
    ));
    let adapter = Arc::new(adapter.with_admission_service(admissions));
    adapter.set_doppelganger_window(std::time::Duration::from_secs(30));
    adapter.fail_after_admit();

    let vm = Arc::new(super::ValidatorManagerAdapter::new(Arc::clone(&store)));
    let vm_dyn: Arc<dyn ValidatorManager> = vm;
    let life = Arc::new(DoppelgangerLifecycle::new(
        std::time::Duration::from_secs(30),
        Arc::new(super::DoppelgangerDisabledMonitor::new()),
        vm_dyn,
    ));
    let listener_ran = Arc::new(AtomicBool::new(false));
    let ran = Arc::clone(&listener_ran);
    let life_listener = Arc::clone(&life);
    store.set_disable_listener(Arc::new(move |pubkey| {
        ran.store(true, std::sync::atomic::Ordering::SeqCst);
        life_listener.cancel_enable_on_disable(pubkey);
    }));

    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    block_on(async {
        life.rearm_persisted_hold(pk, std::time::Duration::from_secs(60)).expect("arm enable task");
    });
    assert!(life.current_cancel_token(&pk).is_some(), "the real enable token must be armed");

    let (import_at_rollback_tx, import_at_rollback_rx) = mpsc::channel::<()>();
    let (delete_holds_state_lock_tx, delete_holds_state_lock_rx) = mpsc::channel::<()>();
    let delete_holds_state_lock_rx =
        Arc::new(std::sync::Mutex::new(Some(delete_holds_state_lock_rx)));
    let locked_dir = keystore_dir.path().to_path_buf();
    adapter.set_before_discard_hook(Arc::new(move || {
        let mut perms = std::fs::metadata(&locked_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked_dir, perms).unwrap();
        import_at_rollback_tx.send(()).expect("import reached rollback");
        delete_holds_state_lock_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .expect("delete signal")
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("DELETE did not take state_lock");
    }));
    let _restore_perms = RestoreDirPerms(keystore_dir.path().to_path_buf());

    let password = "testpass";
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        crypto::EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");

    let (import_done_tx, import_done_rx) = mpsc::channel();
    let import_adapter = Arc::clone(&adapter);
    std::thread::spawn(move || {
        let result = block_on(import_adapter.import_keystore(&json, password));
        let _ = import_done_tx.send(result);
    });

    let (delete_done_tx, delete_done_rx) = mpsc::channel::<Result<(), String>>();
    let delete_adapter = Arc::clone(&adapter);
    let delete_life = Arc::clone(&life);
    std::thread::spawn(move || {
        if import_at_rollback_rx.recv_timeout(std::time::Duration::from_secs(10)).is_err() {
            let _ = delete_done_tx.send(Err("import never reached the tombstone rollback".into()));
            return;
        }
        let _ = delete_life.on_delete(&pk, ImportKind::Local, || {
            delete_holds_state_lock_tx.send(()).expect("signal state_lock");
            match delete_adapter.delete_keystore(&pk) {
                Ok(present) => (ConfigTouch::Apply { keystore_present: present }, Ok(())),
                Err(e) => (ConfigTouch::Skip, Err(e.to_string())),
            }
        });
        let _ = delete_done_tx.send(Ok(()));
    });

    let budget = std::time::Duration::from_secs(5);
    let started = Instant::now();
    let import_result = import_done_rx.recv_timeout(budget).unwrap_or_else(|_| {
        panic!("deadlock: tombstone import held tracked_keys while DELETE held state_lock")
    });
    let delete_result =
        delete_done_rx.recv_timeout(budget.saturating_sub(started.elapsed())).unwrap_or_else(
            |_| panic!("deadlock: DELETE held state_lock while the import held tracked_keys"),
        );

    assert!(import_result.is_err(), "the unlink failure must still fail the import");
    delete_result.expect("DELETE finishes once tracked_keys is free");
    assert!(
        listener_ran.load(std::sync::atomic::Ordering::SeqCst),
        "the real disable listener must still run after tracked_keys is released"
    );
    assert!(life.current_cancel_token(&pk).is_none(), "the enable token must be cancelled");
}

struct RestoreDirPerms(std::path::PathBuf);

impl Drop for RestoreDirPerms {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&self.0) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&self.0, perms);
        }
    }
}
