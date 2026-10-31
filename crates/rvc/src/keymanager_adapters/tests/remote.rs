use super::*;

// --- RemoteKeyManagerAdapter tests ---

#[test]
fn test_remote_key_adapter_empty_list() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    assert!(adapter.list_remote_keys().is_empty());
}

#[test]
fn test_remote_key_adapter_has_key_false() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    assert!(!adapter.has_remote_key(&test_pubkey(1)));
}

#[test]
fn test_remote_key_adapter_import_and_list() {
    let composite = create_empty_composite_signer();
    let (adapter, _, _) = test_remote_adapter(composite.clone(), None);

    let pk = test_pubkey(1);
    let url = "https://signer.example.com".to_string();
    adapter.import_remote_key(pk, url.clone()).unwrap();

    let keys = adapter.list_remote_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, pk);
    assert_eq!(keys[0].1, url);
    assert!(adapter.has_remote_key(&pk));

    assert!(composite.public_keys().contains(&pk));
}

#[test]
fn test_remote_key_adapter_import_duplicate() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);
    adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
    let result = adapter.import_remote_key(pk, "https://signer.example.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)));
}

#[test]
fn test_remote_key_adapter_delete() {
    let composite = create_empty_composite_signer();
    let (adapter, _, _) = test_remote_adapter(composite.clone(), None);

    let pk = test_pubkey(1);
    adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
    assert!(adapter.has_remote_key(&pk));

    let deleted = adapter.delete_remote_key(&pk).unwrap();
    assert!(deleted);
    assert!(!adapter.has_remote_key(&pk));
    assert!(!composite.public_keys().contains(&pk));
}

#[test]
fn test_remote_key_adapter_delete_nonexistent() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    assert!(!adapter.delete_remote_key(&test_pubkey(99)).unwrap());
}

#[test]
fn test_remote_key_adapter_import_rejects_invalid_url_scheme() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);

    // file:// scheme — SSRF risk
    let result = adapter.import_remote_key(pk, "file:///etc/passwd".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));

    // ftp:// scheme
    let result = adapter.import_remote_key(pk, "ftp://evil.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));

    // No scheme
    let result = adapter.import_remote_key(pk, "signer.example.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));

    // Valid schemes should be accepted
    let pk2 = test_pubkey(2);
    let result = adapter.import_remote_key(pk2, "https://signer.example.com".to_string());
    assert!(result.is_ok());
}

// --- Remote signer host allowlist tests ---

#[test]
fn test_import_remote_key_allowed_host_accepted() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["signer.example.com".to_string()]),
    );
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "https://signer.example.com/api".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_import_remote_key_blocked_host_rejected() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["trusted.host".to_string()]),
    );
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "https://evil.attacker.com/api".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::HostNotAllowed(_))));
}

#[test]
fn test_import_remote_key_no_allowlist_allows_all() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "https://any.host.com".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_import_remote_key_allowlist_multiple_hosts() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["signer1.example.com".to_string(), "signer2.example.com".to_string()]),
    );
    let pk1 = test_pubkey(1);
    assert!(adapter.import_remote_key(pk1, "https://signer1.example.com".to_string()).is_ok());

    let pk2 = test_pubkey(2);
    assert!(adapter.import_remote_key(pk2, "https://signer2.example.com".to_string()).is_ok());

    let pk3 = test_pubkey(3);
    let result = adapter.import_remote_key(pk3, "https://signer3.example.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::HostNotAllowed(_))));
}

#[test]
fn test_import_remote_key_invalid_url_parse_error() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "not a valid url".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));
}

#[test]
fn test_import_remote_key_allowlist_with_port() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["signer.example.com".to_string()]),
    );
    let pk = test_pubkey(1);
    // host_str() returns the host without port
    let result = adapter.import_remote_key(pk, "https://signer.example.com:9000/api".to_string());
    assert!(result.is_ok());
}

// --- Cross-backend duplicates and the shared `TrackedKeys` lock (W4-K6a) ---

const REMOTE_URL: &str = "https://signer.example.com";

/// K loaded at boot in `LocalSigner`, with the `PubkeyMap` entry boot builds.
fn boot_loaded_key() -> (Arc<CompositeSigner>, PubkeyMap, crypto::PublicKey) {
    let secret = SecretKey::generate();
    let public = secret.public_key();
    let mut keys = KeyManager::new();
    keys.insert(secret);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(keys)));
    let pubkey_map = create_pubkey_map();
    pubkey_map.write().insert(public.to_bytes(), public.clone());
    (composite, pubkey_map, public)
}

#[test]
fn remote_import_of_a_locally_loaded_pubkey_is_a_duplicate() {
    let (composite, pubkey_map, public) = boot_loaded_key();
    let pk = public.to_bytes();
    let (adapter, key_gen) =
        shared_remote_adapter(Arc::clone(&composite), pubkey_map.clone(), Arc::default());

    let result = adapter.import_remote_key(pk, REMOTE_URL.to_string());

    assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)), "got {result:?}");
    assert!(!adapter.has_remote_key(&pk), "the remote URL list must not gain K");
    assert!(!composite.has_remote_key(&pk), "K must not enter the remote map");
    assert!(composite.has_local_key(&pk), "K stays a local key");
    assert_eq!(pubkey_map.read().keys().copied().collect::<Vec<_>>(), vec![pk]);
    assert_eq!(*key_gen.borrow(), 0, "a refused import must not advance key_gen");
}

/// K is only in `grpc_remote`, and in the `PubkeyMap` as boot leaves it. The
/// remote import call site refuses K and changes nothing.
#[test]
fn remote_import_of_a_grpc_pubkey_is_a_duplicate() {
    let composite = create_empty_composite_signer();
    let public = add_grpc_remote_key(&composite).public_key();
    let pk = public.to_bytes();
    let pubkey_map = create_pubkey_map();
    pubkey_map.write().insert(pk, public);
    let (adapter, key_gen) =
        shared_remote_adapter(Arc::clone(&composite), pubkey_map.clone(), Arc::default());

    let result = adapter.import_remote_key(pk, REMOTE_URL.to_string());

    assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)), "got {result:?}");
    assert!(adapter.list_remote_keys().is_empty(), "the remote URL list must not gain K");
    assert!(!composite.has_remote_key(&pk), "K must not enter the remote map");
    assert!(!composite.has_local_key(&pk), "K must not become a local key");
    assert!(composite.has_grpc_remote(&pk), "K stays a gRPC remote key");
    assert_eq!(pubkey_map.read().keys().copied().collect::<Vec<_>>(), vec![pk]);
    assert_eq!(*key_gen.borrow(), 0, "a refused import must not advance key_gen");
}

/// What the 749-2 scenario leaves behind.
#[derive(Debug, PartialEq)]
struct AfterDuplicateDelete {
    import_is_duplicate: bool,
    delete_is_not_found: bool,
    force_file_exists: bool,
    window: doppelganger::ForwardWindowStatus,
    in_pubkey_map: bool,
}

/// 749-2: K is loaded locally and forced into a window by the force file. A
/// remote import of K is refused, so its DELETE is `not_found` and never
/// cancels K's window or drops K from the duty map.
#[tokio::test(start_paused = true)]
async fn deleting_a_duplicate_remote_key_keeps_the_local_force_window() {
    use keymanager_api::lifecycle::ConfigTouch;
    use keymanager_api::{DoppelgangerLifecycle, ImportKind};

    let data_dir = TempDir::new().unwrap();
    crate::detection_marker::write_force_window(data_dir.path()).expect("force file");
    let force_file = crate::detection_marker::force_window_path(data_dir.path());
    let reader: Arc<dyn slashing::SlashingDbReader> =
        Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    let machine = Arc::new(
        ForwardWindowMachine::new(reader, 1, [0x11; 32]).with_force_window_path(force_file.clone()),
    );
    let (composite, pubkey_map, public) = boot_loaded_key();
    let pk = public.to_bytes();
    machine.register(&public, 5);
    assert_eq!(machine.status(&public), doppelganger::ForwardWindowStatus::Pending);

    let epoch: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 5);
    let monitor = Arc::new(ForwardWindowMonitor::new(Arc::clone(&machine), epoch));
    let validators: Arc<dyn ValidatorManager> = Arc::new(ValidatorManagerAdapter::new(Arc::new(
        ValidatorStore::new([1u8; 20], 30_000_000),
    )));
    let lifecycle = Arc::new(DoppelgangerLifecycle::new(
        std::time::Duration::from_secs(768),
        monitor,
        validators,
    ));
    let (remote, _key_gen) =
        shared_remote_adapter(Arc::clone(&composite), pubkey_map.clone(), Arc::default());

    // `handlers::import_remote_keys`: `on_import` runs only after `Ok`.
    let imported = remote.import_remote_key(pk, REMOTE_URL.to_string());
    if imported.is_ok() {
        lifecycle.on_import(pk, ImportKind::Remote).expect("on_import");
    }
    // `handlers::delete_remote_keys`' `remove_op` mapping.
    let (_, deleted) =
        lifecycle.on_delete(&pk, ImportKind::Remote, || match remote.delete_remote_key(&pk) {
            Ok(true) => (ConfigTouch::Apply { keystore_present: true }, Ok(true)),
            Ok(false) => (ConfigTouch::Skip, Ok(false)),
            Err(e) => (ConfigTouch::Skip, Err(e)),
        });

    assert_eq!(
        AfterDuplicateDelete {
            import_is_duplicate: matches!(imported, Err(ImportRemoteKeyError::Duplicate)),
            delete_is_not_found: matches!(deleted, Ok(false)),
            force_file_exists: force_file.exists(),
            window: machine.status(&public),
            in_pubkey_map: pubkey_map.read().contains_key(&pk),
        },
        AfterDuplicateDelete {
            import_is_duplicate: true,
            delete_is_not_found: true,
            force_file_exists: true,
            window: doppelganger::ForwardWindowStatus::Pending,
            in_pubkey_map: true,
        },
        "import {imported:?}, delete {deleted:?}"
    );
    assert!(composite.has_local_key(&pk));
}

/// `list_remote_keys` from another thread while a writer waits on `TrackedKeys`.
/// The timeout is only a hang guard: the waiting writer must not hold
/// `remote_keys` (lock order `TrackedKeys` → `remote_keys`).
fn list_while_a_writer_waits(remote: &Arc<RemoteKeyManagerAdapter>) -> Vec<(Pubkey, String)> {
    let (tx, rx) = std::sync::mpsc::channel();
    let remote = Arc::clone(remote);
    std::thread::spawn(move || tx.send(remote.list_remote_keys()));
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("list_remote_keys blocked: a writer waiting for TrackedKeys holds remote_keys")
}

/// The cross-backend check runs inside the shared `TrackedKeys` section: a
/// local load made while another writer holds it is seen by the remote import.
#[test]
fn remote_import_waits_for_the_shared_tracked_keys_lock() {
    let composite = create_empty_composite_signer();
    let pubkey_map = create_pubkey_map();
    let tracked_keys = Arc::new(TrackedKeys::new());
    let (remote, _key_gen) = shared_remote_adapter(
        Arc::clone(&composite),
        pubkey_map.clone(),
        Arc::clone(&tracked_keys),
    );
    let remote = Arc::new(remote);
    let secret = SecretKey::generate();
    let public = secret.public_key();
    let pk = public.to_bytes();

    let before = tracked_keys.contended();
    let guard = tracked_keys.lock();
    let import = std::thread::spawn({
        let remote = Arc::clone(&remote);
        move || remote.import_remote_key(pk, REMOTE_URL.to_string())
    });
    tracked_keys.wait_until_contended(before);
    assert!(list_while_a_writer_waits(&remote).is_empty());
    // A keystore import's section: signer, then map.
    composite.add_local_key(secret);
    pubkey_map.write().insert(pk, public);
    drop(guard);

    let result = import.join().expect("import thread");
    assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)), "got {result:?}");
    assert!(!composite.has_remote_key(&pk), "K must not enter the remote map");
    assert!(!remote.has_remote_key(&pk), "the remote URL list must not gain K");
}

/// Remote DELETE waits for the shared `TrackedKeys` section too.
#[test]
fn remote_delete_waits_for_the_shared_tracked_keys_lock() {
    let composite = create_empty_composite_signer();
    let tracked_keys = Arc::new(TrackedKeys::new());
    let (remote, _key_gen) = shared_remote_adapter(
        Arc::clone(&composite),
        create_pubkey_map(),
        Arc::clone(&tracked_keys),
    );
    let remote = Arc::new(remote);
    let pk = SecretKey::generate().public_key().to_bytes();
    remote.import_remote_key(pk, REMOTE_URL.to_string()).expect("import");

    let before = tracked_keys.contended();
    let guard = tracked_keys.lock();
    let delete = std::thread::spawn({
        let remote = Arc::clone(&remote);
        move || remote.delete_remote_key(&pk)
    });
    tracked_keys.wait_until_contended(before);
    assert_eq!(
        list_while_a_writer_waits(&remote),
        vec![(pk, REMOTE_URL.to_string())],
        "DELETE ran while another writer held TrackedKeys"
    );
    assert!(composite.has_remote_key(&pk));
    drop(guard);

    let deleted = delete.join().expect("delete thread");
    assert!(matches!(deleted, Ok(true)), "got {deleted:?}");
    assert!(!composite.has_remote_key(&pk));
}
