//! RR2-11: keystore import decrypts on the blocking pool under [`KdfBudget`].

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Json, State};
use axum::http::HeaderMap;
use crypto::{kdf_working_set_bytes, EncryptionKdf, Keystore, SecretKey};
use keymanager_api::handlers::{import_keystores, AppState};
use keymanager_api::traits::{ImportKeystoreError, KeystoreManager, Pubkey, ValidatorManager};
use keymanager_api::types::ImportKeystoresRequest;
use keymanager_api::DoppelgangerLifecycle;
use parking_lot::{Condvar, Mutex as ParkMutex};

use super::super::kdf_budget::{KdfBudget, KdfBudgetConfig};
use super::*;

const PASSWORD: &str = "testpass";
const MIB: u64 = 1024 * 1024;

/// Blocks inside the import body until [`Gate::release`].
struct Gate {
    entered: Arc<AtomicUsize>,
    inflight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    release: Arc<AtomicBool>,
    lock: Arc<ParkMutex<()>>,
    cv: Arc<Condvar>,
}

impl Gate {
    fn new() -> Self {
        Self {
            entered: Arc::new(AtomicUsize::new(0)),
            inflight: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            release: Arc::new(AtomicBool::new(false)),
            lock: Arc::new(ParkMutex::new(())),
            cv: Arc::new(Condvar::new()),
        }
    }

    fn hook(&self) -> Arc<dyn Fn() + Send + Sync> {
        let entered = Arc::clone(&self.entered);
        let inflight = Arc::clone(&self.inflight);
        let peak = Arc::clone(&self.peak);
        let release = Arc::clone(&self.release);
        let lock = Arc::clone(&self.lock);
        let cv = Arc::clone(&self.cv);
        Arc::new(move || {
            entered.fetch_add(1, Ordering::SeqCst);
            let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            let mut guard = lock.lock();
            while !release.load(Ordering::SeqCst) {
                cv.wait(&mut guard);
            }
            inflight.fetch_sub(1, Ordering::SeqCst);
        })
    }

    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
        self.cv.notify_all();
    }
}

async fn wait_entered(gate: &Gate, n: usize) {
    let start = Instant::now();
    while gate.entered.load(Ordering::SeqCst) < n {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {n} blocking bodies, have {}",
            gate.entered.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn cheap_keystore(password: &str) -> (String, Pubkey) {
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt");
    (keystore.to_json().expect("json"), pk)
}

fn scrypt_with(n: u32, r: u32, p: u32, password: &str) -> (Keystore, String, Pubkey) {
    let sk = SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let keystore = Keystore::encrypt(
        &sk,
        password.as_bytes(),
        "m/12381/3600/0/0/0",
        EncryptionKdf::ScryptWith { n, r, p, dklen: 32 },
    )
    .expect("encrypt");
    let json = keystore.to_json().expect("json");
    (keystore, json, pk)
}

fn scrypt_params_json(n: u32, r: u32, p: u32) -> String {
    format!(
        r#"{{"crypto":{{"kdf":{{"function":"scrypt","params":{{"dklen":32,"n":{n},"p":{p},"r":{r},"salt":"aa"}},"message":""}},"checksum":{{"function":"sha256","params":{{}},"message":"aa"}},"cipher":{{"function":"aes-128-ctr","params":{{"iv":"aa"}},"message":"aa"}}}},"path":"m/12381/3600/0/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}}"#
    )
}

fn adapter_with_budget(dir: &std::path::Path, cfg: KdfBudgetConfig) -> KeystoreManagerAdapter {
    let budget = Arc::new(KdfBudget::new(cfg));
    test_keystore_adapter(dir.to_path_buf(), create_empty_composite_signer())
        .0
        .with_kdf_budget(budget)
}

fn app_state(adapter: Arc<KeystoreManagerAdapter>) -> Arc<AppState> {
    let store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    let vm = Arc::new(ValidatorManagerAdapter::new(Arc::clone(&store)));
    let vm_dyn: Arc<dyn ValidatorManager> = vm;
    let (remote, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    Arc::new(AppState {
        keystore_manager: adapter,
        slashing_protection: Arc::new(SlashingProtectionAdapter::new_in_free_window(
            Arc::new(SlashingDb::open_in_memory().expect("db")),
            [0x11; 32],
        )),
        validator_manager: Arc::clone(&vm_dyn),
        doppelganger: Arc::new(DoppelgangerLifecycle::new(
            Duration::ZERO,
            Arc::new(DoppelgangerDisabledMonitor::new()),
            vm_dyn,
        )),
        remote_key_manager: Arc::new(remote),
        config_manager: Arc::new(ValidatorConfigManagerAdapter::new(store)),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: Mutex::new(std::collections::HashMap::new()),
    })
}

/// Cheap scrypt (`n = 2`) returns in microseconds, so it cannot by itself open
/// a 50 ms gap. `tracked_keys` is held for the import critical section that
/// now runs on the blocking pool, and `set_stall_ms` parks that same thread.
/// Inline import blocks both Tokio workers (one owns the lock, the other waits).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_heartbeat_has_no_gap_over_50ms_while_100_keystores_import() {
    const N: usize = 100;
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    adapter.tracked_keys.set_stall_ms(80);
    let adapter = Arc::new(adapter);

    let mut jsons = Vec::with_capacity(N);
    for _ in 0..N {
        jsons.push(cheap_keystore(PASSWORD).0);
    }

    let gaps = Arc::new(Mutex::new(Vec::<Duration>::new()));
    let stop = CancellationToken::new();
    let gaps_task = Arc::clone(&gaps);
    let stop_task = stop.clone();
    let heartbeat = tokio::spawn(async move {
        let mut last = Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    let now = Instant::now();
                    gaps_task.lock().expect("gaps").push(now.saturating_duration_since(last));
                    last = now;
                }
                _ = stop_task.cancelled() => break,
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    let gap_len_before = gaps.lock().expect("gaps").len();

    let mut joins = Vec::with_capacity(N);
    for json in jsons {
        let adapter = Arc::clone(&adapter);
        joins.push(tokio::spawn(async move {
            adapter.import_keystore(&json, PASSWORD).await.expect("import");
        }));
    }
    for join in joins {
        join.await.expect("import task");
    }
    stop.cancel();
    heartbeat.await.expect("heartbeat");

    let gaps = gaps.lock().expect("gaps");
    let during = &gaps[gap_len_before..];
    assert!(!during.is_empty(), "heartbeat must tick while 100 keystores import");
    let max_gap = during.iter().copied().max().expect("gap");
    assert!(
        max_gap <= Duration::from_millis(50),
        "async heartbeat gap {max_gap:?} exceeded 50 ms while {N} keystores imported"
    );
    assert_eq!(adapter.list_keys().len(), N);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_client_mid_import_does_not_release_the_permit_early() {
    let dir = TempDir::new().unwrap();
    let cfg = KdfBudgetConfig { concurrency: 1, ..KdfBudgetConfig::default() };
    let adapter = Arc::new(adapter_with_budget(dir.path(), cfg));
    let gate = Gate::new();
    adapter.set_during_blocking_hook(gate.hook());

    let (json, pk) = cheap_keystore(PASSWORD);
    let state = app_state(Arc::clone(&adapter));
    let handle = tokio::spawn({
        let state = Arc::clone(&state);
        let json = json.clone();
        async move {
            import_keystores(
                State(state),
                HeaderMap::new(),
                Json(ImportKeystoresRequest {
                    keystores: vec![json],
                    passwords: vec![PASSWORD.to_string()],
                    slashing_protection: None,
                }),
            )
            .await
        }
    });

    wait_entered(&gate, 1).await;
    handle.abort();
    let aborted = handle.await;
    assert!(aborted.is_err(), "dropping the handler future cancels the await");

    let (json2, pk2) = cheap_keystore(PASSWORD);
    let adapter2 = Arc::clone(&adapter);
    let second = tokio::spawn(async move { adapter2.import_keystore(&json2, PASSWORD).await });

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !second.is_finished(),
        "second import acquired a permit while the first body still runs"
    );
    assert_eq!(gate.entered.load(Ordering::SeqCst), 1, "second import entered the blocking body");
    assert!(!adapter.has_key(&pk), "decrypt has not finished");

    gate.release();
    second.await.expect("second task").expect("second import");
    assert!(adapter.has_key(&pk), "dropped handler still finishes the import");
    assert!(adapter.has_key(&pk2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_import_budget_keeps_two_derivations_in_flight() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    let adapter = Arc::new(adapter);
    let gate = Gate::new();
    adapter.set_during_blocking_hook(gate.hook());

    let mut joins = Vec::new();
    for _ in 0..8 {
        let (json, _) = cheap_keystore(PASSWORD);
        let adapter = Arc::clone(&adapter);
        joins.push(tokio::spawn(async move {
            adapter.import_keystore(&json, PASSWORD).await.expect("import");
        }));
    }

    wait_entered(&gate, 2).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        gate.entered.load(Ordering::SeqCst),
        2,
        "default concurrency is 2, not the blocking-pool ceiling"
    );
    assert_eq!(gate.peak.load(Ordering::SeqCst), 2);

    gate.release();
    for join in joins {
        join.await.expect("import task");
    }
    assert_eq!(adapter.list_keys().len(), 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_budget_keystore_is_admitted_alone() {
    let dir = TempDir::new().unwrap();
    let cfg = KdfBudgetConfig {
        concurrency: 2,
        total_bytes: MIB,
        max_keystore_bytes: crypto::MAX_KDF_WORKING_SET_BYTES,
    };
    let adapter = Arc::new(adapter_with_budget(dir.path(), cfg));
    let gate = Gate::new();
    adapter.set_during_blocking_hook(gate.hook());

    let mut joins = Vec::new();
    for _ in 0..4 {
        let (keystore, json, _) = scrypt_with(16_384, 8, 1, PASSWORD);
        let bytes = kdf_working_set_bytes(&keystore);
        assert!(bytes > cfg.total_bytes, "fixture must exceed the byte budget");
        assert!(bytes <= cfg.max_keystore_bytes);
        let adapter = Arc::clone(&adapter);
        joins.push(tokio::spawn(async move {
            adapter.import_keystore(&json, PASSWORD).await.expect("import");
        }));
    }

    wait_entered(&gate, 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(gate.entered.load(Ordering::SeqCst), 1, "an over-budget keystore runs alone");
    assert!(
        gate.peak.load(Ordering::SeqCst) <= 1,
        "peak in-flight derivations must stay within budget + one"
    );

    gate.release();
    for join in joins {
        join.await.expect("import task");
    }
    assert_eq!(adapter.list_keys().len(), 4);
}

#[tokio::test]
async fn keystore_above_max_scrypt_is_rejected_at_the_decrypt_gate() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    // n = 2^23, r = 1 is above MAX_SCRYPT_N and still under the 8 GiB byte cap,
    // so admission succeeds and decrypt's existing parameter gate rejects it.
    let json = scrypt_params_json(1 << 23, 1, 1);
    let err = adapter.import_keystore(&json, PASSWORD).await.expect_err("above MAX_SCRYPT_N");
    match err {
        ImportKeystoreError::DecryptionFailed(msg) => {
            assert!(msg.contains("exceeds maximum"), "{msg}");
        }
        other => panic!("expected the decrypt gate, got {other:?}"),
    }
    assert!(dir.path().read_dir().unwrap().next().is_none(), "rejected keystore is not written");
}

#[tokio::test]
async fn keystore_above_the_byte_cap_is_rejected_before_decrypt() {
    let dir = TempDir::new().unwrap();
    let cfg = KdfBudgetConfig { max_keystore_bytes: 1, ..KdfBudgetConfig::default() };
    let adapter = adapter_with_budget(dir.path(), cfg);
    let (json, pk) = cheap_keystore(PASSWORD);
    let err = adapter.import_keystore(&json, PASSWORD).await.expect_err("above the byte cap");
    match err {
        ImportKeystoreError::InvalidKeystore(msg) => {
            assert!(msg.contains("exceeds"), "{msg}");
        }
        other => panic!("expected the budget gate, got {other:?}"),
    }
    assert!(!adapter.has_key(&pk));
    assert!(dir.path().read_dir().unwrap().next().is_none());
}

#[tokio::test]
async fn no_key_admitted_when_interchange_import_fails() {
    let dir = TempDir::new().unwrap();
    let (adapter, _, _) =
        test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
    let adapter = Arc::new(adapter);
    let (json, pk) = cheap_keystore(PASSWORD);
    let state = app_state(Arc::clone(&adapter));

    let err = import_keystores(
        State(state),
        HeaderMap::new(),
        Json(ImportKeystoresRequest {
            keystores: vec![json],
            passwords: vec![PASSWORD.to_string()],
            slashing_protection: Some("not-json".into()),
        }),
    )
    .await
    .expect_err("interchange must fail the request");

    assert!(matches!(err, keymanager_api::error::ApiError::BadRequest(_)));
    assert!(!adapter.has_key(&pk), "a failed interchange import admits no key");
    assert!(adapter.list_keys().is_empty());
}
