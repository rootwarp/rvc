//! RR3-02: the interchange write path waits for a free slot window.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::IntoResponse;
use http_body_util::BodyExt;
use keymanager_api::error::map_slashing_protection_error;
use keymanager_api::handlers::AppState;
use keymanager_api::traits::{SlashingProtection, SlashingProtectionError};
use keymanager_api::types::{DeleteKeystoresResponse, DeleteStatus};
use timing::{due_ms, MockSlotClock, SlotClock, TimingError, ATTESTATION_DUE_BPS};
use tokio::time::Instant;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

use super::super::import_window::{ImportAdmission, ImportDeferralError, ImportWindowGate};
use super::export_floor::{self, CountingKeys};
use super::*;

const GENESIS: u64 = 1_606_824_023;
const SLOT_MS: u64 = 12_000;

/// `true` when `fut` is still pending after one poll.
///
/// The yield arm keeps a paused clock from auto-advancing to a timer.
async fn poll_pending<F: std::future::Future>(mut fut: std::pin::Pin<&mut F>) -> bool {
    tokio::select! {
        biased;
        _ = fut.as_mut() => false,
        _ = tokio::task::yield_now() => true,
    }
}

fn interchange_json(gvr: [u8; 32]) -> String {
    serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": format!("0x{}", hex::encode(gvr))
        },
        "data": []
    })
    .to_string()
}

fn gate_at(offset_ms: u64, slot: Duration) -> (Arc<MockSlotClock>, Arc<ImportWindowGate>) {
    let clock = Arc::new(MockSlotClock::new(GENESIS, slot, 32));
    clock.set_slot_with_offset_ms(0, offset_ms);
    let gate = Arc::new(ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>));
    (clock, gate)
}

/// Published zero-row estimate, truncated to the millisecond the log stores.
///
/// Includes the 0.440 ms pre-lock spread, the scaled-margin floor, the
/// loaded-run and statement-shape terms on `min_hold`, one group-commit
/// batch, the fill wait, and the 1 ms slot-anchor allowance. Reading the
/// gate's own estimate keeps a truncated millisecond from hiding a missing term.
fn published_zero_row_hold_ms() -> u64 {
    super::super::import_window::truncated_estimated_hold_ms(0)
}

#[derive(Default)]
struct WaitVisitor {
    message: Option<String>,
    wait_ms: Option<u64>,
    window_ms: Option<u64>,
    estimated_hold_ms: Option<u64>,
}

impl Visit for WaitVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let rendered = format!("{value:?}");
            self.message = Some(rendered.trim_matches('"').to_owned());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "wait_ms" => self.wait_ms = Some(value),
            "window_ms" => self.window_ms = Some(value),
            "estimated_hold_ms" => self.estimated_hold_ms = Some(value),
            _ => {}
        }
    }
}

struct DeferralLog {
    logs: Arc<Mutex<Vec<WaitVisitor>>>,
    message: &'static str,
}

impl<S: tracing::Subscriber> Layer<S> for DeferralLog {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = WaitVisitor::default();
        event.record(&mut visitor);
        if visitor.message.as_deref() == Some(self.message) {
            self.logs.lock().expect("deferral log").push(visitor);
        }
    }
}

/// An import issued at t≈1 s must not take `conn` until the free window opens,
/// and the deferral must be visible as `rvc_slashing_import_deferred_ms` plus
/// one `info!`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn interchange_import_waits_for_a_free_window_and_reports_the_wait() {
    let (deferred_before, deferred_sum_before) = crate::test_metrics::import_deferred();
    let open_ms = due_ms(ATTESTATION_DUE_BPS, SLOT_MS) + 500;
    assert_eq!(open_ms, 4_499, "attestation due 3999 ms plus the 500 ms reserve");
    let wait_ms = open_ms - 1_000;
    let window_ms = (SLOT_MS - 200) - open_ms;
    assert_eq!(window_ms, 7_301);
    let estimated_hold_ms = published_zero_row_hold_ms();

    let (clock, gate) = gate_at(1_000, Duration::from_secs(12));
    assert_eq!(clock.ms_into_slot(clock.current_slot().unwrap()), 1_000);

    let gvr = [0x11u8; 32];
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = SlashingProtectionAdapter::new(db, gvr, gate);
    let entered: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let entered_hook = Arc::clone(&entered);
    adapter.set_during_import(Some(Arc::new(move || {
        *entered_hook.lock().expect("entered") = Some(Instant::now());
    })));
    let json = interchange_json(gvr);

    let logs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry()
        .with(DeferralLog { logs: Arc::clone(&logs), message: "interchange import deferred" });
    let _guard = tracing::subscriber::set_default(subscriber);

    let started = Instant::now();
    let import = adapter.import_interchange(&json);
    tokio::pin!(import);

    assert!(
        poll_pending(import.as_mut()).await,
        "import issued at t≈1s must not take conn until the free window opens"
    );
    assert!(entered.lock().expect("entered").is_none(), "conn is not taken at t≈1s");
    assert_eq!(Instant::now(), started, "the import must still be deferred at t≈1s");

    tokio::time::advance(Duration::from_millis(wait_ms - 1)).await;
    assert!(
        poll_pending(import.as_mut()).await,
        "one millisecond before the window the import is still deferred"
    );
    assert!(entered.lock().expect("entered").is_none());

    tokio::time::advance(Duration::from_millis(1)).await;
    import.await.expect("import once the window is open");

    let entered_at = entered.lock().expect("entered").expect("blocking import ran");
    assert_eq!(
        entered_at.duration_since(started),
        Duration::from_millis(wait_ms),
        "the blocking import starts when the window opens"
    );

    let recorded = logs.lock().expect("deferral log");
    assert_eq!(recorded.len(), 1, "exactly one info! per deferred import");
    assert_eq!(recorded[0].wait_ms, Some(wait_ms));
    assert_eq!(recorded[0].window_ms, Some(window_ms));
    assert_eq!(recorded[0].estimated_hold_ms, Some(estimated_hold_ms));

    let (deferred_after, deferred_sum_after) = crate::test_metrics::import_deferred();
    assert_eq!(deferred_after - deferred_before, 1, "one deferred-ms sample");
    let sum_delta = deferred_sum_after - deferred_sum_before;
    assert!(
        (sum_delta - wait_ms as f64).abs() < f64::EPSILON,
        "deferred-ms sample is the wait, got {sum_delta}"
    );
}

/// JSON and version checks return before `admit`, so a bad payload does not
/// sit on the gate at t≈1 s.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn invalid_interchange_is_rejected_before_the_window_wait() {
    let (_clock, gate) = gate_at(1_000, Duration::from_secs(12));
    let gvr = [0x11u8; 32];
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = SlashingProtectionAdapter::new(db, gvr, gate);
    let started = Instant::now();

    let bad_json = adapter.import_interchange("not json").await.expect_err("json");
    assert!(matches!(bad_json, SlashingProtectionError::InvalidInterchange(_)));
    assert_eq!(Instant::now(), started, "invalid JSON does not wait for the window");

    let bad_version = serde_json::json!({
        "metadata": {
            "interchange_format_version": "4",
            "genesis_validators_root": format!("0x{}", hex::encode(gvr))
        },
        "data": []
    });
    let bad_version =
        adapter.import_interchange(&bad_version.to_string()).await.expect_err("version");
    assert!(matches!(bad_version, SlashingProtectionError::InvalidInterchange(_)));
    assert_eq!(Instant::now(), started, "a bad version does not wait for the window");
}

/// A 1 s slot has no free window: the attestation reserve lands after the
/// block reserve. The HTTP response is 503 and names `NoFreeWindow`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn unfittable_import_is_no_free_window_in_the_http_response() {
    let (_clock, gate) = gate_at(0, Duration::from_secs(1));
    let gvr = [0x22u8; 32];
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = SlashingProtectionAdapter::new(db, gvr, gate);
    let err = adapter.import_interchange(&interchange_json(gvr)).await.expect_err("no window");
    let SlashingProtectionError::NoFreeWindow(msg) = &err else {
        panic!("expected NoFreeWindow, got {err}");
    };
    assert!(msg.contains("NoFreeWindow"), "{msg}");
    assert!(msg.contains("split the payload"), "{msg}");

    let response =
        map_slashing_protection_error(err, "slashing protection import failed").into_response();
    assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("Retry-After").is_none());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let message = json["message"].as_str().unwrap_or("");
    assert!(message.contains("NoFreeWindow"), "{message}");
    assert!(message.contains("split the payload"), "{message}");
}

/// An out-of-range epoch is `InvalidInterchange` on the first poll, before `admit`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_out_of_range_interchange_is_a_400_naming_the_field() {
    let (_clock, gate) = gate_at(1_000, Duration::from_secs(12));
    let gvr = [0x11u8; 32];
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = SlashingProtectionAdapter::new(Arc::clone(&db), gvr, gate);
    let above = (1_u64 << 63).to_string();
    let json = serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": format!("0x{}", hex::encode(gvr))
        },
        "data": [{
            "pubkey": "0xaaaa",
            "signed_blocks": [],
            "signed_attestations": [{
                "source_epoch": "1",
                "target_epoch": above,
                "signing_root": null
            }]
        }]
    })
    .to_string();

    let started = Instant::now();
    let import = adapter.import_interchange(&json);
    tokio::pin!(import);
    let polled = tokio::select! {
        biased;
        result = import.as_mut() => result,
        _ = tokio::task::yield_now() => {
            panic!("first poll must be Ready(Err(InvalidInterchange)), not a window wait")
        }
    };
    assert_eq!(Instant::now(), started, "an out-of-range interchange must not wait for the window");
    let err = polled.expect_err("out of range");
    let SlashingProtectionError::InvalidInterchange(msg) = &err else {
        panic!("expected InvalidInterchange, got {err:?}");
    };
    assert!(msg.contains("target_epoch"), "{msg}");
    assert!(msg.contains(&(1_u64 << 63).to_string()), "{msg}");

    let response =
        map_slashing_protection_error(err, "slashing protection import failed").into_response();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let message = json["message"].as_str().unwrap_or("");
    assert!(message.starts_with("invalid interchange:"), "{message}");
    assert!(message.contains("target_epoch"), "{message}");
    assert!(
        json.get("code").is_none(),
        "same message-only shape as other InvalidInterchange errors, got {json}"
    );
    assert!(db.get_attestations("0xaaaa").expect("rows").is_empty());
}

fn history_interchange(gvr: [u8; 32], pubkey: &str) -> String {
    serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": format!("0x{}", hex::encode(gvr))
        },
        "data": [{
            "pubkey": pubkey,
            "signed_blocks": [],
            "signed_attestations": [{
                "source_epoch": "1",
                "target_epoch": "2",
                "signing_root": null
            }]
        }]
    })
    .to_string()
}

/// Sends on drop so a failed assertion cannot leave the blocking import parked.
struct ReleaseOnDrop(Option<std::sync::mpsc::Sender<()>>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

/// Dropping the caller while `import` is inside the blocking section must not
/// drop the admission guard before the transaction commits.
#[tokio::test(flavor = "current_thread")]
async fn dropping_the_client_mid_import_does_not_release_the_guard_before_the_transaction_ends() {
    let (_clock, gate) = gate_at(8_000, Duration::from_secs(12));
    let gvr = [0x33u8; 32];
    let pubkey = format!("0x{}", hex::encode([0x44u8; 48]));
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = Arc::new(SlashingProtectionAdapter::new(Arc::clone(&db), gvr, Arc::clone(&gate)));

    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let entered_tx = Mutex::new(Some(entered_tx));
    let release_rx = Mutex::new(release_rx);
    let hook_db = Arc::clone(&db);
    let hook_pubkey = pubkey.clone();
    adapter.set_during_import(Some(Arc::new(move || {
        if let Some(tx) = entered_tx.lock().expect("entered").take() {
            let _ = tx.send(());
            let _ = release_rx.lock().expect("release").recv();
        } else {
            let rows = hook_db.get_attestations(&hook_pubkey).expect("rows");
            assert_eq!(
                rows.len(),
                1,
                "the guard is released only after the first transaction commits"
            );
            assert_eq!(rows[0].source_epoch, 1);
            assert_eq!(rows[0].target_epoch, 2);
        }
    })));

    let first = {
        let adapter = Arc::clone(&adapter);
        let json = history_interchange(gvr, &pubkey);
        tokio::spawn(async move { adapter.import_interchange(&json).await })
    };
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("first import entered the hook")
        .expect("entered oneshot");
    first.abort();
    let _ = first.await;

    assert!(
        gate.admission_in_progress(),
        "dropping the client must not release the admission guard"
    );

    let _release = ReleaseOnDrop(Some(release_tx));
    let second = {
        let adapter = Arc::clone(&adapter);
        let json = interchange_json(gvr);
        tokio::spawn(async move { adapter.import_interchange(&json).await })
    };
    // The second admission is waiting on the guard. Releasing the hook lets
    // the first transaction commit and only then drop the guard.
    drop(_release);
    tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .expect("second import finished")
        .expect("second import task")
        .expect("second import");
    assert!(!gate.admission_in_progress(), "the guard is free after the transaction ends");
    let rows = db.get_attestations(&pubkey).expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source_epoch, 1);
}

const EXPORT_FAILED: &str = "slashing protection export failed; no keystores deleted";

fn expect_export_internal(err: ApiError) {
    match err {
        ApiError::Internal(message) => assert_eq!(message, EXPORT_FAILED),
        other => panic!("expected Internal, got {other:?}"),
    }
}

fn unavailable_response(err: ApiError, retry_after_secs: Option<u64>) -> axum::response::Response {
    let ApiError::Unavailable { message, retry_after_secs: got } = err else {
        panic!("expected Unavailable, got {err:?}");
    };
    assert_eq!(got, retry_after_secs);
    ApiError::Unavailable { message, retry_after_secs: got }.into_response()
}

/// Blocks inside a `cfg(test)` hook until the test sends on the returned sender.
fn parking_hook(
) -> (Arc<dyn Fn() + Send + Sync>, tokio::sync::oneshot::Receiver<()>, std::sync::mpsc::Sender<()>)
{
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let entered_tx = Mutex::new(Some(entered_tx));
    let release_rx = Mutex::new(release_rx);
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        if let Some(tx) = entered_tx.lock().expect("entered").take() {
            let _ = tx.send(());
            let _ = release_rx.lock().expect("release").recv();
        }
    });
    (hook, entered_rx, release_tx)
}

struct DeleteRig {
    key: Pubkey,
    hex_key: String,
    db: Arc<SlashingDb>,
    adapter: Arc<SlashingProtectionAdapter>,
    gate: Arc<ImportWindowGate>,
    keys: Arc<CountingKeys>,
    store: Arc<ValidatorStore>,
    state: Arc<AppState>,
    keystore_file: PathBuf,
    sidecar: PathBuf,
    secret: PathBuf,
    _dir: TempDir,
}

impl DeleteRig {
    /// Loaded key `k` behind `gate_at(offset_ms)`. `with_history` seeds one
    /// attestation and one block so the admission count is 2.
    fn open(offset_ms: u64, with_history: bool) -> Self {
        let (_clock, gate) = gate_at(offset_ms, Duration::from_secs(12));
        let key = test_pubkey(1);
        let hex_key = pubkey_hex(key);
        let gvr = export_floor::chain_gvr();
        let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
        if with_history {
            db.seed_attestation(&hex_key, 1, 2, Some("0xrow".into()), &gvr).expect("attestation");
            db.seed_block(&hex_key, 7, Some("0xblk".into()), &gvr).expect("block");
        }
        let adapter =
            Arc::new(SlashingProtectionAdapter::new(Arc::clone(&db), gvr, Arc::clone(&gate)));
        let dir = tempfile::tempdir().expect("keystore dir");
        export_floor::write_keystore_bundle(dir.path(), &hex_key);
        let keystore_file = dir.path().join(format!("{hex_key}.json"));
        let sidecar = dir.path().join(format!("{hex_key}.import_meta.json"));
        let secret = dir.path().join(crate::config::Config::IMPORT_SECRETS_DIR).join(&hex_key);
        let keys = Arc::new(CountingKeys::with_keystore_dir(vec![key], dir.path().to_path_buf()));
        let store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
        let manager = ValidatorManagerAdapter::new(Arc::clone(&store));
        manager.add_validator(key, true).expect("add");
        let state = export_floor::app_state(
            Arc::clone(&keys) as Arc<dyn KeystoreManager>,
            Arc::clone(&adapter) as Arc<dyn SlashingProtection>,
            Arc::new(manager) as Arc<dyn ValidatorManager>,
        );
        Self {
            key,
            hex_key,
            db,
            adapter,
            gate,
            keys,
            store,
            state,
            keystore_file,
            sidecar,
            secret,
            _dir: dir,
        }
    }

    async fn delete(&self, pubkeys: Vec<String>) -> Result<DeleteKeystoresResponse, ApiError> {
        export_floor::delete(Arc::clone(&self.state), pubkeys).await
    }

    /// Disable already ran. Nothing was removed and the seeded attestation remains.
    fn assert_nothing_removed(&self) {
        assert_eq!(self.keys.deletes(), 0, "keystore delete must not run");
        assert!(self.keys.has_key(&self.key), "key stays in the keystore");
        assert!(self.keystore_file.exists(), "keystore file remains");
        assert!(self.sidecar.exists(), "sidecar remains");
        assert!(self.secret.exists(), "import secret remains");
        assert!(!self.store.is_signing_enabled(&self.key), "key stays disabled");
        assert_eq!(
            self.db.get_attestations(&self.hex_key).expect("rows").len(),
            1,
            "slashing rows remain"
        );
    }
}

/// DELETE [k] issued at t≈1 s waits for the free window, then exports on the
/// paused clock exactly when that window opens.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn delete_export_waits_for_the_free_window() {
    let open_ms = due_ms(ATTESTATION_DUE_BPS, SLOT_MS) + 500;
    assert_eq!(open_ms, 4_499, "attestation due 3999 ms plus the 500 ms reserve");
    let wait_ms = open_ms - 1_000;
    let window_ms = (SLOT_MS - 200) - open_ms;
    assert_eq!(window_ms, 7_301);
    let estimated_hold_ms = super::super::import_window::truncated_estimated_hold_ms(2);

    let rig = DeleteRig::open(1_000, true);
    let logs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(DeferralLog {
        logs: Arc::clone(&logs),
        message: "keymanager delete export deferred",
    });
    let _guard = tracing::subscriber::set_default(subscriber);

    let started = Instant::now();
    let body = rig.delete(vec![rig.hex_key.clone()]).await.expect("delete once the window opens");
    assert_eq!(
        started.elapsed(),
        Duration::from_millis(wait_ms),
        "the export is admitted when the free window opens"
    );
    assert_eq!(body.data.len(), 1);
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
    assert_eq!(rig.keys.deletes(), 1);
    assert!(!rig.keys.has_key(&rig.key));

    let json: serde_json::Value = serde_json::from_str(&body.slashing_protection).expect("json");
    let atts = json["data"][0]["signed_attestations"].as_array().expect("atts");
    assert!(atts.iter().any(|att| att["source_epoch"] == "1" && att["target_epoch"] == "2"));
    let blocks = json["data"][0]["signed_blocks"].as_array().expect("blocks");
    assert!(blocks.iter().any(|block| block["slot"] == "7"));
    assert_eq!(rig.db.get_attestations(&rig.hex_key).expect("rows").len(), 1);

    let recorded = logs.lock().expect("deferral log");
    assert_eq!(recorded.len(), 1, "exactly one info! per deferred delete export");
    assert_eq!(recorded[0].wait_ms, Some(wait_ms));
    assert_eq!(recorded[0].window_ms, Some(window_ms));
    assert_eq!(recorded[0].estimated_hold_ms, Some(estimated_hold_ms));
}

/// A DELETE that races a parked import is admitted only after that import
/// commits, so the file contains the imported rows.
///
/// `before_export_admit` runs in the same poll as `admit_capped`. If the
/// export skipped the gate, `after_export_admitted` would already be set when
/// that signal arrives: `spawn_blocking` alone makes the first `poll_pending`
/// pending, and releasing the import would then let a gateless export see the
/// committed rows.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_delete_export_waits_for_an_import_that_holds_the_window() {
    let rig = DeleteRig::open(8_000, false);
    let (import_hook, import_entered, import_release) = parking_hook();
    rig.adapter.set_during_import(Some(import_hook));

    let (before_tx, before_rx) = tokio::sync::oneshot::channel();
    let before_tx = Mutex::new(Some(before_tx));
    rig.adapter.set_before_export_admit(Some(Arc::new(move || {
        if let Some(tx) = before_tx.lock().expect("before admit").take() {
            let _ = tx.send(());
        }
    })));
    let admitted = Arc::new(AtomicBool::new(false));
    let admitted_hook = Arc::clone(&admitted);
    rig.adapter.set_after_export_admitted(Some(Arc::new(move || {
        admitted_hook.store(true, Ordering::SeqCst);
    })));

    let gvr = export_floor::CHAIN_GVR_HEX;
    let import_json = serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": gvr
        },
        "data": [{
            "pubkey": rig.hex_key,
            "signed_blocks": [],
            "signed_attestations": [{
                "source_epoch": "3",
                "target_epoch": "4",
                "signing_root": null
            }]
        }]
    })
    .to_string();
    let import = {
        let adapter = Arc::clone(&rig.adapter);
        tokio::spawn(async move { adapter.import_interchange(&import_json).await })
    };
    let _release = ReleaseOnDrop(Some(import_release));
    import_entered.await.expect("import entered the hook");

    let delete_fut = rig.delete(vec![rig.hex_key.clone()]);
    tokio::pin!(delete_fut);
    tokio::select! {
        biased;
        reached = before_rx => {
            reached.expect("export reached admit");
        }
        result = delete_fut.as_mut() => {
            panic!("DELETE finished while the import still holds the window: {result:?}");
        }
    }
    assert!(
        !admitted.load(Ordering::SeqCst),
        "the export must not pass admit while the import holds the gate"
    );
    assert!(
        poll_pending(delete_fut.as_mut()).await,
        "one poll while the import holds the gate must not complete the DELETE"
    );

    drop(_release);
    let body = delete_fut.await.expect("delete after the import commits");
    import.await.expect("import task").expect("import");
    assert_eq!(body.data.len(), 1);
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
    let json: serde_json::Value = serde_json::from_str(&body.slashing_protection).expect("json");
    assert_eq!(export_floor::recorded_pubkeys(&json), vec![rig.hex_key.as_str()]);
    let atts = json["data"][0]["signed_attestations"].as_array().expect("atts");
    assert!(
        atts.iter().any(|att| att["source_epoch"] == "3" && att["target_epoch"] == "4"),
        "the export was admitted only after the import committed"
    );
}

/// The test holds the gate the way an import does. The DELETE waits out the
/// queue bound, then 503s, and removes nothing.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn delete_export_behind_a_held_gate_is_503_and_deletes_nothing() {
    let rig = DeleteRig::open(8_000, true);
    let holder = rig.gate.admit(0).await.expect("the test holds the gate");
    let started = Instant::now();
    let err = rig.delete(vec![rig.hex_key.clone()]).await.expect_err("queue bound");
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(24),
        "QUEUE_WAIT_SLOTS is 2 and the slot is 12s"
    );
    let response = unavailable_response(err, Some(24));
    assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let retry_after = response.headers().get("Retry-After").expect("Retry-After");
    assert_eq!(retry_after.to_str().expect("header"), "24");
    rig.assert_nothing_removed();
    drop(holder);
}

/// The export read runs off the runtime thread and keeps the admission guard
/// after the DELETE task is aborted, until the read returns.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn delete_export_runs_on_a_blocking_thread_and_keeps_the_guard_after_a_disconnect() {
    let rig = DeleteRig::open(8_000, true);
    let runtime_thread = std::thread::current().id();
    let recorded = Arc::new(Mutex::new(None));
    let recorded_hook = Arc::clone(&recorded);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let entered_tx = Mutex::new(Some(entered_tx));
    let release_rx = Mutex::new(release_rx);
    rig.adapter.set_during_export(Some(Arc::new(move || {
        *recorded_hook.lock().expect("thread") = Some(std::thread::current().id());
        if let Some(tx) = entered_tx.lock().expect("entered").take() {
            let _ = tx.send(());
            let _ = release_rx.lock().expect("release").recv();
        }
    })));

    let state = Arc::clone(&rig.state);
    let hex_key = rig.hex_key.clone();
    let task = tokio::spawn(async move { export_floor::delete(state, vec![hex_key]).await });
    let _release = ReleaseOnDrop(Some(release_tx));
    entered_rx.await.expect("export entered the hook");
    let export_thread = recorded.lock().expect("thread").expect("recorded");
    assert_ne!(export_thread, runtime_thread, "the export read is not on the runtime thread");

    task.abort();
    let _ = task.await;
    let admit = rig.gate.admit(0);
    tokio::pin!(admit);
    assert!(
        poll_pending(admit.as_mut()).await,
        "aborting the DELETE must not release the admission guard"
    );
    drop(_release);
    admit.await.expect("the guard drops after the blocking read returns");
    assert!(!rig.gate.admission_in_progress());
    rig.assert_nothing_removed();
}

/// After `export_pubkeys` returns, `gate.admit(0)` is still pending.
///
/// The hook runs after that call and before `drop(admission.guard)`. Dropping
/// the guard between `during_export` and `export_pubkeys` lets `admit(0)`
/// finish while the hook is parked.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gate_admit_stays_pending_after_export_pubkeys_returns() {
    let rig = DeleteRig::open(8_000, true);
    let (hook, entered_rx, release_tx) = parking_hook();
    rig.adapter.set_after_export_read(Some(hook));

    let state = Arc::clone(&rig.state);
    let hex_key = rig.hex_key.clone();
    let task = tokio::spawn(async move { export_floor::delete(state, vec![hex_key]).await });
    let _release = ReleaseOnDrop(Some(release_tx));
    entered_rx.await.expect("export_pubkeys returned");

    let admit = rig.gate.admit(0);
    tokio::pin!(admit);
    assert!(
        poll_pending(admit.as_mut()).await,
        "gate.admit(0) is still pending after export_pubkeys returns"
    );
    drop(_release);
    admit.await.expect("the guard drops after the post-export hook returns");
    let body = task.await.expect("delete task").expect("delete");
    assert_eq!(body.data.len(), 1);
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
}

/// The row-count read is before admission. Aborting it must not hold the gate,
/// and must not remove the key.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn client_disconnect_during_the_row_count_does_not_hold_the_gate() {
    let rig = DeleteRig::open(8_000, true);
    let (hook, entered_rx, release_tx) = parking_hook();
    rig.adapter.set_during_row_count(Some(hook));

    let state = Arc::clone(&rig.state);
    let hex_key = rig.hex_key.clone();
    let task = tokio::spawn(async move { export_floor::delete(state, vec![hex_key]).await });
    let _release = ReleaseOnDrop(Some(release_tx));
    entered_rx.await.expect("row count entered the hook");

    let admit = rig.gate.admit(0);
    tokio::pin!(admit);
    assert!(!poll_pending(admit.as_mut()).await, "the row-count stage must not hold the gate");
    task.abort();
    let _ = task.await;
    rig.assert_nothing_removed();
    assert!(!rig.gate.admission_in_progress());
}

/// Q7: a history whose estimate exceeds the window is admitted inside one
/// slot with the hold capped to that window. Import admission is not capped.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_large_history_delete_export_is_admitted_capped_to_the_window() {
    let open_ms = due_ms(ATTESTATION_DUE_BPS, SLOT_MS) + 500;
    let window = Duration::from_millis((SLOT_MS - 200) - open_ms);
    assert_eq!(window, Duration::from_millis(7_301));

    let (_, at_open) = gate_at(open_ms, Duration::from_secs(12));
    let started = Instant::now();
    let refused = at_open.admit(usize::MAX).await.expect_err("uncapped import");
    assert!(matches!(refused, ImportDeferralError::NoFreeWindow { .. }), "{refused}");
    assert_eq!(Instant::now(), started, "a saturated import is refused without waiting");

    let (_, fitting) = gate_at(8_000, Duration::from_secs(12));
    let capped_small = fitting.admit_capped(1).await.expect("one row fits");
    let capped_hold = capped_small.estimated_hold;
    assert!(capped_hold < capped_small.window, "the cap must not stretch a fitting estimate");
    drop(capped_small);
    let uncapped_small = fitting.admit(1).await.expect("uncapped one row");
    assert_eq!(capped_hold, uncapped_small.estimated_hold);
    drop(uncapped_small);

    let (_, outside) = gate_at(1_000, Duration::from_secs(12));
    let started = Instant::now();
    let capped = outside.admit_capped(usize::MAX);
    tokio::pin!(capped);
    assert!(poll_pending(capped.as_mut()).await, "a capped export waits for the window");
    tokio::time::advance(Duration::from_millis(open_ms - 1_000 - 1)).await;
    assert!(poll_pending(capped.as_mut()).await, "still waiting one millisecond before the window");
    tokio::time::advance(Duration::from_millis(1)).await;
    let admission = capped.await.expect("admitted at the window open");
    assert_eq!(started.elapsed(), Duration::from_millis(open_ms - 1_000));
    assert_eq!(admission.estimated_hold, window);
    assert_eq!(admission.window, window);
    tokio::time::advance(Duration::from_millis(1)).await;
    admission.ensure_still_fits().expect("a capped hold may start after the open");
    tokio::time::advance(window - Duration::from_millis(1)).await;
    admission.ensure_still_fits().expect("the widened start is the window close");
    tokio::time::advance(Duration::from_millis(1)).await;
    let late = admission.ensure_still_fits().expect_err("past the close");
    assert!(matches!(late, ImportDeferralError::NoFreeWindow { .. }), "{late}");
    drop(admission);

    let before = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
    before.set_current_time_ms(GENESIS * 1000 - 5);
    assert!(matches!(before.current_slot(), Err(TimingError::BeforeGenesis { .. })));
    let before_gate = Arc::new(ImportWindowGate::new(Arc::clone(&before) as Arc<dyn SlotClock>));
    let started = Instant::now();
    let pre = before_gate.admit_capped(usize::MAX);
    tokio::pin!(pre);
    assert!(
        poll_pending(pre.as_mut()).await,
        "the cap is applied before the saturated-estimate refusal"
    );
    let until_open = Duration::from_millis(5 + open_ms);
    tokio::time::advance(until_open - Duration::from_millis(1)).await;
    assert!(poll_pending(pre.as_mut()).await);
    tokio::time::advance(Duration::from_millis(1)).await;
    let pre = pre.await.expect("slot 0's window");
    assert_eq!(started.elapsed(), until_open);
    assert_eq!(pre.estimated_hold, window);
    assert_eq!(pre.window, window);
    tokio::time::advance(Duration::from_millis(1)).await;
    pre.ensure_still_fits().expect("capped pre-genesis admission stays valid 1 ms later");
    drop(pre);

    let still_uncapped = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
    still_uncapped.set_current_time(GENESIS - 30);
    let still_uncapped = ImportWindowGate::new(Arc::clone(&still_uncapped) as Arc<dyn SlotClock>);
    let started = Instant::now();
    let uncapped = tokio::select! {
        biased;
        result = still_uncapped.admit(usize::MAX) => result,
        _ = tokio::task::yield_now() => {
            panic!("the cap must not apply to import admission before genesis")
        }
    };
    assert_eq!(Instant::now(), started);
    let uncapped = uncapped.expect_err("saturated import before genesis");
    assert!(matches!(uncapped, ImportDeferralError::NoFreeWindow { .. }), "{uncapped}");
}

fn free_window_bounds_ms() -> (u64, u64) {
    let open_ms = due_ms(ATTESTATION_DUE_BPS, SLOT_MS) + 500;
    let close_ms = SLOT_MS - 200;
    assert_eq!(close_ms - open_ms, 7_301);
    (open_ms, close_ms)
}

fn gate_five_ms_before_genesis() -> Arc<ImportWindowGate> {
    let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
    clock.set_current_time_ms(GENESIS * 1000 - 5);
    assert!(matches!(clock.current_slot(), Err(TimingError::BeforeGenesis { .. })));
    Arc::new(ImportWindowGate::new(clock as Arc<dyn SlotClock>))
}

/// The widened start is this window's close, not the next slot's.
async fn assert_capped_start_widens_to_this_close(admission: &ImportAdmission, offset_ms: u64) {
    let (open_ms, close_ms) = free_window_bounds_ms();
    let window = Duration::from_millis(close_ms - open_ms);
    assert!(offset_ms > open_ms && offset_ms < close_ms);
    assert_eq!(admission.estimated_hold, window);
    assert_eq!(admission.window, window);
    admission.ensure_still_fits().expect("a capped hold fits at the admission instant");
    tokio::time::advance(Duration::from_millis(close_ms - offset_ms)).await;
    admission.ensure_still_fits().expect("the widened start is this window's close");
    tokio::time::advance(Duration::from_millis(1)).await;
    let late = admission.ensure_still_fits().expect_err("past this window's close");
    assert!(matches!(late, ImportDeferralError::NoFreeWindow { .. }), "{late}");
}

/// A capped export that is already 1 ms past the open is admitted at once.
///
/// `start + window <= close` holds only at the open. Waking 1 ms late must
/// still fit this window.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn capped_export_is_admitted_one_millisecond_after_the_open() {
    let (open_ms, _) = free_window_bounds_ms();
    let offset_ms = open_ms + 1;
    let (_, gate) = gate_at(offset_ms, Duration::from_secs(12));
    let started = Instant::now();
    let capped = gate.admit_capped(usize::MAX);
    tokio::pin!(capped);
    let admission = tokio::select! {
        biased;
        result = capped.as_mut() => result,
        _ = tokio::task::yield_now() => {
            panic!("admit_capped(usize::MAX) at open+1 ms must not wait for the next slot")
        }
    };
    let admission = admission.expect("admitted 1 ms after the open");
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_capped_start_widens_to_this_close(&admission, offset_ms).await;
}

/// A capped export that arrives inside the window is admitted in that window.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn capped_export_arriving_mid_window_is_admitted() {
    let (open_ms, close_ms) = free_window_bounds_ms();
    let offset_ms = 8_000;
    assert!(open_ms < offset_ms && offset_ms < close_ms);
    let (_, gate) = gate_at(offset_ms, Duration::from_secs(12));
    let started = Instant::now();
    let capped = gate.admit_capped(usize::MAX);
    tokio::pin!(capped);
    let admission = tokio::select! {
        biased;
        result = capped.as_mut() => result,
        _ = tokio::task::yield_now() => {
            panic!("a capped export arriving mid-window must not wait for the next slot")
        }
    };
    let admission = admission.expect("admitted mid-window");
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_capped_start_widens_to_this_close(&admission, offset_ms).await;
}

/// Before genesis, a capped export woken 1 ms after slot 0's open is admitted.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn capped_export_before_genesis_is_admitted_one_millisecond_after_the_open() {
    let (open_ms, _) = free_window_bounds_ms();
    let gate = gate_five_ms_before_genesis();
    let started = Instant::now();
    let pre = gate.admit_capped(usize::MAX);
    tokio::pin!(pre);
    assert!(
        poll_pending(pre.as_mut()).await,
        "the cap is applied before the saturated-estimate refusal"
    );
    let until = Duration::from_millis(5 + open_ms + 1);
    tokio::time::advance(until).await;
    let admission = tokio::select! {
        biased;
        result = pre.as_mut() => result,
        _ = tokio::task::yield_now() => panic!("still waiting 1 ms after slot 0's open"),
    };
    let admission = admission.expect("admitted 1 ms after slot 0's open");
    assert_eq!(started.elapsed(), until);
    assert_capped_start_widens_to_this_close(&admission, open_ms + 1).await;
}

/// Before genesis, a capped export that reaches mid-window is admitted there.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn capped_export_before_genesis_arriving_mid_window_is_admitted() {
    let (open_ms, close_ms) = free_window_bounds_ms();
    let offset_ms = 8_000;
    assert!(open_ms < offset_ms && offset_ms < close_ms);
    let gate = gate_five_ms_before_genesis();
    let started = Instant::now();
    let pre = gate.admit_capped(usize::MAX);
    tokio::pin!(pre);
    assert!(poll_pending(pre.as_mut()).await, "waiting for slot 0 while still before genesis");
    let until = Duration::from_millis(5 + offset_ms);
    tokio::time::advance(until).await;
    let admission = tokio::select! {
        biased;
        result = pre.as_mut() => result,
        _ = tokio::task::yield_now() => panic!("still waiting after the clock reached mid-window"),
    };
    let admission = admission.expect("admitted mid-window on the pre-genesis path");
    assert_eq!(started.elapsed(), until);
    assert_capped_start_widens_to_this_close(&admission, offset_ms).await;
}

/// A count error is not zero rows. The DELETE aborts and removes nothing.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn history_row_count_error_aborts_the_delete_and_removes_nothing() {
    let rig = DeleteRig::open(8_000, true);
    rig.adapter.fail_next_history_row_count();
    let err = rig.delete(vec![rig.hex_key.clone()]).await.expect_err("count");
    expect_export_internal(err);
    rig.assert_nothing_removed();
    assert!(!rig.gate.admission_in_progress(), "a count error never takes the gate");
}

/// A panic in the row-count `spawn_blocking` is a `JoinError`: HTTP 500, and
/// the key stays disabled with nothing removed.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_row_count_panic_aborts_the_delete_and_removes_nothing() {
    let rig = DeleteRig::open(8_000, true);
    let saw_free_gate = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&saw_free_gate);
    let gate = Arc::clone(&rig.gate);
    rig.adapter.set_during_row_count(Some(Arc::new(move || {
        flag.store(!gate.admission_in_progress(), Ordering::SeqCst);
        panic!("row-count stage");
    })));
    let err = rig.delete(vec![rig.hex_key.clone()]).await.expect_err("join");
    expect_export_internal(err);
    assert!(saw_free_gate.load(Ordering::SeqCst), "the row count runs before admission");
    rig.assert_nothing_removed();
    assert!(!rig.gate.admission_in_progress());
}

/// A panic in the export `spawn_blocking` is a `JoinError`: HTTP 500, nothing
/// removed, and the guard is dropped when the blocking task unwinds.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_export_panic_aborts_the_delete_and_removes_nothing() {
    let rig = DeleteRig::open(8_000, true);
    let saw_held_gate = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&saw_held_gate);
    let gate = Arc::clone(&rig.gate);
    rig.adapter.set_during_export(Some(Arc::new(move || {
        flag.store(gate.admission_in_progress(), Ordering::SeqCst);
        panic!("export stage");
    })));
    let err = rig.delete(vec![rig.hex_key.clone()]).await.expect_err("join");
    expect_export_internal(err);
    assert!(saw_held_gate.load(Ordering::SeqCst), "the export runs while the guard is held");
    assert!(!rig.gate.admission_in_progress(), "unwind drops the admission guard");
    rig.assert_nothing_removed();
}

/// The fit re-check runs after admission, on the blocking thread. Failing it
/// aborts the DELETE with a 503 and no `Retry-After`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn ensure_still_fits_failing_after_admission_aborts_and_removes_nothing() {
    let rig = DeleteRig::open(8_000, true);
    let (hook, entered_rx, release_tx) = parking_hook();
    rig.adapter.set_before_export_fit(Some(hook));
    let delete_fut = rig.delete(vec![rig.hex_key.clone()]);
    tokio::pin!(delete_fut);
    let _release = ReleaseOnDrop(Some(release_tx));
    tokio::select! {
        biased;
        entered = entered_rx => entered.expect("fit hook entered"),
        result = delete_fut.as_mut() => panic!("DELETE finished before the fit re-check: {result:?}"),
    }
    tokio::time::advance(Duration::from_secs(12)).await;
    drop(_release);
    let err = delete_fut.await.expect_err("late fit");
    let response = unavailable_response(err, None);
    assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("Retry-After").is_none());
    rig.assert_nothing_removed();
    assert!(!rig.gate.admission_in_progress());
}

/// An empty DELETE has no members, so it does not wait on a held gate.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_empty_delete_does_not_take_the_import_gate() {
    let rig = DeleteRig::open(8_000, true);
    let holder = rig.gate.admit(0).await.expect("hold");
    assert!(rig.store.is_signing_enabled(&rig.key));
    let started = Instant::now();
    let body = rig.delete(Vec::new()).await.expect("empty request");
    assert_eq!(Instant::now(), started, "an empty DELETE must not wait for the gate");
    assert!(body.data.is_empty());
    assert!(rig.gate.admission_in_progress(), "the test's guard is still the holder");
    assert_eq!(rig.keys.deletes(), 0);
    assert!(rig.keys.has_key(&rig.key));
    assert!(rig.store.is_signing_enabled(&rig.key), "no member was disabled");
    drop(holder);
    assert!(!rig.gate.admission_in_progress());
}

/// A request that mixes a member and an unknown key exports only the member.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_delete_of_a_member_and_an_unknown_key_exports_only_the_member() {
    let rig = DeleteRig::open(8_000, true);
    let stranger = test_pubkey(99);
    let stranger_hex = pubkey_hex(stranger);
    let gvr = export_floor::chain_gvr();
    rig.db.seed_attestation(&stranger_hex, 9, 10, Some("0xother".into()), &gvr).expect("stranger");

    let body =
        rig.delete(vec![rig.hex_key.clone(), stranger_hex.clone()]).await.expect("mixed request");
    assert_eq!(body.data.len(), 2);
    assert_eq!(body.data[0].status, DeleteStatus::Deleted);
    assert_eq!(body.data[1].status, DeleteStatus::NotFound);
    // The handler calls `delete_keystore` for the unknown key too. The stub
    // counts that NotFound call; the key was never a member.
    assert_eq!(rig.keys.deletes(), 2);
    assert!(!rig.keystore_file.exists(), "the member keystore was removed");
    assert!(!rig.keys.has_key(&rig.key));
    assert!(!rig.keys.has_key(&stranger));

    let json: serde_json::Value = serde_json::from_str(&body.slashing_protection).expect("json");
    assert_eq!(export_floor::recorded_pubkeys(&json), vec![rig.hex_key.as_str()]);
    assert!(!body.slashing_protection.contains(&stranger_hex));
    assert_eq!(rig.db.get_attestations(&stranger_hex).expect("stranger rows").len(), 1);
    assert_eq!(rig.db.get_attestations(&rig.hex_key).expect("member rows").len(), 1);
}
