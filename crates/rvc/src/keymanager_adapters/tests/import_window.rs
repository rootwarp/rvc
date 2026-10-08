//! RR3-02: the interchange write path waits for a free slot window.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use axum::response::IntoResponse;
use http_body_util::BodyExt;
use keymanager_api::error::map_slashing_protection_error;
use keymanager_api::traits::{SlashingProtection, SlashingProtectionError};
use slashing::metrics::{RVC_SLASHING_IMPORT_CONN_HOLD_MS, RVC_SLASHING_IMPORT_DEFERRED_MS};
use timing::{due_ms, MockSlotClock, SlotClock, ATTESTATION_DUE_BPS};
use tokio::time::Instant;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

use super::super::import_window::ImportWindowGate;
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
/// `min_hold` is one row (12_311 ns). `post_admit` is the same-host spread
/// 31.116 ms, one group-commit batch 6.018 ms, and the 1 ms fill wait.
fn published_zero_row_hold_ms() -> u64 {
    let total_ns = 12_311u64 + 31_116_000 + 6_018_000 + 1_000_000;
    u64::try_from(Duration::from_nanos(total_ns).as_millis()).unwrap()
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

struct DeferralLog(Arc<Mutex<Vec<WaitVisitor>>>);

impl<S: tracing::Subscriber> Layer<S> for DeferralLog {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = WaitVisitor::default();
        event.record(&mut visitor);
        if visitor.message.as_deref() == Some("interchange import deferred") {
            self.0.lock().expect("deferral log").push(visitor);
        }
    }
}

/// An import issued at t≈1 s must not take `conn` until the free window opens,
/// and the deferral must be visible as `rvc_slashing_import_deferred_ms` plus
/// one `info!`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn interchange_import_waits_for_a_free_window_and_reports_the_wait() {
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
    let subscriber = tracing_subscriber::registry().with(DeferralLog(Arc::clone(&logs)));
    let _guard = tracing::subscriber::set_default(subscriber);

    let deferred_before = RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_count();
    let deferred_sum_before = RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_sum();
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

    assert_eq!(
        RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_count() - deferred_before,
        1,
        "one deferred-ms sample"
    );
    let sum_delta = RVC_SLASHING_IMPORT_DEFERRED_MS.get_sample_sum() - deferred_sum_before;
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

struct Hold {
    entered: AtomicUsize,
    release: AtomicBool,
    lock: Mutex<()>,
    cv: Condvar,
    second_hold_samples: Mutex<Option<u64>>,
}

/// Dropping the caller while `import` is inside the blocking section must not
/// drop the admission guard before the transaction records `conn_hold`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_client_mid_import_does_not_release_the_guard_before_the_transaction_ends() {
    let (_clock, gate) = gate_at(8_000, Duration::from_secs(12));
    let gvr = [0x33u8; 32];
    let db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let adapter = Arc::new(SlashingProtectionAdapter::new(db, gvr, gate));
    let hold = Arc::new(Hold {
        entered: AtomicUsize::new(0),
        release: AtomicBool::new(false),
        lock: Mutex::new(()),
        cv: Condvar::new(),
        second_hold_samples: Mutex::new(None),
    });
    let hook_hold = Arc::clone(&hold);
    adapter.set_during_import(Some(Arc::new(move || {
        let n = hook_hold.entered.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let mut guard = hook_hold.lock.lock().expect("hold");
            while !hook_hold.release.load(Ordering::SeqCst) {
                guard = hook_hold.cv.wait(guard).expect("hold");
            }
        } else {
            let samples = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_count();
            *hook_hold.second_hold_samples.lock().expect("samples") = Some(samples);
        }
    })));

    let before = RVC_SLASHING_IMPORT_CONN_HOLD_MS.get_sample_count();
    let json = interchange_json(gvr);
    let first = {
        let adapter = Arc::clone(&adapter);
        let json = json.clone();
        tokio::spawn(async move { adapter.import_interchange(&json).await })
    };
    let started = std::time::Instant::now();
    while hold.entered.load(Ordering::SeqCst) < 1 {
        assert!(started.elapsed() < Duration::from_secs(5), "first import did not reach the guard");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    first.abort();
    let _ = first.await;

    let second = {
        let adapter = Arc::clone(&adapter);
        tokio::spawn(async move { adapter.import_interchange(&json).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        hold.entered.load(Ordering::SeqCst),
        1,
        "aborting the caller must not let the next import take the guard"
    );

    hold.release.store(true, Ordering::SeqCst);
    hold.cv.notify_all();
    second.await.expect("second import task").expect("second import");
    assert_eq!(hold.entered.load(Ordering::SeqCst), 2);

    let second_samples = hold.second_hold_samples.lock().expect("samples").expect("second hook");
    assert!(
        second_samples > before,
        "the first transaction recorded conn_hold before the guard was released; before={before} at second entry={second_samples}"
    );
}
