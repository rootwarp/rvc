//! Integration tests for M-9: set_attesting_enabled rate-limit + audit log.
//!
//! Verifies that:
//!   - A second call within 60 s returns HTTP 429 with a `Retry-After` header.
//!   - The handler emits a structured audit log entry on every successful call.
//!   - A call that arrives after the 60-s window elapses is accepted again.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::routing::post;
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::{set_attesting_enabled, AppState};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, DoppelgangerMonitor, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection,
    SlashingProtectionError, ValidatorConfigManager, ValidatorManager,
};

// ── Minimal mock implementations ──────────────────────────────────────────

struct NoopKeystoreManager;
#[async_trait]
impl KeystoreManager for NoopKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        vec![]
    }
    fn has_key(&self, _: &Pubkey) -> bool {
        false
    }
    async fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        Ok([0u8; 48])
    }
    fn delete_keystore(&self, _: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        Ok(false)
    }
}

struct NoopSlashingProtection;
#[async_trait]
impl SlashingProtection for NoopSlashingProtection {
    async fn import_interchange(&self, _: &str) -> Result<(), SlashingProtectionError> {
        Ok(())
    }
    fn export_interchange(&self, _: &[Pubkey]) -> Result<String, SlashingProtectionError> {
        Ok(String::new())
    }
}

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
    fn import_remote_key(&self, _: Pubkey, _: String) -> Result<(), ImportRemoteKeyError> {
        Ok(())
    }
    fn delete_remote_key(&self, _: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
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

// ── Helpers ────────────────────────────────────────────────────────────────

fn make_state() -> Arc<AppState> {
    Arc::new(AppState {
        keystore_manager: Arc::new(NoopKeystoreManager),
        slashing_protection: Arc::new(NoopSlashingProtection),
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
        last_set_attesting_enabled: Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
    })
}

fn make_router(state: Arc<AppState>) -> Router {
    Router::new().route("/rvc/v1/attesting", post(set_attesting_enabled)).with_state(state)
}

fn attesting_request(enabled: bool) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/rvc/v1/attesting")
        .header("content-type", "application/json")
        .header(
            "authorization",
            "Bearer abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        )
        .body(axum::body::Body::from(serde_json::json!({ "enabled": enabled }).to_string()))
        .unwrap()
}

// ── Log-capture helper ─────────────────────────────────────────────────────

/// Monotonically increasing span-ID allocator (shared across all instances).
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);

/// Global log buffer shared across all tests in this binary.
/// Populated once by `init_global_capture`; tests assert into it.
static GLOBAL_LOG_LINES: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

/// Installs a global `tracing` subscriber (exactly once per process) that
/// appends every event's fields to `GLOBAL_LOG_LINES`.
/// Returns a clone of the shared buffer for inspection.
fn init_global_capture() -> Arc<Mutex<Vec<String>>> {
    GLOBAL_LOG_LINES
        .get_or_init(|| {
            let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let sub = LineCapture(lines.clone());
            // Ignore the error — another crate may have already set a global
            // subscriber.  If so, we fall back to assertions on whatever WAS
            // captured (the other tests' audit events still satisfy the "at
            // least one audit entry exists" invariant).
            let _ = tracing::subscriber::set_global_default(sub);
            lines
        })
        .clone()
}

/// Minimal `tracing::Subscriber` that records every event into a shared
/// `Vec<String>`.  No filtering, no formatting overhead — just captures.
struct LineCapture(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for LineCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = NEXT_SPAN_ID.fetch_add(1, AtomicOrdering::Relaxed);
        tracing::span::Id::from_u64(id)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        let mut v = EventVisitor(&mut line);
        event.record(&mut v);
        self.0.lock().unwrap().push(line);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

struct EventVisitor<'a>(&'a mut String);

impl<'a> tracing::field::Visit for EventVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        write!(self.0, "{}={:?} ", field.name(), value).ok();
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write;
        write!(self.0, "{}={} ", field.name(), value).ok();
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        use std::fmt::Write;
        write!(self.0, "{}={} ", field.name(), value).ok();
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Second call within the 60-s window must return HTTP 429 with `Retry-After`.
#[tokio::test]
async fn test_rate_limit_429() {
    let state = make_state();
    let app = make_router(state);

    // First call — must succeed
    let resp1 = app.clone().oneshot(attesting_request(false)).await.unwrap();
    assert_eq!(resp1.status(), axum::http::StatusCode::OK, "first call should succeed");

    // Second call immediately after — must be rate-limited
    let resp2 = app.oneshot(attesting_request(true)).await.unwrap();
    assert_eq!(
        resp2.status(),
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "second call within window should be 429"
    );

    let retry_after = resp2
        .headers()
        .get("Retry-After")
        .expect("Retry-After header must be present on 429")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("Retry-After must be a number");
    assert!(retry_after > 0 && retry_after <= 60, "Retry-After={retry_after} should be 1..=60");

    let body_bytes = resp2.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["code"], 429, "body.code should be 429");
    assert_eq!(body["message"], "rate limited", "body.message should be 'rate limited'");
}

/// After the rate-limit window expires, a new call must be accepted (HTTP 200).
#[tokio::test]
async fn test_call_after_window_succeeds() {
    tokio::time::pause();

    let state = make_state();
    let app = make_router(state);

    // First call — succeeds and records the timestamp
    let resp1 = app.clone().oneshot(attesting_request(true)).await.unwrap();
    assert_eq!(resp1.status(), axum::http::StatusCode::OK, "first call should succeed");

    // Advance mock clock past the 60-s window
    tokio::time::advance(Duration::from_secs(61)).await;

    // Second call — window has elapsed, should succeed
    let resp2 = app.oneshot(attesting_request(false)).await.unwrap();
    assert_eq!(resp2.status(), axum::http::StatusCode::OK, "call after window should succeed");
}

/// A successful call must emit a structured audit log entry containing the
/// token prefix and the requested enabled-state.
///
/// Uses `init_global_capture()` to install a process-wide `tracing` subscriber
/// (via `set_global_default`) once, so events from all tasks/threads are
/// captured regardless of async executor boundaries.
#[tokio::test]
async fn test_audit_entry_emitted() {
    let lines = init_global_capture();

    let state = make_state();
    let app = make_router(state);

    // Snapshot the buffer length BEFORE making the call so we only assert on
    // events emitted by *this* test's call — sibling tests sharing the same
    // process-wide buffer (e.g. test_rate_limit_429's first successful call)
    // would otherwise satisfy the assertions even if the audit log was
    // accidentally removed from the handler. (Review M-9 SF-1.)
    let before_len = lines.lock().unwrap().len();

    let resp = app.oneshot(attesting_request(false)).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK, "call should succeed");

    let captured = lines.lock().unwrap();
    assert!(
        captured.len() > before_len,
        "no new tracing events captured after this test's call (expected the \
         audit log line). buffer len: before={before_len} after={}",
        captured.len()
    );
    let new_events = captured[before_len..].join("\n");

    assert!(
        new_events.contains("set_attesting_enabled audit"),
        "audit log entry not found in events emitted by this test. Captured (new only):\n{new_events}"
    );
    assert!(
        new_events.contains("abcdef12"),
        "token prefix (first 8 chars of bearer token) not found. Captured (new only):\n{new_events}"
    );
    assert!(
        new_events.contains("requested=false"),
        "expected `requested=false` field (this test calls with enabled=false). \
         Captured (new only):\n{new_events}"
    );
}
