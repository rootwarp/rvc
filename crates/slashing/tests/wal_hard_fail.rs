//! Integration tests for WAL hard-fail, synchronous=EXTRA, and macOS fullfsync (ISSUE-1.3).
//!
//! # Test strategy
//!
//! ## WAL-failure tests (tests 1 and 2)
//! `PRAGMA journal_mode=WAL` always succeeds on a regular local filesystem, so we
//! cannot simulate WAL failure by pre-poisoning a file. Instead we use SQLite's
//! in-memory mode: an in-memory connection returns "memory" (not "wal") when WAL is
//! requested, which triggers the hard-fail code path. We inject the connection via
//! `SlashingDb::open_with_conn_for_testing` (compiled under `cfg(test)` or the
//! `test-utils` feature; this binary sees it via the crate's dev-dependency).
//! It runs `configure_pragmas` and the schema migration but skips file-permission
//! checks.
//!
//! This matches the research/04 guidance: "Opens a database on a tmpfs with WAL
//! disabled (e.g. via a `:memory:` DB with `journal_mode=memory`) and asserts the
//! constructor returns `Err`."
//!
//! ## WAL-success pragma tests (tests 3 and 4)
//! For `synchronous=EXTRA` and macOS `fullfsync=ON`, the pragmas are connection-level
//! (they reset on every new connection). We open via `SlashingDb::open` on a real file
//! and query through `SlashingDb`'s own connection using `query_pragma_i64`.

use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::Connection;
use tempfile::tempdir;
use tracing_subscriber::layer::SubscriberExt;

use rvc_slashing::{SlashingDb, SlashingError};

// ---------------------------------------------------------------------------
// Env-var serialization
// ---------------------------------------------------------------------------

/// Global mutex to serialize tests that manipulate `RVC_ALLOW_NON_WAL_SLASHING_DB`.
///
/// Tests run in parallel by default. Both `test_non_wal_journal_mode_refused` and
/// `test_non_wal_journal_mode_allowed_with_env_var` touch the same env var; without
/// serialization they race and produce flaky results.
fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

// ---------------------------------------------------------------------------
// Helper: tracing ERROR event capture
// ---------------------------------------------------------------------------

/// Records the formatted message of every tracing event emitted at ERROR level.
struct ErrorEventCapture {
    messages: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ErrorEventCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() == tracing::Level::ERROR {
            struct MsgVisitor(String);
            impl tracing::field::Visit for MsgVisitor {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "message" {
                        self.0 = value.to_string();
                    }
                }
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{:?}", value);
                    }
                }
            }
            let mut visitor = MsgVisitor(String::new());
            event.record(&mut visitor);
            self.messages.lock().unwrap().push(visitor.0);
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: non-WAL mode (in-memory DB) is rejected by default
// ---------------------------------------------------------------------------

/// `SlashingDb::open_with_conn_for_testing` must return `SlashingError::JournalMode`
/// when the connection is in-memory (WAL returns "memory") and
/// `RVC_ALLOW_NON_WAL_SLASHING_DB` is not set.
#[test]
fn test_non_wal_journal_mode_refused() {
    // Serialise all env-var tests to avoid races.
    let _lock = env_var_lock();

    // An in-memory connection returns "memory" (not "wal") when WAL is requested.
    let conn = Connection::open_in_memory().expect("open in-memory");

    // Ensure the override env var is NOT set.
    std::env::remove_var("RVC_ALLOW_NON_WAL_SLASHING_DB");

    let result = SlashingDb::open_with_conn_for_testing(conn);
    match result {
        Err(SlashingError::JournalMode { actual, hint }) => {
            assert!(
                !actual.eq_ignore_ascii_case("wal"),
                "actual mode should not be 'wal', got: {actual}"
            );
            assert!(
                hint.contains("RVC_ALLOW_NON_WAL_SLASHING_DB"),
                "hint should mention the override env var, got: {hint}"
            );
        }
        Err(other) => panic!("expected SlashingError::JournalMode, got: {other:?}"),
        Ok(_) => panic!(
            "expected Err(JournalMode): in-memory connections return 'memory' for WAL requests, \
             not 'wal'"
        ),
    }
}

// ---------------------------------------------------------------------------
// Test 2: env var opt-out allows non-WAL (with an error log)
// ---------------------------------------------------------------------------

/// When `RVC_ALLOW_NON_WAL_SLASHING_DB=true`, `open_with_conn_for_testing` succeeds
/// even on an in-memory DB (which refuses WAL), and emits an ERROR-level tracing event
/// about degraded durability.
#[test]
fn test_non_wal_journal_mode_allowed_with_env_var() {
    // Serialise all env-var tests to avoid races.
    let _lock = env_var_lock();

    // Set the override env var before opening.
    std::env::set_var("RVC_ALLOW_NON_WAL_SLASHING_DB", "true");

    /// RAII guard that removes the env var even on panic.
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("RVC_ALLOW_NON_WAL_SLASHING_DB");
        }
    }
    let _env_guard = EnvGuard;

    // Install a tracing subscriber that captures ERROR-level event messages.
    let messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let layer = ErrorEventCapture { messages: messages.clone() };
    let subscriber = tracing_subscriber::registry().with(layer);
    let _tracing_guard = tracing::subscriber::set_default(subscriber);

    let conn = Connection::open_in_memory().expect("open in-memory");
    let result = SlashingDb::open_with_conn_for_testing(conn);

    assert!(result.is_ok(), "expected Ok(_) with env var set, got Err");

    let captured = messages.lock().unwrap();
    let has_durability_warning = captured.iter().any(|msg| {
        let lower = msg.to_lowercase();
        lower.contains("wal") || lower.contains("durability")
    });
    assert!(
        has_durability_warning,
        "expected an ERROR-level log about WAL / durability after opt-out, \
         captured messages: {captured:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: synchronous=EXTRA is set on every open
// ---------------------------------------------------------------------------

/// After `SlashingDb::open` on a real file, `PRAGMA synchronous` must be 3 (=EXTRA)
/// on the DB's own connection.
///
/// `synchronous` is a per-connection pragma; it cannot be read from a separate
/// connection. We query it via `query_pragma_i64`, a `#[cfg(test)]` helper on
/// `SlashingDb` that queries through the DB's internal connection.
#[test]
fn test_synchronous_extra_set_after_open() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("slashing_sync.db");

    let db = SlashingDb::open(&db_path).expect("open fresh DB");

    let synchronous = db.query_pragma_i64("synchronous").expect("PRAGMA synchronous");

    assert_eq!(
        synchronous, 3,
        "PRAGMA synchronous should be 3 (EXTRA) after SlashingDb::open, got {synchronous}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 (macOS only): fullfsync=ON is set
// ---------------------------------------------------------------------------

/// On macOS, `PRAGMA fullfsync` must be 1 (=ON) after `SlashingDb::open`.
///
/// `fullfsync` is also a per-connection pragma; queried via `query_pragma_i64`.
#[cfg(target_os = "macos")]
#[test]
fn test_fullfsync_set_on_macos() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("slashing_fullfsync.db");

    let db = SlashingDb::open(&db_path).expect("open fresh DB");

    let fullfsync = db.query_pragma_i64("fullfsync").expect("PRAGMA fullfsync");

    assert_eq!(fullfsync, 1, "PRAGMA fullfsync should be 1 (ON) on macOS, got {fullfsync}");
}
