//! ARCH-1a / ARCH-1b / ADR-006: a DB-reading tracing subscriber must not wedge
//! stage→sign→commit, and `"staged"` audit events must fire after the guard is free.
//!
//! Against the pre-ARCH-1a tree, `PubkeyScopedDb::stage_*` called `audit_log` while
//! the staged guard still held the `parking_lot` connection mutex. A subscriber that
//! re-enters the DB on every event deadlocked permanently (C2).
//!
//! Timeout is **thread-based** (`std::thread` + `mpsc::recv_timeout`), never
//! `tokio::time::timeout`: a blocking `parking_lot` lock is not an await point, so
//! an async timeout cannot cancel it and would hang the nextest run instead of failing.
//!
//! Behavioural emit assertions run **same-thread** against the `(Staged, PendingAudit)`
//! [`rvc_signer::StagedRow`] bridge the four production call sites rely on. The full
//! gate path uses `spawn_blocking`, whose threads do not inherit a thread-local
//! `set_default` subscriber — so lock-free / count assertions must not depend on
//! capturing events from that pool.

#![allow(deprecated)]

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crypto::SecretKey;
use eth_types::Root;
use rvc_signer::StagedRow;
use slashing::{PubkeyScopedDb, SlashingDb};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

const GVR: Root = [0xaa; 32];
const TIMEOUT: Duration = Duration::from_secs(5);
const AUDIT_CN: &str = "audit-deadlock-test";

/// Subscriber that acquires the slashing DB lock on every tracing event.
///
/// Reproduces the operator-installable landmine: an ordinary audit/observability
/// layer that reads the slashing DB from `on_event`.
struct DbReadingLayer {
    db: Arc<SlashingDb>,
}

impl<S: tracing::Subscriber> Layer<S> for DbReadingLayer {
    fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // Public API that locks `conn` — deadlocks if the staged guard is held.
        let _ = self.db.get_blocks("0xdead");
    }
}

/// Drive a full stage → sign → commit under a DB-reading subscriber.
///
/// Completes within `TIMEOUT` only when `"staged"` audit emission happens
/// **after** the staged guard is released (ARCH-1b / post-fix). Against HEAD
/// pre-ARCH-1a this times out (RED). With emit-after-commit compile bridges it
/// may already pass — that is correct if emit is outside the guard.
///
/// The hazardous subscriber is installed **on the worker thread** that holds
/// the staged guard and emits, so re-entry is real (not a no-op on a thread
/// without a dispatcher).
#[test]
fn db_reading_subscriber_completes_a_full_stage_sign_commit() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let sk = SecretKey::generate();
    let pubkey_hex = hex::encode(sk.public_key().to_bytes());
    let signing_root: Root = [0x11; 32];
    let slot = 42u64;

    let (tx, rx) = mpsc::channel();
    let db_worker = Arc::clone(&db);
    let pubkey_hex_worker = pubkey_hex.clone();

    thread::spawn(move || {
        // Install the DB-reading layer on *this* thread — same thread as stage/commit/emit.
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::INFO)
            .with(DbReadingLayer { db: Arc::clone(&db_worker) });
        let _guard = tracing::subscriber::set_default(subscriber);

        let scoped = PubkeyScopedDb::new(db_worker, AUDIT_CN.to_string(), GVR);
        let result = (|| {
            let (staged, audit) =
                scoped.stage_block(&pubkey_hex_worker, slot, Some(hex::encode(signing_root)))?;
            // Sign while the guard is still held (production ordering).
            let _sig = sk.sign(signing_root.as_slice());
            staged.commit()?;
            // Emit only after commit released the mutex — subscriber re-enters DB here.
            audit.emit();
            Ok::<(), slashing::SlashingError>(())
        })();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(TIMEOUT) {
        Ok(Ok(())) => {
            // Completed without deadlock — success path under the hazardous subscriber.
            let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
            assert_eq!(blocks.len(), 1, "commit must leave one row");
        }
        Ok(Err(e)) => {
            panic!("stage→sign→commit failed (not a deadlock): {e:?}");
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "db_reading_subscriber_completes_a_full_stage_sign_commit timed out after {TIMEOUT:?}: \
                 audit emission likely still holds the slashing DB mutex (ADR-006 / C2)"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("worker thread disconnected without sending a result");
        }
    }
}

// ── ARCH-1b behavioural coverage ─────────────────────────────────────────────

/// Counts `slashing.audit` events whose `outcome` field is `"staged"`.
struct StagedAuditCounter {
    count: Arc<AtomicUsize>,
}

struct OutcomeVisitor {
    outcome: Option<String>,
}

impl Visit for OutcomeVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.outcome = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "outcome" && self.outcome.is_none() {
            self.outcome = Some(format!("{value:?}").trim_matches('"').to_string());
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for StagedAuditCounter {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "slashing.audit" {
            return;
        }
        let mut visitor = OutcomeVisitor { outcome: None };
        event.record(&mut visitor);
        if visitor.outcome.as_deref() == Some("staged") {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Discard path must still emit exactly one `"staged"` audit event (ARCH-1b).
///
/// Mirrors production: `stage_then_sign` → `discard_row` on the
/// `(Staged, PendingAudit)` StagedRow bridge (both gate Discard and VC unambiguous
/// no-signature paths).
#[test]
fn discarded_sign_still_emits_a_staged_audit_event() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let sk = SecretKey::generate();
    let pubkey_hex = hex::encode(sk.public_key().to_bytes());

    let count = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(StagedAuditCounter { count: Arc::clone(&count) });
    let _guard = tracing::subscriber::set_default(subscriber);

    let scoped = PubkeyScopedDb::new(Arc::clone(&db), AUDIT_CN.to_string(), GVR);
    let staged_pair = scoped
        .stage_block(&pubkey_hex, 7, Some(hex::encode([0x22; 32])))
        .expect("stage must succeed");
    // Production discard branch: bridge emits after discard releases the guard.
    staged_pair.discard_row();

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "discarded sign must still emit exactly one staged audit event"
    );
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(blocks.is_empty(), "discard must leave no row; found {blocks:?}");
}

/// At `"staged"` emission time the connection mutex must be free (ARCH-1b).
///
/// This is the behavioural proof G-7 cannot make: emit runs only after
/// commit/discard released the staged guard.
struct FreeAtEmitLayer {
    db: Arc<SlashingDb>,
    free_at_staged: Arc<AtomicBool>,
    saw_staged: Arc<AtomicBool>,
}

impl<S: tracing::Subscriber> Layer<S> for FreeAtEmitLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "slashing.audit" {
            return;
        }
        let mut visitor = OutcomeVisitor { outcome: None };
        event.record(&mut visitor);
        if visitor.outcome.as_deref() != Some("staged") {
            return;
        }
        self.saw_staged.store(true, Ordering::SeqCst);
        // try_lock free at emit — the staged MutexGuard must already be gone.
        self.free_at_staged.store(self.db.try_lock_free(), Ordering::SeqCst);
    }
}

#[test]
fn audit_event_fires_after_the_guard_is_released() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let sk = SecretKey::generate();
    let pubkey_hex = hex::encode(sk.public_key().to_bytes());

    let free_at_staged = Arc::new(AtomicBool::new(false));
    let saw_staged = Arc::new(AtomicBool::new(false));
    let subscriber = tracing_subscriber::registry().with(LevelFilter::INFO).with(FreeAtEmitLayer {
        db: Arc::clone(&db),
        free_at_staged: Arc::clone(&free_at_staged),
        saw_staged: Arc::clone(&saw_staged),
    });
    let _guard = tracing::subscriber::set_default(subscriber);

    let scoped = PubkeyScopedDb::new(Arc::clone(&db), AUDIT_CN.to_string(), GVR);
    let staged_pair = scoped
        .stage_block(&pubkey_hex, 99, Some(hex::encode([0x33; 32])))
        .expect("stage must succeed");
    // Production success branch: bridge emits after commit releases the guard.
    staged_pair.commit_row().expect("commit");

    assert!(saw_staged.load(Ordering::SeqCst), "expected a staged audit event");
    assert!(
        free_at_staged.load(Ordering::SeqCst),
        "connection mutex must be free at staged audit emission (try_lock free)"
    );
}
