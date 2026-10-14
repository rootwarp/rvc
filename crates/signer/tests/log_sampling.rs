//! Issue 5.3 — log-event sampling (enabled volume-bound + disabled zero-cost).
//!
//! Reproduces the EXACT guard shape used at the production call site in
//! `crates/signer/src/core.rs` (the per-validator-per-slot attestation-stage trace):
//!
//!   if tracing::enabled!(tracing::Level::TRACE)
//!       && observability::logging::should_log_sampled(&CTR, N) { tracing::trace!(...); }
//!
//! Formerly two binaries (`log_sampling_disabled.rs`, `log_sampling_volume.rs`) so a
//! TRACE subscriber could never poison the INFO-only half under process-shared
//! `cargo test`. Merged here under a process-global mutex: tracing's dispatcher and
//! callsite interest are process-wide, so the two scenarios must not run concurrently
//! in the same binary. `cargo nextest` isolates each test in its own process and is
//! unaffected by the mutex.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use observability::logging::should_log_sampled;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

/// Serialize the two scenarios — they share process-global tracing state.
static LOCK: Mutex<()> = Mutex::new(());

/// Counts every event that passes the subscriber's level filter.
struct CountEvents;

static EMITTED: AtomicUsize = AtomicUsize::new(0);

impl<S: tracing::Subscriber> Layer<S> for CountEvents {
    fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        EMITTED.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn disabled_site_never_consults_sampler() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // TRACE off: install info-level only for this critical section.
    let subscriber = tracing_subscriber::registry().with(LevelFilter::INFO).with(CountEvents);
    let _guard = tracing::subscriber::set_default(subscriber);

    let ctr = AtomicU64::new(0);

    EMITTED.store(0, Ordering::SeqCst);
    for _ in 0..10_000u64 {
        // Identical guard shape to the production call site.
        if tracing::enabled!(tracing::Level::TRACE) && should_log_sampled(&ctr, 16) {
            tracing::trace!("staging attestation slashing-protection record (sampled)");
        }
    }

    assert_eq!(
        ctr.load(Ordering::Relaxed),
        0,
        "a DISABLED trace site must NOT consult the sampler (counter must stay 0)"
    );
    assert_eq!(EMITTED.load(Ordering::SeqCst), 0, "no events emitted while TRACE is disabled");
}

#[test]
fn sampled_site_emits_one_in_n_when_enabled() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let subscriber = tracing_subscriber::registry().with(LevelFilter::TRACE).with(CountEvents);
    let _guard = tracing::subscriber::set_default(subscriber);

    let ctr = AtomicU64::new(0);
    let n = 16u64;
    let windows = 100u64;
    let calls = n * windows;

    EMITTED.store(0, Ordering::SeqCst);
    for _ in 0..calls {
        // Identical guard shape to the production call site.
        if tracing::enabled!(tracing::Level::TRACE) && should_log_sampled(&ctr, n) {
            tracing::trace!("staging attestation slashing-protection record (sampled)");
        }
    }

    let emitted = EMITTED.load(Ordering::SeqCst) as u64;
    assert_eq!(
        emitted, windows,
        "1-in-{n} over {windows} windows must emit exactly {windows} events"
    );
    assert!(emitted < calls, "sampling must reduce volume below the raw call count ({calls})");
    // Level was enabled, so every call consulted the sampler exactly once.
    assert_eq!(
        ctr.load(Ordering::Relaxed),
        calls,
        "every enabled call advances the per-site counter"
    );
}
