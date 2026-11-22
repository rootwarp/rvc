//! Gate 4 — the precise zero-allocation invariant (P0-6), per-slot half.
//!
//! Companion to `crates/signer/tests/zero_alloc.rs` (the sign-path half). A
//! dependency-free counting `#[global_allocator]` proves that the disabled
//! `debug!`/`trace!` statements on the orchestrator's per-slot path — including
//! their `%`-formatted arguments — allocate **nothing** under a subscriber whose
//! max level is `info` (debug/trace OFF). A pre-log eager `let` (the R1 trap)
//! would allocate on every slot regardless of level and flip the asserted count
//! from 0 to non-zero.
//!
//! The integer `slot`/`wait_ms`/`jitter_secs` decision lines below mirror real
//! disabled per-slot `debug!` callsites in
//! `crates/rvc/src/orchestrator/coordinator.rs` (≈ lines 398 / 451 / 494 / 543).
//! The final `%TruncatedRoot` line is a SYNTHETIC laziness probe for a
//! `%`-formatted per-slot field — the per-slot path's real `%` fields today are
//! raw roots/pubkeys (e.g. `attestation.rs` `head = %…beacon_block_root`,
//! truncation pending Phase 4), but the disabled-path laziness invariant is
//! identical regardless of the wrapper. The per-slot `slot.process` /
//! `slot.phase.*` spans are `info`-level and intentionally outside this region —
//! their creation is the per-slot baseline, not logging overhead.
//!
//! Determinism: this binary holds exactly ONE `#[test]`, info-only (never a
//! `trace`-level subscriber). Tracing's max-level hint + callsite-interest cache
//! and the `COUNTING`/`ALLOCS` counters are process-global; a second concurrent
//! test would race them and flake under `cargo test`'s default threads. One
//! info-only test makes the result identical under `cargo test`,
//! `-- --test-threads=N`, and `nextest`; non-vacuity is proven in-test by an
//! ENABLED `info!` that DOES allocate over the same consuming layer. The counting
//! allocator is global to this test binary only.

// RF1-12: Counting GlobalAlloc for per-slot zero-alloc invariant requires unsafe impl.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use observability::logging::TruncatedRoot;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

struct CountingAllocator;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Formats every received event into a heap `String` — so an ENABLED event is
/// observably non-free, while a DISABLED one never reaches here.
struct FormatOnEvent;

impl<S: tracing::Subscriber> Layer<S> for FormatOnEvent {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        struct V(String);
        impl tracing::field::Visit for V {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={v:?} ", f.name()));
            }
        }
        let mut v = V(String::new());
        event.record(&mut v);
        std::hint::black_box(v.0);
    }
}

fn allocs_during<F: FnOnce()>(f: F) -> usize {
    COUNTING.store(true, Ordering::SeqCst);
    let before = ALLOCS.load(Ordering::SeqCst);
    f();
    let count = ALLOCS.load(Ordering::SeqCst) - before;
    COUNTING.store(false, Ordering::SeqCst);
    count
}

#[test]
fn disabled_per_slot_logging_is_zero_alloc() {
    let subscriber = tracing_subscriber::registry().with(LevelFilter::INFO).with(FormatOnEvent);
    let _guard = tracing::subscriber::set_default(subscriber);

    let head = [0xcd_u8; 32];

    // Real disabled per-slot coordinator decision lines, then a synthetic
    // `%`-formatted-field laziness probe (see module docs).
    let replay = || {
        tracing::debug!(slot = 1000u64, "No duties for slot");
        tracing::debug!(slot = 1000u64, wait_ms = 4000u128, "Waiting for attestation time");
        tracing::debug!(slot = 1000u64, wait_ms = 8000u128, "Waiting for 2/3 slot time");
        tracing::debug!(
            slot = 1000u64,
            epoch = 31u64,
            head = %TruncatedRoot::new(&head),
            "per-slot %-field laziness probe"
        );
    };

    // Sanity: the counting allocator is live.
    assert!(
        allocs_during(|| {
            let v = std::hint::black_box(vec![1u8, 2, 3]);
            drop(v);
        }) > 0,
        "counting allocator must observe heap allocations"
    );

    // Non-vacuity: an ENABLED `info!` over the SAME consuming layer DOES allocate,
    // proving the subscriber/layer are live (so the zero below is laziness, not a
    // dead/inert subscriber). Kept at `info` so no `trace` dispatcher exists here.
    assert!(
        allocs_during(|| tracing::info!(slot = 1000u64, "non-vacuity probe")) > 0,
        "an ENABLED info! over the consuming layer must allocate"
    );

    // Warm up (callsite registration), then measure steady state.
    let _ = allocs_during(replay);
    let n = allocs_during(replay);
    assert_eq!(n, 0, "disabled per-slot debug!/trace! must not allocate (got {n})");
}
