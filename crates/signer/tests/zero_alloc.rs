//! Gate 4 — the precise zero-allocation invariant (P0-6).
//!
//! A dependency-free counting `#[global_allocator]` turns "a disabled
//! `debug!`/`trace!` performs no allocation / formatting / hashing" from a claim
//! into a tested invariant. Under a subscriber whose max level is `info`
//! (debug/trace OFF), the disabled `debug!`/`trace!` statements on the hot sign
//! path — together with their `%TruncatedRoot` / `%TruncatedPubkey` arguments —
//! must allocate **nothing**. This is the runtime half of the perf gate; the
//! `criterion` latency bench (issue 2.13) is the non-blocking companion.
//!
//! The R1 trap this catches: an eager `let h = hex::encode(root);` computed
//! *purely to feed a log line* allocates a `String` on every call regardless of
//! level. Tracing's macro arguments (`= %TruncatedRoot::new(&root)`) are lazy —
//! never evaluated while the level is disabled — so the asserted count stays 0;
//! re-introducing an eager pre-log `let` in the measured region flips it to
//! non-zero (verified by temporarily adding one during development).
//!
//! The statements below mirror the disabled-level logging on the sign hot path
//! in `crates/signer/src/lib.rs` (`sign_attestation` / `sign_block`),
//! `crates/signer/src/core.rs` (stage traces), and the
//! `compute_signing_root` trace in `crates/crypto/src/signing.rs` — the union of
//! those callsites' fields, so a future eager-alloc field added to any of them is
//! in the measured region.
//!
//! Determinism: this binary holds exactly ONE `#[test]`, and it installs only an
//! `info`-level subscriber — never a `trace`-level one. Tracing's max-level hint
//! and callsite-interest cache are PROCESS-global, and the `COUNTING`/`ALLOCS`
//! counters are statics; a second concurrent test (especially one raising the max
//! level to `trace`) would race both and make the gate flaky under `cargo test`'s
//! default threads. Keeping one test, info-only, makes the result identical under
//! `cargo test`, `cargo test -- --test-threads=N`, and `nextest`. Non-vacuity is
//! proven in-test: an ENABLED `info!` over the same consuming layer DOES allocate.
//! The counting allocator is global to *this test binary only*; a relaxed
//! `COUNTING` flag makes it a transparent `System` passthrough outside the
//! measured region.

// RF1-12: Counting GlobalAlloc for zero-alloc invariant requires unsafe impl GlobalAlloc.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use observability::logging::{TruncatedPubkey, TruncatedRoot};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

struct CountingAllocator;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);
/// Per-site counter for the 1-in-N sampled attestation-stage trace (issue 5.3). The
/// disabled `enabled!` guard must short-circuit before this is ever consulted, so it
/// stays untouched inside the measured (DISABLED) region — zero allocation either way.
static SAMPLE_CTR: AtomicU64 = AtomicU64::new(0);

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

/// A consuming layer that formats every event it receives into a heap `String`.
/// When the event's level passes the subscriber filter, this allocates — so an
/// ENABLED event is observably non-free; a DISABLED one never reaches here.
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

/// Count heap allocations performed on this thread while `f` runs.
fn allocs_during<F: FnOnce()>(f: F) -> usize {
    COUNTING.store(true, Ordering::SeqCst);
    let before = ALLOCS.load(Ordering::SeqCst);
    f();
    let count = ALLOCS.load(Ordering::SeqCst) - before;
    COUNTING.store(false, Ordering::SeqCst);
    count
}

#[test]
fn disabled_sign_hot_path_logging_is_zero_alloc() {
    // info-max subscriber over a real consuming layer: debug + trace are
    // disabled, so the macro never builds the event nor evaluates its
    // `%`-formatted arguments, and `FormatOnEvent` is never reached.
    let subscriber = tracing_subscriber::registry().with(LevelFilter::INFO).with(FormatOnEvent);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Inputs are built OUTSIDE the measured region (their own construction
    // allocates); only the log statements are measured.
    let pubkey_hex = "ab".repeat(48);
    let root = [0xcd_u8; 32];
    let fork_version = [0x01_u8, 0x00, 0x00, 0x00];
    let gvr = [0xee_u8; 32];
    // `?fork_name` on the domain line is a fieldless enum (`&'static str`, lazy)
    // in the real code; a `&str` Debug stands in with the same laziness.
    let fork_name = "deneb";

    // Mirrors the disabled debug!/trace! statements on the sign hot path: the
    // attestation entry, the domain + signing-root lines (with every field), the
    // attestation- and block-stage blocking-thread markers, the block entry, the
    // compute_signing_root trace, and the success milestone.
    let replay = || {
        tracing::debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            slot = 1000u64,
            source_epoch = 100u64,
            target_epoch = 101u64,
            signing_type = "attestation",
            "Signing attestation"
        );
        tracing::debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            fork_version_used = %TruncatedRoot::new(&fork_version),
            genesis_validators_root = %TruncatedRoot::new(&gvr),
            domain = %TruncatedRoot::new(&root),
            fork_name = ?fork_name,
            target_epoch = 101u64,
            "Computed attestation domain"
        );
        tracing::debug!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            signing_root = %TruncatedRoot::new(&root),
            slot = 1000u64,
            index = 5u64,
            source_epoch = 100u64,
            target_epoch = 101u64,
            "Computed attestation signing root"
        );
        // The attestation-stage trace is 1-in-N sampled (issue 5.3): under DISABLED
        // TRACE the `enabled!` guard short-circuits so the sampler is never consulted —
        // this mirrors the production guard shape and must still allocate nothing.
        if tracing::enabled!(tracing::Level::TRACE)
            && observability::logging::should_log_sampled(&SAMPLE_CTR, 16)
        {
            tracing::trace!("staging attestation slashing-protection record (sampled 1-in-16)");
        }
        tracing::trace!("staging block slashing-protection record on blocking thread");
        tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), slot = 3200u64, "Signing block");
        tracing::trace!(
            domain = %TruncatedRoot::new(&root),
            signing_root = %TruncatedRoot::new(&root),
            "Computed signing root"
        );
        tracing::debug!(duration_ms = 5u64, signing_type = "attestation", "Signing completed");
    };

    // Sanity: the counting allocator is live (it observes a real heap alloc).
    assert!(
        allocs_during(|| {
            let v = std::hint::black_box(vec![1u8, 2, 3]);
            drop(v);
        }) > 0,
        "counting allocator must observe heap allocations"
    );

    // Non-vacuity: an ENABLED `info!` over the SAME consuming layer DOES allocate,
    // proving the subscriber/layer are live — so the zero below is the laziness of
    // the disabled levels, not a dead or inert subscriber. Kept at `info` (never
    // `trace`) so no second dispatcher level ever exists in this binary.
    assert!(
        allocs_during(
            || tracing::info!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "non-vacuity probe")
        ) > 0,
        "an ENABLED info! over the consuming layer must allocate"
    );

    // Warm up: the first dispatch registers each callsite (a one-time, cached
    // allocation) — measuring the second call isolates the steady-state cost.
    let _ = allocs_during(replay);
    let n = allocs_during(replay);
    assert_eq!(n, 0, "disabled debug!/trace! on the sign hot path must not allocate (got {n})");
}
