//! Admission gate for slashing-protection interchange imports.
//!
//! The free window in a slot is
//! `[slot_start + due_ms(attestation) + att_reserve_margin, slot_start + slot_duration − block_reserve_margin)`.
//! [`ImportWindowGate::admit`] takes [`ImportWindowGate::one_at_a_time`] first, then sleeps until
//! the estimated hold fits entirely inside one such window.
//!
//! After the mutex is acquired the sleep is at most one slot. Concurrent imports that wait longer
//! than that do so only by serializing on `one_at_a_time`; that queue is the only way the bound
//! is exceeded. Dropping the caller before `admit` returns releases the mutex: the owned guard is
//! held by the future across the sleep, and `lock_owned` is cancellation-safe.

// RR3-02 (#531) is the first production caller.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use timing::{SlotClock, TimingError};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::orchestrator::slot_anchor::SlotAnchor;

/// AQ-6 attestation reserve after `due_ms(attestation)`. Not an operator knob.
const ATT_RESERVE_MARGIN: Duration = Duration::from_millis(500);

/// AQ-6 block reserve before the next slot's t=0. Not an operator knob.
const BLOCK_RESERVE_MARGIN: Duration = Duration::from_millis(200);

/// Connection hold per history row, from RR2-13 / RR2-14.
///
/// The measured value is **0.012311 ms** (12.311 µs), which is 12_311 ns.
/// `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md` records the
/// after-median 10 MB `conn_hold_ms` of **658.322** over **53,474** history
/// rows and publishes the quotient as 0.012311 ms. That product is
/// 658.318414 ms; the 0.003586 ms gap is the note's rounding of the quotient.
/// The const is the published per-row figure, not a second rounding of 658.322.
///
/// Host: hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor
/// (family 6, model 207, stepping 2), 4 cores, 1 thread per core, MemTotal
/// 16,398,384 kB, ext4 on `/dev/vdc`.
/// `uname -a`: `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct  6 05:59:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`.
/// Toolchain: `rustc 1.99.0 (b940084d7 2026-09-28)`; `cargo 1.99.0 (5f94df478 2026-08-27)`;
/// profile `cargo nextest run --release`; `clock_mode` wall.
const PER_ROW_HOLD: Duration = Duration::from_nanos(12_311);

/// Floor for [`estimated_hold`].
///
/// The measurement note does not isolate a fixed cost inside `conn.lock()`.
/// The after duration (665.893 ms) exceeds the hold (658.322 ms) because
/// numeric parsing runs before the lock, so that gap is not connection hold.
/// The floor is one history row, 0.012311 ms, the smallest hold quantum in
/// the note's RR3-01 input table. For every `rows >= 1`,
/// `max(min_hold, rows · per_row_hold)` is the linear term.
const MIN_HOLD: Duration = Duration::from_nanos(12_311);

/// Margins and the measured per-row hold.
///
/// Every field is a const (AQ-6). None of them is an operator knob, so
/// `OPERATOR_KNOB_NAMES` stays 75.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImportWindowConfig {
    /// Time kept clear after the attestation deadline.
    pub(crate) att_reserve_margin: Duration,
    /// Time kept clear before the next slot boundary.
    pub(crate) block_reserve_margin: Duration,
    /// Measured connection hold of one history row.
    pub(crate) per_row_hold: Duration,
    /// Floor applied to the row estimate.
    pub(crate) min_hold: Duration,
}

impl ImportWindowConfig {
    const fn measured() -> Self {
        Self {
            att_reserve_margin: ATT_RESERVE_MARGIN,
            block_reserve_margin: BLOCK_RESERVE_MARGIN,
            per_row_hold: PER_ROW_HOLD,
            min_hold: MIN_HOLD,
        }
    }
}

/// Milliseconds stored as nanoseconds so a fractional hold stays exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MilliSeconds {
    nanos: u128,
}

impl MilliSeconds {
    fn from_duration(duration: Duration) -> Self {
        Self { nanos: duration.as_nanos() }
    }

    fn as_nanos(self) -> u128 {
        self.nanos
    }
}

impl std::fmt::Display for MilliSeconds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format_ms(self.nanos))
    }
}

/// Why [`ImportWindowGate::admit`] did not hand back a guard.
#[derive(Debug, Error)]
pub(crate) enum ImportDeferralError {
    /// The estimate fits no free window that can be reached within one slot
    /// of acquiring the mutex. Split the interchange.
    #[error(
        "estimated hold {estimated_hold_ms} ms does not fit a free window of {window_ms} ms; split the payload"
    )]
    NoFreeWindow {
        /// `max(min_hold, rows · per_row_hold)`, in milliseconds.
        estimated_hold_ms: MilliSeconds,
        /// Length of one free window, in milliseconds.
        window_ms: MilliSeconds,
    },
    /// The slot clock could not name the current slot.
    #[error("slot clock is unavailable: {0}")]
    Clock(#[from] TimingError),
}

/// Serializes interchange imports into a free slot window.
///
/// `clock` places the window. `cfg` is the AQ-6 consts plus the measured
/// per-row hold. `one_at_a_time` is the load-bearing mutex: without it, two
/// imports can both pass the fit check and the second hold then starts when
/// the first finishes, crossing the next slot's t=0 block reserve.
pub(crate) struct ImportWindowGate {
    clock: Arc<dyn SlotClock>,
    cfg: ImportWindowConfig,
    one_at_a_time: Arc<Mutex<()>>,
}

impl ImportWindowGate {
    /// Gate over `clock`, using the measured consts.
    pub(crate) fn new(clock: Arc<dyn SlotClock>) -> Self {
        Self { clock, cfg: ImportWindowConfig::measured(), one_at_a_time: Arc::new(Mutex::new(())) }
    }

    /// Reserve the import mutex and wait until `rows` fits in one free window.
    ///
    /// The estimate is `max(min_hold, rows · per_row_hold)`. The mutex is
    /// acquired before the clock is read. The returned guard is owned so the
    /// caller can move it into `spawn_blocking`; it stays held until that
    /// owner drops it.
    ///
    /// The sleep after the mutex is acquired is at most one slot. A longer
    /// total wait happens only when other imports already hold
    /// `one_at_a_time`. Dropping this future before it returns drops the guard
    /// (or cancels the wait to acquire it).
    pub(crate) async fn admit(
        &self,
        rows: usize,
    ) -> Result<OwnedMutexGuard<()>, ImportDeferralError> {
        let guard = self.one_at_a_time.clone().lock_owned().await;
        let acquired_at = tokio::time::Instant::now();
        let bound = acquired_at.checked_add(self.clock.slot_duration()).unwrap_or(acquired_at);

        let slot = self.clock.current_slot()?;
        let anchor = SlotAnchor::capture(self.clock.as_ref(), slot);
        let bps = self.clock.deadlines().attestation;
        let estimate = estimated_hold(rows);
        let window = free_window_len(&anchor, bps, &self.cfg);

        if estimate > window {
            return Err(no_free_window(estimate, window));
        }

        loop {
            let now = tokio::time::Instant::now();
            match earliest_start(&anchor, bps, &self.cfg, estimate, now) {
                Some(start_at) if start_at > bound => {
                    return Err(no_free_window(estimate, window));
                }
                Some(start_at) if start_at > now => {
                    tokio::time::sleep_until(start_at).await;
                }
                Some(_) => return Ok(guard),
                None => return Err(no_free_window(estimate, window)),
            }
        }
    }
}

/// `max(min_hold, rows · per_row_hold)`.
fn estimated_hold(rows: usize) -> Duration {
    let rows = u128::try_from(rows).unwrap_or(u128::MAX);
    let linear = PER_ROW_HOLD.as_nanos().saturating_mul(rows);
    duration_from_nanos(linear.max(MIN_HOLD.as_nanos()))
}

fn no_free_window(estimate: Duration, window: Duration) -> ImportDeferralError {
    ImportDeferralError::NoFreeWindow {
        estimated_hold_ms: MilliSeconds::from_duration(estimate),
        window_ms: MilliSeconds::from_duration(window),
    }
}

fn free_window_len(anchor: &SlotAnchor, bps: u64, cfg: &ImportWindowConfig) -> Duration {
    match window_bounds(anchor, bps, cfg, 0) {
        Some((open, close)) => close.saturating_duration_since(open),
        None => Duration::ZERO,
    }
}

/// Free window of the captured slot, shifted by `slots_ahead` whole slots.
///
/// The open edge is [`SlotAnchor::deadline`] plus the attestation reserve.
/// The close edge is the slot end minus the block reserve.
fn window_bounds(
    anchor: &SlotAnchor,
    bps: u64,
    cfg: &ImportWindowConfig,
    slots_ahead: u64,
) -> Option<(tokio::time::Instant, tokio::time::Instant)> {
    let shift = Duration::from_millis(anchor.slot_duration_ms().checked_mul(slots_ahead)?);
    let open = anchor.deadline(bps).checked_add(cfg.att_reserve_margin)?.checked_add(shift)?;
    let close = anchor.slot_end().checked_sub(cfg.block_reserve_margin)?.checked_add(shift)?;
    if open >= close {
        return None;
    }
    Some((open, close))
}

/// Earliest tokio instant at or after `now` whose hold fits in this slot or the next.
fn earliest_start(
    anchor: &SlotAnchor,
    bps: u64,
    cfg: &ImportWindowConfig,
    estimate: Duration,
    now: tokio::time::Instant,
) -> Option<tokio::time::Instant> {
    for slots_ahead in 0..2u64 {
        let (open, close) = window_bounds(anchor, bps, cfg, slots_ahead)?;
        let start_at = now.max(open);
        if start_at >= close {
            continue;
        }
        let end = start_at.checked_add(estimate)?;
        if end <= close {
            return Some(start_at);
        }
    }
    None
}

fn duration_from_nanos(ns: u128) -> Duration {
    u64::try_from(ns).map(Duration::from_nanos).unwrap_or(Duration::MAX)
}

fn format_ms(ns: u128) -> String {
    let ms = ns / 1_000_000;
    let mut frac = ns % 1_000_000;
    if frac == 0 {
        return format!("{ms}");
    }
    let mut width = 6usize;
    while frac.is_multiple_of(10) {
        frac /= 10;
        width -= 1;
    }
    format!("{ms}.{frac:0width$}")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use timing::{due_ms, MockSlotClock, SlotClock, ATTESTATION_DUE_BPS};
    use tokio::sync::OwnedMutexGuard;
    use tokio::time::Instant;

    use super::{
        estimated_hold, ImportDeferralError, ImportWindowGate, ATT_RESERVE_MARGIN,
        BLOCK_RESERVE_MARGIN, MIN_HOLD, PER_ROW_HOLD,
    };

    const GENESIS: u64 = 1_606_824_023;
    const SLOT_MS: u64 = 12_000;
    /// History rows in the measured 10 MB interchange
    /// (`plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md`).
    const HISTORY_ROWS_10MB: usize = 53_474;

    fn window_offsets_ms() -> (u64, u64) {
        let open = due_ms(ATTESTATION_DUE_BPS, SLOT_MS)
            + u64::try_from(ATT_RESERVE_MARGIN.as_millis()).unwrap();
        let close = SLOT_MS - u64::try_from(BLOCK_RESERVE_MARGIN.as_millis()).unwrap();
        (open, close)
    }

    fn hold_ns(rows: usize) -> u128 {
        PER_ROW_HOLD
            .as_nanos()
            .saturating_mul(u128::try_from(rows).unwrap())
            .max(MIN_HOLD.as_nanos())
    }

    fn max_rows_fitting(budget: Duration) -> usize {
        let per = PER_ROW_HOLD.as_nanos();
        let budget_ns = budget.as_nanos();
        assert!(MIN_HOLD.as_nanos() <= budget_ns, "budget is below min_hold");
        usize::try_from(budget_ns / per).unwrap()
    }

    /// Whole milliseconds that cover `duration` on a millisecond slot clock.
    fn ceil_ms(duration: Duration) -> Duration {
        let whole = Duration::from_millis(u64::try_from(duration.as_millis()).unwrap());
        if whole == duration {
            whole
        } else {
            whole + Duration::from_millis(1)
        }
    }

    fn ms_text(ns: u128) -> String {
        let ms = ns / 1_000_000;
        let mut frac = ns % 1_000_000;
        if frac == 0 {
            return format!("{ms}");
        }
        let mut width = 6usize;
        while frac.is_multiple_of(10) {
            frac /= 10;
            width -= 1;
        }
        format!("{ms}.{frac:0width$}")
    }

    struct ClockFix {
        clock: Arc<MockSlotClock>,
        gate: Arc<ImportWindowGate>,
        origin: Instant,
        origin_unix_ms: u64,
    }

    fn clock_at(offset_ms: u64) -> ClockFix {
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_slot_with_offset_ms(0, offset_ms);
        let origin_unix_ms = clock.current_time_ms();
        let origin = Instant::now();
        let gate = Arc::new(ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>));
        ClockFix { clock, gate, origin, origin_unix_ms }
    }

    /// `true` when `fut` is still pending after one poll.
    ///
    /// The yield arm keeps the paused clock from auto-advancing to the timer.
    async fn poll_pending<F: std::future::Future>(mut fut: std::pin::Pin<&mut F>) -> bool {
        tokio::select! {
            biased;
            _ = fut.as_mut() => false,
            _ = tokio::task::yield_now() => true,
        }
    }

    fn align(fix: &ClockFix) {
        let elapsed_ms =
            u64::try_from(Instant::now().saturating_duration_since(fix.origin).as_millis())
                .unwrap();
        fix.clock.set_current_time_ms(fix.origin_unix_ms + elapsed_ms);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn import_admitted_at_8s_defers_past_the_next_t0_reserve_when_it_would_cross() {
        let (open, close) = window_offsets_ms();
        assert_eq!(open, 4_499, "attestation due 3999 ms plus the 500 ms reserve");
        assert_eq!(close, 11_800, "slot end minus the 200 ms block reserve");
        let offset_ms = 8_000;
        let remaining = Duration::from_millis(close - offset_ms);
        let fits = max_rows_fitting(remaining);
        let crosses = fits + 1;
        let window = Duration::from_millis(close - open);
        assert!(Duration::from_nanos(u64::try_from(hold_ns(fits)).unwrap()) <= remaining);
        assert!(Duration::from_nanos(u64::try_from(hold_ns(crosses)).unwrap()) > remaining);
        assert!(Duration::from_nanos(u64::try_from(hold_ns(crosses)).unwrap()) <= window);

        let fix = clock_at(offset_ms);
        let started = Instant::now();
        let guard: OwnedMutexGuard<()> = fix.gate.admit(fits).await.unwrap();
        assert_eq!(
            Instant::now(),
            started,
            "an estimate that fits the remainder proceeds immediately"
        );
        drop(guard);

        let gate = Arc::clone(&fix.gate);
        let deferred = gate.admit(crosses);
        tokio::pin!(deferred);
        assert!(
            poll_pending(deferred.as_mut()).await,
            "an estimate that would cross the block reserve must not be admitted at t=8s"
        );

        // Next slot's t=0 is 4_000 ms away. The 200 ms block reserve sits just
        // before it; admission has to land after both.
        let until_next_t0 = Duration::from_millis(SLOT_MS - offset_ms);
        tokio::time::advance(until_next_t0).await;
        assert!(poll_pending(deferred.as_mut()).await, "still inside the next t=0 block reserve");

        let until_window = Duration::from_millis(open);
        tokio::time::advance(until_window - Duration::from_millis(1)).await;
        assert!(
            poll_pending(deferred.as_mut()).await,
            "one millisecond before the next free window"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let guard = deferred.await.expect("admitted when the next free window opens");
        drop(guard);

        let waited = Instant::now().saturating_duration_since(started);
        assert_eq!(waited, until_next_t0 + until_window);
        assert!(waited <= Duration::from_millis(SLOT_MS));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn two_concurrent_10mb_imports_serialize() {
        let (open, close) = window_offsets_ms();
        let estimate = Duration::from_nanos(u64::try_from(hold_ns(HISTORY_ROWS_10MB)).unwrap());
        assert_eq!(estimate.as_nanos(), 658_318_414, "53,474 rows × 0.012311 ms");
        assert_eq!(estimated_hold(HISTORY_ROWS_10MB).as_nanos(), estimate.as_nanos());
        assert!(
            estimate <= Duration::from_millis(close - open),
            "the measured 10 MB hold fits one window"
        );

        // t≈4.5 s is the free-window open from the RR3-01 note: both 10 MB
        // estimates fit the remaining window, so only the mutex stops the
        // second from starting inside the first's hold.
        let fix = clock_at(open);
        let first_at = Arc::new(std::sync::Mutex::new(None));
        let stamp = Arc::clone(&first_at);
        let gate = Arc::clone(&fix.gate);
        let first = tokio::spawn(async move {
            let guard = gate.admit(HISTORY_ROWS_10MB).await.unwrap();
            *stamp.lock().unwrap() = Some(Instant::now());
            guard
        });
        tokio::task::yield_now().await;
        assert!(first.is_finished(), "the first 10 MB import fits at the window open");
        let guard = first.await.unwrap();
        let first_started = first_at.lock().unwrap().unwrap();

        let second_at = Arc::new(std::sync::Mutex::new(None));
        let stamp = Arc::clone(&second_at);
        let gate = Arc::clone(&fix.gate);
        let second = tokio::spawn(async move {
            let guard = gate.admit(HISTORY_ROWS_10MB).await.unwrap();
            *stamp.lock().unwrap() = Some(Instant::now());
            guard
        });
        tokio::task::yield_now().await;
        assert!(!second.is_finished(), "the second waits on one_at_a_time");
        assert!(second_at.lock().unwrap().is_none());

        let hold = ceil_ms(estimate);
        tokio::time::advance(hold).await;
        assert!(!second.is_finished(), "the second does not start inside the first's window");
        assert!(second_at.lock().unwrap().is_none());

        align(&fix);
        drop(guard);
        tokio::task::yield_now().await;
        assert!(
            second.is_finished(),
            "after the first releases, the second 10 MB hold still fits this window"
        );
        let second_started = second_at.lock().unwrap().unwrap();
        assert!(
            second_started >= first_started + hold,
            "second start {second_started:?} is inside the first hold that ends at {:?}",
            first_started + hold
        );
        drop(second.await.unwrap());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn unfittable_payload_returns_no_free_window() {
        let (open, close) = window_offsets_ms();
        let window = Duration::from_millis(close - open);
        assert_eq!(window, Duration::from_millis(7_301));
        let rows = max_rows_fitting(window) + 1;
        let estimate_ns = hold_ns(rows);
        assert!(estimate_ns > window.as_nanos());

        let fix = clock_at(open);
        let started = Instant::now();
        let gate = Arc::clone(&fix.gate);
        let pending = tokio::spawn(async move { gate.admit(rows).await });
        tokio::task::yield_now().await;
        assert!(pending.is_finished(), "an unfittable payload must not wait indefinitely");
        assert_eq!(Instant::now(), started, "rejection does not sleep");
        let err = pending.await.unwrap().unwrap_err();
        let text = err.to_string();
        match &err {
            ImportDeferralError::NoFreeWindow { estimated_hold_ms, window_ms } => {
                assert_eq!(estimated_hold_ms.as_nanos(), estimate_ns);
                assert_eq!(window_ms.as_nanos(), window.as_nanos());
            }
            other => panic!("expected NoFreeWindow, got {other}"),
        }
        assert_eq!(
            text,
            format!(
                "estimated hold {} ms does not fit a free window of {} ms; split the payload",
                ms_text(estimate_ns),
                ms_text(window.as_nanos())
            )
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn deferral_is_bounded_by_one_slot_after_the_mutex_is_acquired() {
        let (open, close) = window_offsets_ms();
        let offset_ms = 8_000;
        let crosses = max_rows_fitting(Duration::from_millis(close - offset_ms)) + 1;
        let until_next_open = Duration::from_millis((SLOT_MS - offset_ms) + open);
        assert!(until_next_open <= Duration::from_millis(SLOT_MS));
        assert!(until_next_open > Duration::from_millis(SLOT_MS - offset_ms));

        // Mutex is free, so the call start is the acquire. The deferral resolves
        // inside one slot and not before the next free window.
        let fix = clock_at(offset_ms);
        let acquired = Instant::now();
        let gate = Arc::clone(&fix.gate);
        let deferred = gate.admit(crosses);
        tokio::pin!(deferred);
        assert!(poll_pending(deferred.as_mut()).await);
        tokio::time::advance(until_next_open - Duration::from_millis(1)).await;
        assert!(
            poll_pending(deferred.as_mut()).await,
            "still deferred one millisecond before the window"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        deferred.await.unwrap();
        let waited = Instant::now().saturating_duration_since(acquired);
        assert_eq!(waited, until_next_open);
        assert!(waited <= Duration::from_millis(SLOT_MS));

        // Queuing on `one_at_a_time` may run longer than one slot. The sleep
        // after the mutex is acquired may not.
        let fix = clock_at(offset_ms);
        let holder_gate = Arc::clone(&fix.gate);
        let holder = tokio::spawn(async move { holder_gate.admit(1).await.unwrap() });
        tokio::task::yield_now().await;
        assert!(holder.is_finished(), "one row fits at t=8s and takes the mutex");
        let guard = holder.await.unwrap();

        let waiter_gate = Arc::clone(&fix.gate);
        let queued_at = Instant::now();
        let waiter = waiter_gate.admit(crosses);
        tokio::pin!(waiter);
        assert!(poll_pending(waiter.as_mut()).await);

        let queued = Duration::from_millis(13_000);
        tokio::time::advance(queued).await;
        assert!(
            poll_pending(waiter.as_mut()).await,
            "still queued; the one-slot bound has not started"
        );
        assert!(
            Instant::now().saturating_duration_since(queued_at) > Duration::from_millis(SLOT_MS)
        );

        align(&fix);
        let acquired_at = Instant::now();
        drop(guard);
        assert!(
            poll_pending(waiter.as_mut()).await,
            "after acquire the payload still does not fit this window"
        );

        let into_slot = (offset_ms + 13_000) % SLOT_MS;
        let post_acquire = Duration::from_millis((SLOT_MS + open) - into_slot);
        assert!(post_acquire <= Duration::from_millis(SLOT_MS));
        assert!(
            Duration::from_nanos(u64::try_from(hold_ns(crosses)).unwrap())
                > Duration::from_millis(close - into_slot)
        );

        tokio::time::advance(post_acquire - Duration::from_millis(1)).await;
        assert!(poll_pending(waiter.as_mut()).await);
        tokio::time::advance(Duration::from_millis(1)).await;
        waiter.await.expect("post-acquire deferral resolved inside one slot");
        let after_acquire = Instant::now().saturating_duration_since(acquired_at);
        assert_eq!(after_acquire, post_acquire);
        assert!(after_acquire <= Duration::from_millis(SLOT_MS));
        let total = Instant::now().saturating_duration_since(queued_at);
        assert!(
            total > Duration::from_millis(SLOT_MS),
            "the queue is what pushes the total past one slot"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn dropping_the_caller_before_admit_returns_releases_the_mutex() {
        let (_open, close) = window_offsets_ms();
        let offset_ms = 8_000;
        let fits = max_rows_fitting(Duration::from_millis(close - offset_ms));
        let crosses = fits + 1;
        let fix = clock_at(offset_ms);

        // Cancelled after the mutex is acquired, while `admit` is sleeping.
        let gate = Arc::clone(&fix.gate);
        let sleeper = tokio::spawn(async move { gate.admit(crosses).await });
        tokio::task::yield_now().await;
        assert!(!sleeper.is_finished(), "sleeper holds the mutex inside the deferral");
        sleeper.abort();
        assert!(sleeper.await.is_err(), "abort drops the caller");

        let gate = Arc::clone(&fix.gate);
        let next = tokio::spawn(async move { gate.admit(fits).await });
        tokio::task::yield_now().await;
        assert!(next.is_finished(), "dropping the sleeper released the mutex");
        let guard = next.await.unwrap().unwrap();

        // Cancelled while queued, before `admit` acquires.
        let gate = Arc::clone(&fix.gate);
        let queued = tokio::spawn(async move { gate.admit(fits).await });
        tokio::task::yield_now().await;
        assert!(!queued.is_finished(), "queued behind the held guard");
        queued.abort();
        assert!(queued.await.is_err(), "abort drops the queued caller");
        drop(guard);

        let gate = Arc::clone(&fix.gate);
        let after = tokio::spawn(async move { gate.admit(fits).await });
        tokio::task::yield_now().await;
        assert!(after.is_finished(), "dropping the queued caller left the mutex usable");
        drop(after.await.unwrap().unwrap());
    }
}
