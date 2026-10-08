//! Admission gate for slashing-protection interchange imports.
//!
//! The free window in a slot is
//! `[slot_start + due_ms(attestation) + att_reserve_margin, slot_start + slot_duration − block_reserve_margin)`.
//! The attestation basis points are `max(pre-Gloas, Gloas)` so a later Gloas
//! deadline cannot open the window early. [`ImportWindowGate::admit`] takes
//! [`ImportWindowGate::one_at_a_time`] first, then sleeps until the estimated
//! hold fits entirely inside one such window.
//!
//! After the mutex is acquired the sleep is at most one slot. The wait to
//! acquire the mutex is capped at [`QUEUE_WAIT_SLOTS`] slot durations; past
//! that, admission returns [`ImportDeferralError::QueueSaturated`] instead of
//! holding a parsed payload. Dropping the caller before `admit` returns
//! releases the mutex: the owned guard is held by the future across the sleep,
//! and `lock_owned` is cancellation-safe.
//!
//! # Before genesis
//!
//! [`TimingError::BeforeGenesis`] admits immediately. No slot is open, so there
//! is no attestation or block deadline to protect. That is the safest moment
//! to install history. Every other clock error still refuses admission.
//!
//! # Time after admission
//!
//! [`estimated_hold`] is the measured per-row connection hold plus
//! [`ImportWindowConfig::post_admit`]. The addition is not a new measurement:
//!
//! * **Fixed BEGIN/COMMIT/fsync/WAL cost** of this import is already inside
//!   `per_row_hold`. `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md`
//!   records `conn.lock()` through `COMMIT` and does not isolate an intercept,
//!   so none is added a second time.
//! * **Parse and prepare before `conn.lock()`** is the published after-run gap
//!   between `duration_ms` and `conn_hold_ms`. The median pair is 665.893 −
//!   658.322 = 7.571 ms over 53,474 history rows. [`PER_ROW_PRE_LOCK`] is that
//!   gap, per row, rounded up to a whole nanosecond so the linear term is not
//!   shorter than the measured gap. It scales with the payload, like
//!   `per_row_hold`. The slowest after-run's own gap is 7.959 ms; the 0.388 ms
//!   above the median is [`PRE_LOCK_SPREAD`], once per import.
//! * **Waiting for `conn` behind one group-commit batch** is the published
//!   per-batch cost 6.018 ms (`24.070 / 4` in
//!   `plan/architecture-2026-08-12/measurements/m3-post-group-commit.md`) plus
//!   [`slashing::GroupCommitConfig::DEFAULT_WAIT_TO_FILL`] (1 ms).
//! * **Hosts slower than the single measurement host** have no second-host
//!   figure. The allowance is the recorded same-host spread of that 10 MB
//!   shape: slowest after-run 689.438 ms minus median 658.322 ms = 31.116 ms,
//!   applied once per import.
//! * **`spawn_blocking` start latency** is not a published duration. [`ImportAdmission::ensure_still_fits`]
//!   re-checks, on the blocking thread and before `conn` is taken, that tokio
//!   time is still at or before the latest start `admit` accepted. It does not
//!   `.await` and it does not hold `conn`. A late start returns `NoFreeWindow`.

use std::sync::Arc;
use std::time::Duration;

use eth_types::ForkName;
use slashing::GroupCommitConfig;
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

/// Parse/prepare time per history row, before `conn.lock()`.
///
/// `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md` publishes the
/// after median `duration_ms` **665.893** against the after median
/// `conn_hold_ms` **658.322**. The difference is the work that moved out of
/// the lock: **7.571 ms** over **53,474** history rows.
///
/// `7_571_000 ns / 53_474 = 141.583… ns`. The const is the ceiling, **142 ns**,
/// so `53_474 · 142 ns = 7.593308 ms` is not shorter than 7.571 ms. A
/// truncated 141 ns would leave the linear term 31.166 µs under the measured
/// gap. Not an operator knob.
const PER_ROW_PRE_LOCK: Duration = Duration::from_nanos(142);

/// Once per import: the slowest after-run's pre-lock minus the median gap.
///
/// `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md` run 2 is the
/// slowest hold: duration **697.397** ms minus hold **689.438** ms = 7.959 ms.
/// The median gap is 7.571 ms. The difference is **0.388 ms**. Same shape as
/// [`SLOW_HOST_MARGIN`]: one allowance per import, not a second per-row rate.
/// Not an operator knob.
const PRE_LOCK_SPREAD: Duration = Duration::from_nanos(388_000);

/// How long a caller may sit on [`ImportWindowGate::one_at_a_time`] before the
/// import is refused. Not an operator knob, so `OPERATOR_KNOB_NAMES` stays 75.
///
/// Two slots cover the holder's post-acquire deferral (at most one slot) plus
/// that holder's own import. A longer queue returns a retryable error so the
/// parsed body is not retained.
const QUEUE_WAIT_SLOTS: u32 = 2;

/// Same-host spread of the RR2-13 after runs, once per import.
///
/// Slowest published after-run 689.438 ms minus median 658.322 ms. There is
/// no second-host measurement. Not an operator knob.
const SLOW_HOST_MARGIN: Duration = Duration::from_nanos(31_116_000);

/// One group-commit batch's published hold on `conn`.
///
/// `plan/architecture-2026-08-12/measurements/m3-post-group-commit.md`:
/// `T_batch = 24.070 / 4 = 6.018` ms. Not an operator knob.
const GROUP_COMMIT_BATCH: Duration = Duration::from_nanos(6_018_000);

/// Floor for [`estimated_hold`].
///
/// The measurement note does not isolate a fixed cost inside `conn.lock()`.
/// The after duration (665.893 ms) exceeds the hold (658.322 ms) because
/// numeric parsing runs before the lock. That gap is [`PER_ROW_PRE_LOCK`],
/// not connection hold, so it is not part of this floor. The floor is one
/// history row, 0.012311 ms, the smallest hold quantum in the note's RR3-01
/// input table. For every `rows >= 1`, `max(min_hold, rows · per_row_hold)`
/// is the connection-hold term.
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
    /// Measured parse/prepare cost of one history row, before `conn.lock()`.
    pub(crate) per_row_pre_lock: Duration,
    /// Floor applied to the row estimate.
    pub(crate) min_hold: Duration,
    /// Allowance for work after `admit` returns and before `conn` is free.
    ///
    /// See the module docs. Read by [`estimated_hold`].
    pub(crate) post_admit: Duration,
}

impl ImportWindowConfig {
    const fn measured() -> Self {
        Self {
            att_reserve_margin: ATT_RESERVE_MARGIN,
            block_reserve_margin: BLOCK_RESERVE_MARGIN,
            per_row_hold: PER_ROW_HOLD,
            per_row_pre_lock: PER_ROW_PRE_LOCK,
            min_hold: MIN_HOLD,
            post_admit: post_admit(),
        }
    }
}

const fn post_admit() -> Duration {
    let Some(total) = SLOW_HOST_MARGIN.checked_add(PRE_LOCK_SPREAD) else {
        return Duration::MAX;
    };
    let Some(total) = total.checked_add(GROUP_COMMIT_BATCH) else {
        return Duration::MAX;
    };
    let Some(sum) = total.checked_add(GroupCommitConfig::DEFAULT_WAIT_TO_FILL) else {
        return Duration::MAX;
    };
    sum
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

    #[cfg(test)]
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
        /// Full [`estimated_hold`], in milliseconds.
        estimated_hold_ms: MilliSeconds,
        /// Length of one free window, in milliseconds.
        window_ms: MilliSeconds,
    },
    /// The slot clock could not name the current slot.
    #[error("slot clock is unavailable: {0}")]
    Clock(#[from] TimingError),
    /// `one_at_a_time` was still held after [`QUEUE_WAIT_SLOTS`].
    ///
    /// `retry_after_secs` is that bound, so the HTTP mapper can set
    /// `Retry-After`. The parsed payload must not stay queued.
    #[error(
        "interchange import queue exceeded {waited_slots} slots; retry after {retry_after_secs}s"
    )]
    QueueSaturated {
        /// Slots the caller was willing to wait.
        waited_slots: u64,
        /// Same bound, in whole seconds.
        retry_after_secs: u64,
    },
}

/// What [`ImportWindowGate::admit`] hands the import once it may take `conn`.
pub(crate) struct ImportAdmission {
    /// Held until the blocking import returns. Move it into `spawn_blocking`.
    pub(crate) guard: OwnedMutexGuard<()>,
    /// Mutex queue plus the sleep until the free window.
    pub(crate) wait: Duration,
    /// Length of one free window. Zero before genesis, where there is no slot.
    pub(crate) window: Duration,
    /// `max(min_hold, rows · per_row_hold) + rows · per_row_pre_lock + post_admit`.
    pub(crate) estimated_hold: Duration,
    /// Latest tokio instant at which `estimated_hold` still ends inside the
    /// window `admit` selected. Before genesis this is a day ahead: there is
    /// no slot close.
    latest_start: tokio::time::Instant,
}

impl std::fmt::Debug for ImportAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportAdmission")
            .field("wait", &self.wait)
            .field("window", &self.window)
            .field("estimated_hold", &self.estimated_hold)
            .field("latest_start", &self.latest_start)
            .finish_non_exhaustive()
    }
}

impl ImportAdmission {
    /// Re-check the fit on the blocking thread, before `conn` is taken.
    ///
    /// Compares tokio time with [`Self::latest_start`]. Does not `.await` and
    /// does not lock the database. A late `spawn_blocking` start returns
    /// [`ImportDeferralError::NoFreeWindow`].
    pub(crate) fn ensure_still_fits(&self) -> Result<(), ImportDeferralError> {
        let now = tokio::time::Instant::now();
        if now <= self.latest_start {
            Ok(())
        } else {
            Err(no_free_window(self.estimated_hold, self.window))
        }
    }
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
        Self::new_with_config(clock, ImportWindowConfig::measured())
    }

    fn new_with_config(clock: Arc<dyn SlotClock>, cfg: ImportWindowConfig) -> Self {
        Self { clock, cfg, one_at_a_time: Arc::new(Mutex::new(())) }
    }

    /// Reserve the import mutex and wait until `rows` fits in one free window.
    ///
    /// The estimate is [`estimated_hold`]. The mutex is acquired before the
    /// clock is read, and that wait is capped at [`QUEUE_WAIT_SLOTS`]. The
    /// returned guard is owned so the caller can move it into `spawn_blocking`;
    /// it stays held until that owner drops it.
    ///
    /// The sleep after the mutex is acquired is at most one slot. Before
    /// genesis the guard is returned without sleeping. Dropping this future
    /// before it returns drops the guard (or cancels the wait to acquire it).
    pub(crate) async fn admit(&self, rows: usize) -> Result<ImportAdmission, ImportDeferralError> {
        let queued_at = tokio::time::Instant::now();
        let queue_bound = self
            .clock
            .slot_duration()
            .checked_mul(QUEUE_WAIT_SLOTS)
            .ok_or(ImportDeferralError::Clock(TimingError::InvalidSlotDuration))?;
        let guard = match tokio::time::timeout(queue_bound, self.one_at_a_time.clone().lock_owned())
            .await
        {
            Ok(guard) => guard,
            Err(_) => {
                return Err(ImportDeferralError::QueueSaturated {
                    waited_slots: u64::from(QUEUE_WAIT_SLOTS),
                    retry_after_secs: queue_bound.as_secs().max(1),
                });
            }
        };
        let acquired_at = tokio::time::Instant::now();
        let estimate = estimated_hold(rows, &self.cfg);

        let slot = match self.clock.current_slot() {
            Ok(slot) => slot,
            // No duties exist yet. Installing history cannot delay a reserve.
            Err(TimingError::BeforeGenesis { .. }) => {
                let latest_start = acquired_at
                    .checked_add(Duration::from_secs(24 * 60 * 60))
                    .unwrap_or(acquired_at);
                return Ok(ImportAdmission {
                    guard,
                    wait: acquired_at.saturating_duration_since(queued_at),
                    window: Duration::ZERO,
                    estimated_hold: estimate,
                    latest_start,
                });
            }
            Err(err) => return Err(err.into()),
        };
        let bound = acquired_at.checked_add(self.clock.slot_duration()).unwrap_or(acquired_at);

        let anchor = SlotAnchor::capture(self.clock.as_ref(), slot);
        let bps = attestation_bps(self.clock.as_ref());
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
                Some(_) => {
                    let latest_start =
                        latest_start_in_fit(&anchor, bps, &self.cfg, estimate, now).unwrap_or(now);
                    return Ok(ImportAdmission {
                        guard,
                        wait: tokio::time::Instant::now().saturating_duration_since(queued_at),
                        window,
                        estimated_hold: estimate,
                        latest_start,
                    });
                }
                None => return Err(no_free_window(estimate, window)),
            }
        }
    }
}

/// Later of the pre-Gloas and Gloas attestation deadlines.
///
/// The gate has no live fork. Using the later deadline keeps the window from
/// opening before either fork's attestation reserve. With the default uniform
/// schedule the two values are equal.
fn attestation_bps(clock: &dyn SlotClock) -> u64 {
    clock.deadlines().attestation.max(clock.deadlines_for(ForkName::Gloas).attestation)
}

/// `max(min_hold, rows · per_row_hold) + rows · per_row_pre_lock + post_admit`, from `cfg`.
fn estimated_hold(rows: usize, cfg: &ImportWindowConfig) -> Duration {
    let rows = u128::try_from(rows).unwrap_or(u128::MAX);
    let linear = cfg.per_row_hold.as_nanos().saturating_mul(rows);
    let row_hold = duration_from_nanos(linear.max(cfg.min_hold.as_nanos()));
    let pre_lock = duration_from_nanos(cfg.per_row_pre_lock.as_nanos().saturating_mul(rows));
    row_hold
        .checked_add(pre_lock)
        .and_then(|total| total.checked_add(cfg.post_admit))
        .unwrap_or(Duration::MAX)
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

/// Latest tokio instant whose hold still ends inside the window `now` fits.
fn latest_start_in_fit(
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
            return close.checked_sub(estimate);
        }
    }
    None
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
        estimated_hold, ImportDeferralError, ImportWindowConfig, ImportWindowGate,
        ATT_RESERVE_MARGIN, BLOCK_RESERVE_MARGIN, GROUP_COMMIT_BATCH, MIN_HOLD, PER_ROW_HOLD,
        PER_ROW_PRE_LOCK, PRE_LOCK_SPREAD, QUEUE_WAIT_SLOTS,
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

    fn row_estimate(rows: usize) -> Duration {
        estimated_hold(rows, &ImportWindowConfig::measured())
    }

    fn max_rows_fitting(budget: Duration) -> usize {
        let cfg = ImportWindowConfig::measured();
        let per = cfg.per_row_hold.as_nanos() + cfg.per_row_pre_lock.as_nanos();
        let fixed = cfg.post_admit.as_nanos();
        let budget_ns = budget.as_nanos();
        assert!(
            fixed.saturating_add(cfg.min_hold.as_nanos()) <= budget_ns,
            "budget is below min_hold + post_admit"
        );
        usize::try_from((budget_ns - fixed) / per).unwrap()
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
        assert!(row_estimate(fits) <= remaining);
        assert!(row_estimate(crosses) > remaining);
        assert!(row_estimate(crosses) <= window);

        let fix = clock_at(offset_ms);
        let started = Instant::now();
        let guard: OwnedMutexGuard<()> = fix.gate.admit(fits).await.unwrap().guard;
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
        let guard = deferred.await.expect("admitted when the next free window opens").guard;
        drop(guard);

        let waited = Instant::now().saturating_duration_since(started);
        assert_eq!(waited, until_next_t0 + until_window);
        assert!(waited <= Duration::from_millis(SLOT_MS));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn two_concurrent_10mb_imports_serialize() {
        let (open, close) = window_offsets_ms();
        let linear = Duration::from_nanos(u64::try_from(hold_ns(HISTORY_ROWS_10MB)).unwrap());
        assert_eq!(linear.as_nanos(), 658_318_414, "53,474 rows × 0.012311 ms");
        let estimate = row_estimate(HISTORY_ROWS_10MB);
        assert!(estimate > linear, "post-admit allowance is on top of the linear hold");
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
            let guard = gate.admit(HISTORY_ROWS_10MB).await.unwrap().guard;
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
            let guard = gate.admit(HISTORY_ROWS_10MB).await.unwrap().guard;
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
        let estimate_ns = row_estimate(rows).as_nanos();
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
        let holder = tokio::spawn(async move { holder_gate.admit(1).await.unwrap().guard });
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
        assert!(row_estimate(crosses) > Duration::from_millis(close - into_slot));

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
        let guard = next.await.unwrap().unwrap().guard;

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
        drop(after.await.unwrap().unwrap().guard);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn import_before_genesis_is_admitted_immediately() {
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_current_time(GENESIS - 10);
        assert!(clock.current_slot().is_err(), "the clock is before genesis");
        let gate = ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>);
        let started = Instant::now();
        let admission =
            gate.admit(HISTORY_ROWS_10MB).await.expect("before genesis is the safe time");
        assert_eq!(Instant::now(), started, "pre-genesis import does not wait for a slot window");
        assert!(admission.wait.is_zero());
        drop(admission.guard);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn later_gloas_attestation_deadline_opens_the_window_later() {
        use timing::{DeadlineBps, DeadlineSchedule};

        let gloas = DeadlineBps { attestation: 5_000, ..DeadlineBps::default() };
        let clock = Arc::new(
            MockSlotClock::new(GENESIS, Duration::from_secs(12), 32).with_deadline_schedule(
                DeadlineSchedule { pre_gloas: DeadlineBps::default(), gloas },
            ),
        );
        // Pre-Gloas opens at 4_499 ms. Gloas attestation is 6_000 ms, plus the
        // 500 ms reserve, so the later deadline opens at 6_500 ms.
        clock.set_slot_with_offset_ms(0, 5_000);
        let gate = Arc::new(ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>));
        let deferred = gate.admit(1);
        tokio::pin!(deferred);
        assert!(
            poll_pending(deferred.as_mut()).await,
            "t=5s is inside the pre-Gloas window and still before the Gloas one"
        );
        tokio::time::advance(Duration::from_millis(1_499)).await;
        assert!(poll_pending(deferred.as_mut()).await, "one millisecond before 6_500 ms");
        tokio::time::advance(Duration::from_millis(1)).await;
        deferred.await.expect("admitted at the later attestation reserve");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn estimate_reads_config_per_row_hold_and_min_hold() {
        let (open, _) = window_offsets_ms();
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_slot_with_offset_ms(0, open);
        let mut cfg = ImportWindowConfig::measured();
        cfg.per_row_hold = Duration::from_millis(8_000);
        cfg.min_hold = Duration::from_millis(8_000);
        let gate = ImportWindowGate::new_with_config(clock as Arc<dyn SlotClock>, cfg);
        let err = gate.admit(1).await.expect_err("8s min_hold does not fit the 7301 ms window");
        match err {
            ImportDeferralError::NoFreeWindow { estimated_hold_ms, .. } => {
                assert!(
                    estimated_hold_ms.as_nanos() >= Duration::from_millis(8_000).as_nanos(),
                    "the config min_hold must be the one that was estimated"
                );
            }
            other => panic!("expected NoFreeWindow, got {other}"),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn queued_import_is_refused_after_two_slots() {
        let fix = clock_at(8_000);
        let holder = fix.gate.admit(1).await.unwrap().guard;
        let gate = Arc::clone(&fix.gate);
        let waiter = gate.admit(1);
        tokio::pin!(waiter);
        assert!(poll_pending(waiter.as_mut()).await, "queued behind the held guard");
        tokio::time::advance(Duration::from_millis(u64::from(QUEUE_WAIT_SLOTS) * SLOT_MS)).await;
        let err = waiter.await.expect_err("the queue bound must refuse instead of waiting forever");
        match err {
            ImportDeferralError::QueueSaturated { waited_slots, retry_after_secs } => {
                assert_eq!(waited_slots, u64::from(QUEUE_WAIT_SLOTS));
                assert_eq!(retry_after_secs, 24);
            }
            other => panic!("expected QueueSaturated, got {other}"),
        }
        drop(holder);
    }

    /// Slowest published hold, plus that run's pre-lock, plus one group-commit
    /// batch and the fill wait, started at `latest_start`.
    ///
    /// Figures are the after table in
    /// `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md` and the
    /// group-commit `T_batch` already cited on [`GROUP_COMMIT_BATCH`].
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn worst_case_recorded_run_admitted_at_latest_start_ends_before_the_block_reserve() {
        let slowest_hold = Duration::from_nanos(689_438_000);
        // Median gap: 665.893 − 658.322 ms. Slowest run: 697.397 − 689.438 ms.
        let median_pre_lock = Duration::from_nanos((665_893 - 658_322) * 1_000);
        let slowest_pre_lock = Duration::from_nanos((697_397 - 689_438) * 1_000);
        assert_eq!(median_pre_lock.as_nanos(), 7_571_000);
        assert_eq!(slowest_pre_lock.as_nanos(), 7_959_000);
        assert_eq!(slowest_pre_lock.saturating_sub(median_pre_lock), PRE_LOCK_SPREAD);
        assert_eq!(PER_ROW_PRE_LOCK.as_nanos(), 142);
        let pre_lock_product =
            PER_ROW_PRE_LOCK.as_nanos() * u128::try_from(HISTORY_ROWS_10MB).unwrap();
        assert!(
            pre_lock_product >= median_pre_lock.as_nanos(),
            "the per-row ceiling must cover the measured 7.571 ms gap"
        );
        let worst = slowest_hold
            + slowest_pre_lock
            + GROUP_COMMIT_BATCH
            + slashing::GroupCommitConfig::DEFAULT_WAIT_TO_FILL;

        let (open, close_ms) = window_offsets_ms();
        assert_eq!(close_ms, 11_800, "the block reserve starts at slot_end − 200 ms");
        let fix = clock_at(open);
        let admission =
            fix.gate.admit(HISTORY_ROWS_10MB).await.expect("10 MB fits at the window open");
        let window_close =
            admission.latest_start.checked_add(admission.estimated_hold).expect("close");
        let end = admission.latest_start.checked_add(worst).expect("end");
        assert!(
            end < window_close,
            "admitting at the latest instant must finish before the 200 ms block reserve"
        );
        assert_eq!(
            window_close.saturating_duration_since(end),
            Duration::from_nanos(18_722),
            "margin before the block reserve"
        );
        drop(admission.guard);
    }
}
