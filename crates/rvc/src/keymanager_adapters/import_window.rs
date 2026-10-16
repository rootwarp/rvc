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
//! [`TimingError::BeforeGenesis`] admits only when [`estimated_hold`] finishes
//! at or before genesis. A saturated estimate is refused. A hold that would
//! still be running at genesis falls through to slot 0's free window, under
//! the same one-slot cap as every other admission. Every other clock error
//! still refuses admission.
//!
//! # Time after admission
//!
//! [`estimated_hold`] is the measured per-row connection hold, plus the
//! per-row pre-lock term, plus the scaled margins below, plus
//! [`ImportWindowConfig::post_admit`]. The additions are not a new measurement:
//!
//! * **Fixed BEGIN/COMMIT/fsync/WAL cost** of this import is already inside
//!   `per_row_hold`. `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md`
//!   records `conn.lock()` through `COMMIT` and does not isolate an intercept,
//!   so none is added a second time. That hold includes this shape's watermark
//!   upserts (three per validator, 1.5 per history row).
//! * **Parse and prepare before `conn.lock()`** is the after-run gap between
//!   `duration_ms` and `conn_hold_ms`. The median run's own gap (median
//!   duration minus median hold, which is run 1) is 665.893 − 658.322 =
//!   7.571 ms over 53,474 history rows. The median of the three per-run gaps
//!   is 7.959 ms, not 7.571. [`PER_ROW_PRE_LOCK`] is the 7.571 ms pair, per
//!   row, rounded up to a whole nanosecond so the linear term is not shorter
//!   than that pair. The measured file has two history rows per validator, so
//!   the budget charges that linear term twice: a one-row-per-validator file
//!   pays the per-validator parse on every row.
//! * **Pre-lock spread** is once per import and scales with the budgeted
//!   pre-lock. The floor is run 3's gap minus the median-run pair:
//!   8.011 − 7.571 = 0.440 ms ([`PRE_LOCK_SPREAD`]). That covers the pairing
//!   of run 2's hold with run 3's gap. Above the floor the spread is
//!   `⌈pre_lock × 0.440/7.571⌉`.
//! * **Waiting for `conn` behind one group-commit batch** is the published
//!   per-batch cost 6.018 ms (`24.070 / 4` in
//!   `plan/architecture-2026-08-12/measurements/m3-post-group-commit.md`) plus
//!   the effective [`slashing::GroupCommitConfig`] wait-to-fill (default 1 ms).
//!   A batch larger than the default is charged at least that published cost,
//!   scaled by `batch_size / DEFAULT_BATCH_SIZE`.
//! * **Hosts slower than the single measurement host** have no second-host
//!   figure. The floor is the recorded same-host spread of the 10 MB shape:
//!   slowest after-run 689.438 ms minus median 658.322 ms = 31.116 ms. Above
//!   that floor the allowance scales as `⌈row_hold × 31.116/658.322⌉`. The
//!   margin is the max of the fixed floor and the sum of the two scaled terms.
//! * **Loaded runs** are slower than the idle 10 MB median. The N=200
//!   `conn_hold_ms` samples in
//!   `plan/review-2026-10-03/measurements/m3-scheduled-path.md` reach
//!   823.799 ms. The excess over the computed idle row product
//!   (53,474 × 12,311 ns) is charged in proportion to `row_hold`.
//! * **A denser statement mix** (one attestation per validator) runs about
//!   20% more SQL statements per history row than the measured two-row shape
//!   (`3 / 2.5 − 1`). That fraction of `row_hold` is charged on every import.
//! * **Slot-anchor quantum.** [`SLOT_QUANTUM_ALLOWANCE`] is 1 ms, inside every
//!   estimate. `ms_into_slot` floors to a whole millisecond; the old 18.7 µs
//!   gap was rounding residue, not slack.
//! * **`spawn_blocking` start latency** is not a published duration. [`ImportAdmission::ensure_still_fits`]
//!   re-checks, on the blocking thread and before `conn` is taken, that tokio
//!   time is still at or before the latest start `admit` accepted. It does not
//!   `.await` and it does not hold `conn`. A late start returns `NoFreeWindow`.

use std::sync::Arc;
use std::time::Duration;

use eth_types::ForkName;
use slashing::GroupCommitConfig;
use thiserror::Error;
use timing::{due_ms, SlotClock, TimingError};
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

/// Floor for the once-per-import pre-lock spread.
///
/// `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md` run 3's gap is
/// the largest: duration **662.903** ms minus hold **654.892** ms = 8.011 ms.
/// The median run's own gap (median duration minus median hold) is 7.571 ms.
/// The difference is **0.440 ms**. Run 2's gap is 7.959 ms, so 0.388 ms would
/// leave run 2's hold paired with run 3's gap 33 µs inside the block reserve.
/// The median of the three per-run gaps is 7.959 ms, not 7.571. Same shape as
/// [`SLOW_HOST_MARGIN`]: a floor per import. Above the floor,
/// [`scaled_margin_ns`] grows with the budgeted pre-lock. Not an operator knob.
const PRE_LOCK_SPREAD: Duration = Duration::from_nanos(440_000);

/// Numerator of [`PRE_LOCK_SPREAD`] / 7.571 ms, in microseconds.
const PRE_LOCK_SPREAD_NUM: u128 = 440;
/// Denominator of the pre-lock spread ratio, in microseconds (7.571 ms).
const PRE_LOCK_SPREAD_DEN: u128 = 7_571;

/// The measured pre-lock gap is spread over two history rows per validator.
///
/// A file with one history row per validator pays that per-validator parse on
/// every row, so the linear term is charged twice.
const PER_VALIDATOR_PARSE_FACTOR: u128 = 2;

/// How long a caller may sit on [`ImportWindowGate::one_at_a_time`] before the
/// import is refused. Not an operator knob, so `OPERATOR_KNOB_NAMES` stays 75.
///
/// Two slots cover the holder's post-acquire deferral (at most one slot) plus
/// that holder's own import. A longer queue returns a retryable error so the
/// parsed body is not retained.
const QUEUE_WAIT_SLOTS: u32 = 2;

/// Floor for the same-host spread of the RR2-13 after runs, once per import.
///
/// Slowest published after-run 689.438 ms minus median 658.322 ms. There is
/// no second-host measurement. Above this floor, [`scaled_margin_ns`] grows
/// with `row_hold`. Not an operator knob.
const SLOW_HOST_MARGIN: Duration = Duration::from_nanos(31_116_000);

/// Numerator of [`SLOW_HOST_MARGIN`] / 658.322 ms, in microseconds.
const SLOW_HOST_NUM: u128 = 31_116;
/// Denominator of the slow-host ratio, in microseconds (658.322 ms).
const SLOW_HOST_DEN: u128 = 658_322;

/// Loaded-run excess over the computed idle row product, in nanoseconds.
///
/// The term is sized from the slowest N=200 `conn_hold_ms` on the 2026-10-08
/// recording, 823.799 ms. The 2026-10-12 clean re-record in
/// `plan/review-2026-10-03/measurements/m3-scheduled-path.md` peaks at
/// 787.345 ms, inside that excess. The idle product is 53,474 × 12,311 ns =
/// 658,318,414 ns. The difference is charged in proportion to `row_hold` by
/// [`load_margin_ns`].
const LOAD_MARGIN_NUM: u128 = 165_480_586;
/// Computed idle row product the load excess is taken against, in nanoseconds.
const LOAD_MARGIN_DEN: u128 = 658_318_414;

/// Extra statements per history row on a one-attestation-per-validator file.
///
/// The measured shape is two history rows and three watermark upserts per
/// validator (2.5 statements per row). One attestation plus its two watermarks
/// is 3 statements per row, and `3/2.5 − 1 = 1/5`. Unmeasured. Charged on
/// `row_hold` by [`shape_margin_ns`].
const SHAPE_STATEMENT_NUM: u128 = 1;
const SHAPE_STATEMENT_DEN: u128 = 5;

/// Explicit slack for the 1 ms slot-anchor quantum.
///
/// `SlotClock::ms_into_slot` floors to a whole millisecond. The previous
/// 18.722 µs gap was ceiling residue on [`PER_ROW_PRE_LOCK`] minus truncation
/// on [`PER_ROW_HOLD`], not slack. Not an operator knob.
const SLOT_QUANTUM_ALLOWANCE: Duration = Duration::from_millis(1);

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
    /// Row-independent tail: one group-commit batch, its wait-to-fill, and
    /// [`SLOT_QUANTUM_ALLOWANCE`].
    ///
    /// Scaled margins are not stored here. [`estimated_hold`] adds them from
    /// the row count. See the module docs.
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
            post_admit: fixed_tail(GROUP_COMMIT_BATCH, GroupCommitConfig::DEFAULT_WAIT_TO_FILL),
        }
    }
}

const fn fixed_tail(batch: Duration, wait_to_fill: Duration) -> Duration {
    let Some(total) = batch.checked_add(wait_to_fill) else {
        return Duration::MAX;
    };
    let Some(sum) = total.checked_add(SLOT_QUANTUM_ALLOWANCE) else {
        return Duration::MAX;
    };
    sum
}

/// Published batch cost for `batch_size`, never below [`GROUP_COMMIT_BATCH`].
///
/// A batch no larger than the default still pays one fsync. A larger batch
/// scales that published cost by `batch_size / DEFAULT_BATCH_SIZE`.
fn batch_allowance(batch_size: usize) -> Duration {
    let default = GroupCommitConfig::DEFAULT_BATCH_SIZE.max(1);
    let size = batch_size.max(1);
    if size <= default {
        return GROUP_COMMIT_BATCH;
    }
    let scaled = GROUP_COMMIT_BATCH.as_nanos().saturating_mul(size as u128) / (default as u128);
    duration_from_nanos(scaled)
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
    /// Row hold, budgeted pre-lock, scaled margins, and [`ImportWindowConfig::post_admit`].
    pub(crate) estimated_hold: Duration,
    /// Latest tokio instant at which `estimated_hold` still ends inside the
    /// window `admit` selected. Before genesis, when the hold finishes first,
    /// this is `now + (time_to_genesis − estimated_hold)`.
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

    /// Use the group-commit knobs actually installed on the database.
    ///
    /// The measured consts assume [`GroupCommitConfig::default`]. A longer
    /// wait-to-fill, or a batch larger than the default, lengthens
    /// [`estimated_hold`].
    pub(crate) fn with_group_commit(mut self, group_commit: GroupCommitConfig) -> Self {
        let batch = batch_allowance(group_commit.batch_size);
        self.cfg.post_admit = fixed_tail(batch, group_commit.wait_to_fill);
        self
    }

    /// Post-admit tail used by [`estimated_hold`] (batch allowance + wait-to-fill).
    #[cfg(test)]
    pub(crate) fn post_admit(&self) -> Duration {
        self.cfg.post_admit
    }

    /// Reserve the import mutex and wait until `rows` fits in one free window.
    ///
    /// The estimate is [`estimated_hold`]. The mutex is acquired before the
    /// clock is read, and that wait is capped at [`QUEUE_WAIT_SLOTS`]. The
    /// returned guard is owned so the caller can move it into `spawn_blocking`;
    /// it stays held until that owner drops it.
    ///
    /// The sleep after the mutex is acquired is at most one slot. Before
    /// genesis the guard is returned without sleeping only when the estimate
    /// finishes at or before genesis. Dropping this future before it returns
    /// drops the guard (or cancels the wait to acquire it).
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
            Err(TimingError::BeforeGenesis { .. }) => {
                return self.admit_before_genesis(guard, queued_at, acquired_at, estimate).await;
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

    /// Admit before genesis, or fall through to slot 0 when the hold would cross it.
    ///
    /// A saturated estimate is refused. When `time_to_genesis >= estimate` the
    /// latest start is the instant at which the hold still ends at genesis.
    /// Otherwise slot 0's free window is used, and the sleep after the mutex
    /// is acquired stays inside one slot.
    async fn admit_before_genesis(
        &self,
        guard: OwnedMutexGuard<()>,
        queued_at: tokio::time::Instant,
        acquired_at: tokio::time::Instant,
        estimate: Duration,
    ) -> Result<ImportAdmission, ImportDeferralError> {
        if estimate == Duration::MAX {
            return Err(no_free_window(estimate, Duration::ZERO));
        }
        let until_genesis = self.clock.time_until_slot(0)?;
        if until_genesis >= estimate {
            let slack = until_genesis.saturating_sub(estimate);
            let latest_start = acquired_at.checked_add(slack).unwrap_or(acquired_at);
            return Ok(ImportAdmission {
                guard,
                wait: acquired_at.saturating_duration_since(queued_at),
                window: Duration::ZERO,
                estimated_hold: estimate,
                latest_start,
            });
        }

        let Some(genesis_at) = acquired_at.checked_add(until_genesis) else {
            return Err(no_free_window(estimate, Duration::ZERO));
        };
        let bps = attestation_bps(self.clock.as_ref());
        let slot_duration = self.clock.slot_duration();
        let slot_ms = u64::try_from(slot_duration.as_millis()).unwrap_or(u64::MAX / 2);
        let open_offset = Duration::from_millis(due_ms(bps, slot_ms))
            .checked_add(self.cfg.att_reserve_margin)
            .ok_or(ImportDeferralError::Clock(TimingError::InvalidSlotDuration))?;
        let Some(close_offset) = slot_duration.checked_sub(self.cfg.block_reserve_margin) else {
            return Err(no_free_window(estimate, Duration::ZERO));
        };
        let window = close_offset.saturating_sub(open_offset);
        if open_offset >= close_offset || estimate > window {
            return Err(no_free_window(estimate, window));
        }
        let bound = acquired_at.checked_add(slot_duration).unwrap_or(acquired_at);

        loop {
            let now = tokio::time::Instant::now();
            match pre_genesis_start(
                genesis_at,
                open_offset,
                close_offset,
                slot_duration,
                estimate,
                now,
            ) {
                Some(start_at) if start_at > bound => {
                    return Err(no_free_window(estimate, window));
                }
                Some(start_at) if start_at > now => {
                    tokio::time::sleep_until(start_at).await;
                }
                Some(_) => {
                    let latest_start = pre_genesis_latest(
                        genesis_at,
                        open_offset,
                        close_offset,
                        slot_duration,
                        estimate,
                        now,
                    )
                    .unwrap_or(now);
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

/// Row hold, budgeted pre-lock, scaled margins, and `cfg.post_admit`.
fn estimated_hold(rows: usize, cfg: &ImportWindowConfig) -> Duration {
    let Some(total_ns) = estimated_hold_ns(rows, cfg) else {
        return Duration::MAX;
    };
    duration_from_nanos(total_ns)
}

/// [`estimated_hold`] for the measured config, truncated to whole milliseconds.
#[cfg(test)]
pub(crate) fn truncated_estimated_hold_ms(rows: usize) -> u64 {
    u64::try_from(estimated_hold(rows, &ImportWindowConfig::measured()).as_millis())
        .unwrap_or(u64::MAX)
}

fn estimated_hold_ns(rows: usize, cfg: &ImportWindowConfig) -> Option<u128> {
    let rows = u128::try_from(rows).unwrap_or(u128::MAX);
    let linear = cfg.per_row_hold.as_nanos().saturating_mul(rows);
    let row_hold = linear.max(cfg.min_hold.as_nanos());
    let pre_lock = cfg.per_row_pre_lock.as_nanos().saturating_mul(rows);
    let pre_lock_budget = pre_lock.saturating_mul(PER_VALIDATOR_PARSE_FACTOR);
    let margin = scaled_margin_ns(row_hold, pre_lock_budget)?;
    let load = load_margin_ns(row_hold)?;
    let shape = shape_margin_ns(row_hold)?;
    row_hold
        .checked_add(pre_lock_budget)?
        .checked_add(margin)?
        .checked_add(load)?
        .checked_add(shape)?
        .checked_add(cfg.post_admit.as_nanos())
}

/// `max(fixed floor, ⌈row_hold × 31.116/658.322⌉ + ⌈pre_lock × 0.440/7.571⌉)`.
fn scaled_margin_ns(row_hold_ns: u128, pre_lock_ns: u128) -> Option<u128> {
    let slow = ceil_mul_div(row_hold_ns, SLOW_HOST_NUM, SLOW_HOST_DEN)?;
    let spread = ceil_mul_div(pre_lock_ns, PRE_LOCK_SPREAD_NUM, PRE_LOCK_SPREAD_DEN)?;
    let proportional = slow.checked_add(spread)?;
    let fixed = SLOW_HOST_MARGIN.as_nanos().checked_add(PRE_LOCK_SPREAD.as_nanos())?;
    Some(proportional.max(fixed))
}

fn load_margin_ns(row_hold_ns: u128) -> Option<u128> {
    ceil_mul_div(row_hold_ns, LOAD_MARGIN_NUM, LOAD_MARGIN_DEN)
}

fn shape_margin_ns(row_hold_ns: u128) -> Option<u128> {
    ceil_mul_div(row_hold_ns, SHAPE_STATEMENT_NUM, SHAPE_STATEMENT_DEN)
}

fn ceil_mul_div(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    value.checked_mul(numerator).map(|product| product.div_ceil(denominator))
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

/// Earliest instant at or after `now` whose hold fits slot 0 or slot 1.
fn pre_genesis_start(
    genesis_at: tokio::time::Instant,
    open_offset: Duration,
    close_offset: Duration,
    slot_duration: Duration,
    estimate: Duration,
    now: tokio::time::Instant,
) -> Option<tokio::time::Instant> {
    pre_genesis_fit(genesis_at, open_offset, close_offset, slot_duration, estimate, now)
        .map(|(start_at, _)| start_at)
}

/// Latest instant whose hold still ends inside the pre-genesis slot that fits.
fn pre_genesis_latest(
    genesis_at: tokio::time::Instant,
    open_offset: Duration,
    close_offset: Duration,
    slot_duration: Duration,
    estimate: Duration,
    now: tokio::time::Instant,
) -> Option<tokio::time::Instant> {
    pre_genesis_fit(genesis_at, open_offset, close_offset, slot_duration, estimate, now)
        .map(|(_, latest)| latest)
}

fn pre_genesis_fit(
    genesis_at: tokio::time::Instant,
    open_offset: Duration,
    close_offset: Duration,
    slot_duration: Duration,
    estimate: Duration,
    now: tokio::time::Instant,
) -> Option<(tokio::time::Instant, tokio::time::Instant)> {
    for ahead in 0..2u32 {
        let shift = slot_duration.checked_mul(ahead)?;
        let open = genesis_at.checked_add(open_offset)?.checked_add(shift)?;
        let close = genesis_at.checked_add(close_offset)?.checked_add(shift)?;
        let start_at = now.max(open);
        if start_at >= close {
            continue;
        }
        let end = start_at.checked_add(estimate)?;
        if end <= close {
            return Some((start_at, close.checked_sub(estimate)?));
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

    use timing::{due_ms, MockSlotClock, SlotClock, TimingError, ATTESTATION_DUE_BPS};
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
        let mut lo = 0usize;
        let mut hi = 1usize;
        while hi < usize::MAX / 2 && fits_budget(hi, budget) {
            hi = hi.saturating_mul(2);
        }
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if fits_budget(mid, budget) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    }

    fn fits_budget(rows: usize, budget: Duration) -> bool {
        let estimate = row_estimate(rows);
        estimate != Duration::MAX && estimate <= budget
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

    /// Run 2's own hold and gap, plus one group-commit batch and the fill wait,
    /// started at `latest_start`, ends at least 1 ms before the 11_800 ms reserve.
    ///
    /// The cross-run pairing (run 2's hold with run 3's gap) is
    /// [`pre_lock_spread_covers_run2_hold_plus_run3_gap_before_the_block_reserve`].
    /// Figures are the after table in
    /// `plan/review-2026-10-03/measurements/rv15-conn-hold-10mb.md`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn worst_case_recorded_run_admitted_at_latest_start_ends_before_the_block_reserve() {
        let slowest_hold = Duration::from_nanos(689_438_000);
        // Median-run pair: 665.893 − 658.322 ms. Run 2's own gap: 697.397 − 689.438 ms.
        let median_run_pair = Duration::from_nanos((665_893 - 658_322) * 1_000);
        let run2_pre_lock = Duration::from_nanos((697_397 - 689_438) * 1_000);
        assert_eq!(median_run_pair.as_nanos(), 7_571_000);
        assert_eq!(run2_pre_lock.as_nanos(), 7_959_000);
        assert!(PRE_LOCK_SPREAD > run2_pre_lock.saturating_sub(median_run_pair));
        assert_eq!(PER_ROW_PRE_LOCK.as_nanos(), 142);
        let pre_lock_product =
            PER_ROW_PRE_LOCK.as_nanos() * u128::try_from(HISTORY_ROWS_10MB).unwrap();
        assert!(
            pre_lock_product >= median_run_pair.as_nanos(),
            "the per-row ceiling must cover the measured 7.571 ms pair"
        );
        let worst = slowest_hold
            + run2_pre_lock
            + GROUP_COMMIT_BATCH
            + slashing::GroupCommitConfig::DEFAULT_WAIT_TO_FILL;

        let (open, close_ms) = window_offsets_ms();
        assert_eq!(close_ms, 11_800, "the block reserve starts at slot end minus 200 ms");
        let fix = clock_at(open);
        let slot_origin = Instant::now();
        let admission =
            fix.gate.admit(HISTORY_ROWS_10MB).await.expect("10 MB fits at the window open");
        let reserve = slot_origin + Duration::from_millis(close_ms - open);
        let end = admission.latest_start.checked_add(worst).expect("end");
        let slack = reserve.saturating_duration_since(end);
        assert!(
            end <= reserve && slack >= Duration::from_millis(1),
            "admitting at the latest instant must finish at least 1 ms before 11_800 ms, slack {slack:?}"
        );
        drop(admission.guard);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn estimate_uses_the_effective_group_commit_config() {
        let (open, _) = window_offsets_ms();
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_slot_with_offset_ms(0, open);
        let group_commit = slashing::GroupCommitConfig {
            batch_size: slashing::GroupCommitConfig::DEFAULT_BATCH_SIZE * 2,
            wait_to_fill: Duration::from_millis(50),
        };
        let gate =
            ImportWindowGate::new(clock as Arc<dyn SlotClock>).with_group_commit(group_commit);
        let admission = gate.admit(1).await.expect("one row still fits the free window");
        assert!(
            admission.estimated_hold > row_estimate(1),
            "a longer wait and a larger batch must increase the estimate"
        );
        assert!(admission.estimated_hold >= Duration::from_millis(50));
        drop(admission.guard);
    }

    fn ceil_div(numerator: u128, denominator: u128) -> u128 {
        numerator.div_ceil(denominator)
    }

    /// 7.571 ms is the median run's own gap (median duration − median hold).
    /// The median of the three per-run gaps is 7.959 ms.
    #[test]
    fn median_of_per_run_gaps_is_run2_not_the_median_run_pair() {
        let run1 = 665_893_000u128 - 658_322_000;
        let run2 = 697_397_000u128 - 689_438_000;
        let run3 = 662_903_000u128 - 654_892_000;
        assert_eq!(run1, 7_571_000, "median duration minus median hold is run 1");
        assert_eq!(run2, 7_959_000);
        assert_eq!(run3, 8_011_000);
        let mut gaps = [run1, run2, run3];
        gaps.sort_unstable();
        assert_eq!(gaps[1], run2, "median of the per-run gaps");
        assert_ne!(gaps[1], run1);
    }

    /// `PRE_LOCK_SPREAD` has to cover run 2's hold paired with run 3's larger gap.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn pre_lock_spread_covers_run2_hold_plus_run3_gap_before_the_block_reserve() {
        let run3_gap = 8_011_000u128;
        let median_run_pair = 7_571_000u128;
        let spread = run3_gap - median_run_pair;
        assert_eq!(spread, 440_000, "8.011 − 7.571 = 0.440 ms");
        assert_eq!(PRE_LOCK_SPREAD.as_nanos(), spread);

        let pairing_ns = 689_438_000u128
            + run3_gap
            + GROUP_COMMIT_BATCH.as_nanos()
            + slashing::GroupCommitConfig::DEFAULT_WAIT_TO_FILL.as_nanos();
        assert_eq!(pairing_ns, 704_467_000, "run-2 hold + run-3 gap + one batch + fill wait");
        let pairing = Duration::from_nanos(u64::try_from(pairing_ns).unwrap());

        let (open, close_ms) = window_offsets_ms();
        assert_eq!(close_ms, 11_800, "the block reserve is slot end minus 200 ms");
        let fix = clock_at(open);
        let slot_origin = Instant::now();
        let admission =
            fix.gate.admit(HISTORY_ROWS_10MB).await.expect("the measured 10 MB shape fits");
        let reserve = slot_origin + Duration::from_millis(close_ms - open);
        let end = admission.latest_start.checked_add(pairing).expect("pairing end");
        let slack = reserve.saturating_duration_since(end);
        assert!(
            end <= reserve && slack >= Duration::from_millis(1),
            "the cross-run pairing must end at least 1 ms before 11_800 ms, slack {slack:?}"
        );
        drop(admission.guard);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn saturated_estimate_before_genesis_is_refused() {
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_current_time(GENESIS - 30);
        assert!(matches!(clock.current_slot(), Err(TimingError::BeforeGenesis { .. })));
        let gate = ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>);
        let admission = tokio::select! {
            biased;
            result = gate.admit(usize::MAX) => result,
            _ = tokio::task::yield_now() => panic!("a saturated estimate must be refused before genesis, not slept on"),
        };
        let err = admission.expect_err("saturated estimate before genesis");
        assert!(matches!(err, ImportDeferralError::NoFreeWindow { .. }), "{err}");
    }

    /// `time_until_slot(0)` is `genesis*1000`. Overflow must refuse import, not wrap.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn genesis_ms_overflow_before_genesis_refuses_import() {
        let genesis = (u64::MAX / 1000) + 1;
        let clock = Arc::new(MockSlotClock::new(genesis, Duration::from_secs(12), 32));
        clock.set_current_time_ms(0);
        // Genesis cannot be represented in milliseconds, so the slot clock
        // fails closed instead of reporting a pre-genesis epoch.
        assert!(matches!(clock.current_slot(), Err(TimingError::TimeOverflow)));
        assert!(matches!(clock.time_until_slot(0), Err(TimingError::TimeOverflow)));
        let gate = ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>);
        let err = gate.admit(1).await.expect_err("overflow must refuse import");
        assert!(matches!(err, ImportDeferralError::Clock(TimingError::TimeOverflow)), "{err}");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn pre_genesis_admission_finishes_at_or_before_genesis() {
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_current_time(GENESIS - 10);
        let gate = ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>);
        let started = Instant::now();
        let admission = gate.admit(1).await.expect("one row finishes well before genesis");
        assert_eq!(Instant::now(), started, "a hold that fits before genesis does not wait");
        let finish = admission.latest_start.checked_add(admission.estimated_hold).expect("finish");
        let genesis_at = started + Duration::from_secs(10);
        assert!(finish <= genesis_at, "latest_start + estimate must fall at or before genesis");
        drop(admission.guard);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn pre_genesis_hold_that_crosses_genesis_uses_the_slot0_window() {
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_current_time_ms(GENESIS * 1000 - 5);
        assert!(matches!(clock.current_slot(), Err(TimingError::BeforeGenesis { .. })));
        let gate = Arc::new(ImportWindowGate::new(Arc::clone(&clock) as Arc<dyn SlotClock>));
        let (open, _) = window_offsets_ms();
        let started = Instant::now();
        let deferred = gate.admit(HISTORY_ROWS_10MB);
        tokio::pin!(deferred);
        assert!(
            poll_pending(deferred.as_mut()).await,
            "a hold longer than the time to genesis must not be admitted immediately"
        );
        let until_open = Duration::from_millis(5 + open);
        tokio::time::advance(until_open - Duration::from_millis(1)).await;
        assert!(
            poll_pending(deferred.as_mut()).await,
            "still waiting one millisecond before slot 0's free window"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let admission = deferred.await.expect("admitted when slot 0's free window opens");
        assert_eq!(Instant::now().saturating_duration_since(started), until_open);
        drop(admission.guard);
    }

    /// Scaled margin, load, shape, and a 1 ms quantum, anchored at 11_800 ms.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn largest_admissible_payload_ends_one_ms_before_the_block_reserve() {
        let (open, close_ms) = window_offsets_ms();
        assert_eq!(close_ms, 11_800);
        let window = Duration::from_millis(close_ms - open);
        let rows = max_rows_fitting(window);
        assert!(row_estimate(rows) <= window);
        assert!(row_estimate(rows + 1) > window);

        let row_hold = hold_ns(rows);
        let pre_lock = PER_ROW_PRE_LOCK.as_nanos() * u128::try_from(rows).unwrap();
        // Measured parse is spread over two history rows per validator.
        let pre_lock_budget = pre_lock.saturating_mul(2);
        let slow = ceil_div(row_hold * 31_116, 658_322);
        let spread = ceil_div(pre_lock_budget * 440, 7_571);
        let proportional = slow + spread;
        let fixed = 31_116_000u128 + 440_000;
        assert!(proportional > fixed, "the largest payload must be past the fixed 10 MB margin");
        let margin = proportional.max(fixed);
        let load = ceil_div(row_hold * 165_480_586, 658_318_414);
        let shape = ceil_div(row_hold, 5);
        let modeled = row_hold
            + pre_lock_budget
            + margin
            + load
            + shape
            + GROUP_COMMIT_BATCH.as_nanos()
            + slashing::GroupCommitConfig::DEFAULT_WAIT_TO_FILL.as_nanos();
        let estimate = row_estimate(rows).as_nanos();
        assert!(
            estimate >= modeled + 1_000_000,
            "estimate {estimate} must cover the scaled model {modeled} plus a 1 ms allowance"
        );

        let latest_ns = u128::from(close_ms) * 1_000_000 - estimate;
        let offset_ms = u64::try_from(latest_ns / 1_000_000).unwrap();
        assert!(offset_ms >= open, "latest start stays inside the free window");
        let fix = clock_at(offset_ms);
        let started = Instant::now();
        let admission =
            fix.gate.admit(rows).await.expect("the largest fitting payload is admitted");
        assert_eq!(
            Instant::now(),
            started,
            "admission at the latest fitting instant does not sleep"
        );
        let reserve = started + Duration::from_millis(close_ms - offset_ms);
        let end = admission
            .latest_start
            .checked_add(Duration::from_nanos(u64::try_from(modeled).unwrap()))
            .expect("modeled end");
        let slack = reserve.saturating_duration_since(end);
        assert!(
            slack >= Duration::from_millis(1),
            "the scaled model must end at least 1 ms before 11_800 ms, slack {slack:?}"
        );
        drop(admission.guard);
    }

    /// Loaded N=200 `conn_hold_ms` samples.
    ///
    /// The first list sized the load margin (2026-10-08). The second is the
    /// clean re-record in `m3-scheduled-path.md` (2026-10-12).
    #[test]
    fn measured_loaded_holds_fit_inside_the_estimate() {
        // 2026-10-08 dirty-tree samples. 823.799 ms sizes `LOAD_MARGIN_NUM`.
        let sizing_ns = [
            735_628_000u128,
            745_365_000,
            767_944_000,
            809_942_000,
            762_694_000,
            749_278_000,
            823_799_000,
            752_647_000,
            805_730_000,
        ];
        // 2026-10-12 clean re-record (`m3-scheduled-path.md`).
        let rerecord_ns = [
            787_345_000u128,
            769_013_000,
            743_446_000,
            725_529_000,
            713_176_000,
            713_599_000,
            679_854_000,
            727_203_000,
            712_291_000,
        ];
        let loaded_ns: Vec<u128> = sizing_ns.into_iter().chain(rerecord_ns).collect();
        let estimate = row_estimate(HISTORY_ROWS_10MB).as_nanos();
        let slowest = loaded_ns.iter().copied().max().unwrap();
        assert!(
            estimate >= slowest,
            "estimate {estimate} ns does not cover the slowest loaded hold {slowest} ns"
        );
        for sample in loaded_ns {
            assert!(estimate >= sample, "loaded hold {sample} ns exceeds estimate {estimate} ns");
        }
    }

    #[test]
    fn zero_row_estimate_includes_spread_and_quantum_before_truncation() {
        let ns = row_estimate(0).as_nanos();
        let floor = 12_311u128 + 31_116_000 + 440_000 + 6_018_000 + 1_000_000 + 1_000_000;
        assert!(
            ns >= floor,
            "zero-row estimate {ns} is below the spread-and-quantum floor {floor}"
        );
        let truncated_with = ns / 1_000_000;
        let truncated_without = (ns - 440_000 - 1_000_000) / 1_000_000;
        assert_ne!(
            truncated_with, truncated_without,
            "PRE_LOCK_SPREAD and the 1 ms allowance must survive millisecond truncation"
        );
    }
}
