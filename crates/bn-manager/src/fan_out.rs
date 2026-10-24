//! Per-BN fan-out. Each attempt is bounded by the operation budget.
//!
//! `first_ok` returns on the first complete success and drains the rest. A
//! partial `Ok` (for example a 400 that lists failed attestations) does not
//! return early. Once any beacon node has accepted, the remaining publishes
//! move to a detached task the caller cannot cancel, and the caller waits
//! for a full success on a channel. That wait ends
//! [`CALLER_CUTOFF_MARGIN`] before the caller's publish deadline, so this
//! task returns the known partial before the outer timeout cancels the wait.
//! If that outer timeout still wins, its error path keeps the same partial.
//! A later beacon node with fewer failures replaces that shared partial, and
//! the cutoff reads the replacement. If none completes, the best partial is
//! returned. `all` waits for every BN so a merge can see a late answer.
//! `best_of` returns blocks in hand at the soft deadline. A block is in hand
//! only when the caller's `in_hand` predicate says so. A candidate the caller
//! rejects does not count, and a penalized candidate is kept without closing
//! the soft window. If none are in hand, the round waits until every attempt
//! has finished or the hard deadline passes. In-flight attempts at return
//! keep running on a detached drain, and a late hard reject is logged there.
//! Health samples are queued with `try_send` and do not block the result or
//! the drain.
//!
//! [`HEALTH_SAMPLE_CAP`] limits how many of those drains record health at
//! once. It does not limit sends. A full pool still runs every remaining
//! publish and does not cancel it. Those overflow drains end at the attempt
//! budget, or at the HTTP client timeout when no budget is set (ADR-001).
//! A full pool still offers an error or a timeout to the recorder. Only a
//! success health sample may be skipped for that reason, and that skip is
//! counted. A broadcast skip increments
//! `rvc_bn_broadcast_drain_health_skipped_total`. A best-of drain skip
//! increments `rvc_bn_best_of_drain_health_skipped_total`. The 16-permit
//! pool is shared.
//!
//! Finished samples are queued to one recorder on that runtime with
//! `try_send`. The attempt result does not wait on that queue. When that
//! queue is full, an error or a timeout sample can be dropped. The drop is
//! counted on that path's skip counter. A hard reject is
//! [`crate::manager::TrackerOutcome::Rejected`]: the health score does not
//! move. A fee-only penalty is a success.
//! Cancelling the caller does not drop a sample that was already queued.
//! Process shutdown drops that unregistered recorder and any overflow drain,
//! so a queued sample or an in-flight overflow publish is not kept. The
//! overflow gauge drops when the HTTP call finishes, before the health sample
//! is queued.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use beacon::BeaconError;
use futures::stream::{FuturesUnordered, StreamExt};
use observability::logging::RedactedUrl;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{trace, warn, Instrument};

use crate::broadcast::{BnOutcome, BroadcastResult};
use crate::health::SharedHealthTrackers;
use crate::manager::{
    await_attempt, error_outcome, log_partial_failure_endpoints, record_outcomes, BoxFut,
    TrackerOutcome,
};

/// Detached drains that may record health at once.
///
/// This caps health recording, not sends. A further drain still runs the
/// publish. Only a success sample is skipped. An error or a timeout is still
/// recorded when the recorder queue accepts it.
pub(crate) const HEALTH_SAMPLE_CAP: usize = 16;

/// Added to the operation budget for the outer `with_op_timeout` backstop.
pub const BACKSTOP_MARGIN: Duration = Duration::from_millis(250);

/// How long before [`ATTESTATION_PUBLISH`]'s deadline the caller returns.
///
/// This is an intentional race against the orchestrator's outer `timeout_at`
/// on that same deadline. Returning this early lets this task deliver the
/// known partial as `Ok` before that timeout cancels the wait. If the outer
/// timeout still wins, its `Err` path reads the same shared partial and keeps
/// it. The detached publishes keep running either way.
const CALLER_CUTOFF_MARGIN: Duration = Duration::from_millis(50);

/// Best attestation result the caller can keep if its deadline cancels the wait.
#[derive(Clone, Debug)]
pub struct KnownAttestationPublish {
    pub endpoint: String,
    pub result: beacon::SubmitAttestationResult,
}

/// Deadline and partial slot for one attestation publish.
///
/// Set by the orchestrator around the propagate call. Fan-out reads it on
/// that same task.
#[derive(Clone)]
pub struct AttestationPublishContext {
    pub deadline: tokio::time::Instant,
    pub known: Arc<std::sync::Mutex<Option<KnownAttestationPublish>>>,
}

tokio::task_local! {
    pub static ATTESTATION_PUBLISH: AttestationPublishContext;
}

/// Health samples waiting on the single recorder. A full queue skips the
/// sample and counts it. The attempt does not wait.
const RECORDER_QUEUE_CAP: usize = 64;

/// Outer broadcast backstop. `None` stays unbounded, as when no budget is set.
pub(crate) fn broadcast_backstop(budget: Option<Duration>) -> Option<Duration> {
    budget.map(|budget| budget.saturating_add(BACKSTOP_MARGIN))
}

/// Soft deadline for best-of block production: half the operation budget.
pub(crate) fn soft_deadline(budget: Duration) -> Duration {
    budget / 2
}

/// Soft and hard deadlines for [`best_of`]. Both `None` waits for every attempt.
pub(crate) struct BestWindow {
    pub soft: Option<Duration>,
    pub hard: Option<Duration>,
}

/// Blocks collected by [`best_of`] before it returned.
pub(crate) struct BestRound<T> {
    /// In-hand successes, in arrival order. The caller ranks them.
    pub values: Vec<(usize, T)>,
    /// Accepted successes that are not in hand, in arrival order.
    ///
    /// A fee-penalized block lives here. It does not close the soft window.
    pub held: Vec<(usize, T)>,
    /// Highest-index transport error. A hard reject does not take this slot.
    /// [`BeaconError::RevokedInFlight`] does not take it either.
    pub last_error: Option<(usize, BeaconError)>,
    /// Hard rejects in arrival order. A fee-only penalty is not an entry.
    pub rejections: Vec<(usize, &'static str)>,
}

/// Static label for one hard reject.
pub(crate) type LabelFn<T> = std::sync::Arc<dyn Fn(&T) -> &'static str + Send + Sync>;

/// One `'static` attempt. The future owns a cloned [`beacon::BeaconClient`]
/// and the `Arc` payload the caller moved in.
pub(crate) struct BnAttempt<T> {
    pub index: usize,
    pub endpoint: String,
    pub fut: BoxFut<'static, T>,
}

struct Finished<T> {
    index: usize,
    outcome: BnOutcome<T>,
}

/// Caps how many detached drains record health at once. Sends are not capped.
pub(crate) struct DrainPool {
    permits: Arc<Semaphore>,
    skipped: Arc<AtomicU64>,
}

impl DrainPool {
    pub(crate) fn new(cap: usize) -> Self {
        Self { permits: Arc::new(Semaphore::new(cap)), skipped: Arc::new(AtomicU64::new(0)) }
    }

    /// Permits still free. The drain holds one until it finishes.
    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Health samples skipped because the pool was full.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    /// A permit while one is free. `None` means the pool is full.
    ///
    /// The caller still runs the drain when this returns `None`. Only a success
    /// health sample is skipped. An error or a timeout is still recorded when
    /// the recorder queue accepts it.
    pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().ok()
    }

    fn skip_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.skipped)
    }
}

pub(crate) fn global_drain_pool() -> &'static DrainPool {
    static POOL: std::sync::OnceLock<DrainPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| DrainPool::new(HEALTH_SAMPLE_CAP))
}

/// Which `Ok` may return early, and which partial to keep otherwise.
#[derive(Clone, Copy)]
pub(crate) struct PublishPolicy<T> {
    is_complete: fn(&T) -> bool,
    /// `true` when `candidate` is a better partial than `current`.
    prefer_partial: fn(current: &T, candidate: &T) -> bool,
    /// Stores a partial the caller can keep if its deadline cancels the wait.
    ///
    /// Called again for each better partial, including from the detached driver.
    remember_partial: fn(endpoint: &str, value: &T),
    /// Reads the partial stored for this publish.
    recall_partial: fn() -> Option<(String, T)>,
}

fn always_complete<T>(_: &T) -> bool {
    true
}

fn keep_first_partial<T>(_: &T, _: &T) -> bool {
    false
}

fn remember_nothing<T>(_: &str, _: &T) {}

fn recall_nothing<T>() -> Option<(String, T)> {
    None
}

impl<T> PublishPolicy<T> {
    /// Every `Ok` is complete. The first one returns.
    pub(crate) fn any_ok() -> Self {
        Self {
            is_complete: always_complete::<T>,
            prefer_partial: keep_first_partial::<T>,
            remember_partial: remember_nothing::<T>,
            recall_partial: recall_nothing::<T>,
        }
    }
}

fn prefer_fewer_attestation_failures(
    current: &beacon::SubmitAttestationResult,
    candidate: &beacon::SubmitAttestationResult,
) -> bool {
    candidate.failures().len() < current.failures().len()
}

fn remember_attestation_partial(endpoint: &str, value: &beacon::SubmitAttestationResult) {
    let _ = ATTESTATION_PUBLISH.try_with(|ctx| {
        *ctx.known.lock().expect("known attestation") =
            Some(KnownAttestationPublish { endpoint: endpoint.to_string(), result: value.clone() });
    });
}

fn recall_attestation_partial() -> Option<(String, beacon::SubmitAttestationResult)> {
    ATTESTATION_PUBLISH
        .try_with(|ctx| {
            ctx.known
                .lock()
                .expect("known attestation")
                .as_ref()
                .map(|known| (known.endpoint.clone(), known.result.clone()))
        })
        .ok()
        .flatten()
}

impl PublishPolicy<beacon::SubmitAttestationResult> {
    /// A 400 partial failure is not complete. Fewer failed indices wins if
    /// no beacon node accepts the whole batch.
    pub(crate) fn attestation() -> Self {
        Self {
            is_complete: beacon::SubmitAttestationResult::is_success,
            prefer_partial: prefer_fewer_attestation_failures,
            remember_partial: remember_attestation_partial,
            recall_partial: recall_attestation_partial,
        }
    }
}

/// Return the first complete `Ok`, treating every `Ok` as complete.
///
/// Test helper. Production passes [`PublishPolicy`] to [`first_ok_with`].
#[cfg(test)]
pub(crate) async fn first_ok<T: Clone + Send + 'static>(
    op_name: &str,
    role: &str,
    attempts: Vec<BnAttempt<T>>,
    budget: Option<Duration>,
    health: &SharedHealthTrackers,
    pool: &DrainPool,
) -> Result<(String, T), BeaconError> {
    first_ok_with(op_name, role, attempts, budget, health, pool, PublishPolicy::any_ok()).await
}

/// Return the first complete `Ok`. Later attempts keep running on the drain.
///
/// [`PublishPolicy::any_ok`] treats every `Ok` as complete. [`PublishPolicy::attestation`]
/// does not: a 400 partial failure waits until a full acceptance or every
/// attempt finishes (each one ends at `budget`, or at the HTTP client timeout
/// when no budget is set). The best partial is returned when nothing completes.
/// Every BN failing returns the error from the highest index. An empty attempt
/// list is [`BeaconError::NoEligibleBn`].
pub(crate) async fn first_ok_with<T: Clone + Send + 'static>(
    op_name: &str,
    role: &str,
    attempts: Vec<BnAttempt<T>>,
    budget: Option<Duration>,
    health: &SharedHealthTrackers,
    pool: &DrainPool,
    policy: PublishPolicy<T>,
) -> Result<(String, T), BeaconError> {
    if attempts.is_empty() {
        return Err(no_eligible(op_name, role));
    }

    // True until a full pool decides that still-pending successes skip health.
    // Attempts that have already finished observed `true` and queued their
    // sample before this is cleared. Errors and timeouts ignore the flag.
    let record = Arc::new(AtomicBool::new(true));
    let skipped = pool.skip_counter();
    let mut slots: Vec<Option<Tracked<T>>> = attempts
        .into_iter()
        .map(|attempt| {
            Some(attempt_fut(
                op_name,
                budget,
                attempt,
                health,
                Arc::clone(&record),
                Arc::clone(&skipped),
            ))
        })
        .collect();
    let mut earlier = Vec::new();
    let mut winner = None;
    let mut best_partial = None;
    // Poll every attempt once before returning. A fast 200 must not skip the
    // other BNs on the first poll.
    std::future::poll_fn(|cx| {
        for slot in slots.iter_mut() {
            let Some(tracked) = slot.as_mut() else { continue };
            if let Poll::Ready(finished) = tracked.fut.as_mut().poll(cx) {
                *slot = None;
                note_finished(finished, &policy, &mut earlier, &mut winner, &mut best_partial);
            }
        }
        Poll::Ready(())
    })
    .await;

    let mut pending: Vec<Tracked<T>> = slots.into_iter().flatten().collect();

    // Errors stay on the caller until something is accepted. A partial `Ok`
    // is an acceptance: the remaining sends must leave this task before the
    // next await, or the caller's timeout drops them.
    if winner.is_none() && best_partial.is_none() {
        while let Some(finished) = next_finished(&mut pending).await {
            let complete = is_complete_ok(&finished, &policy);
            note_finished(finished, &policy, &mut earlier, &mut winner, &mut best_partial);
            if complete || best_partial.is_some() {
                break;
            }
        }
    }

    if let Some(winner) = winner {
        if let Some(partial) = best_partial.take() {
            earlier.push(partial);
        }
        return Ok(finish_ok(winner, earlier, pending, op_name, &record, pool));
    }

    if let Some(partial) = best_partial {
        if pending.is_empty() {
            return Ok(finish_ok(partial, earlier, pending, op_name, &record, pool));
        }
        return wait_for_complete_detached(
            partial, earlier, pending, op_name, policy, &record, pool,
        )
        .await;
    }

    earlier.sort_by_key(|finished| finished.index);
    let last = earlier.pop().expect("non-empty fan-out yields an outcome");
    match last.outcome.result {
        Err(err) => Err(err),
        Ok(_) => unreachable!("an Ok returns before the all-fail path"),
    }
}

type AttemptFut<T> = Pin<Box<dyn Future<Output = Finished<T>> + Send>>;

struct Tracked<T> {
    endpoint: String,
    fut: AttemptFut<T>,
    /// Set when this publish is past the health-sample cap. Dropped when the
    /// HTTP call finishes, before the health sample is queued.
    overflow: Arc<Mutex<Option<OverflowGuard>>>,
}

fn is_complete_ok<T>(finished: &Finished<T>, policy: &PublishPolicy<T>) -> bool {
    match &finished.outcome.result {
        Ok(value) => (policy.is_complete)(value),
        Err(_) => false,
    }
}

fn note_finished<T>(
    finished: Finished<T>,
    policy: &PublishPolicy<T>,
    earlier: &mut Vec<Finished<T>>,
    winner: &mut Option<Finished<T>>,
    best_partial: &mut Option<Finished<T>>,
) {
    let complete = is_complete_ok(&finished, policy);
    let partial = finished.outcome.result.is_ok() && !complete;
    if complete && winner.is_none() {
        *winner = Some(finished);
        return;
    }
    if partial {
        let better = match best_partial.as_ref() {
            Some(current) => match (&current.outcome.result, &finished.outcome.result) {
                (Ok(current_value), Ok(candidate)) => {
                    (policy.prefer_partial)(current_value, candidate)
                }
                _ => false,
            },
            None => true,
        };
        if better {
            if let Ok(value) = finished.outcome.result.as_ref() {
                (policy.remember_partial)(finished.outcome.endpoint.as_str(), value);
            }
            if let Some(previous) = best_partial.replace(finished) {
                earlier.push(previous);
            }
        } else {
            earlier.push(finished);
        }
        return;
    }
    earlier.push(finished);
}

/// Wait for every attempt. Each one is still bounded by `budget`.
///
/// Health is spawned from each attempt as it finishes, so this loop does not
/// take the health write lock between polls.
pub(crate) async fn all<T: Send + 'static>(
    op_name: &str,
    role: &str,
    attempts: Vec<BnAttempt<T>>,
    budget: Option<Duration>,
    health: &SharedHealthTrackers,
) -> Result<BroadcastResult<T>, BeaconError> {
    if attempts.is_empty() {
        return Err(no_eligible(op_name, role));
    }

    let record = Arc::new(AtomicBool::new(true));
    let skipped = Arc::new(AtomicU64::new(0));
    let mut pending = FuturesUnordered::new();
    for attempt in attempts {
        pending.push(
            attempt_fut(
                op_name,
                budget,
                attempt,
                health,
                Arc::clone(&record),
                Arc::clone(&skipped),
            )
            .fut,
        );
    }
    let mut finished = Vec::new();
    while let Some(item) = pending.next().await {
        finished.push(item);
    }
    finished.sort_by_key(|item| item.index);
    Ok(BroadcastResult { outcomes: finished.into_iter().map(|item| item.outcome).collect() })
}

/// Which `Ok` values stay in a best-of round, and how a rejection is logged.
///
/// The predicates are owned so the detached drain can log a late hard reject
/// after this round has returned.
type AcceptFn<T> = std::sync::Arc<dyn Fn(&T) -> bool + Send + Sync>;
type RejectFn<T> = std::sync::Arc<dyn Fn(usize, &str, &T) + Send + Sync>;

pub(crate) struct BestFilter<T> {
    /// Hard checks. `false` is dropped and passed to [`Self::on_reject`].
    /// A rejected `Ok` does not close the soft window.
    pub accept: AcceptFn<T>,
    /// In hand: hard checks and the right fee. Closes the soft window only
    /// together with [`Self::accept`].
    pub in_hand: AcceptFn<T>,
    pub on_reject: RejectFn<T>,
    /// Label for a value that fails [`Self::accept`].
    pub reject_label: LabelFn<T>,
}

impl<T> Clone for BestFilter<T> {
    fn clone(&self) -> Self {
        Self {
            accept: std::sync::Arc::clone(&self.accept),
            in_hand: std::sync::Arc::clone(&self.in_hand),
            on_reject: std::sync::Arc::clone(&self.on_reject),
            reject_label: std::sync::Arc::clone(&self.reject_label),
        }
    }
}

/// Collect `Ok` values under a soft deadline and a hard deadline.
///
/// `window.soft` and `window.hard` are both `None` when no budget is
/// configured: every attempt is awaited. Otherwise attempts are bounded by
/// `window.hard`. An `Ok` closes the soft window only when it passes both
/// [`BestFilter::accept`] and [`BestFilter::in_hand`], and that `Ok` is
/// returned in [`BestRound::values`]. An accepted `Ok` that is not in hand is
/// kept in [`BestRound::held`] and does not close the window. A rejected `Ok`
/// is logged and dropped, and it does not close the window. Order inside each
/// bucket is arrival order; the caller ranks the combined list. The round
/// returns at `window.soft` once a block is in hand, or sooner once every
/// attempt has finished. If none are in hand it waits until every attempt
/// finishes or `window.hard` passes. Finished samples are queued and this
/// function does not wait on the health write lock. Attempts still running go
/// to the drain; a hard reject there is logged, a timeout there is an error,
/// and the drain does not wait on that lock between polls. An empty attempt
/// list is [`BeaconError::NoEligibleBn`].
pub(crate) async fn best_of<T: Send + 'static>(
    op_name: &str,
    role: &str,
    attempts: Vec<BnAttempt<T>>,
    window: BestWindow,
    health: &SharedHealthTrackers,
    pool: &DrainPool,
    filter: &BestFilter<T>,
) -> Result<BestRound<T>, BeaconError> {
    if attempts.is_empty() {
        return Err(no_eligible(op_name, role));
    }

    let round_started = tokio::time::Instant::now();
    let hard = window.hard;
    let mut pending = attempts
        .into_iter()
        .map(|attempt| {
            let op_name = op_name.to_string();
            let span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(&attempt.endpoint),
            );
            Open {
                index: attempt.index,
                endpoint: attempt.endpoint,
                started: tokio::time::Instant::now(),
                fut: Box::pin(
                    async move { await_attempt(&op_name, hard, attempt.fut).await }
                        .instrument(span),
                ),
            }
        })
        .collect();
    let mut finished = Vec::new();
    collect_ready(&mut pending, &mut finished).await;
    let soft_return =
        wait_for_best(round_started, window.soft, &mut pending, &mut finished, filter).await;
    if soft_return {
        crate::metrics::RVC_BN_PRODUCE_SOFT_DEADLINE_RETURNS_TOTAL.inc();
    }

    for done in &finished {
        if let Some(outcome) = tracker_outcome(op_name, done, filter) {
            queue_health_sample(health, op_name, done.index, outcome);
        }
        log_best_failure(op_name, done);
        log_hard_reject(filter, done);
    }
    if !pending.is_empty() {
        detach_best_drain(op_name, pending, health, pool, filter.clone());
    }
    Ok(best_round(finished, filter))
}

struct Open<T> {
    index: usize,
    endpoint: String,
    started: tokio::time::Instant,
    fut: Pin<Box<dyn Future<Output = Result<T, BeaconError>> + Send>>,
}

struct Done<T> {
    index: usize,
    endpoint: String,
    result: Result<T, BeaconError>,
    latency: Duration,
}

fn tracker_outcome<T>(
    op_name: &str,
    done: &Done<T>,
    filter: &BestFilter<T>,
) -> Option<TrackerOutcome> {
    match &done.result {
        Ok(value) if !(filter.accept)(value) => Some(TrackerOutcome::Rejected),
        Ok(_) => Some(TrackerOutcome::Success(done.latency)),
        Err(BeaconError::RevokedInFlight) => None,
        Err(err) => Some(error_outcome(op_name, err)),
    }
}

fn log_best_failure<T>(op_name: &str, done: &Done<T>) {
    let Err(err) = &done.result else { return };
    warn!(
        op = op_name,
        bn_index = done.index,
        endpoint = %RedactedUrl(&done.endpoint),
        error = %err,
        "BN query failed in best-selection"
    );
}

fn log_hard_reject<T>(filter: &BestFilter<T>, done: &Done<T>) {
    let Ok(value) = &done.result else { return };
    if !(filter.accept)(value) {
        (filter.on_reject)(done.index, done.endpoint.as_str(), value);
    }
}

fn best_round<T>(finished: Vec<Done<T>>, filter: &BestFilter<T>) -> BestRound<T> {
    let mut values = Vec::new();
    let mut held = Vec::new();
    let mut rejections = Vec::new();
    let mut last_error: Option<(usize, BeaconError)> = None;
    for done in finished {
        match done.result {
            Ok(value) if closes_soft_window(&value, filter) => values.push((done.index, value)),
            Ok(value) if (filter.accept)(&value) => held.push((done.index, value)),
            Ok(value) => rejections.push((done.index, (filter.reject_label)(&value))),
            Err(BeaconError::RevokedInFlight) => {}
            Err(err) => {
                let replace = last_error.as_ref().is_none_or(|(index, _)| done.index >= *index);
                if replace {
                    last_error = Some((done.index, err));
                }
            }
        }
    }
    BestRound { values, held, last_error, rejections }
}

/// In hand and accepted. A block that fails [`BestFilter::accept`] does not
/// close the soft window, even when [`BestFilter::in_hand`] would be true.
fn closes_soft_window<T>(value: &T, filter: &BestFilter<T>) -> bool {
    (filter.accept)(value) && (filter.in_hand)(value)
}

fn in_hand<T>(done: &Done<T>, filter: &BestFilter<T>) -> bool {
    match &done.result {
        Ok(value) => closes_soft_window(value, filter),
        Err(_) => false,
    }
}

/// `true` when the round returned because of the soft deadline.
///
/// That is a block already in hand once the soft instant has passed, or the
/// first in-hand block after it. Every attempt finishing before that instant
/// returns `false`.
async fn wait_for_best<T>(
    round_started: tokio::time::Instant,
    soft: Option<Duration>,
    pending: &mut Vec<Open<T>>,
    finished: &mut Vec<Done<T>>,
    filter: &BestFilter<T>,
) -> bool {
    loop {
        if pending.is_empty() {
            return false;
        }
        if finished.iter().any(|done| in_hand(done, filter)) {
            if let Some(soft) = soft {
                let at = round_started + soft;
                if tokio::time::Instant::now() >= at {
                    collect_ready(pending, finished).await;
                    return true;
                }
                tokio::select! {
                    biased;
                    done = next_open(pending) => {
                        if let Some(done) = done {
                            finished.push(done);
                        }
                    }
                    _ = tokio::time::sleep_until(at) => {
                        collect_ready(pending, finished).await;
                        return true;
                    }
                }
                continue;
            }
        }

        let Some(done) = next_open(pending).await else { return false };
        let past_soft =
            soft.is_some_and(|soft| tokio::time::Instant::now() >= round_started + soft);
        let first_after_soft = in_hand(&done, filter) && past_soft;
        finished.push(done);
        if first_after_soft {
            collect_ready(pending, finished).await;
            return true;
        }
    }
}

async fn collect_ready<T>(pending: &mut Vec<Open<T>>, finished: &mut Vec<Done<T>>) {
    std::future::poll_fn(|cx| {
        let mut i = 0;
        while i < pending.len() {
            if let Poll::Ready(result) = pending[i].fut.as_mut().poll(cx) {
                let open = pending.swap_remove(i);
                finished.push(finish_open(open, result));
            } else {
                i += 1;
            }
        }
        Poll::Ready(())
    })
    .await;
}

async fn next_open<T>(pending: &mut Vec<Open<T>>) -> Option<Done<T>> {
    std::future::poll_fn(|cx| {
        if pending.is_empty() {
            return Poll::Ready(None);
        }
        for i in 0..pending.len() {
            if let Poll::Ready(result) = pending[i].fut.as_mut().poll(cx) {
                let open = pending.swap_remove(i);
                return Poll::Ready(Some(finish_open(open, result)));
            }
        }
        Poll::Pending
    })
    .await
}

fn finish_open<T>(open: Open<T>, result: Result<T, BeaconError>) -> Done<T> {
    Done { index: open.index, endpoint: open.endpoint, latency: open.started.elapsed(), result }
}

fn detach_best_drain<T: Send + 'static>(
    op_name: &str,
    pending: Vec<Open<T>>,
    health: &SharedHealthTrackers,
    pool: &DrainPool,
    filter: BestFilter<T>,
) {
    let permit = pool.try_acquire();
    let record_success = permit.is_some();
    if permit.is_none() {
        warn!(
            op = op_name,
            pending = pending.len(),
            "best-of drain health skipped; the drain pool is full"
        );
    }
    let op_name = op_name.to_string();
    let health = health.clone();
    spawn_detached(permit, async move {
        drain_best_of(pending, op_name, health, record_success, filter).await;
    });
}

async fn drain_best_of<T: Send>(
    mut pending: Vec<Open<T>>,
    op_name: String,
    health: SharedHealthTrackers,
    record_success: bool,
    filter: BestFilter<T>,
) {
    while let Some(done) = next_open(&mut pending).await {
        log_best_failure(&op_name, &done);
        log_hard_reject(&filter, &done);
        let Some(outcome) = tracker_outcome(&op_name, &done, &filter) else {
            continue;
        };
        if matches!(outcome, TrackerOutcome::Success(_)) && !record_success {
            crate::metrics::RVC_BN_BEST_OF_DRAIN_HEALTH_SKIPPED_TOTAL.inc();
            continue;
        }
        // Queue only. Waiting on the health write lock here stops the next
        // poll, so a later loser's hard-deadline timeout never gets a chance
        // to win against a late `Ok`.
        queue_health_sample(&health, &op_name, done.index, outcome);
    }
}

/// Queue one sample without waiting on the health write lock.
///
/// A full or closed recorder queue drops the sample and counts that drop.
/// The caller, including [`best_of`] and [`drain_best_of`], does not wait.
pub(crate) fn queue_health_sample(
    health: &SharedHealthTrackers,
    op_name: &str,
    index: usize,
    outcome: TrackerOutcome,
) {
    enqueue_health(
        &health_sender(),
        health.clone(),
        op_name.to_string(),
        index,
        outcome,
        SkipFamily::BestOf,
    );
}

#[cfg(test)]
static HEALTH_APPLIED: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static HEALTH_APPLIED_WAITERS: Mutex<Vec<std::task::Waker>> = Mutex::new(Vec::new());

#[cfg(test)]
fn note_health_applied() {
    let waiters = {
        let mut guard = HEALTH_APPLIED_WAITERS.lock().expect("health applied waiters");
        HEALTH_APPLIED.fetch_add(1, Ordering::Release);
        std::mem::take(&mut *guard)
    };
    for waker in waiters {
        waker.wake();
    }
}

/// Samples the recorder has applied on this process.
#[cfg(test)]
pub(crate) fn health_samples_applied() -> u64 {
    HEALTH_APPLIED.load(Ordering::Acquire)
}

/// Wait until the recorder has applied at least `target` samples.
///
/// The counter is read while the waiter list is held, and the increment
/// takes that same list, so a sample that lands during the check wakes this
/// wait. This does not sleep.
#[cfg(test)]
pub(crate) async fn wait_until_health_applied(target: u64) {
    std::future::poll_fn(|cx| {
        let mut guard = HEALTH_APPLIED_WAITERS.lock().expect("health applied waiters");
        if HEALTH_APPLIED.load(Ordering::Acquire) >= target {
            return Poll::Ready(());
        }
        guard.push(cx.waker().clone());
        Poll::Pending
    })
    .await;
}

fn no_eligible(op_name: &str, role: &str) -> BeaconError {
    warn!(
        op = op_name,
        role = %role,
        "no BNs eligible for broadcast; not publishing to off-role clients"
    );
    BeaconError::NoEligibleBn { operation: op_name.to_string(), role: role.to_string() }
}

fn failure_samples<T>(finished: &[Finished<T>]) -> Vec<(String, Duration)> {
    finished
        .iter()
        .filter(|item| item.outcome.result.is_err())
        .map(|item| (item.outcome.endpoint.clone(), item.outcome.latency))
        .collect()
}

fn attempt_fut<T: Send + 'static>(
    op_name: &str,
    budget: Option<Duration>,
    attempt: BnAttempt<T>,
    health: &SharedHealthTrackers,
    record: Arc<AtomicBool>,
    skipped: Arc<AtomicU64>,
) -> Tracked<T> {
    let overflow = Arc::new(Mutex::new(None));
    let endpoint = attempt.endpoint.clone();
    let fut = Box::pin(run_attempt(
        AttemptEnv {
            op_name: op_name.to_string(),
            budget,
            health: health.clone(),
            record,
            skipped,
            health_tx: health_sender(),
            overflow: Arc::clone(&overflow),
        },
        attempt,
    ));
    Tracked { endpoint, fut, overflow }
}

/// After a partial acceptance, finish the other publishes off the caller.
///
/// The oneshot is the only thing the caller waits on. Dropping it does not
/// drop the sends. When [`ATTESTATION_PUBLISH`] is set, the wait ends
/// [`CALLER_CUTOFF_MARGIN`] before that deadline and returns the shared
/// partial. That margin is a race against the outer timeout: this task
/// returns `Ok` first, and the timeout's `Err` path keeps the same partial
/// if it still wins. Each better partial replaces the shared value. The
/// detached driver runs inside the same task-local scope so those replacements
/// land in the slot the cutoff reads.
async fn wait_for_complete_detached<T: Clone + Send + 'static>(
    partial: Finished<T>,
    earlier: Vec<Finished<T>>,
    mut pending: Vec<Tracked<T>>,
    op_name: &str,
    policy: PublishPolicy<T>,
    record: &AtomicBool,
    pool: &DrainPool,
) -> Result<(String, T), BeaconError> {
    let known = match &partial.outcome.result {
        Ok(value) => {
            (policy.remember_partial)(&partial.outcome.endpoint, value);
            Some((partial.outcome.endpoint.clone(), value.clone()))
        }
        Err(_) => None,
    };
    let permit = pool.try_acquire();
    if permit.is_none() {
        record.store(false, Ordering::Release);
        warn!(
            op = op_name,
            pending = pending.len(),
            "broadcast drain health skipped; the drain pool is full"
        );
        pending = pending.into_iter().map(arm_overflow).collect();
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let op_name = op_name.to_string();
    // The spawned task does not inherit the task-local. Scope the same context
    // so a later, better partial replaces the shared slot.
    let publish = ATTESTATION_PUBLISH.try_with(Clone::clone).ok();
    let drive_policy = policy.clone();
    tokio::spawn(async move {
        let drive = drive_after_partial(Some(partial), earlier, pending, op_name, drive_policy, tx);
        if let Some(ctx) = publish {
            ATTESTATION_PUBLISH.scope(ctx, drive).await;
        } else {
            drive.await;
        }
        drop(permit);
    });
    let cutoff = ATTESTATION_PUBLISH.try_with(|ctx| caller_return_at(ctx.deadline)).ok();
    let have_known = known.is_some();
    tokio::select! {
        biased;
        result = rx => match result {
            Ok(result) => result,
            Err(_) => Err(BeaconError::HttpError(
                "broadcast lost the detached publish result".to_string(),
            )),
        },
        _ = sleep_until_cutoff(cutoff), if have_known && cutoff.is_some() => {
            Ok((policy.recall_partial)().or(known).expect("the cutoff branch keeps the partial"))
        }
    }
}

fn caller_return_at(deadline: tokio::time::Instant) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    let remaining = deadline.saturating_duration_since(now);
    if remaining <= CALLER_CUTOFF_MARGIN {
        now
    } else {
        deadline - CALLER_CUTOFF_MARGIN
    }
}

async fn sleep_until_cutoff(cutoff: Option<tokio::time::Instant>) {
    match cutoff {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn drive_after_partial<T: Send>(
    mut best_partial: Option<Finished<T>>,
    mut earlier: Vec<Finished<T>>,
    mut pending: Vec<Tracked<T>>,
    op_name: String,
    policy: PublishPolicy<T>,
    tx: tokio::sync::oneshot::Sender<Result<(String, T), BeaconError>>,
) {
    let mut tx = Some(tx);
    let mut winner = None;
    let mut reported = false;
    let mut successes = 1 + earlier.iter().filter(|item| item.outcome.result.is_ok()).count();
    while let Some(finished) = next_finished(&mut pending).await {
        if reported {
            if finished.outcome.result.is_err() {
                log_partial_failure_endpoints(
                    &op_name,
                    successes,
                    &[(finished.outcome.endpoint, finished.outcome.latency)],
                );
            } else {
                successes += 1;
            }
            continue;
        }
        let complete = is_complete_ok(&finished, &policy);
        note_finished(finished, &policy, &mut earlier, &mut winner, &mut best_partial);
        if !complete {
            continue;
        }
        if let Some(winner) = winner.take() {
            if let Some(partial) = best_partial.take() {
                earlier.push(partial);
            }
            successes = 1 + earlier.iter().filter(|item| item.outcome.result.is_ok()).count();
            reported = true;
            if let Some(tx) = tx.take() {
                let _ = tx.send(Ok(report_chosen(&op_name, winner, &earlier)));
            }
        }
    }
    if reported {
        return;
    }
    if let Some(partial) = best_partial.take() {
        if let Some(tx) = tx.take() {
            let _ = tx.send(Ok(report_chosen(&op_name, partial, &earlier)));
        }
        return;
    }
    earlier.sort_by_key(|finished| finished.index);
    if let Some(last) = earlier.pop() {
        let result = match last.outcome.result {
            Ok(value) => Ok((last.outcome.endpoint, value)),
            Err(err) => Err(err),
        };
        if let Some(tx) = tx.take() {
            let _ = tx.send(result);
        }
    }
}

/// Next finished attempt. Every pending future is polled, so a health write
/// lock inside one attempt cannot hide the others: recording does not await.
async fn next_finished<T>(pending: &mut Vec<Tracked<T>>) -> Option<Finished<T>> {
    std::future::poll_fn(|cx| {
        if pending.is_empty() {
            return Poll::Ready(None);
        }
        for i in 0..pending.len() {
            if let Poll::Ready(finished) = pending[i].fut.as_mut().poll(cx) {
                pending.swap_remove(i);
                return Poll::Ready(Some(finished));
            }
        }
        Poll::Pending
    })
    .await
}

/// Return `chosen` and keep every remaining publish running.
fn finish_ok<T: Send + 'static>(
    chosen: Finished<T>,
    earlier: Vec<Finished<T>>,
    pending: Vec<Tracked<T>>,
    op_name: &str,
    record: &AtomicBool,
    pool: &DrainPool,
) -> (String, T) {
    let successes = 1 + earlier.iter().filter(|item| item.outcome.result.is_ok()).count();
    let (endpoint, value) = report_chosen(op_name, chosen, &earlier);
    // Chosen and earlier samples were queued inside `run_attempt` while
    // `record` was still set. They are not part of this drain.
    if !pending.is_empty() {
        let pending_len = pending.len();
        match pool.try_acquire() {
            Some(permit) => {
                let drain =
                    drain_pending(pending_futs(pending, false), op_name.to_string(), successes);
                spawn_detached(Some(permit), drain);
            }
            None => {
                record.store(false, Ordering::Release);
                warn!(
                    op = op_name,
                    pending = pending_len,
                    "broadcast drain health skipped; the drain pool is full"
                );
                let drain =
                    drain_pending(pending_futs(pending, true), op_name.to_string(), successes);
                spawn_detached(None, drain);
            }
        }
    }
    (endpoint, value)
}

fn report_chosen<T>(op_name: &str, chosen: Finished<T>, earlier: &[Finished<T>]) -> (String, T) {
    let successes = 1 + earlier.iter().filter(|item| item.outcome.result.is_ok()).count();
    let failures = failure_samples(earlier);
    if !failures.is_empty() {
        log_partial_failure_endpoints(op_name, successes, &failures);
    }
    let Finished { outcome, .. } = chosen;
    match outcome.result {
        Ok(value) => (outcome.endpoint, value),
        Err(_) => unreachable!("an error is stored in earlier"),
    }
}

fn pending_futs<T: Send + 'static>(
    pending: Vec<Tracked<T>>,
    overflow: bool,
) -> FuturesUnordered<AttemptFut<T>> {
    let futs = FuturesUnordered::new();
    for tracked in pending {
        let tracked = if overflow { arm_overflow(tracked) } else { tracked };
        futs.push(tracked.fut);
    }
    futs
}

/// Log outcomes that finish after the winner has already been returned.
///
/// Recording is queued inside [`run_attempt`]. This loop only logs, so a
/// health write lock cannot stall the next poll.
async fn drain_pending<T: Send>(
    mut pending: FuturesUnordered<AttemptFut<T>>,
    op_name: String,
    mut successes: usize,
) {
    while let Some(finished) = pending.next().await {
        if finished.outcome.result.is_err() {
            log_partial_failure_endpoints(
                &op_name,
                successes,
                &[(finished.outcome.endpoint, finished.outcome.latency)],
            );
        } else {
            successes += 1;
        }
    }
}

/// Run `fut` to completion. `permit` is held until it finishes. `None` still
/// runs `fut`: a full pool skips success samples, it does not cancel the publish.
/// The task is not registered with the executor (ADR-001). Shutdown drops it.
fn spawn_detached<F>(permit: Option<OwnedSemaphorePermit>, fut: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        fut.await;
        drop(permit);
    });
}

/// Counts one in-flight overflow publish for a redacted endpoint. Drop
/// (completion, cancel, or shutdown) removes that count. The publish itself
/// is not cancelled by the health-sample cap.
struct OverflowGuard(String);

impl Drop for OverflowGuard {
    fn drop(&mut self) {
        crate::metrics::RVC_BN_BROADCAST_OVERFLOW_DRAINS
            .with_label_values(&[self.0.as_str()])
            .dec();
    }
}

fn arm_overflow<T>(tracked: Tracked<T>) -> Tracked<T> {
    let label = crate::metrics::endpoint_label(&tracked.endpoint);
    crate::metrics::RVC_BN_BROADCAST_OVERFLOW_DRAINS.with_label_values(&[label.as_str()]).inc();
    *tracked.overflow.lock().expect("overflow guard") = Some(OverflowGuard(label));
    tracked
}

struct HealthSample {
    health: SharedHealthTrackers,
    op_name: String,
    index: usize,
    outcome: TrackerOutcome,
}

struct HealthRecorder {
    runtime_id: tokio::runtime::Id,
    tx: tokio::sync::mpsc::Sender<HealthSample>,
}

/// One task per runtime applies samples in enqueue order. `try_send` never
/// waits. A sample that does not fit is counted and dropped, so an error or
/// a timeout cannot pin the attempt result to the queue.
///
/// The task is not registered with the executor. Process shutdown, or the
/// end of a test runtime, drops it, so a queued sample is not kept. A later
/// call on a new runtime starts a fresh recorder.
fn health_sender() -> tokio::sync::mpsc::Sender<HealthSample> {
    static RECORDER: std::sync::Mutex<Option<HealthRecorder>> = std::sync::Mutex::new(None);
    let runtime_id = tokio::runtime::Handle::current().id();
    let mut slot = RECORDER.lock().expect("health recorder lock");
    if let Some(recorder) = slot.as_ref() {
        if recorder.runtime_id == runtime_id && !recorder.tx.is_closed() {
            return recorder.tx.clone();
        }
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<HealthSample>(RECORDER_QUEUE_CAP);
    tokio::spawn(async move {
        while let Some(sample) = rx.recv().await {
            record_outcomes(&sample.health, &sample.op_name, &[(sample.index, sample.outcome)])
                .await;
            #[cfg(test)]
            note_health_applied();
        }
    });
    *slot = Some(HealthRecorder { runtime_id, tx: tx.clone() });
    tx
}

struct AttemptEnv {
    op_name: String,
    budget: Option<Duration>,
    health: SharedHealthTrackers,
    record: Arc<AtomicBool>,
    skipped: Arc<AtomicU64>,
    health_tx: tokio::sync::mpsc::Sender<HealthSample>,
    overflow: Arc<Mutex<Option<OverflowGuard>>>,
}

/// Queue one sample without waiting. A full or closed queue drops the sample,
/// including an error or a timeout, and counts that drop.
enum SkipFamily {
    Broadcast,
    BestOf,
}

fn note_queue_skip(family: SkipFamily) {
    match family {
        SkipFamily::Broadcast => {
            crate::metrics::RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.inc();
        }
        SkipFamily::BestOf => {
            crate::metrics::RVC_BN_BEST_OF_DRAIN_HEALTH_SKIPPED_TOTAL.inc();
        }
    }
}

fn enqueue_health(
    tx: &tokio::sync::mpsc::Sender<HealthSample>,
    health: SharedHealthTrackers,
    op_name: String,
    index: usize,
    outcome: TrackerOutcome,
    family: SkipFamily,
) {
    let sample = HealthSample { health, op_name, index, outcome };
    if tx.try_send(sample).is_err() {
        note_queue_skip(family);
    }
}

/// Run one attempt.
///
/// The overflow gauge, when armed, drops as soon as the network call returns
/// and before the health sample is queued. Health uses [`enqueue_health`], so
/// a full queue cannot block this result. A full health-sample pool skips a
/// success. An error or a timeout is still offered to the recorder.
async fn run_attempt<T: Send>(env: AttemptEnv, attempt: BnAttempt<T>) -> Finished<T> {
    let span = tracing::info_span!(
        "bn.attempt",
        bn_url = %RedactedUrl(&attempt.endpoint),
    );
    let index = attempt.index;
    let endpoint = attempt.endpoint;
    let start = tokio::time::Instant::now();
    let result =
        Instrument::instrument(await_attempt(&env.op_name, env.budget, attempt.fut), span).await;
    // The HTTP call is finished. Drop the gauge before the queue, and do not
    // hold the mutex across that enqueue.
    let overflow = env.overflow.lock().expect("overflow guard").take();
    drop(overflow);
    let elapsed = start.elapsed();
    let tracker = match &result {
        Ok(_) => {
            trace!(
                op = %env.op_name,
                bn_index = index,
                endpoint = %RedactedUrl(&endpoint),
                "broadcast succeeded on BN"
            );
            TrackerOutcome::Success(elapsed)
        }
        Err(err) => {
            warn!(
                op = %env.op_name,
                bn_index = index,
                endpoint = %RedactedUrl(&endpoint),
                error = %err,
                "broadcast failed on BN"
            );
            error_outcome(&env.op_name, err)
        }
    };
    // A success `try_send` returns before the recorder takes the write lock,
    // so the caller can return while that lock is held. Cancelling the caller
    // does not drop a sample already queued. Process shutdown still drops the
    // recorder. A full pool clears `record` only after finished attempts have
    // passed this line; a success still pending then skips. Errors and
    // timeouts are offered anyway, and a full queue counts that drop here.
    let success = matches!(tracker, TrackerOutcome::Success(_));
    if success && !env.record.load(Ordering::Acquire) {
        env.skipped.fetch_add(1, Ordering::Relaxed);
        crate::metrics::RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.inc();
    } else {
        enqueue_health(
            &env.health_tx,
            env.health,
            env.op_name,
            index,
            tracker,
            SkipFamily::Broadcast,
        );
    }
    Finished { index, outcome: BnOutcome { endpoint, result, latency: elapsed } }
}

/// One fast partial and one caller-supplied attempt, through [`first_ok_with`].
///
/// The attestation publish tests use this so a short overhang can cut the wait
/// without a second HTTP server.
#[cfg(any(test, feature = "test-utils"))]
pub async fn testing_broadcast_partial_then_slow(
    slow: Pin<
        Box<dyn Future<Output = Result<beacon::SubmitAttestationResult, BeaconError>> + Send>,
    >,
) -> Result<(String, beacon::SubmitAttestationResult), BeaconError> {
    let health = crate::health::new_shared_health_trackers(&[
        "http://fast-partial.example:9".to_string(),
        "http://slow-full.example:9".to_string(),
    ]);
    let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
    first_ok_with(
        "submit_attestation",
        "attestation",
        vec![
            BnAttempt {
                index: 0,
                endpoint: "http://fast-partial.example:9".to_string(),
                fut: Box::pin(async {
                    Ok(beacon::SubmitAttestationResult::PartialFailure {
                        failures: vec![beacon::IndexedAttestationError {
                            index: 0,
                            message: "invalid signature".to_string(),
                        }],
                    })
                }),
            },
            BnAttempt { index: 1, endpoint: "http://slow-full.example:9".to_string(), fut: slow },
        ],
        Some(Duration::from_secs(30)),
        &health,
        &pool,
        PublishPolicy::attestation(),
    )
    .await
}

/// Many failures, then fewer, then one caller-supplied attempt.
///
/// The second partial is not ready on the first poll, so the detach stores
/// the worse result. A deadline during the hang must report the fewer-failure
/// partial.
#[cfg(any(test, feature = "test-utils"))]
pub async fn testing_broadcast_improving_partial_then_slow(
    slow: Pin<
        Box<dyn Future<Output = Result<beacon::SubmitAttestationResult, BeaconError>> + Send>,
    >,
) -> Result<(String, beacon::SubmitAttestationResult), BeaconError> {
    let health = crate::health::new_shared_health_trackers(&[
        "http://many-failures.example:9".to_string(),
        "http://fewer-failures.example:9".to_string(),
        "http://hanging.example:9".to_string(),
    ]);
    let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
    first_ok_with(
        "submit_attestation",
        "attestation",
        vec![
            BnAttempt {
                index: 0,
                endpoint: "http://many-failures.example:9".to_string(),
                fut: Box::pin(async {
                    Ok(beacon::SubmitAttestationResult::PartialFailure {
                        failures: vec![
                            beacon::IndexedAttestationError {
                                index: 0,
                                message: "invalid signature".to_string(),
                            },
                            beacon::IndexedAttestationError {
                                index: 1,
                                message: "invalid signature".to_string(),
                            },
                        ],
                    })
                }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://fewer-failures.example:9".to_string(),
                fut: Box::pin(async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(beacon::SubmitAttestationResult::PartialFailure {
                        failures: vec![beacon::IndexedAttestationError {
                            index: 0,
                            message: "stale head".to_string(),
                        }],
                    })
                }),
            },
            BnAttempt { index: 2, endpoint: "http://hanging.example:9".to_string(), fut: slow },
        ],
        Some(Duration::from_secs(30)),
        &health,
        &pool,
        PublishPolicy::attestation(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::task::Context;

    use super::*;
    use crate::health::new_shared_health_trackers;
    use crate::metrics::RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL;

    fn health_for(n: usize) -> SharedHealthTrackers {
        let endpoints: Vec<String> = (0..n).map(|i| format!("http://bn{i}")).collect();
        new_shared_health_trackers(&endpoints)
    }

    fn health() -> SharedHealthTrackers {
        health_for(2)
    }

    fn err(status: u16, message: &str) -> BeaconError {
        BeaconError::ApiError { status, message: message.to_string() }
    }

    async fn wait_health(
        health: &SharedHealthTrackers,
        pred: impl Fn(&[crate::health::BnHealthTracker]) -> bool,
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let trackers = health.read().await;
            if pred(&trackers) {
                return;
            }
            assert!(std::time::Instant::now() < deadline, "health was not recorded: {trackers:?}");
            drop(trackers);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn broadcast_backstop_adds_a_250ms_margin() {
        assert_eq!(
            broadcast_backstop(Some(Duration::from_millis(200))),
            Some(Duration::from_millis(450))
        );
        assert_eq!(broadcast_backstop(None), None);
    }

    /// Harper P2-1 / P2-2. The health write lock is held for the whole round.
    /// `best_of` must still return the block in hand, and the drain must still
    /// poll the remaining loser so its hard-deadline timeout is what gets
    /// recorded. Waiting on `record_outcomes` drops the block or lets the
    /// loser's late `Ok` win, because `timeout` polls the inner future first
    /// once both are ready.
    #[tokio::test(flavor = "current_thread")]
    async fn best_of_does_not_block_on_the_health_lock() {
        let health = health_for(3);
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let health_hold = health.clone();
        tokio::spawn(async move {
            let _guard = health_hold.write().await;
            let _ = locked_tx.send(());
            let _ = release_rx.await;
        });
        locked_rx.await.expect("lock holder started");

        let pool = DrainPool::new(4);
        let round = tokio::time::timeout(
            Duration::from_millis(200),
            best_of(
                "produce_block_v3",
                "proposal",
                vec![
                    BnAttempt {
                        index: 0,
                        endpoint: "http://bn0".to_string(),
                        fut: Box::pin(async { Ok::<_, BeaconError>(()) }),
                    },
                    BnAttempt {
                        index: 1,
                        endpoint: "http://bn1".to_string(),
                        fut: Box::pin(async {
                            tokio::time::sleep(Duration::from_millis(40)).await;
                            Err(err(500, "loser"))
                        }),
                    },
                    BnAttempt {
                        index: 2,
                        endpoint: "http://bn2".to_string(),
                        fut: Box::pin(async {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            Ok(())
                        }),
                    },
                ],
                BestWindow {
                    soft: Some(Duration::from_millis(30)),
                    hard: Some(Duration::from_millis(80)),
                },
                &health,
                &pool,
                &BestFilter {
                    accept: std::sync::Arc::new(|_: &()| true),
                    in_hand: std::sync::Arc::new(|_: &()| true),
                    on_reject: std::sync::Arc::new(|_: usize, _: &str, _: &()| {}),
                    reject_label: std::sync::Arc::new(|_| "rejected"),
                },
            ),
        )
        .await
        .expect("best_of waited on the health write lock");
        let round = round.expect("best-of round");
        assert_eq!(round.values.len(), 1, "the block in hand must be returned");

        // Hold the lock past the late `Ok` (500 ms) and the hard deadline (80 ms).
        tokio::time::sleep(Duration::from_millis(600)).await;
        drop(release_tx);
        wait_health(&health, |trackers| trackers[2].error_rate() == 1.0).await;
        let trackers = health.read().await;
        assert!(
            trackers[2].latency_ema_ms().is_none(),
            "the hard-deadline loser must be an error, not a late success: {trackers:?}"
        );
        assert_eq!(trackers[1].error_rate(), 1.0, "the earlier loser must still be recorded");
    }

    /// A block that is still in flight when the soft window closes can come
    /// back `Ok` and fail the hard check. That rejection is logged on the drain.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn late_hard_reject_on_the_drain_reaches_on_reject() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u32>::new()));
        let record = std::sync::Arc::clone(&seen);
        let filter = BestFilter {
            accept: std::sync::Arc::new(|value: &u32| *value != 2),
            in_hand: std::sync::Arc::new(|value: &u32| *value == 1),
            on_reject: std::sync::Arc::new(move |_index, _endpoint, value: &u32| {
                record.lock().expect("reject log").push(*value);
            }),
            reject_label: std::sync::Arc::new(|_| "rejected"),
        };
        let health = health_for(2);
        let pool = DrainPool::new(4);
        let round = best_of(
            "produce_block_v3",
            "proposal",
            vec![
                BnAttempt {
                    index: 0,
                    endpoint: "http://bn0".to_string(),
                    fut: Box::pin(async {
                        tokio::time::sleep(Duration::from_millis(1600)).await;
                        Ok::<_, BeaconError>(1u32)
                    }),
                },
                BnAttempt {
                    index: 1,
                    endpoint: "http://bn1".to_string(),
                    fut: Box::pin(async {
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                        Ok(2u32)
                    }),
                },
            ],
            BestWindow {
                soft: Some(Duration::from_millis(1500)),
                hard: Some(Duration::from_secs(3)),
            },
            &health,
            &pool,
            &filter,
        )
        .await
        .expect("best-of round");
        assert_eq!(round.values, vec![(0, 1)]);
        assert!(seen.lock().expect("reject log").is_empty(), "the late block has not finished");
        tokio::time::sleep(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            *seen.lock().expect("reject log"),
            vec![2],
            "the drain must log the late hard reject"
        );
    }

    /// An `Ok` that fails `accept` does not close the soft window, even when
    /// `in_hand` would be true. The later accepted block is still collected.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn unusable_ok_does_not_close_the_soft_window() {
        let filter = BestFilter {
            accept: std::sync::Arc::new(|value: &u32| *value != 9),
            in_hand: std::sync::Arc::new(|_: &u32| true),
            on_reject: std::sync::Arc::new(|_index, _endpoint, _value: &u32| {}),
            reject_label: std::sync::Arc::new(|_| "rejected"),
        };
        let health = health_for(2);
        let pool = DrainPool::new(4);
        let round = best_of(
            "produce_block_v3",
            "proposal",
            vec![
                BnAttempt {
                    index: 0,
                    endpoint: "http://bn0".to_string(),
                    fut: Box::pin(async {
                        tokio::time::sleep(Duration::from_millis(1600)).await;
                        Ok::<_, BeaconError>(1u32)
                    }),
                },
                BnAttempt {
                    index: 1,
                    endpoint: "http://bn1".to_string(),
                    fut: Box::pin(async {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(9u32)
                    }),
                },
            ],
            BestWindow {
                soft: Some(Duration::from_millis(1500)),
                hard: Some(Duration::from_secs(3)),
            },
            &health,
            &pool,
            &filter,
        )
        .await
        .expect("best-of round");
        assert_eq!(
            round.values,
            vec![(0, 1)],
            "the rejected block must not close the soft window before the later block"
        );
        assert!(round.held.is_empty(), "a hard reject is dropped, not held");
    }

    fn u32_filter(
        accept: impl Fn(&u32) -> bool + Send + Sync + 'static,
        in_hand: impl Fn(&u32) -> bool + Send + Sync + 'static,
    ) -> BestFilter<u32> {
        BestFilter {
            accept: std::sync::Arc::new(accept),
            in_hand: std::sync::Arc::new(in_hand),
            on_reject: std::sync::Arc::new(|_, _, _| {}),
            reject_label: std::sync::Arc::new(
                |value: &u32| if *value == 7 { "parent" } else { "slot" },
            ),
        }
    }

    /// A hard-rejected `Ok` does not become a health success or a health error.
    #[tokio::test(flavor = "current_thread")]
    async fn rejected_ok_is_not_recorded_as_health_success() {
        let health = health_for(1);
        let before_score = health.read().await[0].score();
        let applied = health_samples_applied();
        let round = best_of(
            "produce_block_v3",
            "proposal",
            vec![BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<_, BeaconError>(7u32) }),
            }],
            BestWindow { soft: None, hard: None },
            &health,
            &DrainPool::new(4),
            &u32_filter(|value| *value != 7, |_| true),
        )
        .await
        .expect("round");
        assert!(round.values.is_empty());
        assert!(round.held.is_empty());
        assert_eq!(round.rejections, vec![(0, "parent")]);
        wait_until_health_applied(applied + 1).await;
        let trackers = health.read().await;
        assert!(trackers[0].latency_ema_ms().is_none(), "a hard reject is not a success");
        assert_eq!(trackers[0].error_rate(), 0.0, "a hard reject is not an error");
        assert_eq!(trackers[0].score(), before_score);
    }

    /// A fee-only penalty passes `accept` and stays a health success.
    #[tokio::test(flavor = "current_thread")]
    async fn fee_only_penalty_is_still_a_health_success() {
        let health = health_for(1);
        let applied = health_samples_applied();
        let round = best_of(
            "produce_block_v3",
            "proposal",
            vec![BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<_, BeaconError>(7u32) }),
            }],
            BestWindow { soft: None, hard: None },
            &health,
            &DrainPool::new(4),
            &u32_filter(|_| true, |value| *value != 7),
        )
        .await
        .expect("round");
        assert!(round.values.is_empty(), "a fee penalty is not in hand");
        assert_eq!(round.held, vec![(0, 7)]);
        assert!(round.rejections.is_empty(), "a fee penalty is not a hard reject");
        wait_until_health_applied(applied + 1).await;
        let trackers = health.read().await;
        assert!(trackers[0].latency_ema_ms().is_some(), "a fee penalty stays a success");
        assert_eq!(trackers[0].error_rate(), 0.0);
    }

    /// A late hard reject on the drain is neutral for health. The in-hand block is a success.
    #[tokio::test(flavor = "current_thread")]
    async fn drain_hard_reject_is_not_a_health_success() {
        let health = health_for(2);
        let applied = health_samples_applied();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let round = best_of(
            "produce_block_v3",
            "proposal",
            vec![
                BnAttempt {
                    index: 0,
                    endpoint: "http://bn0".to_string(),
                    fut: Box::pin(async { Ok::<_, BeaconError>(1u32) }),
                },
                BnAttempt {
                    index: 1,
                    endpoint: "http://bn1".to_string(),
                    fut: Box::pin(async move { Ok(rx.await.unwrap_or(9)) }),
                },
            ],
            BestWindow { soft: Some(Duration::ZERO), hard: Some(Duration::from_secs(5)) },
            &health,
            &DrainPool::new(4),
            &u32_filter(|value| *value != 9, |value| *value == 1),
        )
        .await
        .expect("round");
        assert_eq!(round.values, vec![(0, 1)]);
        let _ = tx.send(9u32);
        wait_until_health_applied(applied + 2).await;
        let trackers = health.read().await;
        assert!(trackers[0].latency_ema_ms().is_some(), "the block in hand is a success");
        assert!(trackers[1].latency_ema_ms().is_none(), "the drained hard reject is not a success");
        assert_eq!(trackers[1].error_rate(), 0.0, "the drained hard reject is not an error");
    }

    /// The best-of drain pool skip uses its own counter.
    #[tokio::test(flavor = "current_thread")]
    async fn best_of_drain_skip_uses_its_own_counter() {
        let best_before = crate::metrics::RVC_BN_BEST_OF_DRAIN_HEALTH_SKIPPED_TOTAL.get();
        let broadcast_before = RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.get();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let health = health_for(2);
        let _round = best_of(
            "produce_block_v3",
            "proposal",
            vec![
                BnAttempt {
                    index: 0,
                    endpoint: "http://bn0".to_string(),
                    fut: Box::pin(async { Ok::<_, BeaconError>(1u32) }),
                },
                BnAttempt {
                    index: 1,
                    endpoint: "http://bn1".to_string(),
                    fut: Box::pin(async move {
                        let _ = rx.await;
                        Ok(1u32)
                    }),
                },
            ],
            BestWindow { soft: Some(Duration::ZERO), hard: Some(Duration::from_secs(5)) },
            &health,
            &DrainPool::new(0),
            &u32_filter(|_| true, |_| true),
        )
        .await
        .expect("round");
        let _ = tx.send(());
        let best_after = loop {
            let now = crate::metrics::RVC_BN_BEST_OF_DRAIN_HEALTH_SKIPPED_TOTAL.get();
            let broadcast_now = RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.get();
            if now > best_before || broadcast_now > broadcast_before {
                break now;
            }
            tokio::task::yield_now().await;
        };
        let broadcast_after = RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.get();
        assert!(
            best_after > best_before,
            "best-of drain skip must move its own counter; before={best_before} after={best_after}"
        );
        assert_eq!(
            broadcast_after.saturating_sub(broadcast_before),
            0,
            "the best-of skip must not move the broadcast counter"
        );
    }

    /// Returning with a block in hand at a zero soft deadline counts once.
    #[tokio::test(flavor = "current_thread")]
    async fn soft_deadline_return_is_counted() {
        let before = crate::metrics::RVC_BN_PRODUCE_SOFT_DEADLINE_RETURNS_TOTAL.get();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let round = best_of(
            "produce_block_v3",
            "proposal",
            vec![
                BnAttempt {
                    index: 0,
                    endpoint: "http://bn0".to_string(),
                    fut: Box::pin(async { Ok::<_, BeaconError>(1u32) }),
                },
                BnAttempt {
                    index: 1,
                    endpoint: "http://bn1".to_string(),
                    fut: Box::pin(async move {
                        let _ = rx.await;
                        Ok(1u32)
                    }),
                },
            ],
            BestWindow { soft: Some(Duration::ZERO), hard: Some(Duration::from_secs(5)) },
            &health_for(2),
            &DrainPool::new(4),
            &u32_filter(|_| true, |_| true),
        )
        .await
        .expect("round");
        assert_eq!(round.values.len(), 1);
        let after = crate::metrics::RVC_BN_PRODUCE_SOFT_DEADLINE_RETURNS_TOTAL.get();
        assert!(
            after > before,
            "a soft-deadline return must be counted; before={before} after={after}"
        );
        let _ = tx.send(());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn full_pool_skips_health_but_still_finishes_every_attempt() {
        let pool = DrainPool::new(0);
        assert!(pool.try_acquire().is_none(), "a zero cap is already full");
        let health = health_for(3);
        let (hold_tx, mut hold_rx) = tokio::sync::watch::channel(false);
        let finished = Arc::new(AtomicBool::new(false));
        let finished_flag = Arc::clone(&finished);
        let before = RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.get();
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Err::<(), _>(err(500, "already finished")) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 2,
                endpoint: "http://overflow-skip.example:9".to_string(),
                fut: Box::pin(async move {
                    let _ = hold_rx.wait_for(|release| *release).await;
                    finished_flag.store(true, Ordering::SeqCst);
                    Ok::<(), BeaconError>(())
                }),
            },
        ];
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            first_ok("submit_attestation", "attestation", attempts, None, &health, &pool),
        )
        .await
        .expect("a full pool must not wait for the in-flight peer");
        assert!(result.is_ok(), "the accepted publish must still be returned: {result:?}");
        assert_eq!(
            pool.dropped(),
            0,
            "the pending success has not finished, so it is not skipped yet"
        );
        assert!(
            logs_contain("broadcast drain health skipped"),
            "a full pool must log the skipped health sample"
        );
        let slow = crate::metrics::endpoint_label("http://overflow-skip.example:9");
        assert_eq!(
            crate::metrics::RVC_BN_BROADCAST_OVERFLOW_DRAINS
                .with_label_values(&[slow.as_str()])
                .get(),
            1,
            "the in-flight overflow publish is labelled by the redacted endpoint"
        );
        wait_health(&health, |trackers| {
            trackers[0].error_rate() == 1.0 && trackers[1].latency_ema_ms().is_some()
        })
        .await;
        {
            let trackers = health.read().await;
            assert!(trackers[2].latency_ema_ms().is_none(), "the pending success has not finished");
        }
        assert!(hold_tx.send(true).is_ok(), "the in-flight attempt must still be waiting");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !finished.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the in-flight attempt was cancelled instead of running to completion"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        while pool.dropped() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the finished success was not counted as a skipped health sample"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.get() > before,
            "the skipped success sample must increment the production counter"
        );
        let trackers = health.read().await;
        assert!(
            trackers[2].latency_ema_ms().is_none(),
            "a full pool must not record a success that finishes after the cap is full"
        );
        drop(trackers);
        while crate::metrics::RVC_BN_BROADCAST_OVERFLOW_DRAINS
            .with_label_values(&[slow.as_str()])
            .get()
            != 0
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the overflow gauge did not drop when that beacon node's publish finished"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn full_pool_still_records_a_pending_error_after_it_finishes() {
        let pool = DrainPool::new(0);
        let health = health_for(2);
        let (release, mut wait) = tokio::sync::watch::channel(false);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://overflow-error.example:9".to_string(),
                fut: Box::pin(async move {
                    let _ = wait.wait_for(|go| *go).await;
                    Err::<(), _>(err(502, "pending-finished"))
                }),
            },
        ];
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            first_ok("submit_attestation", "attestation", attempts, None, &health, &pool),
        )
        .await
        .expect("a full pool must return before the pending attempt");
        assert!(result.is_ok(), "{result:?}");
        release.send(true).expect("release the pending attempt");

        wait_health(&health, |trackers| trackers[1].error_rate() == 1.0).await;
        assert_eq!(pool.dropped(), 0, "an error is recorded even when success sampling is skipped");
        assert!(logs_contain("pending-finished"), "the pending error must still be logged");
    }

    #[tokio::test]
    async fn drain_pool_holds_the_permit_until_the_drain_finishes() {
        assert_eq!(HEALTH_SAMPLE_CAP, 16);
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let mut held = Vec::new();
        for _ in 0..HEALTH_SAMPLE_CAP - 1 {
            held.push(pool.try_acquire().expect("a permit under the cap"));
        }
        assert_eq!(pool.available_permits(), 1, "one permit is left for the drain");

        let health = health_for(2);
        let (release, mut wait) = tokio::sync::watch::channel(false);
        let resumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resumed_flag = Arc::clone(&resumed);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(async move {
                    // The prime poll stops at this yield. The drain's poll resumes.
                    tokio::task::yield_now().await;
                    resumed_flag.fetch_add(1, Ordering::SeqCst);
                    let _ = wait.wait_for(|go| *go).await;
                    Err::<(), _>(err(500, "late"))
                }),
            },
        ];
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            first_ok("submit_attestation", "attestation", attempts, None, &health, &pool),
        )
        .await
        .expect("the winner must return while the last permit is in use");
        assert!(result.is_ok(), "{result:?}");

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while resumed.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the drain did not resume the pending attempt"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            pool.available_permits(),
            0,
            "the drain must hold its permit until the pending attempt finishes"
        );
        release.send(true).expect("release the drain");
        while pool.available_permits() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the permit was not released when the drain finished"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(pool.available_permits(), 1);
        drop(held);
    }

    #[tokio::test]
    async fn full_pool_still_delivers_the_publish_when_one_bn_hangs() {
        use beacon::{BeaconClient, BeaconClientConfig, VersionedAttestation};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let fast = MockServer::start().await;
        let slow = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .expect(1)
            .mount(&fast)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("[]")
                    .set_delay(Duration::from_millis(800)),
            )
            .expect(1)
            .mount(&slow)
            .await;

        let fast_client =
            BeaconClient::new(BeaconClientConfig::new(fast.uri()).with_max_retries(0))
                .expect("fast client");
        let slow_client =
            BeaconClient::new(BeaconClientConfig::new(slow.uri()).with_max_retries(0))
                .expect("slow client");
        let delivered = Arc::new(AtomicBool::new(false));
        let delivered_flag = Arc::clone(&delivered);
        let pool = DrainPool::new(0);
        let health = health_for(2);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: fast.uri(),
                fut: Box::pin(async move {
                    fast_client
                        .submit_attestation(&VersionedAttestation::Electra(vec![]))
                        .await
                        .map(|_| ())
                }),
            },
            BnAttempt {
                index: 1,
                endpoint: slow.uri(),
                fut: Box::pin(async move {
                    let result = slow_client
                        .submit_attestation(&VersionedAttestation::Electra(vec![]))
                        .await
                        .map(|_| ());
                    delivered_flag.store(true, Ordering::SeqCst);
                    result
                }),
            },
        ];
        let result = tokio::time::timeout(
            Duration::from_millis(400),
            first_ok("submit_attestation", "attestation", attempts, None, &health, &pool),
        )
        .await
        .expect("the fast BN must win before the slow BN answers");
        assert!(result.is_ok(), "{result:?}");

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let fast_posts = fast
                .received_requests()
                .await
                .expect("fast requests")
                .iter()
                .filter(|req| {
                    req.method.as_str() == "POST"
                        && req.url.path() == "/eth/v2/beacon/pool/attestations"
                })
                .count();
            let slow_posts = slow
                .received_requests()
                .await
                .expect("slow requests")
                .iter()
                .filter(|req| {
                    req.method.as_str() == "POST"
                        && req.url.path() == "/eth/v2/beacon/pool/attestations"
                })
                .count();
            if fast_posts >= 1 && slow_posts >= 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for both publishes, fast={fast_posts} slow={slow_posts}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        while !delivered.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the slow publish was cancelled before it finished"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        while pool.dropped() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the slow success's health sample was not skipped"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        wait_health(&health, |trackers| trackers[0].latency_ema_ms().is_some()).await;
        let trackers = health.read().await;
        assert!(
            trackers[1].latency_ema_ms().is_none(),
            "a full pool skips the slow success sample and still finishes the publish"
        );
    }

    #[tokio::test]
    async fn failure_is_recorded_as_it_finishes_even_if_the_caller_is_cancelled() {
        let health = health_for(2);
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let (_release, mut wait) = tokio::sync::watch::channel(false);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Err::<(), _>(err(500, "early")) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(async move {
                    let _ = wait.wait_for(|release| *release).await;
                    Ok::<(), BeaconError>(())
                }),
            },
        ];
        let health_for_call = health.clone();
        let task = tokio::spawn(async move {
            first_ok("submit_attestation", "attestation", attempts, None, &health_for_call, &pool)
                .await
        });
        wait_health(&health, |trackers| trackers[0].error_rate() == 1.0).await;
        task.abort();
        let _ = task.await;
        let trackers = health.read().await;
        assert_eq!(
            trackers[0].error_rate(),
            1.0,
            "cancelling the caller must keep a failure that already finished"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn first_ok_logs_two_successes_already_finished_before_return() {
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 2,
                endpoint: "http://bn2".to_string(),
                fut: Box::pin(async { Err::<(), _>(err(500, "with them")) }),
            },
        ];
        let health = health_for(3);
        let result =
            first_ok("submit_attestation", "attestation", attempts, None, &health, &pool).await;
        assert!(result.is_ok(), "{result:?}");
        assert!(
            logs_contain("partial broadcast failure") && logs_contain("successes=2"),
            "two successes already finished before return must be logged as successes=2"
        );
    }

    /// Sets a flag on the first poll and then stays pending without waking.
    struct FlagOnFirstPoll(Arc<AtomicBool>);

    impl Future for FlagOnFirstPoll {
        type Output = Result<(), BeaconError>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.get_mut().0.store(true, Ordering::SeqCst);
            Poll::Pending
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn first_ok_polls_every_attempt_once_before_returning() {
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let polled = Arc::new(AtomicBool::new(false));
        // The winner is first. `FuturesUnordered` returns on that `Ready` and
        // does not poll the rest, so only the prime poll sets the flag before
        // this function observes it.
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(FlagOnFirstPoll(Arc::clone(&polled))),
            },
        ];
        let result =
            first_ok("submit_attestation", "attestation", attempts, None, &health(), &pool).await;
        assert!(result.is_ok(), "{result:?}");
        assert!(
            polled.load(Ordering::SeqCst),
            "every attempt must be polled once before the winner is returned"
        );
    }

    #[tokio::test]
    async fn all_returns_every_outcome_before_the_health_lock_is_free() {
        let health = health_for(2);
        let guard = health.write().await;
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(async { Err::<(), _>(err(500, "no")) }),
            },
        ];
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            all("submit_attestation", "attestation", attempts, None, &health),
        )
        .await
        .expect("all must not wait on the health write lock between attempts");
        let broadcast = result.expect("both attempts finish");
        assert_eq!(broadcast.outcomes.len(), 2);
        drop(guard);
        wait_health(&health, |trackers| {
            trackers[0].latency_ema_ms().is_some() && trackers[1].error_rate() == 1.0
        })
        .await;
    }

    #[tokio::test]
    async fn first_ok_returns_the_last_error_when_every_bn_fails() {
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        // The lower index finishes last, so "last to complete" is not "last BN".
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async {
                    tokio::task::yield_now().await;
                    Err(err(500, "first"))
                }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(async { Err::<(), _>(err(502, "last")) }),
            },
        ];
        let result =
            first_ok("submit_attestation", "attestation", attempts, None, &health(), &pool).await;
        match result {
            Err(BeaconError::ApiError { status: 502, message }) => assert_eq!(message, "last"),
            other => panic!("expected the last BN's error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn first_ok_with_no_attempts_returns_no_eligible_bn() {
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let result =
            first_ok::<()>("submit_attestation", "attestation", Vec::new(), None, &health(), &pool)
                .await;
        match result {
            Err(BeaconError::NoEligibleBn { operation, role }) => {
                assert_eq!(operation, "submit_attestation");
                assert_eq!(role, "attestation");
            }
            other => panic!("expected NoEligibleBn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn first_ok_returns_before_the_health_write_lock_is_free() {
        let health = health();
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let guard = health.write().await;
        let attempts = vec![BnAttempt {
            index: 0,
            endpoint: "http://bn0".to_string(),
            fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
        }];
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            first_ok("submit_attestation", "attestation", attempts, None, &health, &pool),
        )
        .await
        .expect("the winner must be reported while the health write lock is held");
        assert!(result.is_ok(), "{result:?}");
        drop(guard);

        wait_health(&health, |trackers| trackers[0].latency_ema_ms().is_some()).await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn drain_logs_a_later_failure_with_the_success_count() {
        let health = health_for(3);
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let (release_ok, mut wait_ok) = tokio::sync::watch::channel(false);
        let (release_err, mut wait_err) = tokio::sync::watch::channel(false);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://bn0".to_string(),
                fut: Box::pin(async { Ok::<(), BeaconError>(()) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://bn1".to_string(),
                fut: Box::pin(async move {
                    let _ = wait_ok.wait_for(|release| *release).await;
                    Ok::<(), BeaconError>(())
                }),
            },
            BnAttempt {
                index: 2,
                endpoint: "http://bn2".to_string(),
                fut: Box::pin(async move {
                    let _ = wait_err.wait_for(|release| *release).await;
                    Err::<(), _>(err(500, "drain"))
                }),
            },
        ];
        let result =
            first_ok("submit_attestation", "attestation", attempts, None, &health, &pool).await;
        assert!(result.is_ok(), "{result:?}");
        release_ok.send(true).expect("release the second success");

        wait_health(&health, |trackers| trackers[1].latency_ema_ms().is_some()).await;
        release_err.send(true).expect("release the drain failure");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if logs_contain("partial broadcast failure") && logs_contain("successes=2") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "drain failure was not logged with the real success count"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Batch {
        Full,
        Partial(usize),
    }

    fn batch_policy() -> PublishPolicy<Batch> {
        PublishPolicy {
            is_complete: |batch| matches!(batch, Batch::Full),
            prefer_partial: |current, candidate| match (current, candidate) {
                (Batch::Partial(current_n), Batch::Partial(candidate_n)) => candidate_n < current_n,
                _ => false,
            },
            remember_partial: remember_nothing,
            recall_partial: recall_nothing,
        }
    }

    #[tokio::test]
    async fn first_ok_waits_for_a_complete_success_past_a_fast_partial() {
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let (release, mut wait) = tokio::sync::watch::channel(false);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://fast-partial".to_string(),
                fut: Box::pin(async { Ok(Batch::Partial(2)) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://slow-full".to_string(),
                fut: Box::pin(async move {
                    let _ = wait.wait_for(|go| *go).await;
                    Ok(Batch::Full)
                }),
            },
        ];
        let health = health_for(2);
        let task = tokio::spawn(async move {
            first_ok_with(
                "submit_attestation",
                "attestation",
                attempts,
                None,
                &health,
                &pool,
                batch_policy(),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!task.is_finished(), "a partial Ok must not win before a complete success");
        release.send(true).expect("release the complete success");
        let (endpoint, value) = task.await.expect("task").expect("complete success");
        assert_eq!(endpoint, "http://slow-full");
        assert_eq!(value, Batch::Full);
    }

    #[tokio::test]
    async fn first_ok_keeps_the_partial_with_fewer_failures_when_none_complete() {
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://worse".to_string(),
                fut: Box::pin(async { Ok(Batch::Partial(3)) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://better".to_string(),
                fut: Box::pin(async {
                    tokio::task::yield_now().await;
                    Ok(Batch::Partial(1))
                }),
            },
        ];
        let (endpoint, value) = first_ok_with(
            "submit_attestation",
            "attestation",
            attempts,
            None,
            &health(),
            &pool,
            batch_policy(),
        )
        .await
        .expect("best partial");
        assert_eq!(endpoint, "http://better");
        assert_eq!(value, Batch::Partial(1));
    }

    #[tokio::test]
    async fn first_ok_returns_the_best_partial_when_the_other_bn_hits_the_budget() {
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let health = health_for(2);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://partial".to_string(),
                fut: Box::pin(async { Ok(Batch::Partial(1)) }),
            },
            BnAttempt {
                index: 1,
                endpoint: "http://slow".to_string(),
                fut: Box::pin(async { std::future::pending::<Result<Batch, BeaconError>>().await }),
            },
        ];
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            first_ok_with(
                "submit_attestation",
                "attestation",
                attempts,
                Some(Duration::from_millis(40)),
                &health,
                &pool,
                batch_policy(),
            ),
        )
        .await
        .expect("the partial is returned when the other attempt hits the budget");
        let (endpoint, value) = result.expect("partial");
        assert_eq!(endpoint, "http://partial");
        assert_eq!(value, Batch::Partial(1));
        wait_health(&health, |trackers| trackers[1].error_rate() == 1.0).await;
    }

    #[tokio::test]
    async fn cancelling_the_caller_after_a_partial_still_publishes_to_the_other_bn() {
        use beacon::{
            BeaconClient, BeaconClientConfig, IndexedAttestationError, SubmitAttestationResult,
            VersionedAttestation,
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let slow = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .expect(1)
            .mount(&slow)
            .await;

        let slow_client =
            BeaconClient::new(BeaconClientConfig::new(slow.uri()).with_max_retries(0))
                .expect("slow client");
        let seen = Arc::new(AtomicBool::new(false));
        let seen_flag = Arc::clone(&seen);
        let delivered = Arc::new(AtomicBool::new(false));
        let delivered_flag = Arc::clone(&delivered);
        let (release, mut wait) = tokio::sync::watch::channel(false);
        let pool = DrainPool::new(HEALTH_SAMPLE_CAP);
        let health = health_for(2);
        let attempts = vec![
            BnAttempt {
                index: 0,
                endpoint: "http://fast-partial".to_string(),
                fut: Box::pin(async move {
                    seen_flag.store(true, Ordering::SeqCst);
                    Ok(SubmitAttestationResult::PartialFailure {
                        failures: vec![IndexedAttestationError {
                            index: 0,
                            message: "invalid signature".to_string(),
                        }],
                    })
                }),
            },
            BnAttempt {
                index: 1,
                endpoint: slow.uri(),
                fut: Box::pin(async move {
                    let _ = wait.wait_for(|go| *go).await;
                    let result = slow_client
                        .submit_attestation(&VersionedAttestation::Electra(vec![]))
                        .await;
                    delivered_flag.store(true, Ordering::SeqCst);
                    result
                }),
            },
        ];
        let task = tokio::spawn(async move {
            first_ok_with(
                "submit_attestation",
                "attestation",
                attempts,
                None,
                &health,
                &pool,
                PublishPolicy::attestation(),
            )
            .await
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !seen.load(Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "the fast partial did not run");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        let join = task.await;
        assert!(
            join.expect_err("the caller must still be waiting on the detached publish")
                .is_cancelled(),
            "cancelling the caller after a partial must cancel only the caller"
        );
        release.send(true).expect("release the other beacon node");

        while !delivered.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "the other beacon node did not receive the publish after the caller was cancelled"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let slow_posts = slow
            .received_requests()
            .await
            .expect("slow requests")
            .iter()
            .filter(|req| {
                req.method.as_str() == "POST"
                    && req.url.path() == "/eth/v2/beacon/pool/attestations"
            })
            .count();
        assert_eq!(slow_posts, 1, "the other beacon node must receive the publish");
    }

    #[tokio::test]
    async fn saturated_health_queue_returns_an_error_when_the_caller_is_cancelled() {
        let health = health_for(1);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(HealthSample {
            health: health.clone(),
            op_name: "fill".to_string(),
            index: 0,
            outcome: TrackerOutcome::Error,
        })
        .expect("the queue starts full");
        let before = RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.get();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let health_for_attempt = health.clone();
        let task = tokio::spawn(async move {
            let finished = run_attempt(
                AttemptEnv {
                    op_name: "submit_attestation".to_string(),
                    budget: None,
                    health: health_for_attempt,
                    record: Arc::new(AtomicBool::new(true)),
                    skipped: Arc::new(AtomicU64::new(0)),
                    health_tx: tx,
                    overflow: Arc::new(Mutex::new(None)),
                },
                BnAttempt {
                    index: 0,
                    endpoint: "http://bn0".to_string(),
                    fut: Box::pin(async { Err::<(), _>(err(500, "saturated")) }),
                },
            )
            .await;
            let _ = done_tx.send(finished);
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        task.abort();
        let finished = tokio::time::timeout(Duration::from_millis(200), done_rx)
            .await
            .expect("a full health queue must not block the error result past cancellation")
            .expect("the attempt sent its result before the sleep");
        assert!(finished.outcome.result.is_err(), "the beacon error is the attempt result");
        assert!(
            RVC_BN_BROADCAST_DRAIN_HEALTH_SKIPPED_TOTAL.get() > before,
            "a full health queue counts the drop"
        );
        assert_eq!(rx.len(), 1, "the prefilled sample stays queued");
        let trackers = health.read().await;
        assert_eq!(
            trackers[0].error_rate(),
            0.0,
            "the error sample was not recorded on the saturated queue"
        );
    }

    fn arm_gauge(endpoint: &str) -> (String, Arc<Mutex<Option<OverflowGuard>>>) {
        let label = crate::metrics::endpoint_label(endpoint);
        crate::metrics::RVC_BN_BROADCAST_OVERFLOW_DRAINS.with_label_values(&[label.as_str()]).inc();
        let guard = OverflowGuard(label.clone());
        (label, Arc::new(Mutex::new(Some(guard))))
    }

    fn gauge_of(label: &str) -> i64 {
        crate::metrics::RVC_BN_BROADCAST_OVERFLOW_DRAINS.with_label_values(&[label]).get()
    }

    fn pending_attempt(
        overflow: Arc<Mutex<Option<OverflowGuard>>>,
        budget: Option<Duration>,
    ) -> AttemptEnv {
        AttemptEnv {
            op_name: "submit_attestation".to_string(),
            budget,
            health: health_for(1),
            record: Arc::new(AtomicBool::new(true)),
            skipped: Arc::new(AtomicU64::new(0)),
            health_tx: health_sender(),
            overflow,
        }
    }

    #[tokio::test]
    async fn overflow_gauge_returns_to_zero_when_the_attempt_times_out() {
        let (label, overflow) = arm_gauge("http://overflow-timeout.example:9");
        assert_eq!(gauge_of(&label), 1);
        let finished = run_attempt(
            pending_attempt(overflow, Some(Duration::from_millis(40))),
            BnAttempt {
                index: 0,
                endpoint: "http://overflow-timeout.example:9".to_string(),
                fut: Box::pin(std::future::pending::<Result<(), BeaconError>>()),
            },
        )
        .await;
        assert!(finished.outcome.result.is_err(), "the budget ends the attempt");
        assert_eq!(gauge_of(&label), 0, "the gauge drops when the attempt times out");
    }

    #[tokio::test]
    async fn overflow_gauge_returns_to_zero_when_the_attempt_is_cancelled() {
        let (label, overflow) = arm_gauge("http://overflow-cancel.example:9");
        assert_eq!(gauge_of(&label), 1);
        let started = Arc::new(AtomicBool::new(false));
        let started_flag = Arc::clone(&started);
        let task = tokio::spawn(run_attempt(
            pending_attempt(overflow, None),
            BnAttempt {
                index: 0,
                endpoint: "http://overflow-cancel.example:9".to_string(),
                fut: Box::pin(async move {
                    started_flag.store(true, Ordering::SeqCst);
                    std::future::pending::<Result<(), BeaconError>>().await
                }),
            },
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !started.load(Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "the attempt was not polled");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        match task.await {
            Err(join) => assert!(join.is_cancelled(), "the attempt must be cancelled"),
            Ok(_) => panic!("the attempt finished instead of being cancelled"),
        }
        assert_eq!(gauge_of(&label), 0, "the gauge drops when the attempt is cancelled");
    }

    #[tokio::test]
    async fn overflow_gauge_returns_to_zero_when_the_attempt_panics() {
        let (label, overflow) = arm_gauge("http://overflow-panic.example:9");
        assert_eq!(gauge_of(&label), 1);
        let task = tokio::spawn(run_attempt(
            pending_attempt(overflow, None),
            BnAttempt {
                index: 0,
                endpoint: "http://overflow-panic.example:9".to_string(),
                fut: Box::pin(async {
                    panic!("overflow attempt");
                    #[allow(unreachable_code)]
                    Ok(())
                }),
            },
        ));
        match task.await {
            Err(join) => assert!(join.is_panic(), "the attempt must panic"),
            Ok(_) => panic!("the attempt finished instead of panicking"),
        }
        assert_eq!(gauge_of(&label), 0, "the gauge drops when the attempt panics");
    }
}
