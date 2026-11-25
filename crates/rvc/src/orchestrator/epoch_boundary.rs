//! Epoch boundary runner: the boundary steps, one method each, in a fixed order.
//!
//! [`EpochBoundaryRunner::run_pending`] runs every step of the slot's epoch
//! that is still pending, in [`BoundaryStep`] order. Each step returns a
//! [`StepOutcome`], and only `Done` marks it done. A `Failed` or `NotReady`
//! step stays pending and runs again in the next pass, at the next processed
//! slot of the same epoch: at most one retry per processed slot, and none
//! after the epoch ends: a pass still running when a slot of a later epoch
//! is processed starts no further step, though its step in flight finishes.
//! The order is per pass, not a barrier: the steps after a `Failed` or
//! `NotReady` one still run in that pass. `DutyFetch` has no done mark: it
//! runs in every pass while a step that needs duties is pending.
//! `PrepareProposers` is `NotReady` while a local key has no validator index,
//! and sends again only once more keys have one. It is also `NotReady`, with
//! no POST, while the index registry is stale after a revocation, and a pass
//! that finds the registry token moved since the step's last POST re-opens
//! the step, done or not, so the re-checked indices are sent in the same
//! epoch. `CommitteeSubscriptions` is
//! `NotReady` until the attester duties of E and E+1 are cached.
//! `BuilderRegistration` runs in every epoch and needs no duties: it re-sends
//! each builder key's registration and signs only the new or changed ones.
//! `ProposerPreferences` runs from the epoch before Gloas. It is `NotReady`
//! until the proposer duties of E and E+1 are cached, and `Done` once the
//! proposer and builder broadcasts both succeed. Each attempt signs under one
//! beacon-node admission, taken before it reads the duties, and it is
//! `Failed` when no node is admitted. A proposer root change that
//! ReorgCheck caches re-opens it, so it signs again with the new root.
//! Each step with beacon-node work runs under its own bound,
//! `timeouts.duty_fetch` for ReorgCheck, DutyFetch and
//! CommitteeSubscriptions, `timeouts.preparation` for PrepareProposers, the
//! builder service's `registration_step_timeout()` for BuilderRegistration
//! and `PREFERENCES_STEP_TIMEOUT` for ProposerPreferences: a step that
//! reaches it is dropped and `Failed`.
//! The first pass of a later epoch logs
//! one warn for the steps the old epoch did not finish, with each one's last
//! outcome. The epoch summary is logged once per epoch, at the end of the
//! epoch's first pass. [`EpochBoundaryTask::run`] calls it on its own task
//! ([`TASK_NAME`]) after each slot the slot loop processed, while that
//! slot's epoch has a step pending. Before the first processed slot, while
//! the clock reads before genesis, the task runs epoch 0's pending steps
//! itself once per tick; that progress is epoch 0's, so slot 0 does not
//! repeat it. Each pass is a root `epoch.boundary` span.
//!
//! # Step order
//!
//! The final order. Later issues insert their steps at the reserved
//! positions and do not reorder the existing ones:
//!
//! 1. `BreakerReset`
//! 2. `ReorgCheck` (re-opens `ProposerPreferences` on a proposer root change)
//! 3. `DutyFetch` (the uncached E and E+1 attester and proposer duties,
//!    bounded by `timeouts.duty_fetch`; never waits on the slot loop's warm-up)
//! 4. `PrepareProposers`
//! 5. `CommitteeSubscriptions` (epoch E, then E+1)
//! 6. `SyncCommitteeSubscriptions` (reserved, W4-E9b)
//! 7. `BuilderRegistration` (every epoch)
//! 8. `ProposerPreferences` (from the epoch before Gloas, until the proposer
//!    and builder broadcasts both succeed)
//!
//! # Lock rule
//!
//! The progress and processed-slot mutexes are taken only between steps, or
//! between the subscription step's sends, and no runner mutex is held across
//! an `.await`, so `run_pending(&self)` can run inside a future that borrows
//! the runner shared, and a pass dropped mid-step leaves them unlocked. A
//! step's outcome is recorded only after it returns.
//! Outside tests, only [`EpochBoundaryTask::run`] calls `run_pending`, and it
//! awaits or drops each pass before the next wake, so one pass runs at a
//! time.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bn_manager::OperationTimeouts;
use builder::{legacy_proposer_ops_retired, BuilderService, BuilderServiceError, UpcomingProposal};
use duty_tracker::DutyTracker;
use eth_types::{ForkName, ForkSchedule, Root, Slot};
use signer::CircuitBreakerState;
use timing::{SlotClock, TimingError, SLOTS_PER_EPOCH};
use tokio::sync::watch;
use tracing::{debug, info, info_span, warn, Instrument, Span};
use validator_store::ValidatorStore;

use super::block_proposal::publish_circuit_breaker_metrics;
use super::coordinator::PubkeyMap;
use super::duty_management::{DutyManagementService, PrepareOutcome};
use super::utils;
use crate::pubkey_index::RegistryFreshness;

/// Executor task name. The runner's loop span has the same name.
pub const TASK_NAME: &str = "epoch.boundary.runner";

/// This bound limits one ProposerPreferences attempt, with its signature
/// calls. The deleted slot-0 builder block had the same 10 s bound. A
/// stalled signer thus holds each pass for 10 s at most.
const PREFERENCES_STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// The wait before the next read of a clock that fails for a reason other
/// than genesis.
const CLOCK_RETRY: Duration = Duration::from_secs(1);

/// The runner on its own task, woken by each slot the slot loop processed.
pub struct EpochBoundaryTask {
    runner: Arc<EpochBoundaryRunner>,
    /// Read only before the first processed slot.
    clock: Arc<dyn SlotClock>,
    slots: watch::Receiver<Option<Slot>>,
    shutdown: watch::Receiver<bool>,
}

impl EpochBoundaryTask {
    pub(crate) fn new(
        runner: Arc<EpochBoundaryRunner>,
        clock: Arc<dyn SlotClock>,
        slots: watch::Receiver<Option<Slot>>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        runner.follow(slots.clone());
        Self { runner, clock, slots, shutdown }
    }

    /// Runs the pending steps at each processed slot until shutdown.
    ///
    /// Before the first processed slot, while the clock reads before genesis,
    /// it runs epoch 0's pending steps once per tick instead.
    ///
    /// Returns when the shutdown watch reads `true` or loses its sender, or
    /// when the processed-slot sender is dropped (the slot loop is gone). A
    /// wake reads the latest slot, so wakes during a pass coalesce. A pass in
    /// flight is raced against shutdown and dropped when shutdown wins; the
    /// step it was in stays pending. Shutdown wins ties in both waits.
    pub async fn run(mut self) {
        let loop_span = info_span!(parent: None, "epoch.boundary.runner");
        if !self.run_before_genesis(&loop_span).await {
            return;
        }
        loop {
            tokio::select! {
                biased;
                () = shutdown_requested(&mut self.shutdown) => return,
                changed = self.slots.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let Some(slot) = *self.slots.borrow_and_update() else {
                        continue;
                    };
                    if !self.runner.has_pending(slot) {
                        continue;
                    }
                    let epoch = slot / SLOTS_PER_EPOCH;
                    let pass = info_span!(parent: None, "epoch.boundary", epoch, slot);
                    pass.follows_from(&loop_span);
                    tokio::select! {
                        biased;
                        () = shutdown_requested(&mut self.shutdown) => return,
                        () = self.runner.run_pending(slot).instrument(pass) => {}
                    }
                }
            }
        }
    }

    /// Until a slot is processed, runs epoch 0's pending steps once per tick
    /// while the clock reads before genesis (see [`pre_genesis_tick`]). Any
    /// other clock error is warned and read again after [`CLOCK_RETRY`]. A
    /// pass is raced against shutdown, and each wait against shutdown and
    /// the processed slots. `false` when the task must end.
    async fn run_before_genesis(&mut self, loop_span: &Span) -> bool {
        loop {
            if self.slots.borrow().is_some() {
                return true;
            }
            let wait = match self.clock.current_slot() {
                Ok(_) => return true,
                Err(TimingError::BeforeGenesis { .. }) => {
                    if self.runner.has_pending(0) {
                        let pass = info_span!(parent: None, "epoch.boundary", epoch = 0_u64);
                        pass.follows_from(loop_span);
                        tokio::select! {
                            biased;
                            () = shutdown_requested(&mut self.shutdown) => return false,
                            () = self.runner.run_pending_for_epoch(0).instrument(pass) => {}
                        }
                    }
                    pre_genesis_tick(self.clock.as_ref())
                }
                Err(e) => {
                    warn!(error = %e, "Epoch boundary runner cannot read the current slot");
                    CLOCK_RETRY
                }
            };
            tokio::select! {
                biased;
                () = shutdown_requested(&mut self.shutdown) => return false,
                changed = self.slots.changed() => {
                    // `run` takes the slot from here.
                    self.slots.mark_changed();
                    return changed.is_ok();
                }
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}

/// The wait between two pre-genesis passes: the time left to genesis, at
/// most one slot, and one slot when the clock reads none left.
fn pre_genesis_tick(clock: &dyn SlotClock) -> Duration {
    let slot = clock.slot_duration();
    match clock.time_until_slot(0) {
        Ok(left) if !left.is_zero() => left.min(slot),
        _ => slot,
    }
}

/// Resolves once `shutdown` reads `true` or loses its sender.
async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

/// One boundary step. Declaration order is run order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BoundaryStep {
    BreakerReset,
    ReorgCheck,
    DutyFetch,
    PrepareProposers,
    CommitteeSubscriptions,
    BuilderRegistration,
    ProposerPreferences,
}

impl BoundaryStep {
    const ALL: [Self; 7] = [
        Self::BreakerReset,
        Self::ReorgCheck,
        Self::DutyFetch,
        Self::PrepareProposers,
        Self::CommitteeSubscriptions,
        Self::BuilderRegistration,
        Self::ProposerPreferences,
    ];

    /// Reads E and E+1 duties from the cache, so DutyFetch runs before it.
    fn needs_duties(self) -> bool {
        matches!(self, Self::CommitteeSubscriptions | Self::ProposerPreferences)
    }
}

/// How a step ended in one pass. `Failed` and `NotReady` retry the same way;
/// they stay apart so a step that never finishes can say which it was.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum StepOutcome {
    /// Finished for the epoch: the step does not run again in it.
    Done,
    /// Its beacon-node work failed or timed out.
    Failed,
    /// Its inputs are not there yet.
    NotReady,
}

/// Steps done in `epoch`, and each step's latest outcome.
pub(crate) struct EpochProgress {
    epoch: u64,
    done: BTreeSet<BoundaryStep>,
    /// Read by the warn for the steps the epoch did not finish.
    last_outcome: BTreeMap<BoundaryStep, StepOutcome>,
    /// The duty epochs whose committee subscriptions went out.
    subscribed: BTreeSet<u64>,
    /// The keys with a validator index when the last `Complete` or `Partial`
    /// prepare POST went out.
    prepared_count: Option<usize>,
    /// The registry token sampled before that POST. Set and reset together
    /// with `prepared_count`. It is `None` with a count when the sample was
    /// `Stale`, because a `Stale` sample does not identify the POST.
    prepared_under: Option<RegistryFreshness>,
}

impl EpochProgress {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            done: BTreeSet::new(),
            last_outcome: BTreeMap::new(),
            subscribed: BTreeSet::new(),
            prepared_count: None,
            prepared_under: None,
        }
    }

    /// Keeps the count and the registry token of a `Complete` or `Partial`
    /// prepare POST. Each stale interval gives the same `Stale` value, so the
    /// step does not keep a `Stale` token.
    fn set_prepared(&mut self, resolved: usize, under: RegistryFreshness) {
        self.prepared_count = Some(resolved);
        self.prepared_under = Some(under).filter(|under| *under != RegistryFreshness::Stale);
    }

    /// Whether a prepare POST is kept and its token is not `freshness`. A
    /// kept POST with no token always counts as moved.
    fn prepare_moved(&self, freshness: RegistryFreshness) -> bool {
        self.prepared_count.is_some() && self.prepared_under != Some(freshness)
    }

    /// Forgets the last prepare POST: PrepareProposers is pending again, and
    /// its next attempt POSTs whatever count it reads.
    fn forget_prepared(&mut self) {
        self.done.remove(&BoundaryStep::PrepareProposers);
        self.prepared_count = None;
        self.prepared_under = None;
    }

    /// DutyFetch is never marked done: it is pending while a step that needs
    /// duties is.
    fn is_pending(&self, step: BoundaryStep) -> bool {
        match step {
            BoundaryStep::DutyFetch => BoundaryStep::ALL
                .into_iter()
                .any(|step| step.needs_duties() && !self.done.contains(&step)),
            _ => !self.done.contains(&step),
        }
    }

    /// The pending steps, in order. DutyFetch is named only when its last
    /// attempt failed; otherwise the step that needs duties stands for it.
    fn unfinished(&self) -> Vec<BoundaryStep> {
        BoundaryStep::ALL
            .into_iter()
            .filter(|&step| self.is_pending(step))
            .filter(|&step| {
                step != BoundaryStep::DutyFetch
                    || self.last_outcome.get(&step) == Some(&StepOutcome::Failed)
            })
            .collect()
    }

    /// One warn for the steps the epoch did not finish, with the last outcome
    /// of each one that ran. Silent when every step finished.
    fn warn_unfinished(&self) {
        let pending = self.unfinished();
        if pending.is_empty() {
            return;
        }
        let outcomes: BTreeMap<BoundaryStep, StepOutcome> = pending
            .iter()
            .filter_map(|step| Some((*step, *self.last_outcome.get(step)?)))
            .collect();
        warn!(
            epoch = self.epoch,
            abandoned_steps = ?pending,
            last_outcomes = ?outcomes,
            "epoch-boundary steps did not finish before the epoch ended"
        );
    }
}

/// Runs each epoch-boundary step until it is done in its epoch.
pub(crate) struct EpochBoundaryRunner {
    duty_management: Arc<DutyManagementService>,
    circuit_breaker: Arc<CircuitBreakerState>,
    duty_tracker: Arc<DutyTracker>,
    timeouts: OperationTimeouts,
    /// Registers the builder keys and broadcasts the preferences; none
    /// without a builder service.
    builder_service: Option<Arc<BuilderService>>,
    /// Gloas retired the registration, and the epoch before it starts the
    /// preferences.
    fork_schedule: Arc<ForkSchedule>,
    /// The local keys whose proposals get preferences.
    pubkey_map: PubkeyMap,
    /// Each key's signing gate, fee recipient and gas limit.
    validator_store: Arc<ValidatorStore>,
    /// The signing domain input of each proposer-preferences signature.
    genesis_validators_root: Root,
    /// A proposer root change that has not re-opened ProposerPreferences
    /// yet. The reorg check sets it when it caches the change, and it is
    /// cleared when ReorgCheck re-opens the step, so a check cut in between
    /// leaves it to the next attempt, in this epoch or a later one.
    preferences_owed: AtomicBool,
    progress: parking_lot::Mutex<Option<EpochProgress>>,
    /// The processed slots of the task that runs the passes.
    processed: parking_lot::Mutex<Option<watch::Receiver<Option<Slot>>>>,
}

impl EpochBoundaryRunner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        duty_management: Arc<DutyManagementService>,
        circuit_breaker: Arc<CircuitBreakerState>,
        duty_tracker: Arc<DutyTracker>,
        timeouts: OperationTimeouts,
        builder_service: Option<Arc<BuilderService>>,
        fork_schedule: Arc<ForkSchedule>,
        pubkey_map: PubkeyMap,
        validator_store: Arc<ValidatorStore>,
        genesis_validators_root: Root,
    ) -> Self {
        Self {
            duty_management,
            circuit_breaker,
            duty_tracker,
            timeouts,
            builder_service,
            fork_schedule,
            pubkey_map,
            validator_store,
            genesis_validators_root,
            preferences_owed: AtomicBool::new(false),
            progress: parking_lot::Mutex::new(None),
            processed: parking_lot::Mutex::new(None),
        }
    }

    /// A pass reads `processed` before each step, and starts none once a
    /// slot of a later epoch is processed.
    fn follow(&self, processed: watch::Receiver<Option<Slot>>) {
        *self.processed.lock() = Some(processed);
    }

    /// Whether a slot of an epoch after `epoch` has been processed.
    fn epoch_ended(&self, epoch: u64) -> bool {
        self.processed
            .lock()
            .as_ref()
            .and_then(|processed| *processed.borrow())
            .is_some_and(|slot| slot / SLOTS_PER_EPOCH > epoch)
    }

    /// Runs the pending steps of `slot`'s epoch, in order.
    ///
    /// A slot past the progress epoch starts a new epoch, after one warn for
    /// the steps the old epoch did not finish. A slot before it runs nothing.
    /// Once a slot of a later epoch is processed, the pass starts no further
    /// step.
    pub(crate) async fn run_pending(&self, slot: Slot) {
        self.run_epoch_steps(slot / SLOTS_PER_EPOCH, slot).await;
    }

    /// [`Self::run_pending`] with no processed slot: epoch 0 before genesis.
    /// The summary reads the epoch's first slot.
    pub(crate) async fn run_pending_for_epoch(&self, epoch: u64) {
        self.run_epoch_steps(epoch, epoch.saturating_mul(SLOTS_PER_EPOCH)).await;
    }

    async fn run_epoch_steps(&self, epoch: u64, slot: Slot) {
        let first_pass = self.begin_epoch(epoch);
        self.reopen_moved_prepare(epoch);
        for step in BoundaryStep::ALL {
            if !self.is_pending(epoch, step) {
                continue;
            }
            if self.epoch_ended(epoch) {
                debug!(
                    epoch,
                    ?step,
                    "Epoch boundary pass stopped: a later epoch's slot was processed"
                );
                break;
            }
            let outcome = match step {
                BoundaryStep::BreakerReset => self.breaker_reset(epoch),
                BoundaryStep::ReorgCheck => {
                    bounded(epoch, step, self.timeouts.duty_fetch, self.reorg_check(epoch)).await
                }
                BoundaryStep::DutyFetch => {
                    let outcome = self.duty_fetch(epoch).await;
                    debug!(epoch, ?outcome, "Epoch boundary duty fetch finished");
                    outcome
                }
                BoundaryStep::PrepareProposers => {
                    let prepare = self.prepare_proposers(epoch);
                    bounded(epoch, step, self.timeouts.preparation, prepare).await
                }
                BoundaryStep::CommitteeSubscriptions => {
                    let subscriptions = self.committee_subscriptions(epoch);
                    bounded(epoch, step, self.timeouts.duty_fetch, subscriptions).await
                }
                BoundaryStep::BuilderRegistration => self.builder_registration(epoch).await,
                BoundaryStep::ProposerPreferences => self.proposer_preferences(epoch).await,
            };
            self.record(epoch, step, outcome);
        }
        if first_pass {
            self.duty_management.log_epoch_boundary_summary(epoch, slot).await;
        }
    }

    /// Whether a step of `slot`'s epoch is still pending, or the next pass
    /// re-opens PrepareProposers ([`Self::reopen_moved_prepare`]).
    ///
    /// An epoch before the progress epoch has nothing pending.
    pub(crate) fn has_pending(&self, slot: Slot) -> bool {
        let epoch = slot / SLOTS_PER_EPOCH;
        let freshness = self.duty_management.index_freshness();
        match self.progress.lock().as_ref() {
            Some(current) if current.epoch > epoch => false,
            Some(current) if current.epoch == epoch => {
                current.prepare_moved(freshness)
                    || BoundaryStep::ALL.into_iter().any(|step| current.is_pending(step))
            }
            _ => true,
        }
    }

    /// Moves the progress to `epoch` when that is later, drops the selection
    /// proofs below the epoch's first slot, and warns once for the steps the
    /// old epoch did not finish. `true` when it moved.
    fn begin_epoch(&self, epoch: u64) -> bool {
        let mut progress = self.progress.lock();
        if progress.as_ref().is_some_and(|current| current.epoch >= epoch) {
            return false;
        }
        let old = progress.replace(EpochProgress::new(epoch));
        drop(progress);
        self.duty_management.evict_selection_proofs_before(epoch.saturating_mul(SLOTS_PER_EPOCH));
        if let Some(old) = old {
            old.warn_unfinished();
        }
        true
    }

    fn is_pending(&self, epoch: u64, step: BoundaryStep) -> bool {
        let progress = self.progress.lock();
        progress.as_ref().is_some_and(|current| current.epoch == epoch && current.is_pending(step))
    }

    /// Keeps `outcome` as the step's latest. Only `Done` marks a step done,
    /// and DutyFetch never: `EpochProgress::is_pending` derives its state.
    fn record(&self, epoch: u64, step: BoundaryStep, outcome: StepOutcome) {
        if let Some(current) = self.progress.lock().as_mut().filter(|p| p.epoch == epoch) {
            current.last_outcome.insert(step, outcome);
            if outcome == StepOutcome::Done && step != BoundaryStep::DutyFetch {
                current.done.insert(step);
            }
        }
    }

    fn breaker_reset(&self, epoch: u64) -> StepOutcome {
        self.circuit_breaker.reset_epoch(epoch);
        publish_circuit_breaker_metrics(&self.circuit_breaker);
        info!(epoch, "Circuit breaker reset at epoch boundary");
        StepOutcome::Done
    }

    /// Re-opens ProposerPreferences after a proposer root change, so the
    /// step signs again with the new root later in the same pass. A change
    /// that an earlier attempt cached before its bound cut it re-opens the
    /// step first, before this check's requests. `Done` once it returns. Its
    /// fetch errors are logged; whether the duties are cached is DutyFetch's
    /// concern.
    async fn reorg_check(&self, epoch: u64) -> StepOutcome {
        self.reopen_owed_preferences(epoch);
        let owed = &self.preferences_owed;
        self.duty_management.check_reorg_at_epoch_boundary(epoch, owed).await;
        self.reopen_owed_preferences(epoch);
        StepOutcome::Done
    }

    /// Re-opens ProposerPreferences when a root change owes it.
    fn reopen_owed_preferences(&self, epoch: u64) {
        if self.preferences_owed.swap(false, Ordering::AcqRel) {
            debug!(epoch, "Proposer root changed: the preferences step runs again");
            self.update_progress(epoch, |current| {
                current.done.remove(&BoundaryStep::ProposerPreferences);
            });
        }
    }

    /// Fetches the E and E+1 attester and proposer duties that are not
    /// cached, under one `timeouts.duty_fetch` bound for the whole step.
    ///
    /// Calls the tracker directly. Eviction, PTC duties and the next-period
    /// sync prefetch stay with the slot loop's warm-up. A failed fetch does
    /// not stop the next one. `Done` when all four entries are cached after
    /// the step, else `Failed`: a failed or timed-out request leaves its
    /// entry uncached.
    async fn duty_fetch(&self, epoch: u64) -> StepOutcome {
        let epochs = [epoch, epoch + 1];
        let fetch = async {
            for epoch in epochs {
                if !self.duty_tracker.is_epoch_cached(epoch).await {
                    debug!(epoch, "Epoch boundary fetching attester duties");
                    if let Err(e) = self.duty_tracker.fetch_duties_for_epoch(epoch).await {
                        warn!(epoch, error = %e, "Epoch boundary attester duty fetch failed");
                    }
                }
                if !self.duty_tracker.is_proposer_epoch_cached(epoch).await {
                    debug!(epoch, "Epoch boundary fetching proposer duties");
                    if let Err(e) = self.duty_tracker.fetch_proposer_duties(epoch).await {
                        warn!(epoch, error = %e, "Epoch boundary proposer duty fetch failed");
                    }
                }
            }
        };
        if tokio::time::timeout(self.timeouts.duty_fetch, fetch).await.is_err() {
            warn!(
                epoch,
                "Epoch boundary duty fetch timed out after {}s",
                self.timeouts.duty_fetch.as_secs()
            );
        }
        for epoch in epochs {
            if !self.duty_tracker.is_epoch_cached(epoch).await
                || !self.duty_tracker.is_proposer_epoch_cached(epoch).await
            {
                return StepOutcome::Failed;
            }
        }
        StepOutcome::Done
    }

    /// `Done` once a POST covered every local key, and `Failed` on a failed
    /// or timed-out POST. `NotReady` while a local key has no validator
    /// index, and, with no POST, while the registry is stale. After a
    /// `Partial` POST the step reads the registry and sends again only when
    /// more keys have an index. The count is read before the POST is built,
    /// so an index that lands after the read is sent at the next pass,
    /// whether or not that POST had it.
    ///
    /// The registry token is sampled before the count, and kept with it
    /// after a `Complete` or `Partial` POST. The service captures its own
    /// token under the lock it reads the indices under, so a move between
    /// the two makes the sample older than the POST: the next pass re-opens
    /// the step and sends one extra, idempotent POST. A kept `Fresh` or
    /// `Untracked` sample can equal a later token only if the POST was read
    /// under that token. A `Stale` sample is not kept, because two stale
    /// intervals give the same value. The next pass then re-opens the step.
    /// So a needed re-send is never suppressed. Before Gloas, a registry that
    /// stays stale keeps the step pending until the epoch ends.
    async fn prepare_proposers(&self, epoch: u64) -> StepOutcome {
        let under = self.duty_management.index_freshness();
        let resolved = self.duty_management.resolved_proposer_count();
        if self.prepared_count(epoch) == Some(resolved) {
            debug!(epoch, resolved, "Proposer preparations wait for more validator indices");
            return StepOutcome::NotReady;
        }
        match self.duty_management.prepare_proposers(epoch).await {
            Ok(PrepareOutcome::Complete) => {
                self.update_progress(epoch, |current| current.set_prepared(resolved, under));
                StepOutcome::Done
            }
            Ok(PrepareOutcome::Partial { unresolved }) => {
                debug!(
                    epoch,
                    resolved, unresolved, "Proposer preparations sent for part of the keys"
                );
                self.update_progress(epoch, |current| current.set_prepared(resolved, under));
                StepOutcome::NotReady
            }
            Ok(PrepareOutcome::NoIndices) => StepOutcome::NotReady,
            Ok(PrepareOutcome::Stale) => {
                self.update_progress(epoch, EpochProgress::forget_prepared);
                StepOutcome::NotReady
            }
            Err(_) => StepOutcome::Failed,
        }
    }

    /// The `prepared_count` of `epoch`.
    fn prepared_count(&self, epoch: u64) -> Option<usize> {
        let progress = self.progress.lock();
        progress.as_ref().filter(|p| p.epoch == epoch).and_then(|p| p.prepared_count)
    }

    /// Re-opens PrepareProposers, and clears its `Partial` suppression, when
    /// the registry token moved since the step's last POST, whether or not a
    /// pass saw the registry stale: a revalidation can change the indices
    /// and keep their count. An `Untracked` registry never moves.
    fn reopen_moved_prepare(&self, epoch: u64) {
        let freshness = self.duty_management.index_freshness();
        self.update_progress(epoch, |current| {
            if current.prepare_moved(freshness) {
                debug!(epoch, ?freshness, "Validator indices moved since the last preparation");
                current.forget_prepared();
            }
        });
    }

    /// Applies `change` to the progress of `epoch`, while that is the
    /// progress epoch.
    fn update_progress(&self, epoch: u64, change: impl FnOnce(&mut EpochProgress)) {
        if let Some(current) = self.progress.lock().as_mut().filter(|p| p.epoch == epoch) {
            change(current);
        }
    }

    /// `NotReady` until the attester duties of E and E+1 are cached; then
    /// sends the subscriptions of E, then E+1, that did not go out yet in
    /// this epoch. `Failed` while one of them did not: a failed or timed-out
    /// POST, or a call with duties that are not cached after the call. A revocation
    /// makes the cached duties stale, and a later call can then send nothing
    /// and return `Ok`. The next pass fetches the duties again (Harper B1).
    async fn committee_subscriptions(&self, epoch: u64) -> StepOutcome {
        for duty_epoch in [epoch, epoch + 1] {
            if !self.duty_tracker.is_epoch_cached(duty_epoch).await {
                debug!(epoch, duty_epoch, "Committee subscriptions wait for cached duties");
                return StepOutcome::NotReady;
            }
        }
        let mut outcome = StepOutcome::Done;
        for duty_epoch in [epoch, epoch + 1] {
            if self.subscribed(epoch, duty_epoch) {
                continue;
            }
            let post = self.duty_management.submit_committee_subscriptions(duty_epoch);
            let sent = post.await.is_ok();
            if sent && self.duty_tracker.is_epoch_cached(duty_epoch).await {
                self.mark_subscribed(epoch, duty_epoch);
            } else {
                if sent {
                    warn!(
                        epoch,
                        duty_epoch,
                        "Committee subscriptions stay pending: the duties of the epoch are no longer cached"
                    );
                }
                outcome = StepOutcome::Failed;
            }
        }
        outcome
    }

    /// Whether `duty_epoch`'s subscriptions went out in `epoch`.
    fn subscribed(&self, epoch: u64, duty_epoch: u64) -> bool {
        let progress = self.progress.lock();
        progress.as_ref().is_some_and(|p| p.epoch == epoch && p.subscribed.contains(&duty_epoch))
    }

    fn mark_subscribed(&self, epoch: u64, duty_epoch: u64) {
        if let Some(current) = self.progress.lock().as_mut().filter(|p| p.epoch == epoch) {
            current.subscribed.insert(duty_epoch);
        }
    }

    /// Re-sends every builder key's registration through
    /// `submit_epoch_registrations`, which signs only new or changed keys,
    /// under the builder service's `registration_step_timeout()`. `Done` once
    /// it returns `Ok`, and `Failed` on an error or at the bound. With no
    /// builder service, or from Gloas on, `Done` with no call.
    async fn builder_registration(&self, epoch: u64) -> StepOutcome {
        let Some(builder) = &self.builder_service else {
            return StepOutcome::Done;
        };
        if legacy_proposer_ops_retired(ForkName::from_epoch(epoch, &self.fork_schedule)) {
            return StepOutcome::Done;
        }
        let registration = async {
            match builder.submit_epoch_registrations(epoch).await {
                Ok(()) => {
                    info!(epoch, "Epoch builder registration completed");
                    StepOutcome::Done
                }
                Err(e) => {
                    warn!(epoch, error = %e, "Epoch builder registration failed");
                    StepOutcome::Failed
                }
            }
        };
        let bound = builder.registration_step_timeout();
        bounded(epoch, BoundaryStep::BuilderRegistration, bound, registration).await
    }

    /// Broadcasts the preferences of the local proposals of E and E+1, from
    /// the epoch before Gloas: the gate reads the fork of E+1, so the Gloas
    /// slots of the next epoch go out one epoch early. With no builder
    /// service, or before that epoch, `Done` with no call. `NotReady` while
    /// the proposer duties of E or E+1 are not cached. The full attempt,
    /// with its signature calls, runs under `PREFERENCES_STEP_TIMEOUT`.
    /// Each attempt takes one admission before it reads the duties and signs
    /// every preference under it; with no admitted node, it is `Failed`.
    /// `Done` once the two broadcasts succeed, and `Failed` on an error or at
    /// the bound. Each broadcast skips its cache hits, so a retry signs and
    /// sends only the entries that the beacon node did not accept.
    async fn proposer_preferences(&self, epoch: u64) -> StepOutcome {
        let Some(builder) = &self.builder_service else {
            return StepOutcome::Done;
        };
        if !legacy_proposer_ops_retired(ForkName::from_epoch(epoch + 1, &self.fork_schedule)) {
            return StepOutcome::Done;
        }
        for duty_epoch in [epoch, epoch + 1] {
            if !self.duty_tracker.is_proposer_epoch_cached(duty_epoch).await {
                debug!(epoch, duty_epoch, "Proposer preferences wait for cached proposer duties");
                return StepOutcome::NotReady;
            }
        }
        let broadcast = async {
            match self.broadcast_preferences(builder, epoch).await {
                Some(Ok(())) => StepOutcome::Done,
                Some(Err(e)) => {
                    warn!(epoch, error = %e, "Epoch preferences broadcast failed");
                    StepOutcome::Failed
                }
                None => StepOutcome::Failed,
            }
        };
        let step = BoundaryStep::ProposerPreferences;
        bounded(epoch, step, PREFERENCES_STEP_TIMEOUT, broadcast).await
    }
}

/// Runs `step` under `bound`. At the bound the step is dropped and `Failed`.
async fn bounded(
    epoch: u64,
    step: BoundaryStep,
    bound: Duration,
    work: impl Future<Output = StepOutcome>,
) -> StepOutcome {
    tokio::time::timeout(bound, work).await.unwrap_or_else(|_| {
        warn!(epoch, ?step, timeout = ?bound, "Epoch boundary step timed out");
        StepOutcome::Failed
    })
}

/// The local proposals of the ProposerPreferences step, and their broadcasts.
impl EpochBoundaryRunner {
    /// Takes one beacon-node admission for the attempt, before it reads the
    /// duties. Then it reads the local proposals of `current_epoch` and the
    /// next epoch, and runs the proposer broadcast, then the builder
    /// broadcast, under that admission. A revocation after the capture
    /// refuses each later signature of the attempt. The builder broadcast
    /// runs when the proposer one fails too.
    ///
    /// `None`, with no read and no signature, when no node is admitted.
    /// Else the first error.
    async fn broadcast_preferences(
        &self,
        builder: &BuilderService,
        current_epoch: u64,
    ) -> Option<Result<(), BuilderServiceError>> {
        let admission = builder.preference_admission()?;
        let proposals = self.upcoming_proposals(current_epoch).await;
        let root = &self.genesis_validators_root;
        Some(builder.broadcast_preferences_under(&admission, current_epoch, &proposals, root).await)
    }

    /// Local signing-enabled proposer duties for the current and next epoch.
    async fn upcoming_proposals(&self, current_epoch: u64) -> Vec<UpcomingProposal> {
        let mut out = Vec::new();
        for epoch in [current_epoch, current_epoch.saturating_add(1)] {
            out.extend(self.proposals_for_epoch(epoch).await);
        }
        out
    }

    async fn proposals_for_epoch(&self, epoch: u64) -> Vec<UpcomingProposal> {
        let dependent_root = match self.duty_tracker.get_cached_proposer_dependent_root(epoch).await
        {
            Some(hex) => match eth_types::canonical::gvr_hex::parse_gvr_hex(&hex) {
                Ok(root) => root,
                Err(e) => {
                    warn!(
                        epoch,
                        error = %e,
                        "Invalid proposer dependent_root; skipping preferences"
                    );
                    return Vec::new();
                }
            },
            None => {
                debug!(epoch, "No cached proposer dependent_root for preferences");
                return Vec::new();
            }
        };

        let mut out = Vec::new();
        for offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch.saturating_mul(SLOTS_PER_EPOCH).saturating_add(offset);
            let Some(duty) = self.duty_tracker.get_proposer_duty(slot).await else {
                continue;
            };
            let Some(pk) = utils::find_pubkey(&self.pubkey_map, &duty.pubkey) else {
                continue;
            };
            let pubkey = pk.to_bytes();
            if !self.validator_store.is_signing_enabled(&pubkey) {
                continue;
            }
            let validator_index = duty.validator_index;
            let proposal_slot = duty.slot;
            out.push(UpcomingProposal { pubkey, validator_index, proposal_slot, dependent_root });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bn_manager::{
        BeaconNodeClient, MockBeaconNodeClient, MockCallStamp, MockMethod, Propagator,
    };
    use builder::BuilderService;
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use duty_tracker::DutyTracker;
    use metrics::definitions::{RVC_BUILDER_CONSECUTIVE_MISSES, RVC_BUILDER_EPOCH_MISSES};
    use signer::{always_enabled, SignerService, ValidatorSigner};
    use slashing::SlashingDb;
    use timing::MockSlotClock;
    use tokio::task::JoinHandle;
    use tracing_subscriber::layer::SubscriberExt;
    use validator_store::{ValidatorConfig, ValidatorStore};

    use super::*;
    use crate::bootstrap::executor::{ShutdownTier, TierBudget};
    use crate::orchestrator::coordinator::tests::{
        create_mock_block_beacon, create_mock_validator_store, create_test_config,
        create_test_fork_schedule, fast_timeouts, m2_metric_lock, CountingRegistrationSigner,
        MockBlockBeacon, MockSubmitter, TEST_GENESIS_TIME,
    };
    use crate::orchestrator::selection_proofs::test_support::{call_bounded, ProbeResult};
    use crate::orchestrator::selection_proofs::SelectionProofCache;
    use crate::orchestrator::{
        DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorError,
        OrchestratorHandle,
    };
    use crate::pubkey_index::{PubkeyIndexRegistry, PubkeyIndexSource};
    use futures::future::BoxFuture;

    const ROOT_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROOT_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BREAKER_CONSECUTIVE_LIMIT: u32 = 3;
    const SLOT: Duration = Duration::from_secs(12);
    const GENESIS_MS: u64 = TEST_GENESIS_TIME * 1_000;

    struct Fixture {
        mock: Arc<MockBeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        breaker: Arc<CircuitBreakerState>,
        runner: Arc<EpochBoundaryRunner>,
        /// The selection-proof cache of the runner's duty management.
        selection_proofs: Arc<SelectionProofCache>,
        /// Duty slots of each subscription POST, in POST order.
        subscription_slots: Arc<parking_lot::Mutex<Vec<Vec<String>>>>,
        /// Attester-duties requests still to answer 503, per epoch.
        failing_attester: FailPlan,
        /// Prepare POSTs still to answer 503.
        failing_prepare: Arc<parking_lot::Mutex<usize>>,
        /// Subscription POSTs still to answer 503.
        failing_subscriptions: Arc<parking_lot::Mutex<usize>>,
        /// The tracker's index source: the production one, over the fixture's
        /// pubkey map and index registry.
        index_source: Arc<PubkeyIndexSource>,
        /// The runner task's clock, at genesis until a test moves it.
        clock: Arc<MockSlotClock>,
        /// The builder service's signer. It counts the registrations it signs.
        registrations: Arc<CountingRegistrationSigner>,
        /// The store that the builder service reads the builder URLs from.
        validator_store: Arc<ValidatorStore>,
        /// The beacon node of the builder service. It is open until a test
        /// closes it.
        admission: Arc<AdmissionGate>,
    }

    /// This type supplies the beacon node for the builder service in the
    /// fixture. Each call goes to `inner`. While `closed` is true,
    /// `beacon_admission` returns no admitted node.
    struct AdmissionGate {
        inner: Arc<dyn BeaconNodeClient>,
        closed: AtomicBool,
    }

    #[async_trait::async_trait]
    impl builder::BuilderBeaconClient for AdmissionGate {
        async fn register_validators(
            &self,
            registrations: &[bn_manager::SignedValidatorRegistration],
        ) -> Result<(), beacon::BeaconError> {
            builder::BuilderBeaconClient::register_validators(&self.inner, registrations).await
        }

        async fn prepare_beacon_proposer(
            &self,
            preparations: &[bn_manager::ProposerPreparation],
        ) -> Result<(), beacon::BeaconError> {
            builder::BuilderBeaconClient::prepare_beacon_proposer(&self.inner, preparations).await
        }

        async fn submit_proposer_preferences(
            &self,
            preferences: &[eth_types::SignedProposerPreferences],
        ) -> Result<(), beacon::BeaconError> {
            builder::BuilderBeaconClient::submit_proposer_preferences(&self.inner, preferences)
                .await
        }

        async fn submit_builder_preferences(
            &self,
            entries: &[bn_manager::BuilderPreferencesEntry],
        ) -> Result<bn_manager::SubmitBuilderPreferencesResult, beacon::BeaconError> {
            builder::BuilderBeaconClient::submit_builder_preferences(&self.inner, entries).await
        }

        fn beacon_admission(&self) -> Result<signer::BeaconAdmission, beacon::BeaconError> {
            if self.closed.load(Ordering::Acquire) {
                return Err(beacon::BeaconError::NoAdmittedNode);
            }
            builder::BuilderBeaconClient::beacon_admission(&self.inner)
        }
    }

    impl Fixture {
        /// Resolves a new local key to `index` with no cache clear, as the
        /// index resolver does mid-epoch. Every cached attester epoch stays
        /// present, under an index snapshot that is now stale.
        fn resolve_new_key(&self, index: &str) {
            let pk_bytes = self.add_unresolved_key();
            self.index_source.registry.write().insert(pk_bytes, index.to_string());
        }

        /// Adds a local key with no validator index yet, and returns it.
        fn add_unresolved_key(&self) -> [u8; 48] {
            let pubkey = SecretKey::generate().public_key();
            let pk_bytes = pubkey.to_bytes();
            self.index_source.pubkey_map.write().insert(pk_bytes, pubkey);
            pk_bytes
        }
    }

    /// Requests still to answer 503, per epoch.
    type FailPlan = Arc<parking_lot::Mutex<HashMap<u64, usize>>>;

    /// Spends one armed failure for `epoch`; `true` means answer 503.
    fn take_failure(plan: &FailPlan, epoch: u64) -> bool {
        match plan.lock().get_mut(&epoch) {
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        }
    }

    fn unavailable() -> beacon::BeaconError {
        beacon::BeaconError::ApiError { status: 503, message: "unavailable".to_string() }
    }

    /// Proposer duties at root A with no proposals, failing per `plan`.
    fn proposer_duties_failing(plan: FailPlan) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_proposer_duties(move |epoch| {
            if take_failure(&plan, epoch) {
                return Err(unavailable());
            }
            Ok(beacon::DependentRootResponse {
                dependent_root: ROOT_A.to_string(),
                execution_optimistic: false,
                data: Vec::new(),
            })
        })
    }

    fn proposer_duties_at(root: &'static str) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_proposer_duties(move |_epoch| {
            info!("mock get_proposer_duties");
            Ok(beacon::DependentRootResponse {
                dependent_root: root.to_string(),
                execution_optimistic: false,
                data: Vec::new(),
            })
        })
    }

    /// Proposer duties at root `first` on the first call and `then` after it,
    /// with one proposal for `local_hex` at slot 5 of `epoch`.
    fn proposer_duties_then(
        local_hex: String,
        epoch: u64,
        first: &'static str,
        then: &'static str,
    ) -> MockBeaconNodeClient {
        let calls = AtomicUsize::new(0);
        MockBeaconNodeClient::new()
            .with_get_proposer_duties(move |requested| {
                let root = if calls.fetch_add(1, Ordering::Relaxed) == 0 { first } else { then };
                let data = if requested == epoch {
                    vec![beacon::ProposerDuty {
                        pubkey: local_hex.clone(),
                        validator_index: "42".to_string(),
                        slot: (epoch * SLOTS_PER_EPOCH + 5).to_string(),
                    }]
                } else {
                    Vec::new()
                };
                Ok(beacon::DependentRootResponse {
                    dependent_root: root.to_string(),
                    execution_optimistic: false,
                    data,
                })
            })
            .with_post_ptc_duties(|_epoch, _indices| {
                Ok(beacon::DependentRootResponse {
                    dependent_root: ROOT_A.to_string(),
                    execution_optimistic: false,
                    data: Vec::new(),
                })
            })
            .with_submit_proposer_preferences(|_preferences| Ok(()))
    }

    async fn fixture(mock: MockBeaconNodeClient) -> Fixture {
        fixture_with(mock, SecretKey::generate(), false).await
    }

    /// Local validator 42 with an attester duty at slot 1 of every epoch
    /// requested with its index; epochs 1 and 2 are seeded through
    /// `fetch_duties_for_epoch`.
    /// `with_builder` attaches a `BuilderService` over the same mock and
    /// makes the local key builder-enabled.
    async fn fixture_with(
        mock: MockBeaconNodeClient,
        local: SecretKey,
        with_builder: bool,
    ) -> Fixture {
        fixture_seeded(mock, local, with_builder, &[1, 2]).await
    }

    /// [`fixture_with`], seeding the attester duties of `seed` only.
    async fn fixture_seeded(
        mock: MockBeaconNodeClient,
        local: SecretKey,
        with_builder: bool,
        seed: &[u64],
    ) -> Fixture {
        fixture_config(mock, local, with_builder, seed, create_test_config()).await
    }

    /// [`fixture_seeded`] under `config`'s timeouts.
    async fn fixture_config(
        mock: MockBeaconNodeClient,
        local: SecretKey,
        with_builder: bool,
        seed: &[u64],
        config: OrchestratorConfig,
    ) -> Fixture {
        fixture_batched(mock, local, with_builder, seed, config, Batching::default()).await
    }

    /// The batch knobs of a fixture's builder service, and the number of
    /// builder-enabled keys that the fixture adds next to the local key.
    #[derive(Clone, Copy, Default)]
    struct Batching {
        extra_keys: usize,
        size: usize,
        delay_ms: u64,
    }

    /// [`fixture_config`] with the builder service's `batching`.
    async fn fixture_batched(
        mock: MockBeaconNodeClient,
        local: SecretKey,
        with_builder: bool,
        seed: &[u64],
        config: OrchestratorConfig,
        batching: Batching,
    ) -> Fixture {
        let pubkey = local.public_key();
        let pk_bytes = pubkey.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let subscription_slots = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&subscription_slots);
        let failing_attester = FailPlan::default();
        let failing = Arc::clone(&failing_attester);
        let failing_prepare = Arc::new(parking_lot::Mutex::new(0_usize));
        let prepare_failures = Arc::clone(&failing_prepare);
        let failing_subscriptions = Arc::new(parking_lot::Mutex::new(0_usize));
        let subscription_failures = Arc::clone(&failing_subscriptions);
        let mock = Arc::new(
            mock.with_get_attester_duties(move |epoch, indices| {
                if take_failure(&failing, epoch) {
                    return Err(unavailable());
                }
                let duty = beacon::AttesterDuty {
                    pubkey: pk_hex.clone(),
                    validator_index: "42".to_string(),
                    committee_index: "1".to_string(),
                    committee_length: "8".to_string(),
                    committees_at_slot: "4".to_string(),
                    validator_committee_index: "0".to_string(),
                    slot: (epoch * SLOTS_PER_EPOCH + 1).to_string(),
                };
                let data =
                    if indices.iter().any(|index| index == "42") { vec![duty] } else { Vec::new() };
                Ok(beacon::DependentRootResponse {
                    dependent_root: ROOT_A.to_string(),
                    execution_optimistic: false,
                    data,
                })
            })
            .with_prepare_beacon_proposer(move |_preparations| {
                let mut left = prepare_failures.lock();
                if *left > 0 {
                    *left -= 1;
                    return Err(unavailable());
                }
                Ok(())
            })
            .with_submit_beacon_committee_subscriptions(move |subscriptions| {
                let mut left = subscription_failures.lock();
                if *left > 0 {
                    *left -= 1;
                    return Err(unavailable());
                }
                recorded.lock().push(subscriptions.into_iter().map(|s| s.slot).collect());
                Ok(())
            }),
        );
        mock.track_admission();
        let beacon: Arc<dyn BeaconNodeClient> = mock.clone();

        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::from([(pk_bytes, pubkey)])));
        let pubkey_index = PubkeyIndexRegistry::shared();
        pubkey_index.write().insert(pk_bytes, "42".to_string());
        let index_source = Arc::new(PubkeyIndexSource {
            registry: Arc::clone(&pubkey_index),
            pubkey_map: Arc::clone(&pubkey_map),
        });
        let duty_tracker =
            Arc::new(DutyTracker::new_with_source(beacon.clone(), index_source.clone()));
        for &epoch in seed {
            duty_tracker.fetch_duties_for_epoch(epoch).await.expect("seed attester duties");
        }

        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        let mut validator = ValidatorConfig::new(pk_bytes);
        validator.builder_proposals = with_builder;
        validator_store.add_validator(validator).expect("add validator");

        let mut key_manager = KeyManager::new();
        key_manager.insert(local);
        for _ in 0..batching.extra_keys {
            let extra = SecretKey::generate();
            let mut validator = ValidatorConfig::new(extra.public_key().to_bytes());
            validator.builder_proposals = true;
            validator_store
                .add_validator(validator)
                .expect("The fixture must add each builder-enabled validator.");
            key_manager.insert(extra);
        }
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        let validator_signer: Arc<dyn ValidatorSigner> = signer.clone();
        let registrations = CountingRegistrationSigner::new(validator_signer);
        let admission =
            Arc::new(AdmissionGate { inner: beacon.clone(), closed: AtomicBool::new(false) });
        let builder_service = with_builder.then(|| {
            let schedule = create_test_fork_schedule();
            Arc::new(BuilderService::with_batching(
                registrations.clone(),
                admission.clone(),
                Arc::clone(&validator_store),
                schedule.genesis_fork_version,
                batching.size,
                batching.delay_ms,
                schedule,
            ))
        });
        let timeouts = config.timeouts.clone();
        let fork_schedule = Arc::clone(&config.fork_schedule);
        let genesis_validators_root = config.genesis_validators_root;
        let selection_proofs = Arc::new(SelectionProofCache::default());
        let duty_management = Arc::new(DutyManagementService::new(
            signer,
            beacon,
            Arc::clone(&duty_tracker),
            Arc::clone(&validator_store),
            Arc::clone(&pubkey_map),
            pubkey_index,
            config,
            Arc::clone(&selection_proofs),
        ));
        let breaker = Arc::new(CircuitBreakerState::new(BREAKER_CONSECUTIVE_LIMIT, 5));
        let runner = Arc::new(EpochBoundaryRunner::new(
            duty_management,
            Arc::clone(&breaker),
            Arc::clone(&duty_tracker),
            timeouts,
            builder_service,
            fork_schedule,
            pubkey_map,
            Arc::clone(&validator_store),
            genesis_validators_root,
        ));
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, SLOT, SLOTS_PER_EPOCH));
        Fixture {
            mock,
            duty_tracker,
            breaker,
            runner,
            selection_proofs,
            subscription_slots,
            failing_attester,
            failing_prepare,
            failing_subscriptions,
            index_source,
            clock,
            registrations,
            validator_store,
            admission,
        }
    }

    fn expect_summaries(lines: &[&str], want: usize) -> Result<(), String> {
        let seen = boundary_lines(lines).into_iter().filter(|line| *line == "summary").count();
        if seen == want {
            Ok(())
        } else {
            Err(format!("{seen} epoch summaries, want {want}"))
        }
    }

    fn boundary_lines(lines: &[&str]) -> Vec<&'static str> {
        lines
            .iter()
            .filter_map(|line| {
                if line.contains("Epoch boundary summary") {
                    Some("summary")
                } else if line.contains("Circuit breaker reset at epoch boundary") {
                    Some("breaker")
                } else if line.contains("mock get_proposer_duties") {
                    Some("proposer_duties")
                } else if line.contains("Sent committee subscriptions") {
                    Some("subscriptions")
                } else if line.contains("Sent proposer preparations") {
                    Some("prepare")
                } else {
                    None
                }
            })
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn run_pending_runs_steps_in_the_fixed_order() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        let seeded = f.mock.call_stamps().len();

        f.runner.run_pending(32).await;

        let order: Vec<MockMethod> = f.mock.call_stamps()[seeded..]
            .iter()
            .map(|stamp| stamp.method)
            .filter(|method| *method != MockMethod::GetAttesterDuties)
            .collect();
        assert_eq!(
            order,
            [
                MockMethod::GetProposerDuties,
                MockMethod::GetProposerDuties,
                MockMethod::PrepareBeaconProposer,
                MockMethod::SubmitBeaconCommitteeSubscriptions,
                MockMethod::SubmitBeaconCommitteeSubscriptions,
            ]
        );
        assert_eq!(*f.subscription_slots.lock(), [vec!["33".to_string()], vec!["65".to_string()]]);
        logs_assert(|lines| match boundary_lines(lines).as_slice() {
            ["breaker", "proposer_duties", "proposer_duties", "prepare", "subscriptions", "subscriptions", "summary"] => {
                Ok(())
            }
            seen => Err(format!("steps out of order, or the summary is not last: {seen:?}")),
        });
    }

    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn run_pending_runs_each_step_once_per_epoch() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;

        for slot in [32, 33, 63] {
            f.runner.run_pending(slot).await;
        }
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 1);
        assert_eq!(f.subscription_slots.lock().len(), 2, "one subscription pass: E and E+1");
        logs_assert(|lines| expect_summaries(lines, 1));

        f.runner.run_pending(64).await;
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 2, "epoch 2 runs the steps");
        assert_eq!(f.subscription_slots.lock().len(), 4);
        logs_assert(|lines| expect_summaries(lines, 2));

        f.runner.run_pending(32).await;
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 2, "an older epoch runs nothing");
        assert_eq!(f.subscription_slots.lock().len(), 4);
        logs_assert(|lines| expect_summaries(lines, 2));
    }

    /// Publishes, then checks the trip and both gauges at the consecutive limit.
    fn assert_breaker_tripped(breaker: &CircuitBreakerState) {
        publish_circuit_breaker_metrics(breaker);
        assert!(breaker.is_tripped());
        let limit = i64::from(BREAKER_CONSECUTIVE_LIMIT);
        assert_eq!(RVC_BUILDER_EPOCH_MISSES.get(), limit);
        assert_eq!(RVC_BUILDER_CONSECUTIVE_MISSES.get(), limit);
    }

    fn assert_breaker_reset(breaker: &CircuitBreakerState, epoch: u64) {
        assert!(!breaker.is_tripped(), "epoch {epoch} must clear the trip");
        assert_eq!(breaker.epoch_misses(), 0, "epoch {epoch}");
        assert_eq!(breaker.consecutive_misses(), 0, "epoch {epoch}");
        assert_eq!(RVC_BUILDER_EPOCH_MISSES.get(), 0, "epoch {epoch} gauge");
        assert_eq!(RVC_BUILDER_CONSECUTIVE_MISSES.get(), 0, "epoch {epoch} gauge");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn breaker_reset_zeroes_the_epoch_counters_and_publishes_gauges() {
        let _metrics = m2_metric_lock().await;
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        for _ in 0..BREAKER_CONSECUTIVE_LIMIT {
            f.breaker.record_miss();
        }
        assert_breaker_tripped(&f.breaker);

        f.runner.run_pending(32).await;
        assert_breaker_reset(&f.breaker, 1);

        f.breaker.record_miss();
        f.runner.run_pending(33).await;
        assert_eq!(f.breaker.epoch_misses(), 1, "a second pass in epoch 1 must not reset again");

        for _ in 1..BREAKER_CONSECUTIVE_LIMIT {
            f.breaker.record_miss();
        }
        assert_breaker_tripped(&f.breaker);

        f.runner.run_pending(64).await;
        assert_breaker_reset(&f.breaker, 2);
    }

    /// A proposer root change seen by ReorgCheck re-opens the preferences
    /// step inside the runner's own pass. The step is done before the pass,
    /// and it runs again after the subscription step, with the new root. No
    /// `DutyOrchestrator` exists here. An unchanged root, or no builder
    /// service, sends none.
    #[tokio::test(flavor = "current_thread")]
    async fn reorg_root_change_rebroadcasts_from_the_runner() {
        let epoch = create_test_fork_schedule().gloas_fork_epoch;
        let proposal_slot = epoch * SLOTS_PER_EPOCH + 5;
        for (then, with_builder, want_posts) in
            [(ROOT_B, true, 1), (ROOT_A, true, 0), (ROOT_B, false, 0)]
        {
            let arm = format!("second root {then}, builder {with_builder}");
            let local = SecretKey::generate();
            let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
            let mock = proposer_duties_then(local_hex, epoch, ROOT_A, then);
            let f = fixture_with(mock, local, with_builder).await;
            f.duty_tracker.fetch_proposer_duties(epoch).await.expect("seed root A");
            mark_preferences_done(&f.runner, epoch);

            f.runner.run_pending(epoch * SLOTS_PER_EPOCH).await;

            let prefs = f.mock.submit_proposer_preferences_calls();
            assert_eq!(prefs.len(), want_posts, "{arm}");
            if want_posts == 0 {
                continue;
            }
            assert_eq!(prefs[0].len(), 1, "{arm}");
            let message = &prefs[0][0].message;
            assert_eq!(message.proposal_slot, proposal_slot);
            assert_eq!(message.validator_index, 42);
            assert_eq!(
                message.dependent_root,
                eth_types::canonical::gvr_hex::parse_gvr_hex(ROOT_B).expect("root B")
            );
            let order: Vec<MockMethod> = f
                .mock
                .call_stamps()
                .iter()
                .map(|stamp| stamp.method)
                .filter(|method| {
                    matches!(
                        method,
                        MockMethod::GetProposerDuties
                            | MockMethod::SubmitProposerPreferences
                            | MockMethod::SubmitBeaconCommitteeSubscriptions
                    )
                })
                .collect();
            // The calls must occur in this order:
            //
            // 1. The proposer request of the seed.
            // 2. The proposer requests of ReorgCheck for E and E+1.
            // 3. The two subscription POSTs.
            // 4. The POST of the re-opened preferences step.
            assert_eq!(
                order,
                [
                    MockMethod::GetProposerDuties,
                    MockMethod::GetProposerDuties,
                    MockMethod::GetProposerDuties,
                    MockMethod::SubmitBeaconCommitteeSubscriptions,
                    MockMethod::SubmitBeaconCommitteeSubscriptions,
                    MockMethod::SubmitProposerPreferences,
                ],
                "The calls must occur in the order of the list above."
            );
        }
    }

    /// Marks the ProposerPreferences step of `epoch` done. Thus only a root
    /// change that ReorgCheck finds can make the step run again.
    fn mark_preferences_done(runner: &EpochBoundaryRunner, epoch: u64) {
        runner.begin_epoch(epoch);
        runner.record(epoch, BoundaryStep::ProposerPreferences, StepOutcome::Done);
    }

    fn methods_since(mock: &MockBeaconNodeClient, from: usize) -> Vec<MockMethod> {
        mock.call_stamps()[from..].iter().map(|stamp| stamp.method).collect()
    }

    fn attester_epochs_since(mock: &MockBeaconNodeClient, from: usize) -> Vec<u64> {
        mock.get_attester_duties_calls()[from..].iter().map(|(epoch, _)| *epoch).collect()
    }

    fn slots(posts: &[&[&str]]) -> Vec<Vec<String>> {
        posts.iter().map(|post| post.iter().map(|slot| slot.to_string()).collect()).collect()
    }

    /// DutyFetch requests only what is not cached. On a warm cache a pass
    /// makes ReorgCheck's four requests and no more. With E cached and E+1
    /// not, ReorgCheck's own E+1 requests fail, so the attester and proposer
    /// request for E+1 that follow them, before the prepare POST, are
    /// DutyFetch's. A failed entry does not stop the next one.
    #[tokio::test(flavor = "current_thread")]
    async fn duty_fetch_fetches_only_what_is_uncached() {
        let [att, prop] = [MockMethod::GetAttesterDuties, MockMethod::GetProposerDuties];
        let [prep, subs] =
            [MockMethod::PrepareBeaconProposer, MockMethod::SubmitBeaconCommitteeSubscriptions];

        let warm = fixture(proposer_duties_at(ROOT_A)).await;
        let seeded = warm.mock.call_stamps().len();
        warm.runner.run_pending(32).await;
        assert_eq!(
            methods_since(&warm.mock, seeded),
            [att, prop, att, prop, prep, subs, subs],
            "warm cache: ReorgCheck's requests only"
        );

        let failing_proposer = FailPlan::default();
        let f = fixture(proposer_duties_failing(Arc::clone(&failing_proposer))).await;
        f.duty_tracker.fetch_proposer_duties(1).await.expect("seed proposer E");
        f.duty_tracker.clear_epoch_cache(2).await;
        f.failing_attester.lock().insert(2, 1);
        failing_proposer.lock().insert(2, 1);
        let seeded = f.mock.call_stamps().len();
        let attester_seeded = f.mock.get_attester_duties_calls().len();
        let proposer_seeded = f.mock.get_proposer_duties_calls().len();

        f.runner.run_pending(32).await;

        assert_eq!(
            methods_since(&f.mock, seeded),
            [att, prop, att, prop, att, prop, prep, subs, subs],
            "ReorgCheck E, E+1 (failing), then DutyFetch E+1, before PrepareProposers"
        );
        assert_eq!(attester_epochs_since(&f.mock, attester_seeded), [1, 2, 2]);
        assert_eq!(f.mock.get_proposer_duties_calls()[proposer_seeded..], [1, 2, 2]);
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));

        let calls = f.mock.call_stamps().len();
        assert_eq!(f.runner.duty_fetch(1).await, StepOutcome::Done, "all four entries are cached");
        assert_eq!(f.mock.call_stamps().len(), calls, "a cache read, no beacon node call");
        failing_proposer.lock().insert(3, 1);
        assert_eq!(
            f.runner.duty_fetch(2).await,
            StepOutcome::Failed,
            "E+1's proposer request failed: still uncached"
        );

        let f = fixture(proposer_duties_at(ROOT_A)).await;
        for epoch in [1, 2] {
            f.duty_tracker.clear_epoch_cache(epoch).await;
        }
        f.failing_attester.lock().extend([(1, 2), (2, 1)]);
        let attester_seeded = f.mock.get_attester_duties_calls().len();

        f.runner.run_pending(32).await;

        assert_eq!(
            attester_epochs_since(&f.mock, attester_seeded),
            [1, 2, 1, 2],
            "ReorgCheck E and E+1 fail; DutyFetch's E fails, and it still fetches E+1"
        );
        assert!(f.duty_tracker.is_epoch_cached(2).await);
        assert!(f.subscription_slots.lock().is_empty(), "E is still uncached");
    }

    /// A failed proposer fetch does not stop the next fetch either. ReorgCheck's
    /// proposer E and E+1 and attester E+1 requests fail, so DutyFetch
    /// requests all three; its proposer E request fails too, and the E+1
    /// requests still follow it in the same pass.
    #[tokio::test(flavor = "current_thread")]
    async fn duty_fetch_continues_after_a_failed_proposer_fetch() {
        let [att, prop] = [MockMethod::GetAttesterDuties, MockMethod::GetProposerDuties];
        let [prep, subs] =
            [MockMethod::PrepareBeaconProposer, MockMethod::SubmitBeaconCommitteeSubscriptions];
        let failing_proposer = FailPlan::default();
        let f = fixture(proposer_duties_failing(Arc::clone(&failing_proposer))).await;
        f.duty_tracker.clear_epoch_cache(2).await;
        f.failing_attester.lock().insert(2, 1);
        failing_proposer.lock().extend([(1, 2), (2, 1)]);
        let seeded = f.mock.call_stamps().len();
        let attester_seeded = f.mock.get_attester_duties_calls().len();
        let proposer_seeded = f.mock.get_proposer_duties_calls().len();

        f.runner.run_pending(32).await;

        assert_eq!(
            methods_since(&f.mock, seeded),
            [att, prop, att, prop, prop, att, prop, prep, subs, subs],
            "ReorgCheck E and E+1, then DutyFetch: proposer E fails, E+1 still follows"
        );
        assert_eq!(f.mock.get_proposer_duties_calls()[proposer_seeded..], [1, 2, 1, 2]);
        assert_eq!(attester_epochs_since(&f.mock, attester_seeded), [1, 2, 2]);
        assert!(!f.duty_tracker.is_proposer_epoch_cached(1).await, "both E requests failed");
        assert!(f.duty_tracker.is_proposer_epoch_cached(2).await);
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));
    }

    /// DutyFetch is `Done` only when all four entries, the attester and
    /// proposer duties of E and E+1, are cached after it. Each case leaves
    /// one entry uncached: its ReorgCheck and DutyFetch requests fail, and
    /// the other three are cached. DutyFetch is `Failed`, and not done. Once
    /// the request succeeds, DutyFetch is `Done`: at the next wake while the
    /// subscription step waits for the attester entry, and on its next run
    /// for a proposer entry.
    #[tokio::test(flavor = "current_thread")]
    async fn duty_fetch_is_failed_while_any_of_the_four_entries_is_uncached() {
        use BoundaryStep::DutyFetch;
        for (attester, epoch) in [(true, 1), (false, 1), (true, 2), (false, 2)] {
            let kind = if attester { "attester" } else { "proposer" };
            let case = format!("{kind} duties of epoch {epoch}");
            let failing_proposer = FailPlan::default();
            let f = fixture(proposer_duties_failing(Arc::clone(&failing_proposer))).await;
            if attester {
                f.duty_tracker.clear_epoch_cache(epoch).await;
                f.failing_attester.lock().insert(epoch, 2);
            } else {
                failing_proposer.lock().insert(epoch, 2);
            }

            f.runner.run_pending(32).await;

            for cached in [1, 2] {
                let missing = cached == epoch;
                assert_eq!(
                    f.duty_tracker.is_epoch_cached(cached).await,
                    !(attester && missing),
                    "{case}: attester duties of epoch {cached}"
                );
                assert_eq!(
                    f.duty_tracker.is_proposer_epoch_cached(cached).await,
                    attester || !missing,
                    "{case}: proposer duties of epoch {cached}"
                );
            }
            assert_eq!(
                step_state(&f.runner, DutyFetch),
                (Some(StepOutcome::Failed), false),
                "{case} uncached: failed, and not done"
            );

            if attester {
                f.runner.run_pending(33).await;
                assert_eq!(
                    step_state(&f.runner, DutyFetch),
                    (Some(StepOutcome::Done), false),
                    "{case} fetched at the next wake"
                );
            } else {
                assert_eq!(f.runner.duty_fetch(1).await, StepOutcome::Done, "{case} fetched");
            }
        }
    }

    /// DutyFetch keys on `is_epoch_cached`, the index-snapshot rule, not on
    /// presence. E+1 fails for the whole first pass, so the subscription
    /// step stays pending. A key resolved before the next wake leaves E
    /// present under the old index set, and that wake's DutyFetch requests E
    /// again with the new set.
    #[tokio::test(flavor = "current_thread")]
    async fn duty_fetch_refetches_an_epoch_cached_under_an_older_index_set() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        f.duty_tracker.clear_epoch_cache(2).await;
        f.failing_attester.lock().insert(2, 2);
        f.runner.run_pending(32).await;
        assert!(f.subscription_slots.lock().is_empty(), "E+1's requests failed: no POST");
        assert!(f.runner.has_pending(33), "the subscription step stays pending");

        f.resolve_new_key("43");
        assert!(f.duty_tracker.get_cached_dependent_root(1).await.is_some(), "E is present");
        assert!(!f.duty_tracker.is_epoch_cached(1).await, "under the old index set");
        let attester_seeded = f.mock.get_attester_duties_calls().len();

        f.runner.run_pending(33).await;

        let grown = vec!["42".to_string(), "43".to_string()];
        assert_eq!(
            f.mock.get_attester_duties_calls()[attester_seeded..],
            [(1, grown.clone()), (2, grown)],
            "DutyFetch requests the stale E again with the new index set, then E+1"
        );
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));
    }

    /// Held on the prepare POST, so a cache entry can turn into a miss after
    /// DutyFetch and before the subscription step.
    const PREPARE_HOLD: Duration = Duration::from_secs(1);

    /// CommitteeSubscriptions waits until E and E+1 are cached, and DutyFetch
    /// has no done mark: it runs again at each wake while the subscription
    /// step is pending, and refetches an entry that turned into a miss.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[tracing_test::traced_test]
    async fn subscriptions_wait_for_runner_fetched_duties() {
        let held = proposer_duties_at(ROOT_A)
            .with_method_delay(MockMethod::PrepareBeaconProposer, PREPARE_HOLD);
        let f = fixture(held).await;
        f.duty_tracker.clear_epoch_cache(2).await;
        f.failing_attester.lock().insert(2, 2);

        f.runner.run_pending(32).await;
        assert!(
            f.subscription_slots.lock().is_empty(),
            "ReorgCheck's and DutyFetch's E+1 requests failed: no subscription POST"
        );
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 1, "the other steps ran");
        assert_eq!(
            step_state(&f.runner, BoundaryStep::CommitteeSubscriptions),
            (Some(StepOutcome::NotReady), false),
            "cold E+1: not ready, and not done"
        );
        assert!(f.runner.has_pending(33), "the subscription step stays pending");

        f.runner.run_pending(33).await;
        assert_eq!(
            *f.subscription_slots.lock(),
            slots(&[&["33"], &["65"]]),
            "the next wake fetches E+1, then POSTs E and E+1 once"
        );
        assert!(!f.runner.has_pending(34), "nothing is pending once both epochs are subscribed");
        logs_assert(|lines| expect_summaries(lines, 1));

        // Epoch 2: its E, cached by epoch 1's DutyFetch, turns into a miss
        // after this pass's DutyFetch, while the prepare POST is held.
        let clear_during_prepare = async {
            tokio::time::sleep(PREPARE_HOLD / 2).await;
            f.duty_tracker.clear_epoch_cache(2).await;
        };
        tokio::join!(f.runner.run_pending(64), clear_during_prepare);
        assert_eq!(f.subscription_slots.lock().len(), 2, "E uncached at the step: no POST");
        assert!(!f.duty_tracker.is_epoch_cached(2).await, "the miss came after DutyFetch");
        assert_eq!(
            step_state(&f.runner, BoundaryStep::DutyFetch).0,
            Some(StepOutcome::Done),
            "every entry was cached after DutyFetch"
        );
        assert_eq!(
            step_state(&f.runner, BoundaryStep::CommitteeSubscriptions),
            (Some(StepOutcome::NotReady), false),
            "E was uncached at the subscription step"
        );
        assert!(f.runner.has_pending(65), "the subscription step stays pending");

        f.runner.run_pending(65).await;
        assert_eq!(
            f.subscription_slots.lock()[2..],
            slots(&[&["65"], &["97"]]),
            "DutyFetch refetched E at the next wake"
        );
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 2, "one prepare per epoch");
        logs_assert(|lines| expect_summaries(lines, 2));
    }

    /// The subscription step reads the same index-snapshot rule, not
    /// presence. A key resolved after DutyFetch, while the prepare POST is
    /// held, leaves E and E+1 present under the old index set: no POST, and
    /// the step stays pending. The next wake's DutyFetch requests both with
    /// the new set, then the step POSTs.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn subscriptions_wait_when_a_key_resolves_after_duty_fetch() {
        let held = proposer_duties_at(ROOT_A)
            .with_method_delay(MockMethod::PrepareBeaconProposer, PREPARE_HOLD);
        let f = fixture(held).await;
        let resolve_during_prepare = async {
            tokio::time::sleep(PREPARE_HOLD / 2).await;
            f.resolve_new_key("43");
        };

        tokio::join!(f.runner.run_pending(32), resolve_during_prepare);

        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 1, "the pass reached prepare");
        assert!(f.subscription_slots.lock().is_empty(), "stale E and E+1 at the step: no POST");
        for epoch in [1, 2] {
            assert!(f.duty_tracker.get_cached_dependent_root(epoch).await.is_some(), "{epoch}");
            assert!(!f.duty_tracker.is_epoch_cached(epoch).await, "{epoch}: old index set");
        }
        assert!(f.runner.has_pending(33), "the subscription step stays pending");
        let attester_seeded = f.mock.get_attester_duties_calls().len();

        f.runner.run_pending(33).await;

        let grown = vec!["42".to_string(), "43".to_string()];
        assert_eq!(
            f.mock.get_attester_duties_calls()[attester_seeded..],
            [(1, grown.clone()), (2, grown)],
            "the next wake's DutyFetch requests E and E+1 with the new index set"
        );
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));
        assert!(!f.runner.has_pending(34), "nothing is pending once both epochs are subscribed");
    }

    /// The latest outcome of `step` in the runner's epoch, and whether it is done.
    fn step_state(runner: &EpochBoundaryRunner, step: BoundaryStep) -> (Option<StepOutcome>, bool) {
        let progress = runner.progress.lock();
        let progress = progress.as_ref().expect("a pass ran");
        (progress.last_outcome.get(&step).copied(), progress.done.contains(&step))
    }

    /// DutyFetch's E+1 attester request fails at slot 32, after ReorgCheck's:
    /// DutyFetch is `Failed`, CommitteeSubscriptions is `NotReady` and not
    /// done, and PrepareProposers between them still runs. At slot 33 only
    /// the fetch runs again; it succeeds, and the subscriptions go out once.
    #[tokio::test(flavor = "current_thread")]
    async fn duty_fetch_failure_is_retried_next_slot() {
        use BoundaryStep::{CommitteeSubscriptions, DutyFetch};
        let [att, subs] =
            [MockMethod::GetAttesterDuties, MockMethod::SubmitBeaconCommitteeSubscriptions];
        let f =
            fixture_seeded(proposer_duties_at(ROOT_A), SecretKey::generate(), false, &[1]).await;
        f.failing_attester.lock().insert(2, 2);
        let attester_seeded = f.mock.get_attester_duties_calls().len();

        f.runner.run_pending(32).await;

        assert_eq!(
            attester_epochs_since(&f.mock, attester_seeded),
            [1, 2, 2],
            "ReorgCheck E and E+1, then DutyFetch's E+1, which fails too"
        );
        assert_eq!(
            step_state(&f.runner, DutyFetch),
            (Some(StepOutcome::Failed), false),
            "the E+1 fetch failed"
        );
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::NotReady), false),
            "E+1 uncached: not ready, and not done"
        );
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 1, "PrepareProposers still ran");
        assert!(f.subscription_slots.lock().is_empty(), "E+1 is uncached: no POST");
        assert!(f.runner.has_pending(33));
        let seeded = f.mock.call_stamps().len();

        f.runner.run_pending(33).await;

        assert_eq!(
            methods_since(&f.mock, seeded),
            [att, subs, subs],
            "DutyFetch's E+1 request, then the subscriptions; no done step runs again"
        );
        assert_eq!(attester_epochs_since(&f.mock, attester_seeded + 3), [2]);
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]), "E and E+1, once");
        assert_eq!(
            step_state(&f.runner, DutyFetch),
            (Some(StepOutcome::Done), false),
            "DutyFetch is never marked done"
        );
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::Done), true),
            "sent: done"
        );
        assert!(!f.runner.has_pending(34));
    }

    /// The order is per pass, not a barrier: PrepareProposers fails at slot
    /// 32, and the subscription step after it still POSTs in that pass. At
    /// slot 33 only PrepareProposers runs again: the breaker is not reset,
    /// and the prepare POST is the only beacon-node request.
    #[tokio::test(flavor = "current_thread")]
    async fn later_steps_run_after_an_earlier_failure() {
        use BoundaryStep::{CommitteeSubscriptions, PrepareProposers};
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        *f.failing_prepare.lock() = 1;

        f.runner.run_pending(32).await;

        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 1);
        assert_eq!(
            step_state(&f.runner, PrepareProposers),
            (Some(StepOutcome::Failed), false),
            "the 503 leaves PrepareProposers failed, and not done"
        );
        assert_eq!(
            *f.subscription_slots.lock(),
            slots(&[&["33"], &["65"]]),
            "the subscriptions after the failed prepare go out in the same pass"
        );
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::Done), true),
            "sent: done"
        );
        assert!(f.runner.has_pending(33), "PrepareProposers stays pending");
        f.breaker.record_miss();
        let seeded = f.mock.call_stamps().len();

        f.runner.run_pending(33).await;

        assert_eq!(
            methods_since(&f.mock, seeded),
            [MockMethod::PrepareBeaconProposer],
            "only PrepareProposers runs again"
        );
        assert_eq!(f.breaker.epoch_misses(), 1, "BreakerReset is not repeated");
        assert_eq!(
            step_state(&f.runner, PrepareProposers),
            (Some(StepOutcome::Done), true),
            "the retry succeeded: done"
        );
        assert_eq!(f.subscription_slots.lock().len(), 2, "the subscriptions are not sent again");
        assert!(!f.runner.has_pending(34));
    }

    /// Only `Done` finishes a step, however many attempts fail before it. The
    /// prepare POST answers 503 at slots 32 and 33: PrepareProposers is
    /// `Failed` and pending after each. At slot 34 it succeeds and is done,
    /// slot 35 makes no attempt, and the steps that succeeded at slot 32 do
    /// not run again.
    #[tokio::test(flavor = "current_thread")]
    async fn prepare_retries_after_consecutive_failures_until_done() {
        use BoundaryStep::PrepareProposers;
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        *f.failing_prepare.lock() = 2;

        f.runner.run_pending(32).await;
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Failed), false));
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));
        f.breaker.record_miss();

        let seeded = f.mock.call_stamps().len();
        f.runner.run_pending(33).await;
        assert_eq!(methods_since(&f.mock, seeded), [MockMethod::PrepareBeaconProposer]);
        assert_eq!(
            step_state(&f.runner, PrepareProposers),
            (Some(StepOutcome::Failed), false),
            "the second 503 in a row leaves PrepareProposers failed, and not done"
        );
        assert!(f.runner.has_pending(34), "PrepareProposers stays pending");

        let seeded = f.mock.call_stamps().len();
        f.runner.run_pending(34).await;
        assert_eq!(methods_since(&f.mock, seeded), [MockMethod::PrepareBeaconProposer]);
        assert_eq!(
            step_state(&f.runner, PrepareProposers),
            (Some(StepOutcome::Done), true),
            "the third attempt succeeded: done"
        );
        assert!(!f.runner.has_pending(35));

        let seeded = f.mock.call_stamps().len();
        f.runner.run_pending(35).await;
        assert_eq!(f.mock.call_stamps().len(), seeded, "slot 35 makes no attempt");
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 3, "slots 32, 33 and 34");
        assert_eq!(f.breaker.epoch_misses(), 1, "BreakerReset is not repeated");
        assert_eq!(f.subscription_slots.lock().len(), 2, "the subscriptions are not sent again");
    }

    /// The summary logs once per epoch, at the end of its first pass, however
    /// many passes the epoch's pending steps take. The passes at slots 32 and
    /// 33 both end with PrepareProposers `Failed` (503) and the subscription
    /// step `NotReady` (E+1's attester requests fail); slot 34's finishes
    /// both. Epoch 2's first pass logs the second summary.
    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn the_summary_logs_once_per_epoch_across_pending_passes() {
        use BoundaryStep::{CommitteeSubscriptions, PrepareProposers};
        let f =
            fixture_seeded(proposer_duties_at(ROOT_A), SecretKey::generate(), false, &[1]).await;
        *f.failing_prepare.lock() = 2;
        f.failing_attester.lock().insert(2, 3);

        for slot in [32, 33] {
            f.runner.run_pending(slot).await;
            assert_eq!(
                step_state(&f.runner, PrepareProposers),
                (Some(StepOutcome::Failed), false),
                "slot {slot}"
            );
            assert_eq!(
                step_state(&f.runner, CommitteeSubscriptions),
                (Some(StepOutcome::NotReady), false),
                "slot {slot}"
            );
            logs_assert(|lines| expect_summaries(lines, 1));
        }

        f.runner.run_pending(34).await;
        assert!(!f.runner.has_pending(35), "slot 34 finishes both");
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));
        logs_assert(|lines| expect_summaries(lines, 1));

        f.runner.run_pending(64).await;
        logs_assert(|lines| expect_summaries(lines, 2));
    }

    /// A hung beacon node does not hold the runner: the pass returns when
    /// DutyFetch's `timeouts.duty_fetch` bound fires, with DutyFetch `Failed`
    /// and the subscription step pending. ReorgCheck's own `duty_fetch` bound
    /// fired before it, at its E+1 request. The next wake retries both, each
    /// under its own bound.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn duty_fetch_is_bounded_by_the_duty_fetch_timeout() {
        let held = proposer_duties_at(ROOT_A)
            .with_method_delay(MockMethod::GetAttesterDuties, Duration::from_secs(3_600));
        let f = fixture_seeded(held, SecretKey::generate(), false, &[]).await;
        let duty_fetch = create_test_config().timeouts.duty_fetch;
        let attester_stamps = || -> Vec<tokio::time::Instant> {
            f.mock
                .call_stamps()
                .iter()
                .filter(|stamp| stamp.method == MockMethod::GetAttesterDuties)
                .map(|stamp| stamp.at)
                .collect()
        };

        f.runner.run_pending(32).await;
        let stamps = attester_stamps();
        assert_eq!(stamps.len(), 3, "ReorgCheck E and E+1, then DutyFetch's E");
        assert_eq!(stamps[2].elapsed(), duty_fetch, "the pass ends at DutyFetch's bound");
        assert_eq!(
            step_state(&f.runner, BoundaryStep::DutyFetch),
            (Some(StepOutcome::Failed), false),
            "timed out: failed, and not done"
        );
        assert_eq!(
            step_state(&f.runner, BoundaryStep::ReorgCheck),
            (Some(StepOutcome::Failed), false),
            "ReorgCheck timed out at its own bound: failed, and not done"
        );
        assert!(f.subscription_slots.lock().is_empty());
        assert!(f.runner.has_pending(33), "the subscription step stays pending");

        let start = tokio::time::Instant::now();
        f.runner.run_pending(33).await;
        assert_eq!(
            start.elapsed(),
            2 * duty_fetch,
            "the next wake retries ReorgCheck and DutyFetch, each under its bound"
        );
        assert_eq!(attester_stamps().len(), 6, "ReorgCheck E and E+1, then DutyFetch's E");
        assert_eq!(
            step_state(&f.runner, BoundaryStep::DutyFetch),
            (Some(StepOutcome::Failed), false),
            "the retry timed out too"
        );
        assert!(f.subscription_slots.lock().is_empty());
        assert!(f.runner.has_pending(34));
    }

    /// The one `timeouts.duty_fetch` bound covers the proposer fetches too.
    /// With the attester duties cached and every proposer request hung, the
    /// step ends `Failed` at the bound after its first proposer request, and
    /// the steps after it still run in the same pass.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn duty_fetch_bound_covers_a_hung_proposer_fetch() {
        let held = proposer_duties_at(ROOT_A)
            .with_method_delay(MockMethod::GetProposerDuties, Duration::from_secs(3_600));
        let f = fixture(held).await;
        let duty_fetch = create_test_config().timeouts.duty_fetch;
        let seeded = f.mock.call_stamps().len();

        f.runner.run_pending(32).await;

        let proposer_stamps: Vec<tokio::time::Instant> = f.mock.call_stamps()[seeded..]
            .iter()
            .filter(|stamp| stamp.method == MockMethod::GetProposerDuties)
            .map(|stamp| stamp.at)
            .collect();
        assert_eq!(proposer_stamps.len(), 3, "ReorgCheck E and E+1, then DutyFetch's E");
        assert_eq!(proposer_stamps[2].elapsed(), duty_fetch, "the pass ends at DutyFetch's bound");
        assert!(!f.duty_tracker.is_proposer_epoch_cached(1).await);
        assert_eq!(
            step_state(&f.runner, BoundaryStep::DutyFetch),
            (Some(StepOutcome::Failed), false),
            "timed out with E's proposer duties uncached: failed, and not done"
        );
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]), "the steps after ran");
    }

    /// DutyFetch calls the tracker directly. Eviction, PTC duties and the
    /// next-period sync prefetch stay with the slot loop's warm-up, so
    /// `maybe_prefetch_next_sync_period` keeps its single-task invariant.
    #[test]
    fn duty_fetch_does_not_call_fetch_epoch_duties() {
        let source = include_str!("epoch_boundary.rs");
        let production = source.split("#[cfg(test)]").next().expect("production part");
        let code: String = production
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .flat_map(str::split_whitespace)
            .collect();
        for call in [
            "self.duty_tracker.fetch_duties_for_epoch(",
            "self.duty_tracker.fetch_proposer_duties(",
        ] {
            assert!(code.contains(call), "DutyFetch must call `{call}` itself");
        }
        for call in ["fetch_epoch_duties(", "maybe_prefetch_next_sync_period("] {
            assert!(!code.contains(call), "the runner must not call `{call}`");
        }
    }

    type TestOrchestrator = DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>;

    /// An orchestrator with no validators over `beacon`.
    fn orchestrator_over(beacon: MockBeaconNodeClient) -> (TestOrchestrator, OrchestratorHandle) {
        orchestrator_with(beacon, create_test_config())
    }

    fn orchestrator_with(
        beacon: MockBeaconNodeClient,
        config: OrchestratorConfig,
    ) -> (TestOrchestrator, OrchestratorHandle) {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon = Arc::new(beacon);
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), Vec::new()));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
        let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));
        DutyOrchestrator::new(OrchestratorDeps::for_test(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        ))
    }

    /// Spawns the runner of a fresh orchestrator whose slot loop never runs,
    /// and checks that the runner waits.
    async fn spawn_idle_runner() -> (TestOrchestrator, OrchestratorHandle, JoinHandle<()>) {
        let (mut orchestrator, handle) = orchestrator_over(MockBeaconNodeClient::new());
        let runner = tokio::spawn(orchestrator.take_epoch_boundary_runner().expect("runner").run());
        assert!(orchestrator.take_epoch_boundary_runner().is_none(), "the runner is taken once");
        tokio::time::advance(Duration::from_secs(12)).await;
        assert!(!runner.is_finished(), "an idle runner keeps waiting");
        (orchestrator, handle, runner)
    }

    async fn assert_ends(runner: JoinHandle<()>, arm: &str) {
        tokio::time::timeout(Duration::from_secs(1), runner)
            .await
            .unwrap_or_else(|_| panic!("{arm}: the runner task must end"))
            .expect("runner task");
    }

    /// The runner task cannot outlive `run`: it ends when the orchestrator
    /// (the processed-slot sender) is dropped, and when the shutdown watch
    /// flips or loses its sender while the runner is idle.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn runner_exits_when_run_returns() {
        let (orchestrator, handle, runner) = spawn_idle_runner().await;
        drop(orchestrator);
        assert_ends(runner, "processed-slot sender dropped").await;
        drop(handle);

        let (orchestrator, handle, runner) = spawn_idle_runner().await;
        handle.shutdown();
        assert_ends(runner, "shutdown requested").await;
        drop(orchestrator);

        let (orchestrator, handle, runner) = spawn_idle_runner().await;
        drop(handle);
        assert_ends(runner, "shutdown sender dropped").await;
        drop(orchestrator);
    }

    /// The runner fetches into the orchestrator's own tracker, the one the
    /// slot loop and the subscription step read, under the configured
    /// `duty_fetch` bound rather than the default.
    #[test]
    fn runner_uses_the_orchestrators_tracker_and_timeouts() {
        let config = create_test_config().with_timeouts(fast_timeouts());
        let (orchestrator, _handle) = orchestrator_with(MockBeaconNodeClient::new(), config);
        let runner = &orchestrator.epoch_boundary;
        assert!(Arc::ptr_eq(&runner.duty_tracker, &orchestrator.duty_tracker));
        assert_eq!(runner.timeouts.duty_fetch, fast_timeouts().duty_fetch);
        assert_ne!(runner.timeouts.duty_fetch, OperationTimeouts::default().duty_fetch);
    }

    /// A pass parked in a slow step runs on the runner task, not in the slot
    /// loop: shutdown still ends `run` at once, from its post-duty window.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_held_pass_does_not_hold_the_slot_loop() {
        let _metrics = m2_metric_lock().await;
        let held = MockBeaconNodeClient::new()
            .with_method_delay(MockMethod::GetProposerDuties, Duration::from_secs(3600));
        let (mut orchestrator, handle) = orchestrator_over(held);
        orchestrator.clock.set_slot(64);
        orchestrator.clock.advance_time(9);
        let runner_state = Arc::clone(&orchestrator.epoch_boundary);
        let runner = tokio::spawn(orchestrator.take_epoch_boundary_runner().expect("runner").run());
        let mut run = tokio::spawn(async move { orchestrator.run().await });

        let parked_in_reorg_check = || {
            runner_state.progress.lock().as_ref().is_some_and(|progress| {
                progress.epoch == 2
                    && progress.done.contains(&BoundaryStep::BreakerReset)
                    && !progress.done.contains(&BoundaryStep::ReorgCheck)
            })
        };
        let mut waited_ms = 0u64;
        while !parked_in_reorg_check() && waited_ms < 2_000 {
            waited_ms += 1;
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert!(
            parked_in_reorg_check(),
            "the pass must be held in ReorgCheck; virtual ms {waited_ms}"
        );

        handle.shutdown();
        let result = tokio::time::timeout(Duration::from_millis(1), &mut run)
            .await
            .expect("shutdown must end run while the runner's pass is held")
            .expect("run task");
        assert!(result.is_ok(), "shutdown ends the slot loop: {result:?}");
        runner.await.expect("runner task");
    }

    /// Longer than the tier budget, so only shutdown can end a held step in it.
    const HOLD: Duration = Duration::from_secs(3_600);

    /// The fixture's runner on its own task, over test-held senders.
    struct RunnerTask {
        slots: watch::Sender<Option<Slot>>,
        shutdown: watch::Sender<bool>,
        task: JoinHandle<()>,
    }

    fn spawn_runner(f: &Fixture) -> RunnerTask {
        spawn_runner_on(f, f.clock.clone())
    }

    /// [`spawn_runner`] over `clock`.
    fn spawn_runner_on(f: &Fixture, clock: Arc<dyn SlotClock>) -> RunnerTask {
        let (slots, slots_rx) = watch::channel(None);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task = EpochBoundaryTask::new(Arc::clone(&f.runner), clock, slots_rx, shutdown_rx);
        RunnerTask { slots, shutdown, task: tokio::spawn(task.run()) }
    }

    fn arrivals(mock: &MockBeaconNodeClient, method: MockMethod) -> usize {
        mock.call_stamps().iter().filter(|stamp| stamp.method == method).count()
    }

    /// Bounded 1 ms steps, far below `HOLD`, until `method` has `count` arrivals.
    async fn await_arrivals(mock: &MockBeaconNodeClient, method: MockMethod, count: usize) {
        for _ in 0..5_000 {
            if arrivals(mock, method) >= count {
                return;
            }
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        panic!("{method:?}: {count} arrivals did not come within 5,000 virtual ms");
    }

    /// Flips shutdown; the task must end inside the Orchestrator tier budget.
    async fn shut_down_within_budget(runner: RunnerTask, arm: &str) {
        let RunnerTask { slots: _slots, shutdown, task } = runner;
        let budget = TierBudget::default().for_tier(ShutdownTier::Orchestrator);
        shutdown.send_replace(true);
        tokio::time::timeout(budget, task)
            .await
            .unwrap_or_else(|_| panic!("{arm}: the runner must end within the {budget:?} budget"))
            .expect("runner task");
    }

    /// `method` held for `HOLD`. `preparation` and `duty_fetch` outlast it,
    /// so no inner bound ends a held pass first.
    async fn held_fixture(method: MockMethod, seed: &[u64]) -> Fixture {
        let timeouts = OperationTimeouts {
            preparation: 2 * HOLD,
            duty_fetch: 2 * HOLD,
            ..OperationTimeouts::default()
        };
        let mock = proposer_duties_at(ROOT_A).with_method_delay(method, HOLD);
        let config = create_test_config().with_timeouts(timeouts);
        fixture_config(mock, SecretKey::generate(), false, seed, config).await
    }

    /// Records the name of every span opened.
    #[derive(Clone, Default)]
    struct OpenedSpans(Arc<parking_lot::Mutex<Vec<&'static str>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for OpenedSpans {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.0.lock().push(attrs.metadata().name());
        }
    }

    /// Shutdown with a pass in flight drops the pass, so the task ends inside
    /// the Orchestrator tier budget, with the cancelled step still pending:
    /// held in PrepareProposers, then in DutyFetch on the epoch's second
    /// pass. A slot wake and shutdown ready together: shutdown wins, and no
    /// pass starts.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn runner_exits_on_shutdown_within_tier_budget() {
        let f = held_fixture(MockMethod::PrepareBeaconProposer, &[1, 2]).await;
        let runner = spawn_runner(&f);
        runner.slots.send_replace(Some(32));
        await_arrivals(&f.mock, MockMethod::PrepareBeaconProposer, 1).await;
        shut_down_within_budget(runner, "prepare in flight").await;
        assert!(f.mock.prepare_beacon_proposer_calls().is_empty(), "dropped, not finished");
        assert!(f.subscription_slots.lock().is_empty(), "no step after the cancelled one ran");
        f.runner.run_pending(32).await;
        assert_eq!(
            arrivals(&f.mock, MockMethod::PrepareBeaconProposer),
            2,
            "the cancelled step is still pending: a fresh pass prepares again"
        );
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 1);
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));

        // The first pass ends with E+1 uncached: ReorgCheck's and DutyFetch's
        // E+1 requests fail. The second pass starts at DutyFetch.
        let f = held_fixture(MockMethod::GetAttesterDuties, &[1]).await;
        f.failing_attester.lock().insert(2, 2);
        f.runner.run_pending(32).await;
        assert!(f.subscription_slots.lock().is_empty(), "the subscription step is pending");
        let fetches = arrivals(&f.mock, MockMethod::GetAttesterDuties);
        let runner = spawn_runner(&f);
        runner.slots.send_replace(Some(33));
        await_arrivals(&f.mock, MockMethod::GetAttesterDuties, fetches + 1).await;
        shut_down_within_budget(runner, "DutyFetch in flight").await;
        assert!(!f.duty_tracker.is_epoch_cached(2).await, "dropped, not finished");
        assert!(f.runner.has_pending(33), "the cancelled step is still pending");
        f.runner.run_pending(33).await;
        assert_eq!(arrivals(&f.mock, MockMethod::GetAttesterDuties), fetches + 2);
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));

        // A slot wake and shutdown ready at the task's first poll. Repeated:
        // an unbiased select picks a random first arm.
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        let calls = f.mock.call_stamps().len();
        let spans = OpenedSpans::default();
        let subscriber = tracing_subscriber::registry().with(spans.clone());
        let _default = tracing::subscriber::set_default(subscriber);
        for _ in 0..16 {
            let runner = spawn_runner(&f);
            runner.slots.send_replace(Some(32));
            shut_down_within_budget(runner, "slot wake and shutdown together").await;
        }
        assert!(!spans.0.lock().contains(&"epoch.boundary"), "shutdown wins: no pass span");
        assert_eq!(f.mock.call_stamps().len(), calls, "shutdown wins: no step ran");
        assert!(f.runner.progress.lock().is_none(), "shutdown wins: no epoch started");
    }

    /// Retries stop at the epoch's end, also in a pass held past it. Pass 62
    /// leaves ReorgCheck and PrepareProposers `Failed` and the subscription
    /// step pending. Pass 63 parks in ReorgCheck's retry, and slot 64 is
    /// processed meanwhile. When ReorgCheck's bound ends the hold, pass 63
    /// starts no prepare retry, and epoch 2's pass parks in ReorgCheck's
    /// first request. Epoch 2's own prepare comes after its ReorgCheck, so
    /// any prepare by then is epoch 1's.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_held_pass_starts_no_step_once_the_next_epoch_is_processed() {
        use BoundaryStep::{CommitteeSubscriptions, PrepareProposers, ReorgCheck};
        let [att, prep] = [MockMethod::GetAttesterDuties, MockMethod::PrepareBeaconProposer];
        let _metrics = m2_metric_lock().await;
        let held = proposer_duties_at(ROOT_A).with_method_delay(att, HOLD);
        let f = fixture_seeded(held, SecretKey::generate(), false, &[]).await;
        *f.failing_prepare.lock() = 1;
        f.runner.run_pending(62).await;
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Failed), false));
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::NotReady), false)
        );
        assert_eq!(arrivals(&f.mock, prep), 1, "pass 62's prepare");
        let fetches = arrivals(&f.mock, att);

        let runner = spawn_runner(&f);
        runner.slots.send_replace(Some(63));
        await_arrivals(&f.mock, att, fetches + 1).await;
        runner.slots.send_replace(Some(64));
        tokio::time::advance(f.runner.timeouts.duty_fetch).await;
        await_arrivals(&f.mock, att, fetches + 2).await;

        let (epoch, reorg_checked) = {
            let progress = f.runner.progress.lock();
            let progress = progress.as_ref().expect("a pass ran");
            (progress.epoch, progress.done.contains(&ReorgCheck))
        };
        assert_eq!((epoch, reorg_checked), (2, false), "epoch 2's pass is held in ReorgCheck");
        assert_eq!(
            arrivals(&f.mock, prep),
            1,
            "pass 63 starts no epoch-1 prepare retry once slot 64 is processed"
        );
        shut_down_within_budget(runner, "epoch 2's ReorgCheck in flight").await;

        f.runner.run_pending(64).await;
        assert_eq!(arrivals(&f.mock, prep), 2, "epoch 2's own prepare");
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Done), true));
    }

    /// Records the `slot` of each `epoch.boundary` pass span opened.
    #[derive(Clone, Default)]
    struct PassSlots(Arc<parking_lot::Mutex<Vec<Slot>>>);

    /// Reads a span's `slot` field.
    struct SlotField(Option<Slot>);

    impl tracing::field::Visit for SlotField {
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            if field.name() == "slot" {
                self.0 = Some(value);
            }
        }

        fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PassSlots {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().name() == "epoch.boundary" {
                let mut slot = SlotField(None);
                attrs.record(&mut slot);
                self.0.lock().extend(slot.0);
            }
        }
    }

    /// Bounded 1 ms steps, far below `HOLD`, until `done` holds or 5,000
    /// virtual ms pass. The caller asserts what came.
    async fn advance_until(done: impl Fn() -> bool) {
        for _ in 0..5_000 {
            if done() {
                return;
            }
            tokio::time::advance(Duration::from_millis(1)).await;
        }
    }

    /// Wakes during a pass coalesce into one, at the newest slot. While the
    /// slot-32 pass is held in a prepare POST that answers 503, slots 33 and
    /// 34 are processed. Once it ends, the task runs one pass, at slot 34,
    /// whose retry answers 503 too. Then it waits: the next pass is at slot
    /// 35, once that slot is processed.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wakes_during_a_held_pass_coalesce_into_one_pass_at_the_newest_slot() {
        let prep = MockMethod::PrepareBeaconProposer;
        let _metrics = m2_metric_lock().await;
        let f = held_fixture(prep, &[1, 2]).await;
        *f.failing_prepare.lock() = 2;
        let passes = PassSlots::default();
        let subscriber = tracing_subscriber::registry().with(passes.clone());
        let _default = tracing::subscriber::set_default(subscriber);
        let pass_slots = || passes.0.lock().clone();
        let runner = spawn_runner(&f);

        runner.slots.send_replace(Some(32));
        await_arrivals(&f.mock, prep, 1).await;
        runner.slots.send_replace(Some(33));
        runner.slots.send_replace(Some(34));
        tokio::time::advance(HOLD).await;
        advance_until(|| arrivals(&f.mock, prep) == 2).await;
        assert_eq!(pass_slots(), [32, 34], "one retry, at the newest slot processed meanwhile");

        tokio::time::advance(HOLD).await;
        advance_until(|| f.mock.prepare_beacon_proposer_calls().len() == 2).await;
        assert_eq!(
            step_state(&f.runner, BoundaryStep::PrepareProposers),
            (Some(StepOutcome::Failed), false),
            "the retry answered 503: still pending"
        );
        advance_until(|| arrivals(&f.mock, prep) > 2).await;
        assert_eq!(pass_slots(), [32, 34], "no pass until another slot is processed");

        runner.slots.send_replace(Some(35));
        await_arrivals(&f.mock, prep, 3).await;
        assert_eq!(pass_slots(), [32, 34, 35]);
        shut_down_within_budget(runner, "the slot-35 retry in flight").await;
    }

    /// The fixture's runner as a local future over test-held senders, so the
    /// test decides when it is polled.
    struct LocalRunner {
        slots: watch::Sender<Option<Slot>>,
        shutdown: watch::Sender<bool>,
        run: Pin<Box<dyn Future<Output = ()>>>,
    }

    impl LocalRunner {
        fn new(f: &Fixture, clock: Arc<dyn SlotClock>) -> Self {
            let (slots, slots_rx) = watch::channel(None);
            let (shutdown, shutdown_rx) = watch::channel(false);
            let task = EpochBoundaryTask::new(Arc::clone(&f.runner), clock, slots_rx, shutdown_rx);
            Self { slots, shutdown, run: Box::pin(task.run()) }
        }

        /// Polls `run`, 1 ms apart, until the `nth` held prepare arrives, and
        /// returns its stamp. Nothing polls `run` again until the test does.
        async fn poll_until_prepare(
            &mut self,
            mock: &MockBeaconNodeClient,
            nth: usize,
        ) -> MockCallStamp {
            for _ in 0..5_000 {
                assert!(futures::poll!(self.run.as_mut()).is_pending(), "only shutdown ends it");
                let mut prepares = mock
                    .call_stamps()
                    .into_iter()
                    .filter(|stamp| stamp.method == MockMethod::PrepareBeaconProposer);
                if let Some(held) = prepares.nth(nth - 1) {
                    return held;
                }
                tokio::time::advance(Duration::from_millis(1)).await;
            }
            panic!("PrepareBeaconProposer: arrival {nth} did not come within 5,000 virtual ms");
        }
    }

    fn prepare_done(runner: &EpochBoundaryRunner) -> bool {
        runner
            .progress
            .lock()
            .as_ref()
            .is_some_and(|p| p.done.contains(&BoundaryStep::PrepareProposers))
    }

    /// Shutdown and a ready pass on the same poll of the in-flight select:
    /// shutdown wins, and the ready prepare never completes. The test stops
    /// polling `run` once the held prepare arrives, flips shutdown and lets
    /// the hold elapse, then polls once with both arms ready. Repeated: an
    /// unbiased select picks a random first arm. Without shutdown, the same
    /// poll completes the prepare and the steps after it.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_wins_an_in_flight_tie_with_a_ready_pass() {
        let f = held_fixture(MockMethod::PrepareBeaconProposer, &[1, 2]).await;
        for round in 1..=32 {
            let mut runner = LocalRunner::new(&f, f.clock.clone());
            runner.slots.send_replace(Some(32));
            let held = runner.poll_until_prepare(&f.mock, round).await;
            let mut hold_end = std::pin::pin!(tokio::time::sleep_until(held.at + HOLD));
            assert!(futures::poll!(hold_end.as_mut()).is_pending(), "round {round}: still held");
            runner.shutdown.send_replace(true);
            tokio::time::advance(HOLD).await;
            assert!(futures::poll!(hold_end.as_mut()).is_ready(), "round {round}: hold elapsed");
            let tie = futures::poll!(runner.run.as_mut());
            assert!(
                f.mock.prepare_beacon_proposer_calls().is_empty(),
                "round {round}: shutdown wins: the ready prepare did not complete"
            );
            assert!(
                !prepare_done(&f.runner),
                "round {round}: shutdown wins: no PrepareProposers done mark"
            );
            assert_eq!(
                arrivals(&f.mock, MockMethod::SubmitBeaconCommitteeSubscriptions),
                0,
                "round {round}: shutdown wins: no subscription request"
            );
            assert!(tie.is_ready(), "round {round}: shutdown wins: the tie poll ends the runner");
        }

        let mut runner = LocalRunner::new(&f, f.clock.clone());
        runner.slots.send_replace(Some(32));
        runner.poll_until_prepare(&f.mock, 33).await;
        tokio::time::advance(HOLD).await;
        assert!(futures::poll!(runner.run.as_mut()).is_pending(), "no shutdown: still running");
        assert_eq!(
            f.mock.prepare_beacon_proposer_calls().len(),
            1,
            "no shutdown: the same poll completes the held prepare"
        );
        assert!(prepare_done(&f.runner), "no shutdown: PrepareProposers is marked done");
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"], &["65"]]));
        runner.shutdown.send_replace(true);
        assert!(futures::poll!(runner.run.as_mut()).is_ready(), "shutdown ends the idle runner");
    }

    /// The in-flight select is `biased;` with the shutdown arm first, so a
    /// same-poll tie never takes `select!`'s random first arm. The tie test
    /// above catches an unbiased select only when the random draw picks the
    /// pass.
    ///
    /// RSA F2: the pre-genesis method `run_before_genesis` has two selects,
    /// the pass select and then the wait select. Each one must open with
    /// `biased;` and then the shutdown arm. The test reads the source, so it
    /// pins the syntax of these selects and no runtime behavior.
    #[test]
    fn the_in_flight_select_is_biased_with_the_shutdown_arm_first() {
        use std::ops::Range;

        fn block(code: &str, open: usize) -> Range<usize> {
            assert_eq!(code.as_bytes().get(open), Some(&b'{'), "a block opens at byte {open}");
            let mut depth = 0_usize;
            for (at, byte) in code.bytes().enumerate().skip(open) {
                match byte {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return open + 1..at;
                        }
                    }
                    _ => {}
                }
            }
            panic!("the block at byte {open} never closes");
        }
        fn blocks(code: &str, within: Range<usize>, head: &str) -> Vec<Range<usize>> {
            let base = within.start;
            code[within]
                .match_indices(head)
                .map(|(at, _)| block(code, base + at + head.len() - 1))
                .collect()
        }

        let source = include_str!("epoch_boundary.rs");
        let production = source.split("#[cfg(test)]").next().expect("production part");
        let code: String = production
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .flat_map(str::split_whitespace)
            .collect();
        let tasks = blocks(&code, 0..code.len(), "implEpochBoundaryTask{");
        assert_eq!(tasks.len(), 1, "one `impl EpochBoundaryTask` block");
        let runs = blocks(&code, tasks[0].clone(), "pubasyncfnrun(mutself){");
        assert_eq!(runs.len(), 1, "one `EpochBoundaryTask::run`");
        let run = &code[runs[0].clone()];
        assert_eq!(
            run.matches("select!").count(),
            2,
            "`run` has the idle and the in-flight select"
        );
        let selects = blocks(&code, runs[0].clone(), "tokio::select!{");
        let [idle, in_flight] = selects.as_slice() else {
            panic!("both selects in `run` are `tokio::select!`: {run}");
        };
        assert!(
            idle.start < in_flight.start && in_flight.end < idle.end,
            "the in-flight select is nested in the idle select: {run}"
        );
        assert!(
            code[idle.clone()].contains("self.slots.changed()"),
            "the outer select waits for a slot"
        );

        let inner = &code[in_flight.clone()];
        assert_eq!(inner.matches("=>").count(), 2, "the in-flight select has two arms: {inner}");
        let arm = |head: &str| {
            assert_eq!(
                inner.matches(head).count(),
                1,
                "the in-flight select has one `{head}` arm: {inner}"
            );
            inner.find(head).expect("counted above")
        };
        let shutdown = arm("()=shutdown_requested(&mutself.shutdown)=>");
        let pass = arm("()=self.runner.run_pending(slot)");
        assert!(
            inner.starts_with("biased;"),
            "the in-flight select opens with `biased;`, so a tie never takes a random first arm: {inner}"
        );
        assert!(
            shutdown < pass,
            "the in-flight select lists the shutdown arm before the pass arm: {inner}"
        );

        let helpers = blocks(
            &code,
            tasks[0].clone(),
            "asyncfnrun_before_genesis(&mutself,loop_span:&Span)->bool{",
        );
        assert_eq!(helpers.len(), 1, "There must be one `run_before_genesis` method.");
        let helper = &code[helpers[0].clone()];
        assert_eq!(
            helper.matches("select!").count(),
            2,
            "`run_before_genesis` must have the pass select and the wait select: {helper}"
        );
        let selects = blocks(&code, helpers[0].clone(), "tokio::select!{");
        let [pass_select, wait_select] = selects.as_slice() else {
            panic!("Both selects in `run_before_genesis` must be `tokio::select!`: {helper}");
        };
        assert!(
            pass_select.end < wait_select.start,
            "The pass select must come before the wait select, and must not contain it: {helper}"
        );
        let shutdown_first = "biased;()=shutdown_requested(&mutself.shutdown)=>";
        for (name, select, arms, work) in [
            ("pass", pass_select, 2, "()=self.runner.run_pending_for_epoch(0)"),
            ("wait", wait_select, 3, "changed=self.slots.changed()=>"),
        ] {
            let body = &code[select.clone()];
            assert_eq!(
                body.matches("=>").count(),
                arms,
                "The pre-genesis {name} select must have {arms} arms: {body}"
            );
            assert_eq!(
                body.matches(work).count(),
                1,
                "The pre-genesis {name} select must have one `{work}` arm: {body}"
            );
            assert!(
                body.starts_with("biased;"),
                "The pre-genesis {name} select must open with `biased;`: {body}"
            );
            assert!(
                body.starts_with(shutdown_first),
                "The pre-genesis {name} select must put the shutdown arm first: {body}"
            );
        }
    }

    const ABANDONED: &str = "epoch-boundary steps did not finish before the epoch ended";

    /// Records each WARN as `message key=value ...`, fields in order.
    #[derive(Clone, Default)]
    struct Warns(Arc<parking_lot::Mutex<Vec<String>>>);

    #[derive(Default)]
    struct WarnLine {
        message: String,
        fields: String,
    }

    impl tracing::field::Visit for WarnLine {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            } else {
                self.fields.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warns {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut line = WarnLine::default();
                event.record(&mut line);
                self.0.lock().push(line.message + &line.fields);
            }
        }
    }

    impl Warns {
        /// Captures this thread's events until the guard drops.
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()))
        }

        fn lines(&self) -> Vec<String> {
            self.0.lock().clone()
        }

        /// The fields of each abandoned-steps warn.
        fn abandoned(&self) -> Vec<String> {
            self.lines()
                .iter()
                .filter_map(|line| Some(line.strip_prefix(ABANDONED)?.trim_start().to_string()))
                .collect()
        }
    }

    /// `duty_fetch` at 2 s and `preparation` at 60 s.
    fn short_duty_fetch() -> OrchestratorConfig {
        create_test_config().with_timeouts(OperationTimeouts {
            duty_fetch: Duration::from_secs(2),
            preparation: Duration::from_secs(60),
            ..OperationTimeouts::default()
        })
    }

    /// The source check requires these bounds:
    ///
    /// - ReorgCheck and CommitteeSubscriptions use `duty_fetch`.
    /// - PrepareProposers uses `preparation`.
    /// - DutyFetch applies its own bound inside the step.
    /// - BuilderRegistration uses `registration_step_timeout()` inside the
    ///   step.
    /// - ProposerPreferences uses `PREFERENCES_STEP_TIMEOUT` inside the step,
    ///   for the full broadcast.
    /// - BreakerReset has no bound, because it has no I/O.
    ///
    /// The PrepareProposers bound has the length of the `preparation` bound
    /// of its POST, but it starts earlier.
    /// `the_prepare_step_bound_starts_before_the_map_read` checks this.
    #[test]
    fn each_step_with_beacon_node_work_has_its_own_bound() {
        let source = include_str!("epoch_boundary.rs");
        let production = source.split("#[cfg(test)]").next().expect("production part");
        let code: String = production
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .flat_map(str::split_whitespace)
            .collect();
        let run = code
            .split("pub(crate)asyncfnrun_pending(")
            .nth(1)
            .and_then(|rest| rest.split("pub(crate)fnhas_pending(").next())
            .expect("`run_pending`, then `has_pending`");
        assert_eq!(run.matches("bounded(").count(), 3, "Three steps must run under a bound: {run}");
        for arm in [
            "BoundaryStep::BreakerReset=>self.breaker_reset(epoch),",
            "BoundaryStep::ReorgCheck=>{bounded(epoch,step,self.timeouts.duty_fetch,\
             self.reorg_check(epoch)).await}",
            "BoundaryStep::DutyFetch=>{letoutcome=self.duty_fetch(epoch).await;",
            "BoundaryStep::PrepareProposers=>{letprepare=self.prepare_proposers(epoch);\
             bounded(epoch,step,self.timeouts.preparation,prepare).await}",
            "BoundaryStep::CommitteeSubscriptions=>{letsubscriptions=\
             self.committee_subscriptions(epoch);\
             bounded(epoch,step,self.timeouts.duty_fetch,subscriptions).await}",
            "BoundaryStep::BuilderRegistration=>self.builder_registration(epoch).await,",
            "BoundaryStep::ProposerPreferences=>self.proposer_preferences(epoch).await,",
        ] {
            assert!(run.contains(arm), "`run_pending` has the arm `{arm}`: {run}");
        }
        let registration = code
            .split("asyncfnbuilder_registration(")
            .nth(1)
            .and_then(|rest| rest.split("asyncfnproposer_preferences(").next())
            .expect("`builder_registration`, then `proposer_preferences`");
        let bound = "letbound=builder.registration_step_timeout();\
                     bounded(epoch,BoundaryStep::BuilderRegistration,bound,registration).await";
        assert!(
            registration.contains(bound),
            "The registration step must run under the builder service's bound: {registration}"
        );
        let preferences = code
            .split("asyncfnproposer_preferences(")
            .nth(1)
            .and_then(|rest| rest.split("asyncfnbounded(").next())
            .expect("`proposer_preferences`, then `bounded`");
        for bound in [
            "letbroadcast=async{matchself.broadcast_preferences(builder,epoch).await{",
            "letstep=BoundaryStep::ProposerPreferences;\
             bounded(epoch,step,PREFERENCES_STEP_TIMEOUT,broadcast).await",
        ] {
            assert!(
                preferences.contains(bound),
                "The full preferences broadcast must run under PREFERENCES_STEP_TIMEOUT: \
                 {preferences}"
            );
        }
    }

    /// With the default timeouts and no time passing before the POST, the
    /// prepare POST's own 3 s `preparation` bound fires at the same instant
    /// as the step's, and first: the step is `Failed`, the held POST is
    /// dropped unanswered, and the next slot's pass retries it.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn inner_preparation_timeout_is_a_failed_step() {
        use BoundaryStep::PrepareProposers;
        let prep = MockMethod::PrepareBeaconProposer;
        let f = fixture(proposer_duties_at(ROOT_A).with_method_delay(prep, Duration::from_secs(5)))
            .await;
        let defaults = OperationTimeouts::default();
        assert_eq!(
            (f.runner.timeouts.preparation, f.runner.timeouts.duty_fetch),
            (defaults.preparation, defaults.duty_fetch),
            "default timeouts"
        );
        let warns = Warns::default();
        let _default = warns.install();

        f.runner.run_pending(32).await;

        assert_eq!(arrivals(&f.mock, prep), 1);
        assert!(f.mock.prepare_beacon_proposer_calls().is_empty(), "dropped, not answered");
        assert_eq!(
            step_state(&f.runner, PrepareProposers),
            (Some(StepOutcome::Failed), false),
            "the inner timeout leaves PrepareProposers failed, and not done"
        );
        assert_eq!(
            warns.lines(),
            ["Proposer preparation timed out after 3s"],
            "the POST's own bound fired, not the step's"
        );
        assert!(f.runner.has_pending(33));

        f.runner.run_pending(33).await;

        assert_eq!(arrivals(&f.mock, prep), 2, "the next slot's pass retries it");
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Failed), false));
    }

    /// A cold cache that never fills is visible at the epoch end. Every
    /// attester request is held past `duty_fetch`, so in each pass of epoch
    /// 1 ReorgCheck and DutyFetch end `Failed` at their bounds and the
    /// subscription step is `NotReady`. Epoch 2's first pass warns once for
    /// epoch 1, naming the three steps and their last outcomes.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn duty_fetch_failure_is_named_in_the_abandoned_warn() {
        let held =
            proposer_duties_at(ROOT_A).with_method_delay(MockMethod::GetAttesterDuties, HOLD);
        let f = fixture_config(held, SecretKey::generate(), false, &[], short_duty_fetch()).await;
        let warns = Warns::default();
        let _default = warns.install();

        for slot in 32..64 {
            f.runner.run_pending(slot).await;
        }
        assert_eq!(
            step_state(&f.runner, BoundaryStep::DutyFetch),
            (Some(StepOutcome::Failed), false),
            "the last pass of epoch 1 left the cache cold"
        );
        assert_eq!(warns.abandoned(), Vec::<String>::new(), "no warn inside the epoch");

        f.runner.run_pending(64).await;

        assert_eq!(
            warns.abandoned(),
            [
                "epoch=1 abandoned_steps=[ReorgCheck, DutyFetch, CommitteeSubscriptions] \
                 last_outcomes={ReorgCheck: Failed, DutyFetch: Failed, CommitteeSubscriptions: NotReady}"
            ],
            "one warn for epoch 1, at epoch 2's first pass"
        );
    }

    /// A watch that jumps several epochs warns once, for the last epoch with
    /// progress. Epoch 1's prepare answers 503 at slot 32, and the next pass
    /// is at slot 130, in epoch 4. It warns for epoch 1 only, as the runner
    /// never saw epochs 2 and 3, and runs epoch 4's steps in the same pass.
    #[tokio::test(flavor = "current_thread")]
    async fn epoch_jump_warns_once_for_the_last_progress() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        *f.failing_prepare.lock() = 1;
        f.runner.run_pending(32).await;
        assert!(f.runner.has_pending(33), "PrepareProposers is pending in epoch 1");
        let warns = Warns::default();
        let _default = warns.install();

        f.runner.run_pending(130).await;

        assert_eq!(
            warns.abandoned(),
            ["epoch=1 abandoned_steps=[PrepareProposers] last_outcomes={PrepareProposers: Failed}"],
            "one warn, for epoch 1"
        );
        assert_eq!(f.mock.prepare_beacon_proposer_calls().len(), 2, "epoch 4's prepare ran");
        assert_eq!(
            *f.subscription_slots.lock(),
            slots(&[&["33"], &["65"], &["129"], &["161"]]),
            "epoch 4's subscriptions went out in the same pass"
        );
        assert!(!f.runner.has_pending(131), "every step of epoch 4 is done");
    }

    /// RSA N2 (#980): a new epoch's progress keeps no outcome from the last
    /// one. Epoch 1 attempts every step, and PrepareProposers ends `Failed`.
    /// Epoch 2's pass is held in ReorgCheck's proposer request: only
    /// BreakerReset has an outcome, and the later steps have none. That pass
    /// is dropped, so epoch 3's first pass warns for epoch 2 with the steps
    /// it never attempted and no outcome for any of them. DutyFetch is not
    /// named: it never failed in epoch 2.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn new_epoch_progress_keeps_no_outcome_from_the_previous_epoch() {
        let timeouts = OperationTimeouts {
            preparation: 4 * HOLD,
            duty_fetch: 4 * HOLD,
            ..OperationTimeouts::default()
        };
        let held =
            proposer_duties_at(ROOT_A).with_method_delay(MockMethod::GetProposerDuties, HOLD);
        let config = create_test_config().with_timeouts(timeouts);
        let f = fixture_config(held, SecretKey::generate(), false, &[1, 2], config).await;
        *f.failing_prepare.lock() = 1;
        f.runner.run_pending(32).await;
        for step in BoundaryStep::ALL {
            let want = if step == BoundaryStep::PrepareProposers {
                StepOutcome::Failed
            } else {
                StepOutcome::Done
            };
            assert_eq!(step_state(&f.runner, step).0, Some(want), "{step:?} in epoch 1");
        }

        let mut pass = Box::pin(f.runner.run_pending(64));
        let held_pass = tokio::time::timeout(HOLD / 2, &mut pass).await;
        assert!(held_pass.is_err(), "epoch 2's pass is held in ReorgCheck");
        assert_eq!(f.runner.progress.lock().as_ref().map(|p| p.epoch), Some(2));
        for step in BoundaryStep::ALL {
            let want = (step == BoundaryStep::BreakerReset).then_some(StepOutcome::Done);
            assert_eq!(
                step_state(&f.runner, step).0,
                want,
                "{step:?}: no outcome from epoch 1 while epoch 2's pass is held"
            );
        }
        drop(pass);
        let warns = Warns::default();
        let _default = warns.install();

        f.runner.run_pending(96).await;

        assert_eq!(
            warns.abandoned(),
            ["epoch=2 abandoned_steps=[ReorgCheck, PrepareProposers, CommitteeSubscriptions, \
              BuilderRegistration, ProposerPreferences] last_outcomes={}"],
            "epoch 2's unattempted steps, with no outcome from epoch 1"
        );
    }

    // --- PR #982 R1: cancellation-safe retries ---

    /// RSA B2: a retry does not redo an epoch whose subscriptions went out,
    /// nor a selection proof already signed. E's POST is answered and E+1's
    /// is held past the 2 s step bound, so the step is `Failed` with E sent.
    /// The slot-33 pass sends E+1 only, with the proof signed at slot 32,
    /// and the step is done. Epoch 2 keeps only its own proofs.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_subscription_retry_sends_only_the_epochs_not_sent() {
        use BoundaryStep::CommitteeSubscriptions;
        let subs = MockMethod::SubmitBeaconCommitteeSubscriptions;
        let mock = proposer_duties_at(ROOT_A).with_call_delays(subs, [Duration::ZERO, HOLD]);
        let f =
            fixture_config(mock, SecretKey::generate(), false, &[1, 2], short_duty_fetch()).await;
        let spans = OpenedSpans::default();
        let _default =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(spans.clone()));

        f.runner.run_pending(32).await;

        assert_eq!(*f.subscription_slots.lock(), slots(&[&["33"]]), "E sent, E+1 held");
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::Failed), false)
        );

        f.runner.run_pending(33).await;

        assert_eq!(
            *f.subscription_slots.lock(),
            slots(&[&["33"], &["65"]]),
            "the retry sends E+1 only"
        );
        assert_eq!(arrivals(&f.mock, subs), 3, "E, E+1 held, then E+1");
        assert_eq!(step_state(&f.runner, CommitteeSubscriptions), (Some(StepOutcome::Done), true));
        let signed = spans.0.lock().iter().filter(|name| **name == "sign.selection_proof").count();
        assert_eq!(signed, 2, "one selection proof each for E and E+1, signed once");

        f.runner.run_pending(64).await;

        assert_eq!(
            f.selection_proofs.slots(),
            BTreeSet::from([65, 97]),
            "epoch 2 keeps the proofs of epochs 2 and 3"
        );
        let signed = spans.0.lock().iter().filter(|name| **name == "sign.selection_proof").count();
        assert_eq!(signed, 3, "epoch 2 reuses the slot-65 proof that epoch 1 signed");
    }

    /// W4-E8a3: the first pass of epoch 2 drops the proofs below slot 64 and
    /// keeps slot 64. The pass then adds the subscription proofs of epochs 2
    /// and 3 (slots 65 and 97).
    #[tokio::test(flavor = "current_thread")]
    async fn new_epoch_evicts_old_proofs() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        let proof = signer::mock_sig(b"seeded selection proof");
        for slot in [63, 64] {
            let seeded = proof.clone();
            let sign =
                move || -> BoxFuture<'static, ProbeResult> { Box::pin(async move { Ok(seeded) }) };
            let cached = call_bounded(&f.selection_proofs, (slot, [0x77; 48]), sign).await;
            assert!(matches!(cached, Some(Ok(_))), "slot {slot} is seeded: {cached:?}");
        }

        f.runner.run_pending(64).await;

        assert_eq!(
            f.selection_proofs.slots(),
            BTreeSet::from([64, 65, 97]),
            "slot 63 is evicted; slot 64 and the proofs of epochs 2 and 3 stay"
        );
    }

    /// Lead note on #880 (RSA B1 of #1035): over six epochs of runner passes,
    /// the cache holds only the subscription proofs of the current and the
    /// next epoch.
    #[tokio::test(flavor = "current_thread")]
    async fn selection_proofs_stay_bounded_over_epochs() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;

        for epoch in 1..=6 {
            let first = epoch * SLOTS_PER_EPOCH;
            for slot in [first, first + 1] {
                f.runner.run_pending(slot).await;
                assert_eq!(
                    f.selection_proofs.slots(),
                    BTreeSet::from([first + 1, first + SLOTS_PER_EPOCH + 1]),
                    "slot {slot}: the proofs of epochs {epoch} and {} only",
                    epoch + 1
                );
            }
        }
    }

    /// Harper B4 (#855 Decisions): a subscription POST cut by its own 3 s
    /// `preparation` bound, as by the step's, makes the step `Failed`, and
    /// so does a POST error. With the default timeouts, E's first POST is
    /// held 5 s, or answers 503. E+1's POST still goes out in that pass. The
    /// slot-33 pass sends E only, and the step is done.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_failed_or_timed_out_subscription_post_is_a_failed_step() {
        use BoundaryStep::CommitteeSubscriptions;
        let subs = MockMethod::SubmitBeaconCommitteeSubscriptions;
        for (arm, hold, failures, warn) in [
            (
                "inner timeout",
                Duration::from_secs(5),
                0,
                "Committee subscription timed out after 3s epoch=1",
            ),
            (
                "503",
                Duration::ZERO,
                1,
                "Failed to send committee subscriptions epoch=1 \
                 error=Beacon node returned error: 503 - unavailable",
            ),
        ] {
            let f = fixture(proposer_duties_at(ROOT_A).with_call_delays(subs, [hold])).await;
            *f.failing_subscriptions.lock() = failures;
            let warns = Warns::default();
            let _default = warns.install();

            f.runner.run_pending(32).await;

            assert_eq!(
                step_state(&f.runner, CommitteeSubscriptions),
                (Some(StepOutcome::Failed), false),
                "{arm}: E's POST failed, so the step is failed, and not done"
            );
            assert_eq!(*f.subscription_slots.lock(), slots(&[&["65"]]), "{arm}: E+1 went out");
            assert_eq!(warns.lines(), [warn], "{arm}: the POST's own warn, no step-bound warn");

            f.runner.run_pending(33).await;

            assert_eq!(
                *f.subscription_slots.lock(),
                slots(&[&["65"], &["33"]]),
                "{arm}: the slot-33 pass sends E only"
            );
            assert_eq!(
                step_state(&f.runner, CommitteeSubscriptions),
                (Some(StepOutcome::Done), true),
                "{arm}"
            );
        }
    }

    /// RSA B1 / Harper B1: ReorgCheck caches a changed proposer root. The
    /// step bound then stops the check before it opens the preferences step
    /// again. The preferences step must open again after that timeout. Root
    /// A is cached for E and the beacon node answers B, under the 2 s step
    /// bound. The fixture marks the step Done before the first pass. Passes
    /// run until ReorgCheck is done; the list is the preferences POSTs
    /// answered after each pass.
    /// - Cut after the change: E's request takes 1 s and E+1's is held, so
    ///   the bound cuts the check after it cached B. The retry re-opens the
    ///   step, and the step broadcasts.
    /// - Retry cut too: the retry is cut the same way. It re-opens the step
    ///   before its own check, so the step broadcasts in that pass. The pass
    ///   after it broadcasts nothing more.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_root_change_cut_before_its_broadcast_is_broadcast_on_retry() {
        use BoundaryStep::ReorgCheck;
        let epoch = create_test_fork_schedule().gloas_fork_epoch;
        let first = epoch * SLOTS_PER_EPOCH;
        let (zero, slow) = (Duration::ZERO, Duration::from_secs(1));
        // Proposer requests: the seed, ReorgCheck's E and E+1, DutyFetch's
        // E+1, then the retry's E and E+1.
        let arms = [
            ("cut after the change", vec![zero, slow, HOLD], vec![0, 1]),
            ("retry cut too", vec![zero, slow, HOLD, zero, slow, HOLD], vec![0, 1, 1]),
        ];
        for (arm, duties, want) in arms {
            let local = SecretKey::generate();
            let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
            let mock = proposer_duties_then(local_hex, epoch, ROOT_A, ROOT_B)
                .with_call_delays(MockMethod::GetProposerDuties, duties);
            let seed = [epoch, epoch + 1];
            let f = fixture_config(mock, local, true, &seed, short_duty_fetch()).await;
            f.duty_tracker.fetch_proposer_duties(epoch).await.expect("seed root A");
            mark_preferences_done(&f.runner, epoch);

            let mut posts = Vec::new();
            for slot in first..first + 3 {
                f.runner.run_pending(slot).await;
                posts.push(f.mock.submit_proposer_preferences_calls().len());
                if slot == first {
                    let root = f.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
                    assert_eq!(root.as_deref(), Some(ROOT_B), "{arm}: B cached before the cut");
                    assert_eq!(
                        step_state(&f.runner, ReorgCheck),
                        (Some(StepOutcome::Failed), false),
                        "{arm}: cut at the step bound"
                    );
                }
                if step_state(&f.runner, ReorgCheck).1 {
                    break;
                }
            }
            assert_eq!(posts, want, "{arm}: B's preferences are POSTed once");
            assert_eq!(step_state(&f.runner, ReorgCheck), (Some(StepOutcome::Done), true), "{arm}");
        }
    }

    /// The last pass of E caches a changed proposer root before the timeout
    /// stops ReorgCheck. The preferences step of E+1 must send preferences
    /// with that root. Root A is cached for E+1, where the local proposal
    /// is. At slot 31 of E the check caches B for E+1 after 1 s, and its E+1
    /// PTC request is held, so the 2 s step bound cuts it. Epoch E+1's first
    /// pass broadcasts B.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_root_change_owed_at_the_epoch_end_is_broadcast_in_the_next_epoch() {
        let epoch = create_test_fork_schedule().gloas_fork_epoch;
        let next = epoch + 1;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        // Proposer requests: the seed of E+1, then ReorgCheck's E and E+1.
        let slow = [Duration::ZERO, Duration::ZERO, Duration::from_secs(1)];
        let mock = proposer_duties_then(local_hex, next, ROOT_A, ROOT_B)
            .with_call_delays(MockMethod::GetProposerDuties, slow)
            .with_call_delays(MockMethod::PostPtcDuties, [Duration::ZERO, HOLD]);
        let f = fixture_config(mock, local, true, &[epoch, next], short_duty_fetch()).await;
        f.duty_tracker.fetch_proposer_duties(next).await.expect("seed root A");
        mark_preferences_done(&f.runner, epoch);

        f.runner.run_pending(next * SLOTS_PER_EPOCH - 1).await;

        let root = f.duty_tracker.get_cached_proposer_dependent_root(next).await;
        assert_eq!(root.as_deref(), Some(ROOT_B), "B cached for E+1 before the cut");
        assert_eq!(
            step_state(&f.runner, BoundaryStep::ReorgCheck),
            (Some(StepOutcome::Failed), false)
        );
        assert!(f.mock.submit_proposer_preferences_calls().is_empty(), "cut before the broadcast");

        f.runner.run_pending(next * SLOTS_PER_EPOCH).await;

        let prefs = f.mock.submit_proposer_preferences_calls();
        assert_eq!(prefs.len(), 1, "epoch E+1's first pass broadcasts B once");
        assert_eq!(
            prefs[0][0].message.dependent_root,
            eth_types::canonical::gvr_hex::parse_gvr_hex(ROOT_B).expect("root B")
        );
    }

    /// Hands the pass to a lock holder when the first proposer reorg check
    /// returns, after it cached the beacon node's root and before the caller
    /// reads that root back, and waits until the holder has the proposer
    /// cache's write lock.
    #[derive(Clone)]
    struct CachedRootGate(Arc<parking_lot::Mutex<Option<Handoff>>>);

    impl<S> tracing_subscriber::Layer<S> for CachedRootGate
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
            let check = "duty_tracker.check_proposer_reorg";
            if !ctx.span(&id).is_some_and(|span| span.name() == check) {
                return;
            }
            let handoff = self.0.lock().take();
            if let Some((returned, locked)) = handoff {
                returned.send(()).expect("the holder waits for the check");
                locked.recv().expect("the holder took the write lock");
            }
        }
    }

    /// RSA B1 / Harper B1 (fix2): a root change the reorg check cached is
    /// broadcast on retry when the step bound cuts the check at its read of
    /// the new root, the first await after the cache write. Root A is cached
    /// for E and the beacon node answers B. When E's proposer check returns,
    /// a thread takes the proposer cache's write lock, so that read waits
    /// until the 2 s step bound drops the check. The retry broadcasts B once.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_root_change_cut_at_its_cached_root_read_is_broadcast_on_retry() {
        let epoch = create_test_fork_schedule().gloas_fork_epoch;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let mock = proposer_duties_then(local_hex, epoch, ROOT_A, ROOT_B);
        let f = fixture_config(mock, local, true, &[epoch, epoch + 1], short_duty_fetch()).await;
        f.duty_tracker.fetch_proposer_duties(epoch).await.expect("seed root A");
        let (returned, returned_rx) = std::sync::mpsc::sync_channel(0);
        let (locked, locked_rx) = std::sync::mpsc::sync_channel(0);
        let (release, release_rx) = std::sync::mpsc::channel();
        let gate = CachedRootGate(Arc::new(parking_lot::Mutex::new(Some((returned, locked_rx)))));
        let tracker = Arc::clone(&f.duty_tracker);
        let holder = std::thread::spawn(move || {
            if returned_rx.recv().is_ok() {
                tracker.with_proposer_cache_locked(|| {
                    locked.send(()).expect("the check waits for the lock");
                    release_rx.recv().expect("the test releases the lock");
                });
            }
        });
        let warns = Warns::default();
        let subscriber = tracing_subscriber::registry().with(warns.clone()).with(gate.clone());
        let default = tracing::subscriber::set_default(subscriber);
        let start = tokio::time::Instant::now();

        let (step, bound) = (BoundaryStep::ReorgCheck, f.runner.timeouts.duty_fetch);
        let cut = bounded(epoch, step, bound, f.runner.reorg_check(epoch)).await;

        let elapsed = start.elapsed();
        release.send(()).expect("the holder takes the release");
        drop(default);
        drop(gate.0.lock().take());
        holder.join().expect("lock holder");
        assert_eq!(cut, StepOutcome::Failed, "the step bound cut the check");
        assert_eq!(elapsed, bound, "at the 2 s step bound");
        assert_eq!(
            warns.lines(),
            [format!("Epoch boundary step timed out epoch={epoch} step=ReorgCheck timeout=2s")],
            "cut at the read, before the reorg warn"
        );
        let root = f.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
        assert_eq!(root.as_deref(), Some(ROOT_B), "B cached before the cut");
        assert!(f.mock.submit_proposer_preferences_calls().is_empty(), "cut before the broadcast");

        f.runner.run_pending(epoch * SLOTS_PER_EPOCH).await;

        let prefs = f.mock.submit_proposer_preferences_calls();
        assert_eq!(prefs.len(), 1, "the retry broadcasts B once");
        assert_eq!(
            prefs[0][0].message.dependent_root,
            eth_types::canonical::gvr_hex::parse_gvr_hex(ROOT_B).expect("root B")
        );
        assert_eq!(
            step_state(&f.runner, BoundaryStep::ReorgCheck),
            (Some(StepOutcome::Done), true)
        );
    }

    /// Hands the pass to a lock holder when it enters
    /// `orchestrator.prepare_proposers`, after the step bound started and
    /// before the step reads the pubkey map, and waits until the holder has
    /// the map's write lock.
    #[derive(Clone)]
    struct PrepareGate(Arc<parking_lot::Mutex<Option<Handoff>>>);

    /// Signals that the step started; then waits for the lock holder.
    type Handoff = (std::sync::mpsc::SyncSender<()>, std::sync::mpsc::Receiver<()>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PrepareGate {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().name() != "orchestrator.prepare_proposers" {
                return;
            }
            let handoff = self.0.lock().take();
            if let Some((entered, locked)) = handoff {
                entered.send(()).expect("the holder waits for the step");
                locked.recv().expect("the holder took the write lock");
            }
        }
    }

    /// Harper B2 (T3): PrepareProposers' step bound starts before the step
    /// reads the pubkey map; the POST's own `preparation` bound starts after
    /// that read. A thread takes the map's write lock as the step starts and
    /// holds it while 250 virtual ms pass. The POST answers 2.9 s after it
    /// is sent, 3.15 s after the step started: past the step's 3 s bound,
    /// inside the POST's own. The step bound cuts it.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_prepare_step_bound_starts_before_the_map_read() {
        let prep = MockMethod::PrepareBeaconProposer;
        let mock = proposer_duties_at(ROOT_A).with_method_delay(prep, Duration::from_millis(2_900));
        let f = fixture(mock).await;
        let (entered, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (locked, locked_rx) = std::sync::mpsc::sync_channel(0);
        let gate = PrepareGate(Arc::new(parking_lot::Mutex::new(Some((entered, locked_rx)))));
        let map = Arc::clone(&f.index_source.pubkey_map);
        let runtime = tokio::runtime::Handle::current();
        let holder = std::thread::spawn(move || {
            if entered_rx.recv().is_ok() {
                let write = map.write();
                locked.send(()).expect("the step waits for the lock");
                runtime.block_on(tokio::time::advance(Duration::from_millis(250)));
                drop(write);
            }
        });
        let warns = Warns::default();
        let subscriber = tracing_subscriber::registry().with(warns.clone()).with(gate.clone());
        let default = tracing::subscriber::set_default(subscriber);
        let start = tokio::time::Instant::now();

        f.runner.run_pending(32).await;

        let elapsed = start.elapsed();
        drop(default);
        drop(gate.0.lock().take());
        holder.join().expect("lock holder");
        assert_eq!(elapsed, f.runner.timeouts.preparation, "the step bound ends the pass at 3 s");
        assert_eq!(
            step_state(&f.runner, BoundaryStep::PrepareProposers),
            (Some(StepOutcome::Failed), false),
            "the step bound cut the POST"
        );
        assert!(f.mock.prepare_beacon_proposer_calls().is_empty(), "dropped, not answered");
        assert_eq!(
            warns.lines(),
            ["Epoch boundary step timed out epoch=1 step=PrepareProposers timeout=3s"],
            "the step's bound fired, not the POST's"
        );
    }

    // --- W4-E3c: a key with no validator index keeps PrepareProposers pending ---

    /// The validator indices of each prepare POST, sorted.
    fn prepared_indices(mock: &MockBeaconNodeClient) -> Vec<Vec<String>> {
        mock.prepare_beacon_proposer_calls()
            .into_iter()
            .map(|preparations| {
                let mut indices: Vec<String> =
                    preparations.into_iter().map(|p| p.validator_index).collect();
                indices.sort();
                indices
            })
            .collect()
    }

    /// 653-AC7: three local keys, two with an index. The slot-32 pass POSTs
    /// the two, and PrepareProposers is `NotReady`. The slot-33 pass finds
    /// the same two and sends nothing. Once the third index lands, the
    /// slot-34 pass POSTs all three, and the step is done.
    #[tokio::test(flavor = "current_thread")]
    async fn test_partial_index_resolution_is_not_ready() {
        use BoundaryStep::PrepareProposers;
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        f.resolve_new_key("43");
        let late = f.add_unresolved_key();

        f.runner.run_pending(32).await;

        assert_eq!(prepared_indices(&f.mock), [["42", "43"]], "one POST of the two resolved");
        assert_eq!(
            step_state(&f.runner, PrepareProposers),
            (Some(StepOutcome::NotReady), false),
            "the third key has no index: not ready, and not done"
        );
        assert!(f.runner.has_pending(33));

        f.runner.run_pending(33).await;

        assert_eq!(arrivals(&f.mock, MockMethod::PrepareBeaconProposer), 1, "same two: no POST");
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::NotReady), false));

        f.index_source.registry.write().insert(late, "44".to_string());
        f.runner.run_pending(34).await;

        assert_eq!(
            prepared_indices(&f.mock),
            [vec!["42", "43"], vec!["42", "43", "44"]],
            "the third index landed: one POST of all three"
        );
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Done), true));
        assert!(!f.runner.has_pending(35));
    }

    /// RSA R1 B1 (Harper R1 B3): the prepare service's own result. With validator 42 and two
    /// keys with no index, the call POSTs 42 and is `Partial` with 2
    /// unresolved; once one index lands, `Partial` with 1; once the other
    /// lands, `Complete`.
    #[tokio::test(flavor = "current_thread")]
    async fn test_partial_prepare_counts_the_keys_still_without_an_index() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        let first = f.add_unresolved_key();
        let second = f.add_unresolved_key();
        let prepare = || f.runner.duty_management.prepare_proposers(1);

        let outcome = prepare().await.expect("the POST is answered");
        assert_eq!(outcome, PrepareOutcome::Partial { unresolved: 2 }, "two keys have no index");

        f.index_source.registry.write().insert(first, "43".to_string());
        let outcome = prepare().await.expect("the POST is answered");
        assert_eq!(outcome, PrepareOutcome::Partial { unresolved: 1 }, "one key has no index");

        f.index_source.registry.write().insert(second, "44".to_string());
        let outcome = prepare().await.expect("the POST is answered");
        assert_eq!(outcome, PrepareOutcome::Complete, "every key has an index");

        assert_eq!(
            prepared_indices(&f.mock),
            [vec!["42"], vec!["42", "43"], vec!["42", "43", "44"]],
            "each call POSTs the keys with an index"
        );
    }

    /// Harper R1 B4: the beacon node's 503 for the prepare POST, unchanged:
    /// same status, same message.
    #[tokio::test(flavor = "current_thread")]
    async fn test_a_failed_prepare_post_keeps_the_beacon_error() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        *f.failing_prepare.lock() = 1;

        let outcome = f.runner.duty_management.prepare_proposers(1).await;

        assert!(
            matches!(
                &outcome,
                Err(OrchestratorError::Beacon(beacon::BeaconError::ApiError { status: 503, message }))
                    if message == "unavailable"
            ),
            "the beacon node's own error: {outcome:?}"
        );
        assert_eq!(arrivals(&f.mock, MockMethod::PrepareBeaconProposer), 1);
    }

    /// Harper R1 B4: the beacon node's 503 for the subscription POST,
    /// unchanged: same status, same message.
    #[tokio::test(flavor = "current_thread")]
    async fn test_a_failed_subscription_post_keeps_the_beacon_error() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        *f.failing_subscriptions.lock() = 1;

        let outcome = f.runner.duty_management.submit_committee_subscriptions(1).await;

        assert!(
            matches!(
                &outcome,
                Err(OrchestratorError::Beacon(beacon::BeaconError::ApiError { status: 503, message }))
                    if message == "unavailable"
            ),
            "the beacon node's own error: {outcome:?}"
        );
        assert_eq!(arrivals(&f.mock, MockMethod::SubmitBeaconCommitteeSubscriptions), 1);
        assert!(f.subscription_slots.lock().is_empty(), "the one POST was refused");
    }

    /// 653-AC8, the runner half: with no index for any local key, each of the
    /// 32 passes of epoch 1 leaves PrepareProposers `NotReady`, with no
    /// prepare POST and no signature. Control: once validator 42's index
    /// lands, epoch 2's first pass POSTs it and signs its selection proofs.
    #[tokio::test(flavor = "current_thread")]
    async fn test_no_resolved_indices_does_not_register_every_slot() {
        use BoundaryStep::PrepareProposers;
        let prep = MockMethod::PrepareBeaconProposer;
        let f = fixture_seeded(proposer_duties_at(ROOT_A), SecretKey::generate(), false, &[]).await;
        let registry = std::mem::take(&mut *f.index_source.registry.write());
        let spans = OpenedSpans::default();
        let _default =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(spans.clone()));
        let named = |name: &str| spans.0.lock().iter().filter(|opened| **opened == name).count();
        let signed = || spans.0.lock().iter().filter(|name| name.starts_with("sign.")).count();

        for slot in 32..64 {
            f.runner.run_pending(slot).await;
            assert_eq!(
                step_state(&f.runner, PrepareProposers),
                (Some(StepOutcome::NotReady), false),
                "slot {slot}: no index, not ready"
            );
        }

        assert_eq!(arrivals(&f.mock, prep), 0, "no prepare POST in any pass");
        assert_eq!(signed(), 0, "no signature in any pass");
        assert_eq!(named("orchestrator.prepare_proposers"), 32, "the step ran in each pass");

        *f.index_source.registry.write() = registry;
        f.runner.run_pending(64).await;

        assert_eq!(prepared_indices(&f.mock), [["42"]], "control: the index landed");
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Done), true));
        assert_eq!(signed(), 2, "control: the selection proofs of epochs 2 and 3 are signed");
    }

    /// The resolved count is read before the prepare POST. A key whose
    /// index lands while the partial POST of validator 42 is in flight is
    /// not in that POST, and the next pass sends it.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn an_index_that_lands_during_a_partial_post_is_sent_at_the_next_pass() {
        use BoundaryStep::PrepareProposers;
        let prep = MockMethod::PrepareBeaconProposer;
        let hold = Duration::from_secs(1);
        let f = fixture(proposer_duties_at(ROOT_A).with_call_delays(prep, [hold])).await;
        let late = f.add_unresolved_key();
        let registry = Arc::clone(&f.index_source.registry);

        tokio::join!(f.runner.run_pending(32), async {
            tokio::time::sleep(hold / 2).await;
            registry.write().insert(late, "44".to_string());
        });

        assert_eq!(prepared_indices(&f.mock), [["42"]], "built before the index landed");
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::NotReady), false));

        f.runner.run_pending(33).await;

        assert_eq!(
            prepared_indices(&f.mock),
            [vec!["42"], vec!["42", "44"]],
            "the next pass sends the key that resolved during the POST"
        );
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Done), true));
    }

    // --- W4-E4b: the runner covers boot: epoch 0 before genesis, and the
    // boot epoch's builder registration ---

    /// A clock with no time left to genesis whose every slot read returns
    /// `slot`, stamped with the paused time of the read.
    struct ScriptedClock {
        slot: fn() -> Result<Slot, TimingError>,
        reads: parking_lot::Mutex<Vec<tokio::time::Instant>>,
    }

    impl ScriptedClock {
        fn new(slot: fn() -> Result<Slot, TimingError>) -> Arc<Self> {
            Arc::new(Self { slot, reads: parking_lot::Mutex::new(Vec::new()) })
        }

        fn reads(&self) -> Vec<tokio::time::Instant> {
            self.reads.lock().clone()
        }
    }

    impl SlotClock for ScriptedClock {
        fn genesis_time(&self) -> u64 {
            TEST_GENESIS_TIME
        }

        fn slot_duration(&self) -> Duration {
            SLOT
        }

        fn slots_per_epoch(&self) -> u64 {
            SLOTS_PER_EPOCH
        }

        fn now_since_epoch(&self) -> Duration {
            Duration::from_secs(TEST_GENESIS_TIME)
        }

        fn current_slot(&self) -> Result<Slot, TimingError> {
            self.reads.lock().push(tokio::time::Instant::now());
            (self.slot)()
        }
    }

    fn before_genesis() -> Result<Slot, TimingError> {
        Err(TimingError::BeforeGenesis {
            current_time: TEST_GENESIS_TIME,
            genesis_time: TEST_GENESIS_TIME,
        })
    }

    fn arrival_stamps(
        mock: &MockBeaconNodeClient,
        method: MockMethod,
    ) -> Vec<tokio::time::Instant> {
        mock.call_stamps().iter().filter(|stamp| stamp.method == method).map(|s| s.at).collect()
    }

    /// W4-E4b AC1: 50 ms before genesis, with no slot processed, the runner
    /// task prepares epoch 0 on its own: validator 7's prepare POST goes out
    /// while the clock still reads before genesis.
    ///
    /// Then the mock holds a pre-genesis prepare. The test polls the runner
    /// itself, sets shutdown, and polls one more time. That poll must end
    /// the runner, and the held prepare must not finish.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn runner_prepares_epoch_zero_before_genesis() {
        let local = SecretKey::generate();
        let pk_bytes = local.public_key().to_bytes();
        let f = fixture_seeded(proposer_duties_at(ROOT_A), local, false, &[]).await;
        f.index_source.registry.write().insert(pk_bytes, "7".to_string());
        f.clock.set_current_time_ms(GENESIS_MS - 50);
        let runner = spawn_runner(&f);

        advance_until(|| !f.mock.prepare_beacon_proposer_calls().is_empty()).await;

        assert_eq!(
            prepared_indices(&f.mock),
            [["7"]],
            "validator 7's prepare POST must go out before genesis"
        );
        assert!(
            matches!(f.clock.current_slot(), Err(TimingError::BeforeGenesis { .. })),
            "the clock must still read before genesis"
        );
        assert_eq!(*runner.slots.borrow(), None, "no slot was processed");
        let epoch = f.runner.progress.lock().as_ref().map(|progress| progress.epoch);
        assert_eq!(epoch, Some(0), "the runner ran epoch 0's steps");
        shut_down_within_budget(runner, "before genesis").await;

        // A pre-genesis pass held in its prepare POST is raced against
        // shutdown, as a pass at a processed slot is.
        let f = held_fixture(MockMethod::PrepareBeaconProposer, &[]).await;
        f.clock.set_current_time_ms(GENESIS_MS - 50);
        let mut runner = LocalRunner::new(&f, f.clock.clone());
        runner.poll_until_prepare(&f.mock, 1).await;
        assert!(
            matches!(f.clock.current_slot(), Err(TimingError::BeforeGenesis { .. })),
            "The held prepare must start before genesis."
        );
        runner.shutdown.send_replace(true);
        // The test task yields, so the next poll starts with a full tokio
        // coop budget. Nothing else polls the runner.
        tokio::task::yield_now().await;
        let after_shutdown = futures::poll!(runner.run.as_mut());
        assert!(
            after_shutdown.is_ready(),
            "The first poll after shutdown must end the runner while the pre-genesis prepare is held."
        );
        assert!(f.mock.prepare_beacon_proposer_calls().is_empty(), "dropped, not finished");
        drop(runner);
        tokio::time::advance(HOLD).await;
        assert!(
            f.mock.prepare_beacon_proposer_calls().is_empty(),
            "The dropped prepare must not finish when the hold ends."
        );
        assert!(!prepare_done(&f.runner), "PrepareProposers must not be done in epoch 0.");
        assert_eq!(
            arrivals(&f.mock, MockMethod::PrepareBeaconProposer),
            1,
            "The runner must send no other prepare."
        );
    }

    /// RSA F2: shutdown has priority over the pre-genesis pass. Before
    /// genesis, epoch 0 has pending steps, and the mock answers at once.
    /// The test sets shutdown before it polls the runner for the first time.
    /// Each round must show these results:
    ///
    /// - The first poll ends the runner.
    /// - The runner starts no epoch-0 progress.
    /// - The runner sends no request.
    ///
    /// An unbiased select takes a random first arm, so the test has 32
    /// rounds. The source contract
    /// `the_in_flight_select_is_biased_with_the_shutdown_arm_first` pins the
    /// arm order with no random draw. In the control part, the test does not
    /// set shutdown, and the first polls prepare epoch 0.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_before_the_first_poll_starts_no_pre_genesis_pass() {
        let prep = MockMethod::PrepareBeaconProposer;
        let f = fixture_seeded(proposer_duties_at(ROOT_A), SecretKey::generate(), false, &[]).await;
        f.clock.set_current_time_ms(GENESIS_MS - 50);
        let calls = f.mock.call_stamps().len();
        assert!(f.runner.has_pending(0), "Epoch 0 must have pending steps before the first poll.");

        for round in 1..=32 {
            // Each first poll starts with a full tokio coop budget.
            tokio::task::yield_now().await;
            let mut runner = LocalRunner::new(&f, f.clock.clone());
            runner.shutdown.send_replace(true);
            let first = futures::poll!(runner.run.as_mut());
            assert!(
                f.runner.progress.lock().is_none(),
                "Round {round}: shutdown must win, so the runner must start no epoch-0 progress."
            );
            assert_eq!(
                f.mock.call_stamps().len(),
                calls,
                "Round {round}: shutdown must win, so the runner must send no request."
            );
            assert!(first.is_ready(), "Round {round}: the first poll must end the runner.");
        }

        let mut control = LocalRunner::new(&f, f.clock.clone());
        control.poll_until_prepare(&f.mock, 1).await;
        assert_eq!(
            arrivals(&f.mock, prep),
            1,
            "Control: with no shutdown, the runner must prepare."
        );
        let epoch = f.runner.progress.lock().as_ref().map(|progress| progress.epoch);
        assert_eq!(epoch, Some(0), "Control: with no shutdown, the runner must start epoch 0.");
        control.shutdown.send_replace(true);
        tokio::task::yield_now().await;
        assert!(
            futures::poll!(control.run.as_mut()).is_ready(),
            "Control: shutdown must end the runner while it waits for the next tick."
        );
    }

    /// W4-E4b AC3: this test checks the floor of the tick with no runner. It
    /// reads the tick directly, because a zero tick makes the runner loop
    /// with no wait.
    /// The tick is the time left to genesis, and one slot at most. When the
    /// clock reads no time left, the tick is one slot, not zero.
    #[test]
    fn pre_genesis_tick_is_one_slot_when_no_time_is_left() {
        let clock = MockSlotClock::new(TEST_GENESIS_TIME, SLOT, SLOTS_PER_EPOCH);
        clock.set_current_time_ms(GENESIS_MS - 50);
        assert_eq!(
            pre_genesis_tick(&clock),
            Duration::from_millis(50),
            "With 50 ms to genesis, the tick must be 50 ms."
        );
        clock.set_current_time_ms(GENESIS_MS - 30_000);
        assert_eq!(
            pre_genesis_tick(&clock),
            SLOT,
            "With 30 s to genesis, the tick must be one slot."
        );

        let no_time_left = ScriptedClock::new(before_genesis);
        assert_eq!(
            no_time_left.time_until_slot(0).expect("time to genesis"),
            Duration::ZERO,
            "The scripted clock must read no time left to genesis."
        );
        assert_eq!(
            pre_genesis_tick(&*no_time_left),
            SLOT,
            "With no time left to genesis, the tick must be one slot, not zero."
        );
    }

    /// W4-E4b AC2: the epoch-0 progress made before genesis carries into
    /// slot 0. 30 s before genesis the first tick prepares epoch 0, and E+1's
    /// attester requests fail, so the subscription step stays pending. Slot
    /// 0, the first slot processed, comes during the 12 s wait. The task
    /// runs slot 0's pass at once: it fetches E+1 and subscribes, and does
    /// not prepare again.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn pre_genesis_progress_carries_into_slot_zero() {
        use BoundaryStep::{CommitteeSubscriptions, PrepareProposers};
        let [att, prep, subs] = [
            MockMethod::GetAttesterDuties,
            MockMethod::PrepareBeaconProposer,
            MockMethod::SubmitBeaconCommitteeSubscriptions,
        ];
        let f = fixture_seeded(proposer_duties_at(ROOT_A), SecretKey::generate(), false, &[]).await;
        f.failing_attester.lock().insert(1, 2);
        f.clock.set_current_time_ms(GENESIS_MS - 30_000);
        let runner = spawn_runner(&f);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(arrivals(&f.mock, prep), 1, "the pre-genesis tick must prepare epoch 0");
        assert_eq!(step_state(&f.runner, PrepareProposers), (Some(StepOutcome::Done), true));
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::NotReady), false),
            "E+1 is uncached"
        );

        f.clock.set_current_time_ms(GENESIS_MS);
        let (calls, processed) = (f.mock.call_stamps().len(), tokio::time::Instant::now());
        runner.slots.send_replace(Some(0));
        tokio::time::sleep(Duration::from_millis(1)).await;

        let since: Vec<(MockMethod, tokio::time::Instant)> =
            f.mock.call_stamps()[calls..].iter().map(|stamp| (stamp.method, stamp.at)).collect();
        assert_eq!(
            since,
            [(att, processed), (subs, processed), (subs, processed)],
            "slot 0's pass runs at once: DutyFetch's E+1 request and the subscriptions, \
             and it must not prepare again"
        );
        assert_eq!(*f.subscription_slots.lock(), slots(&[&["1"], &["33"]]));
        assert_eq!(arrivals(&f.mock, prep), 1, "slot 0 must not prepare again");
        assert!(!f.runner.has_pending(1), "every epoch-0 step is done");
        shut_down_within_budget(runner, "after slot 0").await;
    }

    /// W4-E4b AC3: a prepare that answers 503 before genesis is retried at
    /// the next tick, not earlier. A tick is the time left to genesis, at
    /// most one slot, and one slot when the clock reads none left: 50 ms,
    /// 12 s and 12 s here. The retry succeeds, and the step is done.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn pre_genesis_prepare_failure_retries_next_tick() {
        use BoundaryStep::PrepareProposers;
        let prep = MockMethod::PrepareBeaconProposer;
        for (arm, to_genesis_ms, tick) in [
            ("50 ms to genesis", Some(50), Duration::from_millis(50)),
            ("30 s to genesis: one slot at most", Some(30_000), SLOT),
            ("no time left on the clock: one slot", None, SLOT),
        ] {
            let f =
                fixture_seeded(proposer_duties_at(ROOT_A), SecretKey::generate(), false, &[]).await;
            *f.failing_prepare.lock() = 1;
            let clock: Arc<dyn SlotClock> = match to_genesis_ms {
                Some(ms) => {
                    f.clock.set_current_time_ms(GENESIS_MS - ms);
                    f.clock.clone()
                }
                None => ScriptedClock::new(before_genesis),
            };
            let start = tokio::time::Instant::now();
            let runner = spawn_runner_on(&f, clock);

            tokio::time::sleep(tick - Duration::from_millis(1)).await;
            assert_eq!(
                arrival_stamps(&f.mock, prep),
                [start],
                "{arm}: one prepare, at the first tick, and no retry before the next"
            );
            assert_eq!(
                step_state(&f.runner, PrepareProposers),
                (Some(StepOutcome::Failed), false),
                "{arm}: the 503 leaves PrepareProposers failed, and not done"
            );

            tokio::time::sleep(Duration::from_millis(2)).await;
            assert_eq!(
                arrival_stamps(&f.mock, prep),
                [start, start + tick],
                "{arm}: the 503 must be retried at the next tick"
            );
            assert_eq!(
                step_state(&f.runner, PrepareProposers),
                (Some(StepOutcome::Done), true),
                "{arm}: the retry succeeded: done"
            );
            shut_down_within_budget(runner, arm).await;
        }
    }

    /// W4-E4b AC4: a clock that cannot give the current slot for a reason
    /// other than genesis gets one warn, and the next read 1 s of virtual
    /// time later, not earlier. No pass runs on it.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn clock_error_waits_one_second() {
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        let calls = f.mock.call_stamps().len();
        let clock = ScriptedClock::new(|| Err(TimingError::InvalidSlotDuration));
        let warns = Warns::default();
        let _default = warns.install();
        let warn = "Epoch boundary runner cannot read the current slot \
                    error=slot duration must be at least 1 second";
        let start = tokio::time::Instant::now();
        let mut runner = LocalRunner::new(&f, clock.clone());

        assert!(futures::poll!(runner.run.as_mut()).is_pending(), "it waits");
        assert_eq!(clock.reads(), [start], "the first read");
        assert_eq!(warns.lines(), [warn], "one warn");

        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(futures::poll!(runner.run.as_mut()).is_pending(), "it still waits");
        assert_eq!(clock.reads(), [start], "no read before 1 s");
        assert_eq!(warns.lines(), [warn], "still one warn");

        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(futures::poll!(runner.run.as_mut()).is_pending(), "it waits again");
        assert_eq!(
            clock.reads(),
            [start, start + Duration::from_secs(1)],
            "the next read must come 1 s later"
        );
        assert_eq!(warns.lines(), [warn, warn], "one warn per read");
        assert_eq!(f.mock.call_stamps().len(), calls, "no pass runs on a broken clock");
        assert!(f.runner.progress.lock().is_none(), "no epoch started");

        runner.shutdown.send_replace(true);
        assert!(futures::poll!(runner.run.as_mut()).is_ready(), "shutdown ends the waiting runner");
    }

    /// The registration calls: one `builder.register` span each.
    fn registrations(spans: &OpenedSpans) -> usize {
        spans.0.lock().iter().filter(|name| **name == "builder.register").count()
    }

    /// W4-E4b AC5: the boot epoch's registration needs no validator index.
    /// With none resolved, it is `Ok` at slot 2, and done; slots 3..31 make
    /// no further `register_validators` call, while PrepareProposers stays
    /// `NotReady` in every pass.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn boot_registration_is_not_repeated_after_it_succeeds() {
        use BoundaryStep::{BuilderRegistration, PrepareProposers};
        let mock = proposer_duties_at(ROOT_A).with_register_validators(|_registrations| Ok(()));
        let f = fixture_seeded(mock, SecretKey::generate(), true, &[]).await;
        let _resolved = std::mem::take(&mut *f.index_source.registry.write());
        let spans = OpenedSpans::default();
        let _default =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(spans.clone()));

        f.runner.run_pending(2).await;

        assert_eq!(registrations(&spans), 1, "slot 2 must make one register_validators call");
        assert_eq!(f.mock.register_validators_calls().len(), 1, "its POST was answered");
        assert_eq!(
            step_state(&f.runner, BuilderRegistration),
            (Some(StepOutcome::Done), true),
            "Ok: done"
        );
        for slot in 3..SLOTS_PER_EPOCH {
            f.runner.run_pending(slot).await;
            assert_eq!(
                step_state(&f.runner, PrepareProposers),
                (Some(StepOutcome::NotReady), false),
                "slot {slot}: no index, not ready"
            );
        }

        assert_eq!(
            registrations(&spans),
            1,
            "slots 3..31 must make no further register_validators call"
        );
        assert_eq!(arrivals(&f.mock, MockMethod::RegisterValidators), 1, "one registration POST");
    }

    /// W4-E6a: the registration step runs in every epoch. The first pass is
    /// in epoch 2. These conditions must hold:
    ///
    /// - The step must run in epochs 2 and 3.
    /// - In the held arm, the first POST must reach
    ///   `registration_step_timeout()`, and the step must be `Failed`.
    /// - The slot-65 pass must retry the failed step.
    /// - Without a builder service, the step must finish without a call.
    /// - From Gloas, the step must finish without a call.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn registration_runs_every_epoch() {
        use BoundaryStep::BuilderRegistration;
        let gloas = create_test_fork_schedule().gloas_fork_epoch;
        let register = MockMethod::RegisterValidators;
        for (arm, with_builder, boot, held, want_calls, want_posts) in [
            ("boot epoch 2", true, 2, false, 1, 1),
            ("boot epoch 2, first POST held", true, 2, true, 2, 1),
            ("no builder service", false, 2, false, 0, 0),
            ("Gloas boot epoch", true, gloas, false, 0, 0),
        ] {
            let delays = if held { vec![HOLD] } else { Vec::new() };
            let mock = proposer_duties_at(ROOT_A)
                .with_register_validators(|_registrations| Ok(()))
                .with_call_delays(register, delays);
            let f = fixture_seeded(mock, SecretKey::generate(), with_builder, &[]).await;
            let spans = OpenedSpans::default();
            let _default = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(spans.clone()),
            );
            let first = boot * SLOTS_PER_EPOCH;
            let start = tokio::time::Instant::now();

            f.runner.run_pending(first).await;

            if held {
                let builder = f
                    .runner
                    .builder_service
                    .clone()
                    .expect("The fixture must have a builder service.");
                assert_eq!(
                    start.elapsed(),
                    builder.registration_step_timeout(),
                    "{arm}: cut at the bound"
                );
                assert_eq!(
                    step_state(&f.runner, BuilderRegistration),
                    (Some(StepOutcome::Failed), false),
                    "{arm}: timed out: failed, and not done"
                );
                f.runner.run_pending(first + 1).await;
            }
            assert_eq!(
                step_state(&f.runner, BuilderRegistration),
                (Some(StepOutcome::Done), true),
                "{arm}: done in the boot epoch"
            );
            assert_eq!(registrations(&spans), want_calls, "{arm}: calls in the boot epoch");
            assert_eq!(
                f.mock.register_validators_calls().len(),
                want_posts,
                "{arm}: answered POSTs"
            );

            f.runner.run_pending(first + SLOTS_PER_EPOCH).await;

            assert_eq!(
                step_state(&f.runner, BuilderRegistration),
                (Some(StepOutcome::Done), true),
                "{arm}: The next epoch must finish the step again."
            );
            let next = usize::from(want_posts > 0);
            assert_eq!(
                (registrations(&spans), f.mock.register_validators_calls().len()),
                (want_calls + next, want_posts + next),
                "For arm {arm}, the call and POST counts must match the next-epoch expectations."
            );
        }
    }

    /// Harper B2: the boot-epoch registration needs no duties. The fixture
    /// has a builder service, and boot epoch 2 is before Gloas. Each attester
    /// and proposer request for epochs 2 and 3 fails, so the tracker caches
    /// no duty epoch. The registration step must call `register_validators`
    /// and be `Done`, and must not be `NotReady`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn boot_registration_does_not_wait_for_duties() {
        use BoundaryStep::{BuilderRegistration, DutyFetch};
        let failing_proposer = FailPlan::default();
        failing_proposer.lock().extend([(2, usize::MAX), (3, usize::MAX)]);
        let mock = proposer_duties_failing(Arc::clone(&failing_proposer))
            .with_register_validators(|_registrations| Ok(()));
        let f = fixture_seeded(mock, SecretKey::generate(), true, &[]).await;
        f.failing_attester.lock().extend([(2, usize::MAX), (3, usize::MAX)]);
        assert!(
            create_test_fork_schedule().gloas_fork_epoch > 2,
            "Boot epoch 2 must be before Gloas."
        );
        let spans = OpenedSpans::default();
        let _default =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(spans.clone()));

        f.runner.run_pending(2 * SLOTS_PER_EPOCH).await;

        assert_eq!(
            step_state(&f.runner, DutyFetch),
            (Some(StepOutcome::Failed), false),
            "DutyFetch must fail, because each duty request fails."
        );
        for epoch in [2, 3] {
            assert!(
                !f.duty_tracker.is_epoch_cached(epoch).await,
                "The attester duties of epoch {epoch} must not be cached."
            );
            assert!(
                !f.duty_tracker.is_proposer_epoch_cached(epoch).await,
                "The proposer duties of epoch {epoch} must not be cached."
            );
        }
        assert_eq!(
            registrations(&spans),
            1,
            "With no cached duties, the registration step must call register_validators one time."
        );
        assert_eq!(
            arrivals(&f.mock, MockMethod::RegisterValidators),
            1,
            "The registration step must send one registration POST."
        );
        assert_eq!(
            step_state(&f.runner, BuilderRegistration),
            (Some(StepOutcome::Done), true),
            "The registration step must be Done, and must not wait for duties."
        );
    }

    // --- W4-E6a: the registration step runs every epoch ---

    /// Returns `mock` with a registration route. The route rejects the first
    /// `failures` registration POSTs with status 503. It accepts the later
    /// POSTs with status 200.
    fn registrations_failing(mock: MockBeaconNodeClient, failures: usize) -> MockBeaconNodeClient {
        let left = parking_lot::Mutex::new(failures);
        mock.with_register_validators(move |_registrations| {
            let mut left = left.lock();
            if *left == 0 {
                return Ok(());
            }
            *left -= 1;
            Err(unavailable())
        })
    }

    /// 654-AC3, the runner half. The first registration POST answers 503,
    /// and the next one answers 200. After the 503, the step must stay
    /// pending. At slot 33, these conditions must hold:
    ///
    /// - The POST contains the first signed registration.
    /// - The signer adds no signature.
    /// - The successful POST finishes the step.
    #[tokio::test(flavor = "current_thread")]
    async fn test_registration_503_then_200_sends_at_next_slot() {
        use BoundaryStep::BuilderRegistration;
        let mock = registrations_failing(proposer_duties_at(ROOT_A), 1);
        let f = fixture_with(mock, SecretKey::generate(), true).await;

        f.runner.run_pending(32).await;

        assert_eq!(
            step_state(&f.runner, BuilderRegistration),
            (Some(StepOutcome::Failed), false),
            "The 503 must leave the registration step failed and pending."
        );
        assert_eq!(f.registrations.total(), 1, "The slot-32 pass must sign one registration.");

        f.runner.run_pending(33).await;

        let posts = f.mock.register_validators_calls();
        assert_eq!(posts.len(), 2, "The slot-33 pass must send the registration again.");
        assert_eq!(posts[1], posts[0], "The slot-33 POST must carry the same signed registration.");
        assert_eq!(f.registrations.total(), 1, "The slot-33 pass must sign no new registration.");
        assert_eq!(
            step_state(&f.runner, BuilderRegistration),
            (Some(StepOutcome::Done), true),
            "The 200 must finish the registration step."
        );
    }

    /// 653-AC6: a retry re-sends the cached signature and signs nothing again.
    ///
    /// 1. The POSTs of slots 32, 33 and 34 answer 503, and the slot-35 POST
    ///    answers 200. Slots 32 to 35 must each send one POST, and slot 36
    ///    must send none. Epoch 1 must sign one registration.
    /// 2. Each POST of epoch 1 answers 503. The slot-64 pass must warn one
    ///    time for epoch 1 and name BuilderRegistration. Then it must send
    ///    the epoch-1 signed registration again, with no new signature.
    /// 3. No local key has a validator index, and each POST answers 200.
    ///    Epochs 1 and 2 must each send one POST, not one POST per slot.
    #[tokio::test(flavor = "current_thread")]
    async fn test_retried_step_resigns_nothing_already_cached() {
        use BoundaryStep::{BuilderRegistration, PrepareProposers};
        let register = MockMethod::RegisterValidators;

        let mock = registrations_failing(proposer_duties_at(ROOT_A), 3);
        let f = fixture_with(mock, SecretKey::generate(), true).await;
        let mut posts = Vec::new();
        for slot in 32..=36 {
            f.runner.run_pending(slot).await;
            posts.push(arrivals(&f.mock, register));
        }
        assert_eq!(
            posts,
            [1, 2, 3, 4, 4],
            "Slots 32 to 35 must each send one POST, and slot 36 must send none."
        );
        assert_eq!(f.registrations.total(), 1, "Epoch 1 must sign one registration.");
        assert_eq!(step_state(&f.runner, BuilderRegistration), (Some(StepOutcome::Done), true));

        let mock = registrations_failing(proposer_duties_at(ROOT_A), 32);
        let f = fixture_with(mock, SecretKey::generate(), true).await;
        let warns = Warns::default();
        let _default = warns.install();
        for slot in 32..64 {
            f.runner.run_pending(slot).await;
        }
        assert_eq!(arrivals(&f.mock, register), 32, "Each pass of epoch 1 must send one POST.");
        assert_eq!(warns.abandoned(), Vec::<String>::new(), "Epoch 1 must not warn in the epoch.");

        f.runner.run_pending(64).await;

        assert_eq!(
            warns.abandoned(),
            ["epoch=1 abandoned_steps=[BuilderRegistration] \
              last_outcomes={BuilderRegistration: Failed}"],
            "The slot-64 pass must warn one time for epoch 1."
        );
        let posts = f.mock.register_validators_calls();
        assert_eq!(posts.len(), 33, "The slot-64 pass must send the registration.");
        assert_eq!(posts[32], posts[0], "Epoch 2 must send the epoch-1 signed registration.");
        assert_eq!(f.registrations.total(), 1, "The two epochs must sign one registration.");
        assert_eq!(step_state(&f.runner, BuilderRegistration), (Some(StepOutcome::Done), true));

        let mock = registrations_failing(proposer_duties_at(ROOT_A), 0);
        let f = fixture_with(mock, SecretKey::generate(), true).await;
        let _resolved = std::mem::take(&mut *f.index_source.registry.write());
        let mut posts = Vec::new();
        for epoch in [1, 2] {
            for slot in epoch * SLOTS_PER_EPOCH..(epoch + 1) * SLOTS_PER_EPOCH {
                f.runner.run_pending(slot).await;
            }
            assert_eq!(
                step_state(&f.runner, PrepareProposers),
                (Some(StepOutcome::NotReady), false),
                "Epoch {epoch}: with no validator index, PrepareProposers must not be ready."
            );
            posts.push(arrivals(&f.mock, register));
        }
        assert_eq!(posts, [1, 2], "With no validator index, each epoch must send one POST.");
        assert_eq!(f.registrations.total(), 1, "The two epochs must sign one registration.");
    }

    /// The registration step runs under `registration_step_timeout()`, not
    /// a fixed 10 s. Three builder keys go out in batches of one, 6 s apart.
    /// The step bound is 22 s, and the last batch goes out at 12 s. The
    /// slot-32 pass must send all three batches and finish the step.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn registration_step_uses_the_scaled_timeout() {
        let mock = registrations_failing(proposer_duties_at(ROOT_A), 0);
        let batching = Batching { extra_keys: 2, size: 1, delay_ms: 6_000 };
        let config = create_test_config();
        let f = fixture_batched(mock, SecretKey::generate(), true, &[1, 2], config, batching).await;
        let builder =
            f.runner.builder_service.clone().expect("The fixture must have a builder service.");
        assert_eq!(
            builder.registration_step_timeout(),
            Duration::from_secs(22),
            "Three batches 6 s apart must give a 22 s bound."
        );

        f.runner.run_pending(32).await;

        let sizes: Vec<usize> = f.mock.register_validators_calls().iter().map(Vec::len).collect();
        assert_eq!(sizes, [1, 1, 1], "All three batches must land, although the delays are 12 s.");
        assert_eq!(
            step_state(&f.runner, BoundaryStep::BuilderRegistration),
            (Some(StepOutcome::Done), true),
            "The registration step must finish inside its bound."
        );
    }

    /// Proposer duties at root A in which validator 42 (`local_hex`)
    /// proposes at slot 5 of each epoch from `from`.
    fn proposals_from(local_hex: String, from: u64) -> MockBeaconNodeClient {
        proposals_failing(local_hex, from, FailPlan::default())
    }

    /// [`proposals_from`], with a 503 for each proposer-duties request that
    /// `plan` arms. The mock also accepts each registration POST.
    fn proposals_failing(local_hex: String, from: u64, plan: FailPlan) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new()
            .with_get_proposer_duties(move |epoch| {
                if take_failure(&plan, epoch) {
                    return Err(unavailable());
                }
                let duty = beacon::ProposerDuty {
                    pubkey: local_hex.clone(),
                    validator_index: "42".to_string(),
                    slot: (epoch * SLOTS_PER_EPOCH + 5).to_string(),
                };
                Ok(beacon::DependentRootResponse {
                    dependent_root: ROOT_A.to_string(),
                    execution_optimistic: false,
                    data: if epoch >= from { vec![duty] } else { Vec::new() },
                })
            })
            .with_post_ptc_duties(|_epoch, _indices| {
                Ok(beacon::DependentRootResponse {
                    dependent_root: ROOT_A.to_string(),
                    execution_optimistic: false,
                    data: Vec::new(),
                })
            })
            .with_submit_proposer_preferences(|_preferences| Ok(()))
            .with_register_validators(|_registrations| Ok(()))
    }

    /// When each POST succeeds, the runner broadcasts the preferences one
    /// time per epoch, as the slot-0 builder block did. The test has this
    /// setup:
    ///
    /// - The local key proposes at slot 5 of each epoch from Gloas onward.
    /// - The dependent root stays unchanged.
    /// - Two passes run in each of the epochs Gloas-1, Gloas and Gloas+1.
    ///
    /// Each epoch must make one broadcast. Its POST must carry the proposal
    /// of the next epoch.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_step_runs_once_per_epoch() {
        let gloas = create_test_fork_schedule().gloas_fork_epoch;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let mock = registrations_failing(proposals_from(local_hex, gloas), 0);
        let f = fixture_seeded(mock, local, true, &[]).await;
        let spans = OpenedSpans::default();
        let _default =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(spans.clone()));
        let broadcasts = || {
            let name = "builder.broadcast_proposer_preferences";
            spans.0.lock().iter().filter(|opened| **opened == name).count()
        };

        let mut seen = Vec::new();
        for epoch in [gloas - 1, gloas, gloas + 1] {
            for slot in [epoch * SLOTS_PER_EPOCH, epoch * SLOTS_PER_EPOCH + 1] {
                f.runner.run_pending(slot).await;
            }
            seen.push(broadcasts());
        }

        assert_eq!(seen, [1, 2, 3], "Each epoch must make one preferences broadcast.");
        let posted: Vec<Vec<Slot>> = f
            .mock
            .submit_proposer_preferences_calls()
            .iter()
            .map(|post| post.iter().map(|signed| signed.message.proposal_slot).collect())
            .collect();
        let proposal = |epoch: u64| vec![epoch * SLOTS_PER_EPOCH + 5];
        assert_eq!(
            posted,
            [proposal(gloas), proposal(gloas + 1), proposal(gloas + 2)],
            "Each epoch must send the preferences of the next epoch's proposal."
        );
    }

    /// Harper B1 and RSA B1: a stalled signer must not hold the runner in
    /// the epoch of a preferences attempt. The test has this setup:
    ///
    /// - The local key proposes at slot 5 of each epoch from Gloas onward.
    /// - The signer of the builder service waits `HOLD` (1 h) before each
    ///   preferences signature.
    /// - The runner task processes slots 0 and 1 of Gloas.
    /// - One epoch later, the task processes slots 0 and 1 of Gloas+1.
    ///
    /// These conditions must hold:
    ///
    /// - At slot 0 of Gloas+1, ReorgCheck and CommitteeSubscriptions of
    ///   Gloas+1 must finish.
    /// - The 10 s bound must stop each held attempt, and the step must then
    ///   be `Failed` and stay pending.
    /// - Each pass must start one preferences signature.
    /// - No preferences POST must reach the beacon node.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stalled_preferences_signer_does_not_hold_the_next_epoch() {
        use BoundaryStep::{CommitteeSubscriptions, ProposerPreferences, ReorgCheck};
        let gloas = create_test_fork_schedule().gloas_fork_epoch;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let f = fixture_seeded(proposals_from(local_hex, gloas), local, true, &[]).await;
        f.registrations.delay_preferences(HOLD);
        let runner = spawn_runner(&f);
        let bound = Duration::from_secs(10);
        let second = Duration::from_secs(1);
        let first = gloas * SLOTS_PER_EPOCH;
        let next = first + SLOTS_PER_EPOCH;
        let start = tokio::time::Instant::now();

        runner.slots.send_replace(Some(first));
        tokio::time::sleep(bound + second).await;
        runner.slots.send_replace(Some(first + 1));
        tokio::time::sleep(second).await;
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Failed), false),
            "The bound must stop the first attempt, and the step must stay pending."
        );
        assert_eq!(
            f.registrations.preferences_calls(),
            2,
            "Each of the two passes of epoch {gloas} must start one preferences signature."
        );

        let epoch_length = Duration::from_secs(SLOT.as_secs() * SLOTS_PER_EPOCH);
        tokio::time::sleep_until(start + epoch_length).await;
        let at_next = tokio::time::Instant::now();
        runner.slots.send_replace(Some(next));
        tokio::time::sleep(second).await;

        let later = f.runner.progress.lock().as_ref().map(|progress| {
            let done = |step| progress.done.contains(&step);
            (progress.epoch, done(ReorgCheck), done(CommitteeSubscriptions))
        });
        assert_eq!(
            later,
            Some((gloas + 1, true, true)),
            "At slot 0 of epoch {}, ReorgCheck and CommitteeSubscriptions of that epoch must \
             finish.",
            gloas + 1
        );
        let duty_slot = |epoch: u64| vec![(epoch * SLOTS_PER_EPOCH + 1).to_string()];
        assert_eq!(
            *f.subscription_slots.lock(),
            [duty_slot(gloas), duty_slot(gloas + 1), duty_slot(gloas + 1), duty_slot(gloas + 2)],
            "Each of the two epochs must send the subscriptions of that epoch and the next epoch."
        );
        assert_eq!(
            f.registrations.preferences_calls(),
            3,
            "The first pass of epoch {} must start one preferences signature.",
            gloas + 1
        );

        tokio::time::sleep_until(at_next + bound - second).await;
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (None, false),
            "The held attempt must still run 1 s before the bound."
        );
        tokio::time::sleep_until(at_next + bound + second).await;
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Failed), false),
            "The bound must stop the held attempt, and the step must stay pending."
        );
        runner.slots.send_replace(Some(next + 1));
        tokio::time::sleep(second).await;
        assert_eq!(
            f.registrations.preferences_calls(),
            4,
            "Slot 1 of epoch {} must retry the step and start one more preferences signature.",
            gloas + 1
        );
        assert!(
            f.mock.submit_proposer_preferences_calls().is_empty(),
            "No preferences POST must reach the beacon node."
        );
        shut_down_within_budget(runner, "stalled preferences signer").await;
    }

    // --- W4-E6b1: the preferences step retries each slot from Gloas-1 ---

    /// The URL of the builder in the builder-preferences tests.
    const BUILDER_URL: &str = "https://builder.example.com";

    /// The first slot of the epoch before Gloas. The test schedule has Gloas
    /// at epoch 70.
    fn gloas_minus_one_slot() -> Slot {
        (create_test_fork_schedule().gloas_fork_epoch - 1) * SLOTS_PER_EPOCH
    }

    /// The proposal slots of each proposer-preferences POST, in POST order.
    fn preference_slots(mock: &MockBeaconNodeClient) -> Vec<Vec<Slot>> {
        let posts = mock.submit_proposer_preferences_calls();
        posts.iter().map(|post| post.iter().map(|p| p.message.proposal_slot).collect()).collect()
    }

    /// The slots of each builder-preferences POST, in POST order.
    fn builder_preference_slots(mock: &MockBeaconNodeClient) -> Vec<Vec<Slot>> {
        let posts = mock.submit_builder_preferences_calls();
        posts.iter().map(|post| post.iter().map(|e| e.auth.message.slot).collect()).collect()
    }

    /// 654-AC6: the step uses the proposer duties that the runner fetches. The
    /// tracker starts empty, and no slot loop or warm-up runs. The epoch E is
    /// Gloas-1, and the local key proposes at slot 5 of E+1. The proposer
    /// requests of ReorgCheck for E and E+1 answer 503.
    ///
    /// 1. DutyFetch must request the proposer duties of E and E+1. The step
    ///    must send the preferences in the same pass.
    /// 2. The E+1 request of DutyFetch also answers 503. The step must be
    ///    `NotReady` and must send no POST. The next pass must fetch E+1 and
    ///    send one POST.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_from_a_cold_cache_use_runner_fetched_duties() {
        use BoundaryStep::ProposerPreferences;
        let first = gloas_minus_one_slot();
        let (epoch, next) = (first / SLOTS_PER_EPOCH, first / SLOTS_PER_EPOCH + 1);
        let proposal = next * SLOTS_PER_EPOCH + 5;
        for (arm, next_failures) in [("DutyFetch fills E+1", 1), ("DutyFetch fails for E+1", 2)] {
            let local = SecretKey::generate();
            let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
            let plan = FailPlan::default();
            plan.lock().extend([(epoch, 1), (next, next_failures)]);
            let f =
                fixture_seeded(proposals_failing(local_hex, next, plan), local, true, &[]).await;

            f.runner.run_pending(first).await;

            assert_eq!(
                f.mock.get_proposer_duties_calls(),
                [epoch, next, epoch, next],
                "{arm}: ReorgCheck and then DutyFetch must each request E and E+1."
            );
            if next_failures == 1 {
                assert_eq!(
                    preference_slots(&f.mock),
                    [vec![proposal]],
                    "{arm}: The same pass must send the preferences."
                );
                assert_eq!(
                    step_state(&f.runner, ProposerPreferences),
                    (Some(StepOutcome::Done), true),
                    "{arm}: The accepted POST must finish the step."
                );
                continue;
            }
            assert_eq!(
                step_state(&f.runner, ProposerPreferences),
                (Some(StepOutcome::NotReady), false),
                "{arm}: With E+1 uncached, the step must not be ready and must stay pending."
            );
            assert_eq!(
                arrivals(&f.mock, MockMethod::SubmitProposerPreferences),
                0,
                "{arm}: The step must not send a POST."
            );

            f.runner.run_pending(first + 1).await;

            assert_eq!(
                f.mock.get_proposer_duties_calls()[4..],
                [next],
                "{arm}: The next pass must request E+1 again."
            );
            assert_eq!(
                preference_slots(&f.mock),
                [vec![proposal]],
                "{arm}: The next pass must send one POST."
            );
            assert_eq!(
                step_state(&f.runner, ProposerPreferences),
                (Some(StepOutcome::Done), true),
                "{arm}: The accepted POST must finish the step."
            );
        }
    }

    /// 654-AC6: before Gloas-1, the step finishes with no call. The epoch E is
    /// Gloas-2, so E+1 is still Fulu. The local key proposes in each epoch.
    /// In the cold arm, each proposer request for E+1 answers 503. In the two
    /// arms, the step must be `Done`, and it must not call the builder service.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_skip_before_gloas_minus_one() {
        let first = gloas_minus_one_slot() - SLOTS_PER_EPOCH;
        let next = first / SLOTS_PER_EPOCH + 1;
        for (arm, next_failures) in [("warm E+1", 0), ("cold E+1", usize::MAX)] {
            let local = SecretKey::generate();
            let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
            let plan = FailPlan::default();
            plan.lock().insert(next, next_failures);
            let f = fixture_seeded(proposals_failing(local_hex, 0, plan), local, true, &[]).await;
            let spans = OpenedSpans::default();
            let _default = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(spans.clone()),
            );

            f.runner.run_pending(first).await;

            assert_eq!(
                f.duty_tracker.is_proposer_epoch_cached(next).await,
                next_failures == 0,
                "{arm}: Only the warm arm must have the E+1 proposer duties in the cache."
            );
            assert_eq!(
                step_state(&f.runner, BoundaryStep::ProposerPreferences),
                (Some(StepOutcome::Done), true),
                "{arm}: The step must finish before Gloas-1."
            );
            let calls =
                spans.0.lock().iter().filter(|name| name.starts_with("builder.broadcast_")).count();
            assert_eq!(calls, 0, "{arm}: The step must not call the builder service.");
        }
    }

    /// 654-AC6: the step is `Done` only when the two broadcasts succeed. The
    /// epoch is Gloas-1, and the local key has one builder URL. The proposer
    /// POST answers 200, and the first builder POST answers 503.
    ///
    /// - The first pass must leave the step `Failed` and pending.
    /// - The retry must send the builder entry again.
    /// - The retry must not send or sign the proposer entry again.
    #[tokio::test(flavor = "current_thread")]
    async fn builder_preferences_failure_keeps_the_step_pending() {
        use BoundaryStep::ProposerPreferences;
        let first = gloas_minus_one_slot();
        let next = first / SLOTS_PER_EPOCH + 1;
        let proposal = next * SLOTS_PER_EPOCH + 5;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let failures = parking_lot::Mutex::new(1_usize);
        let mock =
            proposals_from(local_hex, next).with_submit_builder_preferences(move |_entries| {
                let mut left = failures.lock();
                if *left == 0 {
                    return Ok(beacon::SubmitBuilderPreferencesResult::Success);
                }
                *left -= 1;
                Err(unavailable())
            });
        let f = fixture_seeded(mock, local, true, &[]).await;
        f.validator_store
            .set_global_builders(vec![BUILDER_URL.to_string()])
            .expect("The builder URL must be valid.");

        f.runner.run_pending(first).await;

        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Failed), false),
            "The builder POST failed, so the step must be failed and pending."
        );
        assert_eq!(
            preference_slots(&f.mock),
            [vec![proposal]],
            "The first pass must send the proposer POST."
        );
        assert_eq!(
            builder_preference_slots(&f.mock),
            [vec![proposal]],
            "The first builder POST must carry the Gloas proposal."
        );

        f.runner.run_pending(first + 1).await;

        assert_eq!(
            builder_preference_slots(&f.mock),
            [vec![proposal], vec![proposal]],
            "The retry must send the builder entry again."
        );
        assert_eq!(
            arrivals(&f.mock, MockMethod::SubmitProposerPreferences),
            1,
            "The retry must not send the proposer entry again."
        );
        assert_eq!(
            f.registrations.preferences_calls(),
            1,
            "The retry must not sign the proposer preferences again."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Done), true),
            "The accepted builder POST must finish the step."
        );
    }

    /// 654-AC6: the preferences step fails in each pass of the epoch. The
    /// first pass of the next epoch must issue one abandoned-step warning.
    /// That warning must name ProposerPreferences. The epoch is Gloas-1, and
    /// each proposer-preferences POST answers 503.
    ///
    /// - Each of the 32 passes of the epoch must make one attempt.
    /// - No abandoned-steps warn must occur inside the epoch.
    /// - The first pass of Gloas must warn one time and name the step.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_abandoned_warn() {
        let first = gloas_minus_one_slot();
        let epoch = first / SLOTS_PER_EPOCH;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let mock = proposals_from(local_hex, epoch + 1)
            .with_submit_proposer_preferences(|_preferences| Err(unavailable()));
        let f = fixture_seeded(mock, local, true, &[]).await;
        let warns = Warns::default();
        let _default = warns.install();

        for slot in first..first + SLOTS_PER_EPOCH {
            f.runner.run_pending(slot).await;
        }
        assert_eq!(
            arrivals(&f.mock, MockMethod::SubmitProposerPreferences),
            32,
            "Each of the 32 passes of epoch {epoch} must make one attempt."
        );
        assert_eq!(warns.abandoned(), Vec::<String>::new(), "No warn must occur inside the epoch.");

        f.runner.run_pending(first + SLOTS_PER_EPOCH).await;

        assert_eq!(
            warns.abandoned(),
            [format!(
                "epoch={epoch} abandoned_steps=[ProposerPreferences] \
                 last_outcomes={{ProposerPreferences: Failed}}"
            )],
            "The first pass of epoch {} must warn one time for epoch {epoch}.",
            epoch + 1
        );
    }

    // --- W4-E6b1 R1: only complete work finishes the preferences step ---

    /// The second builder URL in the builder-preferences tests.
    const SECOND_BUILDER_URL: &str = "https://second-builder.example.com";

    /// Returns a check that is `true` for its first `count` calls.
    fn fails_first(count: usize) -> impl Fn() -> bool + Send + Sync + 'static {
        let left = parking_lot::Mutex::new(count);
        move || {
            let mut left = left.lock();
            let fail = *left > 0;
            *left = left.saturating_sub(1);
            fail
        }
    }

    /// The URLs of each builder-preferences POST, in POST order.
    fn builder_preference_urls(mock: &MockBeaconNodeClient) -> Vec<Vec<String>> {
        let posts = mock.submit_builder_preferences_calls();
        posts.iter().map(|post| post.iter().map(|e| e.url.clone()).collect()).collect()
    }

    /// Harper B1 and RSA B3: the step waits for the proposer duties of E.
    /// The epoch E is Gloas, and the local key proposes at slot 5 of E and
    /// E+1. The first two proposer requests for E answer 503. Thus
    /// ReorgCheck caches only E+1, and DutyFetch fails for E.
    ///
    /// - The first pass must be `NotReady`, and it must send no POST.
    /// - The next pass must fetch E and send the preferences of E and E+1.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_wait_for_the_proposer_duties_of_e() {
        use BoundaryStep::ProposerPreferences;
        let epoch = create_test_fork_schedule().gloas_fork_epoch;
        let first = epoch * SLOTS_PER_EPOCH;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let plan = FailPlan::default();
        plan.lock().insert(epoch, 2);
        let f = fixture_seeded(proposals_failing(local_hex, epoch, plan), local, true, &[]).await;

        f.runner.run_pending(first).await;

        assert_eq!(
            f.mock.get_proposer_duties_calls(),
            [epoch, epoch + 1, epoch],
            "ReorgCheck must request E and E+1, and DutyFetch must request E only."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::NotReady), false),
            "With E uncached, the step must not be ready and must stay pending."
        );
        assert_eq!(
            arrivals(&f.mock, MockMethod::SubmitProposerPreferences),
            0,
            "With E uncached, the step must not send a POST."
        );

        f.runner.run_pending(first + 1).await;

        assert_eq!(
            preference_slots(&f.mock),
            [vec![first + 5, first + SLOTS_PER_EPOCH + 5]],
            "The next pass must send the preferences of E and E+1."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Done), true),
            "The accepted POST must finish the step."
        );
    }

    /// Harper B2 and RSA B4: a failed proposer POST does not stop the
    /// builder broadcast of the same pass. The epoch is Gloas-1, and the
    /// local key has one builder URL. The first proposer POST answers 503.
    ///
    /// 1. The builder POST answers 200. The step must be `Failed` and
    ///    pending. The retry must send the proposer entry again. It must
    ///    not send or sign the builder entry again.
    /// 2. The first builder POST answers 500. The runner must report the
    ///    error of the proposer POST.
    #[tokio::test(flavor = "current_thread")]
    async fn a_proposer_failure_still_sends_the_builder_preferences() {
        use BoundaryStep::ProposerPreferences;
        let first = gloas_minus_one_slot();
        let epoch = first / SLOTS_PER_EPOCH;
        let proposal = (epoch + 1) * SLOTS_PER_EPOCH + 5;
        for (arm, builder_failures) in [("builder POST accepted", 0), ("builder POST fails", 1)] {
            let local = SecretKey::generate();
            let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
            let (proposer_fails, builder_fails) = (fails_first(1), fails_first(builder_failures));
            let mock = proposals_from(local_hex, epoch + 1)
                .with_submit_proposer_preferences(move |_preferences| {
                    if proposer_fails() {
                        return Err(unavailable());
                    }
                    Ok(())
                })
                .with_submit_builder_preferences(move |_entries| {
                    if builder_fails() {
                        let message = "builder down".to_string();
                        return Err(beacon::BeaconError::ApiError { status: 500, message });
                    }
                    Ok(beacon::SubmitBuilderPreferencesResult::Success)
                });
            let f = fixture_seeded(mock, local, true, &[]).await;
            f.validator_store
                .set_global_builders(vec![BUILDER_URL.to_string()])
                .expect("The builder URL must be valid.");
            let warns = Warns::default();
            let _default = warns.install();

            f.runner.run_pending(first).await;

            assert_eq!(
                builder_preference_slots(&f.mock),
                [vec![proposal]],
                "{arm}: The pass must send the builder entry after the failed proposer POST."
            );
            assert_eq!(
                step_state(&f.runner, ProposerPreferences),
                (Some(StepOutcome::Failed), false),
                "{arm}: The proposer POST failed, so the step must be failed and pending."
            );
            if builder_failures == 1 {
                let failed = "Epoch preferences broadcast failed";
                let reported: Vec<String> =
                    warns.lines().into_iter().filter(|line| line.starts_with(failed)).collect();
                let proposer_error = "Beacon node returned error: 503 - unavailable";
                assert_eq!(
                    reported,
                    [format!("{failed} epoch={epoch} error=beacon node error: {proposer_error}")],
                    "{arm}: The runner must report the error of the proposer POST."
                );
                continue;
            }

            f.runner.run_pending(first + 1).await;

            assert_eq!(
                preference_slots(&f.mock),
                [vec![proposal], vec![proposal]],
                "{arm}: The retry must send the proposer entry again."
            );
            assert_eq!(
                arrivals(&f.mock, MockMethod::SubmitBuilderPreferences),
                1,
                "{arm}: The retry must not send the builder entry again."
            );
            assert_eq!(
                f.registrations.auth_calls(),
                1,
                "{arm}: The retry must not sign the builder entry again."
            );
            assert_eq!(
                step_state(&f.runner, ProposerPreferences),
                (Some(StepOutcome::Done), true),
                "{arm}: The accepted proposer POST must finish the step."
            );
        }
    }

    /// RSA B1: a rejected builder entry keeps the step pending. The epoch is
    /// Gloas-1, and the local key has two builder URLs. The first builder
    /// POST answers 200, but it rejects the entry at index 1.
    ///
    /// - The first pass must leave the step `Failed` and pending.
    /// - The retry must send only the rejected entry.
    /// - The accepted retry must finish the step.
    #[tokio::test(flavor = "current_thread")]
    async fn a_rejected_builder_entry_keeps_the_step_pending() {
        use BoundaryStep::ProposerPreferences;
        let first = gloas_minus_one_slot();
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let rejects = fails_first(1);
        let mock = proposals_from(local_hex, first / SLOTS_PER_EPOCH + 1)
            .with_submit_builder_preferences(move |_entries| {
                if !rejects() {
                    return Ok(beacon::SubmitBuilderPreferencesResult::Success);
                }
                let message = "The builder rejects the entry.".to_string();
                let failures = vec![bn_manager::IndexedFailure { index: 1, message }];
                Ok(beacon::SubmitBuilderPreferencesResult::PartialFailure { failures })
            });
        let f = fixture_seeded(mock, local, true, &[]).await;
        let urls = vec![BUILDER_URL.to_string(), SECOND_BUILDER_URL.to_string()];
        f.validator_store.set_global_builders(urls.clone()).expect("The URLs must be valid.");

        f.runner.run_pending(first).await;

        assert_eq!(
            builder_preference_urls(&f.mock),
            std::slice::from_ref(&urls),
            "The first builder POST must carry the two entries."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Failed), false),
            "The beacon node rejected an entry, so the step must be failed and pending."
        );

        f.runner.run_pending(first + 1).await;

        assert_eq!(
            builder_preference_urls(&f.mock),
            [urls.clone(), vec![urls[1].clone()]],
            "The retry must send only the rejected entry."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Done), true),
            "The accepted retry must finish the step."
        );
    }

    /// RSA B2: a preferences signature error keeps the step pending. The
    /// epoch E is Gloas, and the local key proposes at slot 5 of E and E+1.
    /// The signer refuses the first signatures of the first pass:
    ///
    /// 1. Every signature fails, so the first pass sends no POST.
    /// 2. The first of the two signatures fails, so the first pass sends
    ///    the E+1 entry only.
    ///
    /// In each arm, the step must be `Failed` and pending after the first
    /// pass. The retry must sign and send only the unsigned entries, and it
    /// must finish the step.
    #[tokio::test(flavor = "current_thread")]
    async fn a_preferences_signature_error_keeps_the_step_pending() {
        use BoundaryStep::ProposerPreferences;
        let epoch = create_test_fork_schedule().gloas_fork_epoch;
        let first = epoch * SLOTS_PER_EPOCH;
        let (own, next) = (first + 5, first + SLOTS_PER_EPOCH + 5);
        let arms = [
            ("every signature fails", 2, vec![], vec![vec![own, next]]),
            ("the first signature fails", 1, vec![vec![next]], vec![vec![next], vec![own]]),
        ];
        for (arm, failures, after_first, after_retry) in arms {
            let local = SecretKey::generate();
            let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
            let f = fixture_seeded(proposals_from(local_hex, epoch), local, true, &[]).await;
            f.registrations.fail_preferences(failures);

            f.runner.run_pending(first).await;

            assert_eq!(
                preference_slots(&f.mock),
                after_first,
                "{arm}: The first pass must send only the signed entries."
            );
            assert_eq!(
                step_state(&f.runner, ProposerPreferences),
                (Some(StepOutcome::Failed), false),
                "{arm}: A signature failed, so the step must be failed and pending."
            );

            f.runner.run_pending(first + 1).await;

            assert_eq!(
                preference_slots(&f.mock),
                after_retry,
                "{arm}: The retry must send only the unsigned entries."
            );
            assert_eq!(
                f.registrations.preferences_calls(),
                2 + failures,
                "{arm}: The retry must sign only the unsigned entries."
            );
            assert_eq!(
                step_state(&f.runner, ProposerPreferences),
                (Some(StepOutcome::Done), true),
                "{arm}: The accepted retry must finish the step."
            );
        }
    }

    // --- W4-E6b2: one admission for each preferences attempt ---

    /// The step needs an admitted node before it signs. The epoch is
    /// Gloas-1, and the local key proposes at slot 5 of Gloas.
    ///
    /// With no admitted node, the test requires these results:
    ///
    /// - The step has the `Failed` state and remains pending.
    /// - The pass emits one warning.
    /// - The step signs no preference.
    /// - The step sends no preference.
    ///
    /// The fixture restores admission. The next pass must send the
    /// preference and finish the step.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_without_admission_fail_and_retry() {
        use BoundaryStep::ProposerPreferences;
        let first = gloas_minus_one_slot();
        let next = first / SLOTS_PER_EPOCH + 1;
        let proposal = next * SLOTS_PER_EPOCH + 5;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let f = fixture_seeded(proposals_from(local_hex, next), local, true, &[]).await;
        f.admission.closed.store(true, Ordering::Release);
        let warns = Warns::default();
        let _default = warns.install();

        f.runner.run_pending(first).await;

        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Failed), false),
            "With no admitted node, the step must be failed and pending."
        );
        assert_eq!(
            warns.lines(),
            ["skipping builder preference sign: beacon node admission revoked"],
            "The pass must give one warn, for the missing admission."
        );
        assert_eq!(
            f.registrations.preferences_calls(),
            0,
            "The step must not sign a preference with no admission."
        );
        assert_eq!(
            arrivals(&f.mock, MockMethod::SubmitProposerPreferences),
            0,
            "The step must not send a preference with no admission."
        );

        f.admission.closed.store(false, Ordering::Release);
        f.runner.run_pending(first + 1).await;

        assert_eq!(
            preference_slots(&f.mock),
            [vec![proposal]],
            "The next pass must send the preference of slot {proposal}."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Done), true),
            "The accepted POST must finish the step."
        );
    }

    /// This layer moves `generation` from 0 to 1, as a beacon node
    /// revocation does. It does this when the first span with the name
    /// `name` closes. When `slot` is set, only a span with that `slot` field
    /// counts.
    struct RevokeOnClose {
        name: &'static str,
        slot: Option<Slot>,
        generation: Arc<std::sync::atomic::AtomicU64>,
        span: Arc<parking_lot::Mutex<Option<tracing::span::Id>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RevokeOnClose {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut slot = SlotField(None);
            attrs.record(&mut slot);
            let wanted = attrs.metadata().name() == self.name
                && self.slot.is_none_or(|want| slot.0 == Some(want));
            if wanted && self.generation.load(Ordering::Acquire) == 0 {
                self.span.lock().get_or_insert_with(|| id.clone());
            }
        }

        fn on_close(&self, id: tracing::span::Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            if self.span.lock().take_if(|span| *span == id).is_some() {
                self.generation.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    /// This function returns the `Epoch preferences broadcast failed`
    /// warnings that `warns` holds.
    fn broadcast_failures(warns: &Warns) -> Vec<String> {
        let failed = "Epoch preferences broadcast failed";
        warns.lines().into_iter().filter(|line| line.starts_with(failed)).collect()
    }

    /// Harper B1 and RSA B1: the step takes its admission before it reads
    /// the duties. The epoch E is Gloas-1, and the local key proposes at
    /// slot 5 of E+1. The generation moves when the last proposer-duty read
    /// of the step closes. This occurs before `upcoming_proposals` returns.
    /// Thus the admission and the duties are both older than the
    /// revocation. If the step reads the duties first, its admission is
    /// newer than the duties.
    ///
    /// The first pass must give these results:
    ///
    /// - The signer refuses the one preference signature.
    /// - The step sends no preference.
    /// - The step has the `Failed` state and remains pending.
    ///
    /// The next pass must fetch the proposer duties of E and E+1 again. It
    /// must sign and send the preference under a new admission, and it must
    /// finish the step.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_revoked_after_the_duty_read_are_not_signed() {
        use BoundaryStep::ProposerPreferences;
        let first = gloas_minus_one_slot();
        let epoch = first / SLOTS_PER_EPOCH;
        let proposal = (epoch + 1) * SLOTS_PER_EPOCH + 5;
        let last_read = (epoch + 2) * SLOTS_PER_EPOCH - 1;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let f = fixture_seeded(proposals_from(local_hex, epoch + 1), local, true, &[]).await;
        let generation = f.mock.track_admission();
        let (name, slot) = ("duty_tracker.get_proposer_duty", Some(last_read));
        let revoke =
            RevokeOnClose { name, slot, generation: Arc::clone(&generation), span: Arc::default() };
        let warns = Warns::default();
        let subscriber = tracing_subscriber::registry().with(warns.clone()).with(revoke);
        let _default = tracing::subscriber::set_default(subscriber);

        f.runner.run_pending(first).await;

        assert_eq!(
            generation.load(Ordering::Acquire),
            1,
            "The generation must move one time, after the read of slot {last_read}."
        );
        assert_eq!(
            arrivals(&f.mock, MockMethod::SubmitProposerPreferences),
            0,
            "The step must not send a preference after the revocation."
        );
        assert_eq!(
            broadcast_failures(&warns),
            [format!(
                "Epoch preferences broadcast failed epoch={epoch} \
                 error=1 of 1 proposer preferences signatures failed"
            )],
            "The signer must refuse the preference signature after the revocation."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Failed), false),
            "After the revocation, the step must be failed and pending."
        );

        let fetched = f.mock.get_proposer_duties_calls().len();
        f.runner.run_pending(first + 1).await;

        assert_eq!(
            f.mock.get_proposer_duties_calls()[fetched..],
            [epoch, epoch + 1],
            "The next pass must fetch the proposer duties of E and E+1 again."
        );
        assert_eq!(
            preference_slots(&f.mock),
            [vec![proposal]],
            "The next pass must sign and send the preference under a new admission."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Done), true),
            "The accepted POST must finish the step."
        );
        assert_eq!(generation.load(Ordering::Acquire), 1, "The next pass must not revoke.");
    }

    /// Harper B2: the proposer half and the builder half of an attempt sign
    /// under one admission. The epoch E is Gloas-1. The local key proposes
    /// at slot 5 of E+1, and it has one builder URL. The generation moves
    /// when the first proposer-preferences signature closes.
    ///
    /// The pass must give these results:
    ///
    /// - The proposer POST holds only the preference that the step signed
    ///   before the revocation.
    /// - The signer refuses the one builder auth signature.
    /// - The step sends no builder entry.
    /// - The step has the `Failed` state and remains pending.
    #[tokio::test(flavor = "current_thread")]
    async fn preferences_revoked_after_the_first_signature_sign_no_builder_auth() {
        use BoundaryStep::ProposerPreferences;
        let first = gloas_minus_one_slot();
        let epoch = first / SLOTS_PER_EPOCH;
        let proposal = (epoch + 1) * SLOTS_PER_EPOCH + 5;
        let local = SecretKey::generate();
        let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
        let mock =
            proposals_from(local_hex, epoch + 1).with_submit_builder_preferences(|_entries| {
                Ok(beacon::SubmitBuilderPreferencesResult::Success)
            });
        let f = fixture_seeded(mock, local, true, &[]).await;
        f.validator_store
            .set_global_builders(vec![BUILDER_URL.to_string()])
            .expect("The builder URL must be valid.");
        let generation = f.mock.track_admission();
        let (name, slot) = ("sign.proposer_preferences", None);
        let revoke =
            RevokeOnClose { name, slot, generation: Arc::clone(&generation), span: Arc::default() };
        let warns = Warns::default();
        let subscriber = tracing_subscriber::registry().with(warns.clone()).with(revoke);
        let _default = tracing::subscriber::set_default(subscriber);

        f.runner.run_pending(first).await;

        assert_eq!(
            generation.load(Ordering::Acquire),
            1,
            "The generation must move one time, after the first preference signature."
        );
        assert_eq!(
            preference_slots(&f.mock),
            [vec![proposal]],
            "The proposer POST must hold only the preference signed before the revocation."
        );
        assert_eq!(
            arrivals(&f.mock, MockMethod::SubmitBuilderPreferences),
            0,
            "The builder half must not send an auth signed after the revocation."
        );
        assert_eq!(
            broadcast_failures(&warns),
            [format!(
                "Epoch preferences broadcast failed epoch={epoch} \
                 error=1 of 1 builder request auth signatures failed"
            )],
            "The signer must refuse the auth signature after the revocation."
        );
        assert_eq!(
            step_state(&f.runner, ProposerPreferences),
            (Some(StepOutcome::Failed), false),
            "After the revocation, the step must be failed and pending."
        );
    }

    /// Harper B1 (#1043 R1): the generation moves after the read of slot 33
    /// in the subscription step. Slot 33 is the duty slot of E. The call for
    /// E reads its duty before the move, and the call for E+1 starts after
    /// the move. The step must send no subscription, and it must stay
    /// pending. The next pass must send the subscriptions of E and E+1, and
    /// it must finish the step.
    #[tokio::test(flavor = "current_thread")]
    async fn a_revocation_during_the_subscription_step_keeps_it_pending() {
        use BoundaryStep::CommitteeSubscriptions;
        let f = fixture(proposer_duties_at(ROOT_A)).await;
        let generation = f.mock.track_admission();
        let (name, slot) = ("duty_tracker.get_duties_for_slot", Some(33));
        let revoke =
            RevokeOnClose { name, slot, generation: Arc::clone(&generation), span: Arc::default() };
        let _default =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(revoke));

        f.runner.run_pending(32).await;

        assert_eq!(
            generation.load(Ordering::Acquire),
            1,
            "The generation must move one time, after the read of slot 33."
        );
        assert!(
            f.subscription_slots.lock().is_empty(),
            "The step must send no subscription for the duties read before the move."
        );
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::Failed), false),
            "After the revocation, the subscription step must be failed and pending."
        );

        f.runner.run_pending(33).await;

        assert_eq!(
            *f.subscription_slots.lock(),
            slots(&[&["33"], &["65"]]),
            "The next pass must send the subscriptions of E and E+1."
        );
        assert_eq!(
            step_state(&f.runner, CommitteeSubscriptions),
            (Some(StepOutcome::Done), true),
            "The accepted POSTs must finish the step."
        );
    }
}
