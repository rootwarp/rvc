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
//! and sends again only once more keys have one. `CommitteeSubscriptions` is
//! `NotReady` until the attester duties of E and E+1 are cached. Each step
//! with beacon-node work runs under its own bound,
//! `timeouts.duty_fetch` for ReorgCheck, DutyFetch and CommitteeSubscriptions
//! and `timeouts.preparation` for PrepareProposers: a step that reaches it is
//! dropped and `Failed`. The first pass of a later epoch logs one warn for
//! the steps the old epoch did not finish, with each one's last outcome. The
//! epoch summary is logged once per epoch, at the end of the epoch's first
//! pass. [`EpochBoundaryTask::run`] calls it on its own task ([`TASK_NAME`])
//! after each slot the slot loop processed, while that slot's epoch has a
//! step pending. Each pass is a root `epoch.boundary` span.
//!
//! # Step order
//!
//! The final order. Later issues insert their steps at the reserved
//! positions and do not reorder the existing ones:
//!
//! 1. `BreakerReset`
//! 2. `ReorgCheck` (re-broadcasts preferences on a proposer root change)
//! 3. `DutyFetch` (the uncached E and E+1 attester and proposer duties,
//!    bounded by `timeouts.duty_fetch`; never waits on the slot loop's warm-up)
//! 4. `PrepareProposers`
//! 5. `CommitteeSubscriptions` (epoch E, then E+1)
//! 6. `SyncCommitteeSubscriptions` (reserved, W4-E9b)
//! 7. `BuilderRegistration` (reserved, W4-E4b boot epoch, W4-E6a every epoch)
//! 8. `ProposerPreferences` (reserved, W4-E6a interim, W4-E6b1)
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
use builder::{BuilderService, UpcomingProposal};
use duty_tracker::DutyTracker;
use eth_types::{Root, Slot};
use signer::CircuitBreakerState;
use timing::SLOTS_PER_EPOCH;
use tokio::sync::watch;
use tracing::{debug, info, info_span, warn, Instrument};
use validator_store::ValidatorStore;

use super::block_proposal::publish_circuit_breaker_metrics;
use super::coordinator::PubkeyMap;
use super::duty_management::{DutyManagementService, PrepareOutcome, SelectionProofs};
use super::utils;

/// Executor task name. The runner's loop span has the same name.
pub const TASK_NAME: &str = "epoch.boundary.runner";

/// The runner on its own task, woken by each slot the slot loop processed.
pub struct EpochBoundaryTask {
    runner: Arc<EpochBoundaryRunner>,
    slots: watch::Receiver<Option<Slot>>,
    shutdown: watch::Receiver<bool>,
}

impl EpochBoundaryTask {
    pub(crate) fn new(
        runner: Arc<EpochBoundaryRunner>,
        slots: watch::Receiver<Option<Slot>>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        runner.follow(slots.clone());
        Self { runner, slots, shutdown }
    }

    /// Runs the pending steps at each processed slot until shutdown.
    ///
    /// Returns when the shutdown watch reads `true` or loses its sender, or
    /// when the processed-slot sender is dropped (the slot loop is gone). A
    /// wake reads the latest slot, so wakes during a pass coalesce. A pass in
    /// flight is raced against shutdown and dropped when shutdown wins; the
    /// step it was in stays pending. Shutdown wins ties in both waits.
    pub async fn run(mut self) {
        let loop_span = info_span!(parent: None, "epoch.boundary.runner");
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
}

impl BoundaryStep {
    const ALL: [Self; 5] = [
        Self::BreakerReset,
        Self::ReorgCheck,
        Self::DutyFetch,
        Self::PrepareProposers,
        Self::CommitteeSubscriptions,
    ];

    /// Reads E and E+1 duties from the cache, so DutyFetch runs before it.
    fn needs_duties(self) -> bool {
        matches!(self, Self::CommitteeSubscriptions)
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
    /// The keys with a validator index when the last `Partial` prepare POST
    /// went out.
    prepared_count: Option<usize>,
}

impl EpochProgress {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            done: BTreeSet::new(),
            last_outcome: BTreeMap::new(),
            subscribed: BTreeSet::new(),
            prepared_count: None,
        }
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
    preferences: Arc<PreferenceBroadcaster>,
    duty_tracker: Arc<DutyTracker>,
    timeouts: OperationTimeouts,
    /// A proposer root change whose preferences are not broadcast yet. The
    /// reorg check sets it when it caches the change, and it is cleared once
    /// the broadcast returns, so an attempt cut in between leaves it to the
    /// next one, in this epoch or a later one.
    preferences_owed: AtomicBool,
    progress: parking_lot::Mutex<Option<EpochProgress>>,
    /// The selection proofs the subscription step signed in the progress
    /// epoch, kept across its attempts.
    selection_proofs: SelectionProofs,
    /// The processed slots of the task that runs the passes.
    processed: parking_lot::Mutex<Option<watch::Receiver<Option<Slot>>>>,
}

impl EpochBoundaryRunner {
    pub(crate) fn new(
        duty_management: Arc<DutyManagementService>,
        circuit_breaker: Arc<CircuitBreakerState>,
        preferences: Arc<PreferenceBroadcaster>,
        duty_tracker: Arc<DutyTracker>,
        timeouts: OperationTimeouts,
    ) -> Self {
        Self {
            duty_management,
            circuit_breaker,
            preferences,
            duty_tracker,
            timeouts,
            preferences_owed: AtomicBool::new(false),
            progress: parking_lot::Mutex::new(None),
            selection_proofs: SelectionProofs::default(),
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
        let epoch = slot / SLOTS_PER_EPOCH;
        let first_pass = self.begin_epoch(epoch);
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
            };
            self.record(epoch, step, outcome);
        }
        if first_pass {
            self.duty_management.log_epoch_boundary_summary(epoch, slot).await;
        }
    }

    /// Whether a step of `slot`'s epoch is still pending.
    ///
    /// An epoch before the progress epoch has nothing pending.
    pub(crate) fn has_pending(&self, slot: Slot) -> bool {
        let epoch = slot / SLOTS_PER_EPOCH;
        match self.progress.lock().as_ref() {
            Some(current) if current.epoch > epoch => false,
            Some(current) if current.epoch == epoch => {
                BoundaryStep::ALL.into_iter().any(|step| current.is_pending(step))
            }
            _ => true,
        }
    }

    /// Moves the progress to `epoch` when that is later, and warns once for
    /// the steps the old epoch did not finish. `true` when it moved.
    fn begin_epoch(&self, epoch: u64) -> bool {
        let mut progress = self.progress.lock();
        if progress.as_ref().is_some_and(|current| current.epoch >= epoch) {
            return false;
        }
        let old = progress.replace(EpochProgress::new(epoch));
        drop(progress);
        self.selection_proofs.lock().clear();
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

    /// Re-broadcasts preferences after a proposer root change. One that an
    /// earlier attempt cached before its bound cut it goes first, before
    /// this check's requests. `Done` once it returns. Its fetch errors are
    /// logged; whether the duties are cached is DutyFetch's concern.
    async fn reorg_check(&self, epoch: u64) -> StepOutcome {
        self.broadcast_owed_preferences(epoch).await;
        let owed = &self.preferences_owed;
        self.duty_management.check_reorg_at_epoch_boundary(epoch, owed).await;
        self.broadcast_owed_preferences(epoch).await;
        StepOutcome::Done
    }

    /// Broadcasts the preferences a root change owes, if any.
    async fn broadcast_owed_preferences(&self, epoch: u64) {
        if self.preferences_owed.load(Ordering::Acquire) {
            self.preferences.on_proposer_dependent_root_changed(epoch).await;
            self.preferences_owed.store(false, Ordering::Release);
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
    /// index. After a `Partial` POST the step reads the registry and sends
    /// again only when more keys have an index. The count is read before the
    /// POST is built, so an index that lands after the read is sent at the
    /// next pass, whether or not that POST had it.
    async fn prepare_proposers(&self, epoch: u64) -> StepOutcome {
        let resolved = self.duty_management.resolved_proposer_count();
        if self.prepared_count(epoch) == Some(resolved) {
            debug!(epoch, resolved, "Proposer preparations wait for more validator indices");
            return StepOutcome::NotReady;
        }
        match self.duty_management.prepare_proposers(epoch).await {
            Ok(PrepareOutcome::Complete) => StepOutcome::Done,
            Ok(PrepareOutcome::Partial { unresolved }) => {
                debug!(
                    epoch,
                    resolved, unresolved, "Proposer preparations sent for part of the keys"
                );
                self.set_prepared_count(epoch, resolved);
                StepOutcome::NotReady
            }
            Ok(PrepareOutcome::NoIndices) => StepOutcome::NotReady,
            Err(_) => StepOutcome::Failed,
        }
    }

    /// The `prepared_count` of `epoch`.
    fn prepared_count(&self, epoch: u64) -> Option<usize> {
        let progress = self.progress.lock();
        progress.as_ref().filter(|p| p.epoch == epoch).and_then(|p| p.prepared_count)
    }

    fn set_prepared_count(&self, epoch: u64, resolved: usize) {
        if let Some(current) = self.progress.lock().as_mut().filter(|p| p.epoch == epoch) {
            current.prepared_count = Some(resolved);
        }
    }

    /// `NotReady` until the attester duties of E and E+1 are cached; then
    /// sends the subscriptions of E, then E+1, that did not go out yet in
    /// this epoch. `Failed` while one of them did not: a failed or timed-out
    /// POST.
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
            let proofs = &self.selection_proofs;
            let post = self.duty_management.submit_committee_subscriptions_with(duty_epoch, proofs);
            if post.await.is_ok() {
                self.mark_subscribed(epoch, duty_epoch);
            } else {
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

/// Picks local proposals and broadcasts proposer and builder preferences for them.
///
/// One instance is shared by the runner's ReorgCheck and the slot-0 builder
/// block. They run on different tasks, so two broadcasts can overlap. The
/// broadcaster holds no mutable state; two overlapping broadcasts may each
/// sign the same `(pubkey, slot)` once, and a duplicate POST is harmless.
pub(crate) struct PreferenceBroadcaster {
    builder_service: Option<Arc<BuilderService>>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    validator_store: Arc<ValidatorStore>,
    genesis_validators_root: Root,
}

impl PreferenceBroadcaster {
    pub(crate) fn new(
        builder_service: Option<Arc<BuilderService>>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        validator_store: Arc<ValidatorStore>,
        genesis_validators_root: Root,
    ) -> Self {
        Self { builder_service, duty_tracker, pubkey_map, validator_store, genesis_validators_root }
    }

    /// Re-broadcast preferences after a proposer `dependent_root` change.
    ///
    /// Call when [`DutyTracker::cache_proposer_duties`] returns `true`.
    pub(crate) async fn on_proposer_dependent_root_changed(&self, current_epoch: u64) {
        self.broadcast_preferences(current_epoch).await;
    }

    pub(crate) async fn broadcast_preferences(&self, current_epoch: u64) {
        let Some(bs) = &self.builder_service else {
            return;
        };
        let proposals = self.upcoming_proposals(current_epoch).await;
        match bs
            .broadcast_proposer_preferences(
                current_epoch,
                &proposals,
                &self.genesis_validators_root,
            )
            .await
        {
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Proposer preferences broadcast failed (non-fatal)"),
        }
        match bs.broadcast_builder_preferences(current_epoch, &proposals).await {
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Builder preferences broadcast failed (non-fatal)"),
        }
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
        create_test_fork_schedule, fast_timeouts, m2_metric_lock, MockBlockBeacon, MockSubmitter,
        TEST_GENESIS_TIME,
    };
    use crate::orchestrator::{
        DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorError,
        OrchestratorHandle,
    };
    use crate::pubkey_index::{PubkeyIndexRegistry, PubkeyIndexSource};

    const ROOT_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROOT_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BREAKER_CONSECUTIVE_LIMIT: u32 = 3;

    struct Fixture {
        mock: Arc<MockBeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        breaker: Arc<CircuitBreakerState>,
        runner: Arc<EpochBoundaryRunner>,
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
    /// `with_builder` attaches a `BuilderService` over the same mock.
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
        validator_store.add_validator(ValidatorConfig::new(pk_bytes)).expect("add validator");

        let mut key_manager = KeyManager::new();
        key_manager.insert(local);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        let builder_service = with_builder.then(|| {
            let registration_signer: Arc<dyn ValidatorSigner> = signer.clone();
            let schedule = create_test_fork_schedule();
            Arc::new(BuilderService::new(
                Arc::new(registration_signer),
                Arc::new(beacon.clone()),
                Arc::clone(&validator_store),
                schedule.genesis_fork_version,
                schedule,
            ))
        });
        let timeouts = config.timeouts.clone();
        let preferences = Arc::new(PreferenceBroadcaster::new(
            builder_service,
            Arc::clone(&duty_tracker),
            Arc::clone(&pubkey_map),
            Arc::clone(&validator_store),
            config.genesis_validators_root,
        ));
        let duty_management = Arc::new(DutyManagementService::new(
            signer,
            beacon,
            Arc::clone(&duty_tracker),
            validator_store,
            pubkey_map,
            pubkey_index,
            config,
        ));
        let breaker = Arc::new(CircuitBreakerState::new(BREAKER_CONSECUTIVE_LIMIT, 5));
        let runner = Arc::new(EpochBoundaryRunner::new(
            duty_management,
            Arc::clone(&breaker),
            preferences,
            Arc::clone(&duty_tracker),
            timeouts,
        ));
        Fixture {
            mock,
            duty_tracker,
            breaker,
            runner,
            subscription_slots,
            failing_attester,
            failing_prepare,
            failing_subscriptions,
            index_source,
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

    /// A proposer root change seen by ReorgCheck re-broadcasts preferences
    /// inside the runner's own pass, before the subscription step. No
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
            assert_eq!(
                order,
                [
                    MockMethod::GetProposerDuties,
                    MockMethod::GetProposerDuties,
                    MockMethod::GetProposerDuties,
                    MockMethod::SubmitProposerPreferences,
                    MockMethod::SubmitBeaconCommitteeSubscriptions,
                    MockMethod::SubmitBeaconCommitteeSubscriptions,
                ],
                "seed, ReorgCheck E and E+1, re-broadcast, then subscriptions"
            );
        }
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
        let (slots, slots_rx) = watch::channel(None);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task = EpochBoundaryTask::new(Arc::clone(&f.runner), slots_rx, shutdown_rx);
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
        fn new(f: &Fixture) -> Self {
            let (slots, slots_rx) = watch::channel(None);
            let (shutdown, shutdown_rx) = watch::channel(false);
            let task = EpochBoundaryTask::new(Arc::clone(&f.runner), slots_rx, shutdown_rx);
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
            let mut runner = LocalRunner::new(&f);
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

        let mut runner = LocalRunner::new(&f);
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

    /// The step bounds, as source: `duty_fetch` for ReorgCheck and
    /// CommitteeSubscriptions, `preparation` for PrepareProposers, DutyFetch's
    /// inside the step, and none for BreakerReset (no I/O). PrepareProposers'
    /// bound has the length of its POST's own `preparation` bound but starts
    /// earlier: `the_prepare_step_bound_starts_before_the_map_read` sees it.
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
        assert_eq!(run.matches("bounded(").count(), 3, "three steps run under a bound: {run}");
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
        ] {
            assert!(run.contains(arm), "`run_pending` has the arm `{arm}`: {run}");
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
            ["epoch=2 abandoned_steps=[ReorgCheck, PrepareProposers, CommitteeSubscriptions] \
                 last_outcomes={}"],
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

        let kept: BTreeSet<Slot> =
            f.runner.selection_proofs.lock().keys().map(|(slot, _)| *slot).collect();
        assert_eq!(kept, BTreeSet::from([65, 97]), "epoch 2 keeps the proofs of epochs 2 and 3");
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

    /// RSA B1 / Harper B1: a proposer root change that ReorgCheck commits to
    /// the cache is broadcast even when the step bound cuts the check before
    /// it gets there. Root A is cached for E and the beacon node answers B,
    /// under the 2 s step bound. Passes run until ReorgCheck is done; the
    /// list is the preferences POSTs answered after each pass.
    /// - Cut after the change: E's request takes 1 s and E+1's is held, so
    ///   the bound cuts the check after it cached B. The retry broadcasts.
    /// - Retry cut too: the retry is cut the same way, and broadcasts before
    ///   its own check. The pass after it broadcasts nothing more.
    /// - Cut in the broadcast: the first preferences POST is held. The retry
    ///   broadcasts again.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_root_change_cut_before_its_broadcast_is_broadcast_on_retry() {
        use BoundaryStep::ReorgCheck;
        let epoch = create_test_fork_schedule().gloas_fork_epoch;
        let first = epoch * SLOTS_PER_EPOCH;
        let (zero, slow) = (Duration::ZERO, Duration::from_secs(1));
        // Proposer requests: the seed, ReorgCheck's E and E+1, DutyFetch's
        // E+1, then the retry's E and E+1.
        let arms = [
            ("cut after the change", vec![zero, slow, HOLD], vec![], vec![0, 1]),
            ("retry cut too", vec![zero, slow, HOLD, zero, slow, HOLD], vec![], vec![0, 1, 1]),
            ("cut in the broadcast", vec![], vec![HOLD], vec![0, 1]),
        ];
        for (arm, duties, preferences, want) in arms {
            let local = SecretKey::generate();
            let local_hex = format!("0x{}", hex::encode(local.public_key().to_bytes()));
            let mock = proposer_duties_then(local_hex, epoch, ROOT_A, ROOT_B)
                .with_call_delays(MockMethod::GetProposerDuties, duties)
                .with_call_delays(MockMethod::SubmitProposerPreferences, preferences);
            let seed = [epoch, epoch + 1];
            let f = fixture_config(mock, local, true, &seed, short_duty_fetch()).await;
            f.duty_tracker.fetch_proposer_duties(epoch).await.expect("seed root A");

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

    /// A root change the last pass of an epoch cached, cut before its
    /// broadcast, is broadcast by the next epoch's ReorgCheck. Root A is
    /// cached for E+1, where the local proposal is. At slot 31 of E the
    /// check caches B for E+1 after 1 s, and its E+1 PTC request is held, so
    /// the 2 s step bound cuts it. Epoch E+1's first pass broadcasts B.
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
}
