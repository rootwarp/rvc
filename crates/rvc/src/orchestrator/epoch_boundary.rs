//! Epoch boundary runner: the boundary steps, one method each, in a fixed order.
//!
//! [`EpochBoundaryRunner::run_pending`] runs every step of the slot's epoch
//! that is still pending, in [`BoundaryStep`] order, and marks each step done
//! after one attempt, with two exceptions. `DutyFetch` has no done mark: it
//! runs in every pass while a step that needs duties is pending.
//! `CommitteeSubscriptions` stays pending until the attester duties of E and
//! E+1 are cached. The epoch summary is logged once per epoch, at the end of
//! the epoch's first pass. [`EpochBoundaryTask::run`] calls it on its own
//! task ([`TASK_NAME`]) after each slot the slot loop processed, while that
//! slot's epoch has a step pending. Each pass is a root `epoch.boundary` span.
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
//! The progress mutex is taken only between steps and is never held across
//! an `.await`, so `run_pending(&self)` can run inside a future that borrows
//! the runner shared, and a pass dropped mid-step leaves it unlocked. A step
//! is marked done only after it returns. Outside tests, only
//! [`EpochBoundaryTask::run`] calls `run_pending`, and it awaits or drops
//! each pass before the next wake, so one pass runs at a time.

use std::collections::BTreeSet;
use std::sync::Arc;

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
use super::duty_management::DutyManagementService;
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

/// Steps already run in `epoch`.
pub(crate) struct EpochProgress {
    epoch: u64,
    done: BTreeSet<BoundaryStep>,
}

impl EpochProgress {
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
}

/// Runs the epoch-boundary steps once per epoch.
pub(crate) struct EpochBoundaryRunner {
    duty_management: Arc<DutyManagementService>,
    circuit_breaker: Arc<CircuitBreakerState>,
    preferences: Arc<PreferenceBroadcaster>,
    duty_tracker: Arc<DutyTracker>,
    timeouts: OperationTimeouts,
    progress: parking_lot::Mutex<Option<EpochProgress>>,
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
            progress: parking_lot::Mutex::new(None),
        }
    }

    /// Runs the pending steps of `slot`'s epoch, in order.
    ///
    /// A slot past the progress epoch starts a new epoch. A slot before it
    /// runs nothing.
    pub(crate) async fn run_pending(&self, slot: Slot) {
        let epoch = slot / SLOTS_PER_EPOCH;
        let first_pass = self.progress.lock().as_ref().is_none_or(|p| p.epoch < epoch);
        for step in BoundaryStep::ALL {
            if !self.is_pending(epoch, step) {
                continue;
            }
            let done = match step {
                BoundaryStep::BreakerReset => {
                    self.breaker_reset(epoch);
                    true
                }
                BoundaryStep::ReorgCheck => {
                    self.reorg_check(epoch).await;
                    true
                }
                BoundaryStep::DutyFetch => {
                    let cached = self.duty_fetch(epoch).await;
                    debug!(epoch, cached, "Epoch boundary duty fetch finished");
                    // No done mark: `EpochProgress::is_pending` derives DutyFetch's state.
                    false
                }
                BoundaryStep::PrepareProposers => {
                    self.prepare_proposers(epoch).await;
                    true
                }
                BoundaryStep::CommitteeSubscriptions => self.committee_subscriptions(epoch).await,
            };
            if done {
                self.mark_done(epoch, step);
            }
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

    fn is_pending(&self, epoch: u64, step: BoundaryStep) -> bool {
        let mut progress = self.progress.lock();
        let current =
            progress.get_or_insert_with(|| EpochProgress { epoch, done: BTreeSet::new() });
        if epoch > current.epoch {
            *current = EpochProgress { epoch, done: BTreeSet::new() };
        }
        current.epoch == epoch && current.is_pending(step)
    }

    fn mark_done(&self, epoch: u64, step: BoundaryStep) {
        if let Some(current) = self.progress.lock().as_mut().filter(|p| p.epoch == epoch) {
            current.done.insert(step);
        }
    }

    fn breaker_reset(&self, epoch: u64) {
        self.circuit_breaker.reset_epoch(epoch);
        publish_circuit_breaker_metrics(&self.circuit_breaker);
        info!(epoch, "Circuit breaker reset at epoch boundary");
    }

    async fn reorg_check(&self, epoch: u64) {
        if self.duty_management.check_reorg_at_epoch_boundary(epoch).await {
            self.preferences.on_proposer_dependent_root_changed(epoch).await;
        }
    }

    /// Fetches the E and E+1 attester and proposer duties that are not
    /// cached, under one `timeouts.duty_fetch` bound for the whole step.
    ///
    /// Calls the tracker directly. Eviction, PTC duties and the next-period
    /// sync prefetch stay with the slot loop's warm-up. A failed fetch does
    /// not stop the next one. Returns whether all four entries are cached.
    async fn duty_fetch(&self, epoch: u64) -> bool {
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
                return false;
            }
        }
        true
    }

    async fn prepare_proposers(&self, epoch: u64) {
        self.duty_management.prepare_proposers(epoch).await;
    }

    /// Sends the E and E+1 subscriptions once both epochs' attester duties
    /// are cached. `false` leaves the step pending for the next wake.
    async fn committee_subscriptions(&self, epoch: u64) -> bool {
        for duty_epoch in [epoch, epoch + 1] {
            if !self.duty_tracker.is_epoch_cached(duty_epoch).await {
                debug!(epoch, duty_epoch, "Committee subscriptions wait for cached duties");
                return false;
            }
        }
        self.duty_management.submit_committee_subscriptions(epoch).await;
        self.duty_management.submit_committee_subscriptions(epoch + 1).await;
        true
    }
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
        DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorHandle,
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
        /// The tracker's index source: the production one, over the fixture's
        /// pubkey map and index registry.
        index_source: Arc<PubkeyIndexSource>,
    }

    impl Fixture {
        /// Resolves a new local key to `index` with no cache clear, as the
        /// index resolver does mid-epoch. Every cached attester epoch stays
        /// present, under an index snapshot that is now stale.
        fn resolve_new_key(&self, index: &str) {
            let pubkey = SecretKey::generate().public_key();
            let pk_bytes = pubkey.to_bytes();
            self.index_source.pubkey_map.write().insert(pk_bytes, pubkey);
            self.index_source.registry.write().insert(pk_bytes, index.to_string());
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

    /// Local validator 42 with an attester duty at slot 1 of every epoch;
    /// epochs 1 and 2 are seeded through `fetch_duties_for_epoch`.
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
        let mock = Arc::new(
            mock.with_get_attester_duties(move |epoch, _indices| {
                if take_failure(&failing, epoch) {
                    return Err(unavailable());
                }
                Ok(beacon::DependentRootResponse {
                    dependent_root: ROOT_A.to_string(),
                    execution_optimistic: false,
                    data: vec![beacon::AttesterDuty {
                        pubkey: pk_hex.clone(),
                        validator_index: "42".to_string(),
                        committee_index: "1".to_string(),
                        committee_length: "8".to_string(),
                        committees_at_slot: "4".to_string(),
                        validator_committee_index: "0".to_string(),
                        slot: (epoch * SLOTS_PER_EPOCH + 1).to_string(),
                    }],
                })
            })
            .with_prepare_beacon_proposer(|_preparations| Ok(()))
            .with_submit_beacon_committee_subscriptions(move |subscriptions| {
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
        assert!(f.runner.duty_fetch(1).await, "all four entries are cached");
        assert_eq!(f.mock.call_stamps().len(), calls, "a cache read, no beacon node call");
        failing_proposer.lock().insert(3, 1);
        assert!(!f.runner.duty_fetch(2).await, "E+1's proposer duties are still uncached");

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

    /// A hung beacon node does not hold the runner: the pass returns when
    /// DutyFetch's `timeouts.duty_fetch` bound fires, with the subscription
    /// step pending, and the next wake retries under the same bound.
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
        assert!(f.subscription_slots.lock().is_empty());
        assert!(f.runner.has_pending(33), "the subscription step stays pending");

        let start = tokio::time::Instant::now();
        f.runner.run_pending(33).await;
        assert_eq!(start.elapsed(), duty_fetch, "the next wake retries under the same bound");
        assert_eq!(attester_stamps().len(), 4);
        assert!(f.subscription_slots.lock().is_empty());
        assert!(f.runner.has_pending(34));
    }

    /// The one `timeouts.duty_fetch` bound covers the proposer fetches too.
    /// With the attester duties cached and every proposer request hung, the
    /// step ends at the bound after its first proposer request, and the
    /// steps after it still run in the same pass.
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
}
