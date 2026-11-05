//! Epoch boundary runner: the boundary steps, one method each, in a fixed order.
//!
//! [`EpochBoundaryRunner::run_pending`] runs every step of the slot's epoch
//! that has not run yet, in [`BoundaryStep`] order, and marks each step done
//! after one attempt. The epoch summary is logged once per epoch, after the
//! last step. The slot loop calls it from the post-duty tail of slot 0 of
//! each epoch, under the `epoch.boundary` span.
//!
//! # Step order
//!
//! The final order. Later issues insert their steps at the reserved
//! positions and do not reorder the existing ones:
//!
//! 1. `BreakerReset`
//! 2. `ReorgCheck` (re-broadcasts preferences on a proposer root change)
//! 3. `DutyFetch` (reserved, W4-E2c: the runner's own bounded duty fetch)
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
//! the runner shared.

use std::collections::BTreeSet;
use std::sync::Arc;

use builder::{BuilderService, UpcomingProposal};
use duty_tracker::DutyTracker;
use eth_types::{Root, Slot};
use signer::CircuitBreakerState;
use timing::SLOTS_PER_EPOCH;
use tracing::{debug, info, warn};
use validator_store::ValidatorStore;

use super::block_proposal::publish_circuit_breaker_metrics;
use super::coordinator::PubkeyMap;
use super::duty_management::DutyManagementService;
use super::utils;

/// One boundary step. Declaration order is run order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BoundaryStep {
    BreakerReset,
    ReorgCheck,
    PrepareProposers,
    CommitteeSubscriptions,
}

impl BoundaryStep {
    const ALL: [Self; 4] = [
        Self::BreakerReset,
        Self::ReorgCheck,
        Self::PrepareProposers,
        Self::CommitteeSubscriptions,
    ];
}

/// Steps already run in `epoch`.
pub(crate) struct EpochProgress {
    epoch: u64,
    done: BTreeSet<BoundaryStep>,
}

/// Runs the epoch-boundary steps once per epoch.
pub(crate) struct EpochBoundaryRunner {
    duty_management: Arc<DutyManagementService>,
    circuit_breaker: Arc<CircuitBreakerState>,
    preferences: Arc<PreferenceBroadcaster>,
    progress: parking_lot::Mutex<Option<EpochProgress>>,
}

impl EpochBoundaryRunner {
    pub(crate) fn new(
        duty_management: Arc<DutyManagementService>,
        circuit_breaker: Arc<CircuitBreakerState>,
        preferences: Arc<PreferenceBroadcaster>,
    ) -> Self {
        Self {
            duty_management,
            circuit_breaker,
            preferences,
            progress: parking_lot::Mutex::new(None),
        }
    }

    /// Runs the steps of `slot`'s epoch that have not run yet, in order.
    ///
    /// A slot past the progress epoch starts a new epoch. A slot before it
    /// runs nothing.
    pub(crate) async fn run_pending(&self, slot: Slot) {
        let epoch = slot / SLOTS_PER_EPOCH;
        let mut ran = false;
        for step in BoundaryStep::ALL {
            if !self.is_pending(epoch, step) {
                continue;
            }
            ran = true;
            match step {
                BoundaryStep::BreakerReset => self.breaker_reset(epoch),
                BoundaryStep::ReorgCheck => self.reorg_check(epoch).await,
                BoundaryStep::PrepareProposers => self.prepare_proposers(epoch).await,
                BoundaryStep::CommitteeSubscriptions => self.committee_subscriptions(epoch).await,
            }
            self.mark_done(epoch, step);
        }
        if ran {
            self.duty_management.log_epoch_boundary_summary(epoch, slot).await;
        }
    }

    fn is_pending(&self, epoch: u64, step: BoundaryStep) -> bool {
        let mut progress = self.progress.lock();
        let current =
            progress.get_or_insert_with(|| EpochProgress { epoch, done: BTreeSet::new() });
        if epoch > current.epoch {
            *current = EpochProgress { epoch, done: BTreeSet::new() };
        }
        current.epoch == epoch && !current.done.contains(&step)
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

    async fn prepare_proposers(&self, epoch: u64) {
        self.duty_management.prepare_proposers(epoch).await;
    }

    async fn committee_subscriptions(&self, epoch: u64) {
        self.duty_management.submit_committee_subscriptions(epoch).await;
        self.duty_management.submit_committee_subscriptions(epoch + 1).await;
    }
}

/// Picks local proposals and broadcasts proposer and builder preferences for them.
///
/// One instance is shared by the runner's ReorgCheck and the slot-0 builder
/// block.
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bn_manager::{BeaconNodeClient, MockBeaconNodeClient, MockMethod};
    use builder::BuilderService;
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use duty_tracker::DutyTracker;
    use metrics::definitions::{RVC_BUILDER_CONSECUTIVE_MISSES, RVC_BUILDER_EPOCH_MISSES};
    use signer::{always_enabled, SignerService, ValidatorSigner};
    use slashing::SlashingDb;
    use validator_store::{ValidatorConfig, ValidatorStore};

    use super::*;
    use crate::orchestrator::coordinator::tests::{
        create_test_config, create_test_fork_schedule, m2_metric_lock,
    };
    use crate::pubkey_index::PubkeyIndexRegistry;

    const ROOT_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROOT_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BREAKER_CONSECUTIVE_LIMIT: u32 = 3;

    struct Fixture {
        mock: Arc<MockBeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        breaker: Arc<CircuitBreakerState>,
        runner: EpochBoundaryRunner,
        /// Duty slots of each subscription POST, in POST order.
        subscription_slots: Arc<parking_lot::Mutex<Vec<Vec<String>>>>,
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
        let pubkey = local.public_key();
        let pk_bytes = pubkey.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let subscription_slots = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&subscription_slots);
        let mock = Arc::new(
            mock.with_get_attester_duties(move |epoch, _indices| {
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

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["42".to_string()]));
        for epoch in [1, 2] {
            duty_tracker.fetch_duties_for_epoch(epoch).await.expect("seed attester duties");
        }

        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        validator_store.add_validator(ValidatorConfig::new(pk_bytes)).expect("add validator");
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::from([(pk_bytes, pubkey)])));
        let pubkey_index = PubkeyIndexRegistry::shared();
        pubkey_index.write().insert(pk_bytes, "42".to_string());

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
        let config = create_test_config();
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
        let runner = EpochBoundaryRunner::new(duty_management, Arc::clone(&breaker), preferences);
        Fixture { mock, duty_tracker, breaker, runner, subscription_slots }
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
}
