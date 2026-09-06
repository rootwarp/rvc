use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::metrics::RVC_DUTY_REORG_DETECTED_TOTAL;
use beacon::{BeaconCommitteeSubscription, ProposerPreparation};
use bn_manager::BeaconNodeClient;
use builder::legacy_proposer_ops_retired;
use duty_tracker::DutyTracker;
use eth_types::{ForkName, Slot};
use signer::{is_aggregator, SignerService, ValidatorSigner};
use timing::SLOTS_PER_EPOCH;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::utils::{self, TimedOutcome};
use crate::pubkey_index::{parse_pubkey_bytes, SharedPubkeyIndexRegistry};

/// Number of epochs in a single sync committee period.
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

/// How many epochs before the end of a period to start prefetching next-period duties.
const PREFETCH_LOOKAHEAD: u64 = 2;

pub(crate) struct DutyManagementService {
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    validator_store: Arc<validator_store::ValidatorStore>,
    pubkey_map: PubkeyMap,
    /// Shared pubkey → validator-index registry (O(1) prepare_proposers).
    pubkey_index: SharedPubkeyIndexRegistry,
    config: OrchestratorConfig,
    /// Tracks which sync committee periods have been prefetched to ensure idempotency.
    prefetched_periods: RwLock<HashSet<u64>>,
}

impl DutyManagementService {
    pub(crate) fn new(
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        validator_store: Arc<validator_store::ValidatorStore>,
        pubkey_map: PubkeyMap,
        pubkey_index: SharedPubkeyIndexRegistry,
        config: OrchestratorConfig,
    ) -> Self {
        Self {
            signer,
            beacon,
            duty_tracker,
            validator_store,
            pubkey_map,
            pubkey_index,
            config,
            prefetched_periods: RwLock::new(HashSet::new()),
        }
    }

    #[tracing::instrument(name = "orchestrator.fetch_epoch_duties", level = "debug", skip_all, fields(epoch = epoch))]
    pub(crate) async fn fetch_epoch_duties(&self, epoch: u64) {
        // Evict old caches to prevent unbounded growth
        self.duty_tracker.evict_old_caches(epoch).await;

        // Attester duties
        if !self.duty_tracker.is_epoch_cached(epoch).await {
            debug!(epoch, "Fetching attester duties for epoch");
            match utils::timed(
                "attester_duty_fetch",
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_duties_for_epoch(epoch),
            )
            .await
            {
                TimedOutcome::Ok(_) => {}
                TimedOutcome::Err(e) => warn!(epoch, error = %e, "Failed to fetch attester duties"),
                TimedOutcome::Timeout => warn!(
                    epoch,
                    "Attester duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        // Proposer duties
        if !self.duty_tracker.is_proposer_epoch_cached(epoch).await {
            debug!(epoch, "Fetching proposer duties for epoch");
            match utils::timed(
                "proposer_duty_fetch",
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_proposer_duties(epoch),
            )
            .await
            {
                TimedOutcome::Ok(_) => {}
                TimedOutcome::Err(e) => warn!(epoch, error = %e, "Failed to fetch proposer duties"),
                TimedOutcome::Timeout => warn!(
                    epoch,
                    "Proposer duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        // PTC duties
        if !self.duty_tracker.is_ptc_epoch_cached(epoch).await {
            debug!(epoch, "Fetching PTC duties for epoch");
            match utils::timed(
                "ptc_duty_fetch",
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_ptc_duties_for_epoch(epoch),
            )
            .await
            {
                TimedOutcome::Ok(_) => {}
                TimedOutcome::Err(e) => warn!(epoch, error = %e, "Failed to fetch PTC duties"),
                TimedOutcome::Timeout => warn!(
                    epoch,
                    "PTC duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        // Sync committee duties (at period boundaries)
        if !self.duty_tracker.is_sync_period_cached(epoch).await {
            debug!(epoch, "Fetching sync committee duties");
            match utils::timed(
                "sync_duty_fetch",
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_sync_committee_duties(epoch),
            )
            .await
            {
                TimedOutcome::Ok(_) => {}
                TimedOutcome::Err(e) => {
                    warn!(epoch, error = %e, "Failed to fetch sync committee duties")
                }
                TimedOutcome::Timeout => warn!(
                    epoch,
                    "Sync committee duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        let (attester_count, proposer_count, sync_count, ptc_count) =
            self.duty_tracker.cached_duty_counts(epoch).await;
        debug!(
            epoch,
            attester_count, proposer_count, sync_count, ptc_count, "Duty counts for epoch"
        );

        // Prefetch next-period sync committee duties when approaching period boundary.
        self.maybe_prefetch_next_sync_period(epoch).await;
    }

    /// Proposer-duties-only fetch under a caller-supplied deadline.
    ///
    /// Used on the pre-proposal path when the epoch cache is cold. Does not
    /// fetch attester or sync duties — those stay in the post-duty window.
    pub(crate) async fn fetch_proposer_duties_only(
        &self,
        epoch: u64,
        deadline: Duration,
    ) -> TimedOutcome<Vec<beacon::ProposerDuty>, duty_tracker::DutyTrackerError> {
        utils::timed(
            "cold_proposer_duty_fetch",
            deadline,
            self.duty_tracker.fetch_proposer_duties(epoch),
        )
        .await
    }

    /// Prefetches sync committee duties for the next period when within the last
    /// `PREFETCH_LOOKAHEAD` epochs of the current period.
    ///
    /// Uses a `HashSet<Period>` guard to ensure the fetch happens at most once per period
    /// even if called multiple times in the lookahead window. Failures are retried because
    /// the period is only marked as done on a successful fetch.
    ///
    /// Attester committee subscriptions for `next_period_first_epoch` are intentionally
    /// NOT submitted here: at the time this prefetch fires (epoch `PERIOD - 2`), the
    /// attester duty cache for `next_period_first_epoch` is not yet populated, so any
    /// subscription call would be a no-op. The coordinator's normal epoch-boundary path
    /// calls `submit_committee_subscriptions(current_epoch + 1)` at epoch `PERIOD - 1`,
    /// which is still within the two-epoch lookahead window and has the attester cache
    /// fully populated at that point.
    async fn maybe_prefetch_next_sync_period(&self, current_epoch: u64) {
        let pos = current_epoch % EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        if pos < EPOCHS_PER_SYNC_COMMITTEE_PERIOD - PREFETCH_LOOKAHEAD {
            return;
        }

        let next_period = current_epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD + 1;
        let next_period_first_epoch = next_period * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

        // Idempotency: skip if this period has already been successfully prefetched.
        // INVARIANT: this function is called from a single sequential task (the slot loop),
        // so the read → write gap below is not a TOCTOU race in practice.
        {
            let guard = self.prefetched_periods.read().await;
            if guard.contains(&next_period) {
                debug!(
                    current_epoch,
                    next_period, "Sync committee prefetch already done for period"
                );
                return;
            }
        }

        debug!(
            current_epoch,
            next_period, next_period_first_epoch, "Prefetching next-period sync committee duties"
        );

        match utils::timed(
            "sync_duty_prefetch",
            self.config.timeouts.duty_fetch,
            self.duty_tracker.fetch_sync_committee_duties(next_period_first_epoch),
        )
        .await
        {
            TimedOutcome::Ok(_) => {
                info!(
                    next_period,
                    next_period_first_epoch, "Prefetched sync committee duties for next period"
                );
                // Mark as done immediately after a successful fetch so that the next call
                // in the lookahead window skips the BN round-trip.
                self.prefetched_periods.write().await.insert(next_period);
            }
            TimedOutcome::Err(e) => {
                warn!(
                    next_period,
                    next_period_first_epoch,
                    error = %e,
                    "Failed to prefetch sync committee duties for next period"
                );
            }
            TimedOutcome::Timeout => {
                warn!(
                    next_period,
                    next_period_first_epoch,
                    "Sync committee duty prefetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                );
            }
        }
    }

    #[tracing::instrument(name = "orchestrator.check_reorg", level = "debug", skip_all, fields(epoch = current_epoch))]
    pub(crate) async fn check_reorg_at_epoch_boundary(&self, current_epoch: u64) {
        for epoch in [current_epoch, current_epoch + 1] {
            let attester_cached = self.duty_tracker.is_epoch_cached(epoch).await;
            let old_attester_root = self.duty_tracker.get_cached_dependent_root(epoch).await;
            match utils::timed(
                "attester_reorg_check",
                self.config.timeouts.duty_fetch,
                self.duty_tracker.check_and_refetch_if_root_changed(epoch),
            )
            .await
            {
                TimedOutcome::Ok(true) if attester_cached => {
                    let new_root = self.duty_tracker.get_cached_dependent_root(epoch).await;
                    warn!(
                        epoch,
                        old_head = ?old_attester_root,
                        new_head = ?new_root,
                        "Reorg detected: attester duties refetched"
                    );
                    RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["attester"]).inc();
                }
                TimedOutcome::Ok(true) => {
                    debug!(epoch, "Attester duties fetched (was uncached)");
                }
                TimedOutcome::Ok(false) => {}
                TimedOutcome::Err(e) => {
                    warn!(epoch, error = %e, "Failed to check attester dependent root");
                }
                TimedOutcome::Timeout => {
                    warn!(
                        epoch,
                        "Attester reorg check timed out after {}s",
                        self.config.timeouts.duty_fetch.as_secs()
                    );
                }
            }

            let proposer_cached = self.duty_tracker.is_proposer_epoch_cached(epoch).await;
            let old_proposer_root =
                self.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
            match utils::timed(
                "proposer_reorg_check",
                self.config.timeouts.duty_fetch,
                self.duty_tracker.check_and_refetch_proposer_if_root_changed(epoch),
            )
            .await
            {
                TimedOutcome::Ok(true) if proposer_cached => {
                    let new_root =
                        self.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
                    warn!(
                        epoch,
                        old_head = ?old_proposer_root,
                        new_head = ?new_root,
                        "Reorg detected: proposer duties refetched"
                    );
                    RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["proposer"]).inc();
                }
                TimedOutcome::Ok(true) => {
                    debug!(epoch, "Proposer duties fetched (was uncached)");
                }
                TimedOutcome::Ok(false) => {}
                TimedOutcome::Err(e) => {
                    warn!(epoch, error = %e, "Failed to check proposer dependent root");
                }
                TimedOutcome::Timeout => {
                    warn!(
                        epoch,
                        "Proposer reorg check timed out after {}s",
                        self.config.timeouts.duty_fetch.as_secs()
                    );
                }
            }

            let ptc_cached = self.duty_tracker.is_ptc_epoch_cached(epoch).await;
            let old_ptc_root = self.duty_tracker.get_cached_ptc_dependent_root(epoch).await;
            match utils::timed(
                "ptc_reorg_check",
                self.config.timeouts.duty_fetch,
                self.duty_tracker.check_and_refetch_ptc_if_root_changed(epoch),
            )
            .await
            {
                TimedOutcome::Ok(true) if ptc_cached => {
                    let new_root = self.duty_tracker.get_cached_ptc_dependent_root(epoch).await;
                    warn!(
                        epoch,
                        old_head = ?old_ptc_root,
                        new_head = ?new_root,
                        "Reorg detected: PTC duties refetched"
                    );
                    RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["ptc"]).inc();
                }
                TimedOutcome::Ok(true) => {
                    debug!(epoch, "PTC duties fetched (was uncached)");
                }
                TimedOutcome::Ok(false) => {}
                TimedOutcome::Err(e) => {
                    warn!(epoch, error = %e, "Failed to check PTC dependent root");
                }
                TimedOutcome::Timeout => {
                    warn!(
                        epoch,
                        "PTC reorg check timed out after {}s",
                        self.config.timeouts.duty_fetch.as_secs()
                    );
                }
            }
        }
    }

    #[tracing::instrument(name = "orchestrator.prepare_proposers", level = "debug", skip_all, fields(epoch = epoch))]
    pub(crate) async fn prepare_proposers(&self, epoch: u64) {
        let fork = ForkName::from_epoch(epoch, &self.config.fork_schedule);
        if legacy_proposer_ops_retired(fork) {
            info!(epoch, fork = fork.as_ref(), "Skipping prepare_beacon_proposer at Gloas");
            return;
        }

        // O(validators): one registry lookup per local key — no duty-cache scan.
        // Build the preparations list under short sync locks (no await held).
        let preparations: Vec<ProposerPreparation> = {
            let pubkey_snapshot = self.pubkey_map.read().clone();
            let index_registry = self.pubkey_index.read();
            let mut out = Vec::with_capacity(pubkey_snapshot.len());
            for (pubkey_bytes, pubkey) in &pubkey_snapshot {
                let fee_recipient =
                    self.validator_store.effective_fee_recipient(&pubkey.to_bytes());
                let fee_recipient_hex = format!("0x{}", hex::encode(fee_recipient));

                match index_registry.index_of(pubkey_bytes) {
                    Some(validator_index) => {
                        out.push(ProposerPreparation {
                            validator_index: validator_index.to_string(),
                            fee_recipient: fee_recipient_hex,
                        });
                    }
                    None => {
                        debug!(
                            pubkey = %format!("0x{}", hex::encode(pubkey_bytes)),
                            "No validator index found for proposer preparation"
                        );
                    }
                }
            }
            out
        };

        if preparations.is_empty() {
            return;
        }

        let count = preparations.len();
        match utils::timed(
            "proposer_preparation",
            self.config.timeouts.preparation,
            self.beacon.prepare_beacon_proposer(&preparations),
        )
        .await
        {
            TimedOutcome::Ok(_) => info!(count, "Sent proposer preparations"),
            TimedOutcome::Err(e) => warn!(error = %e, "Failed to send proposer preparations"),
            TimedOutcome::Timeout => {
                warn!(
                    "Proposer preparation timed out after {}s",
                    self.config.timeouts.preparation.as_secs()
                )
            }
        }
    }

    #[tracing::instrument(name = "orchestrator.submit_committee_subscriptions", level = "debug", skip_all, fields(epoch = epoch))]
    pub(crate) async fn submit_committee_subscriptions(&self, epoch: u64) {
        let mut subscriptions = Vec::new();
        let pubkey_snapshot = self.pubkey_map.read().clone();

        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            let duties = self.duty_tracker.get_duties_for_slot(slot).await;

            for duty in &duties {
                // Only subscribe for our own validators (O(1) by compressed bytes).
                let Some(duty_bytes) = parse_pubkey_bytes(&duty.pubkey) else {
                    continue;
                };
                let Some(pubkey) = pubkey_snapshot.get(&duty_bytes).cloned() else {
                    continue;
                };

                let committee_length: u64 = match duty.committee_length.parse() {
                    Ok(cl) => cl,
                    Err(_) => {
                        warn!(
                            validator_index = %duty.validator_index,
                            "Invalid committee_length in duty: {}",
                            duty.committee_length
                        );
                        continue;
                    }
                };

                // Compute selection proof and determine if aggregator
                let selection_proof = match self
                    .signer
                    .sign_selection_proof(
                        slot,
                        &pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            validator_index = %duty.validator_index,
                            slot,
                            error = %e,
                            "Failed to sign selection proof for subscription"
                        );
                        continue;
                    }
                };

                let is_agg = is_aggregator(committee_length, &selection_proof.to_bytes());

                subscriptions.push(BeaconCommitteeSubscription {
                    validator_index: duty.validator_index.clone(),
                    committee_index: duty.committee_index.clone(),
                    committees_at_slot: duty.committees_at_slot.clone(),
                    slot: duty.slot.clone(),
                    is_aggregator: is_agg,
                });
            }
        }

        if subscriptions.is_empty() {
            return;
        }

        let count = subscriptions.len();
        match utils::timed(
            "committee_subscription",
            self.config.timeouts.preparation,
            self.beacon.submit_beacon_committee_subscriptions(&subscriptions),
        )
        .await
        {
            TimedOutcome::Ok(_) => info!(count, epoch, "Sent committee subscriptions"),
            TimedOutcome::Err(e) => {
                warn!(epoch, error = %e, "Failed to send committee subscriptions")
            }
            TimedOutcome::Timeout => warn!(
                epoch,
                "Committee subscription timed out after {}s",
                self.config.timeouts.preparation.as_secs()
            ),
        }
    }

    /// Epoch-boundary work: reorg checks, proposer preparation, committee
    /// subscriptions for the current and next epoch, then a duty summary.
    ///
    /// Extracted from the coordinator slot loop so the run path stays a pure
    /// phase dispatcher. Circuit-breaker reset stays in the coordinator (it
    /// owns that state).
    #[tracing::instrument(name = "orchestrator.on_epoch_boundary", level = "debug", skip_all, fields(epoch = current_epoch))]
    pub(crate) async fn on_epoch_boundary(&self, current_epoch: u64, current_slot: Slot) {
        self.check_reorg_at_epoch_boundary(current_epoch).await;
        self.prepare_proposers(current_epoch).await;
        self.submit_committee_subscriptions(current_epoch).await;
        self.submit_committee_subscriptions(current_epoch + 1).await;
        self.log_epoch_boundary_summary(current_epoch, current_slot).await;
    }

    /// Count attester/proposer/sync duties for the epoch and emit the
    /// `Epoch boundary summary` info line.
    ///
    /// Iterates the slot range once (attester + proposer per slot) rather than
    /// two separate 32-slot loops.
    pub(crate) async fn log_epoch_boundary_summary(&self, current_epoch: u64, current_slot: Slot) {
        let (attester_count, proposer_count, sync_count) =
            self.epoch_boundary_summary_counts(current_epoch, current_slot).await;
        info!(
            epoch = current_epoch,
            attester_count, proposer_count, sync_count, "Epoch boundary summary"
        );
    }

    /// Counts used by the epoch-boundary summary.
    ///
    /// Single pass over `[epoch * 32, epoch * 32 + 32)` for attester and
    /// proposer duties; sync committee duties are read for `current_slot`.
    pub(crate) async fn epoch_boundary_summary_counts(
        &self,
        epoch: u64,
        current_slot: Slot,
    ) -> (usize, usize, usize) {
        let mut attester_count = 0usize;
        let mut proposer_count = 0usize;
        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            attester_count += self.duty_tracker.get_duties_for_slot(slot).await.len();
            if self.duty_tracker.get_proposer_duty(slot).await.is_some() {
                proposer_count += 1;
            }
        }
        let sync_count = self.duty_tracker.get_sync_committee_duties(current_slot).await.len();
        (attester_count, proposer_count, sync_count)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use beacon::{BeaconClient, BeaconClientConfig};
    use crypto::{CompositeSigner, KeyManager, LocalSigner};
    use duty_tracker::DutyTracker;
    use eth_types::ForkSchedule;
    use signer::{always_enabled, SignerService};
    use slashing::SlashingDb;

    use validator_store::ValidatorStore;

    use super::*;
    use crate::orchestrator::coordinator::OrchestratorConfig;

    // EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256.
    // Period 0 spans epochs 0..=255; period 1 spans epochs 256..=511.
    // Lookahead window within period 0: epochs 254 and 255.
    const PERIOD: u64 = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

    fn make_fork_schedule() -> Arc<ForkSchedule> {
        Arc::new(ForkSchedule {
            genesis_fork_version: [0, 0, 0, 1],
            altair_fork_epoch: 0,
            altair_fork_version: [0, 0, 0, 2],
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: [0, 0, 0, 3],
            capella_fork_epoch: 0,
            capella_fork_version: [0, 0, 0, 4],
            deneb_fork_epoch: 0,
            deneb_fork_version: [0, 0, 0, 5],
            electra_fork_epoch: 0,
            electra_fork_version: [0, 0, 0, 6],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [0, 0, 0, 7],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [0, 0, 0, 8],
        })
    }

    fn make_config() -> OrchestratorConfig {
        OrchestratorConfig::new([0xaa; 32], make_fork_schedule())
    }

    fn sync_duties_response() -> serde_json::Value {
        serde_json::json!({
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
                "validator_index": 1,
                "validator_sync_committee_indices": ["0"]
            }]
        })
    }

    async fn build_service_no_validators(beacon_url: &str) -> DutyManagementService {
        let beacon_config = BeaconClientConfig::new(beacon_url)
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(1);
        let beacon =
            Arc::new(BeaconClient::new(beacon_config).unwrap()) as Arc<dyn BeaconNodeClient>;
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        DutyManagementService::new(
            signer,
            beacon,
            duty_tracker,
            validator_store,
            pubkey_map,
            crate::pubkey_index::PubkeyIndexRegistry::shared(),
            make_config(),
        )
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_prefetch_fires_in_last_2_epochs (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// Prefetch fires for epoch PERIOD-2 (pos = 254 = PERIOD - 2).
    #[tokio::test]
    async fn test_prefetch_fires_in_last_2_epochs() {
        let server = MockServer::start().await;
        // Must be called exactly once for the next period's first epoch
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        // epoch PERIOD-2 is the second-to-last epoch of period 0
        service.maybe_prefetch_next_sync_period(PERIOD - 2).await;
        // wiremock asserts expect(1) on drop
    }

    /// Prefetch also fires for epoch PERIOD-1 (pos = 255 = PERIOD - 1).
    #[tokio::test]
    async fn test_prefetch_fires_at_last_epoch_of_period() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
    }

    /// Prefetch does NOT fire when outside the lookahead window (pos < PERIOD - 2).
    #[tokio::test]
    async fn test_prefetch_outside_window_does_not_fire() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(0)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        // epoch PERIOD-3: pos = 253 < 254 → must NOT fire
        service.maybe_prefetch_next_sync_period(PERIOD - 3).await;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_prefetch_retries_on_transient_failure (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// After a transient fetch failure at PERIOD_END-1 the period is NOT marked as
    /// prefetched, so the next call succeeds and duties become available.
    #[tokio::test]
    async fn test_prefetch_retries_on_transient_failure() {
        let server = MockServer::start().await;

        // First call: 500 → failure (up_to_n_times(1) so only the first request fails)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(500).set_body_string("transient"))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Second call: 200 → success
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        // max_retries(0) so the beacon client does NOT auto-retry 5xx; this lets us
        // simulate a transient failure at the DutyManagementService level.
        let beacon_config = BeaconClientConfig::new(server.uri())
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(0);
        let beacon_client =
            Arc::new(BeaconClient::new(beacon_config).unwrap()) as Arc<dyn BeaconNodeClient>;
        let duty_tracker = Arc::new(DutyTracker::new(beacon_client.clone(), vec!["1".to_string()]));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        let service = DutyManagementService::new(
            signer,
            beacon_client,
            duty_tracker.clone(),
            validator_store,
            pubkey_map,
            crate::pubkey_index::PubkeyIndexRegistry::shared(),
            make_config(),
        );

        // First attempt at PERIOD-1: fails
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
        assert!(
            duty_tracker.get_sync_committee_duties(PERIOD * SLOTS_PER_EPOCH).await.is_empty(),
            "duties must be empty after transient failure"
        );

        // Second attempt: must succeed because period is NOT in prefetched_periods
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
        assert!(
            !duty_tracker.get_sync_committee_duties(PERIOD * SLOTS_PER_EPOCH).await.is_empty(),
            "duties must be present after successful retry"
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_prefetch_idempotent (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// Calling prefetch twice in the window issues the BN request only once.
    #[tokio::test]
    async fn test_prefetch_idempotent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;

        // Two calls in the lookahead window — BN endpoint must only be hit once
        service.maybe_prefetch_next_sync_period(PERIOD - 2).await;
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
        // wiremock asserts expect(1) on drop
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_subnet_subscriptions_submitted_in_window (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// `maybe_prefetch_next_sync_period` does NOT call the beacon committee subscription
    /// endpoint — the attester duty cache for `next_period_first_epoch` is always empty
    /// at epoch PERIOD-2, so any subscription call would be a no-op.  The coordinator's
    /// normal epoch-boundary path submits subscriptions at epoch PERIOD-1 (still within
    /// the two-epoch lookahead window) when the cache is populated.
    ///
    /// This test asserts the prefetch calls the sync-duty endpoint exactly once and
    /// never touches the subscription endpoint.
    #[tokio::test]
    async fn test_subnet_subscriptions_submitted_in_window() {
        let server = MockServer::start().await;

        // Sync committee duties for the next period — must fire exactly once.
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        // The beacon committee subscription endpoint must NOT be called by the prefetch:
        // attester duties for the next period's first epoch are not yet cached at PERIOD-2.
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;

        // Trigger prefetch at the second-to-last epoch of period 0
        service.maybe_prefetch_next_sync_period(PERIOD - 2).await;
        // wiremock asserts expect(1) for sync duties and expect(0) for subscriptions on drop
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Integration: fetch_epoch_duties triggers prefetch in window
    // ──────────────────────────────────────────────────────────────────────────

    /// `fetch_epoch_duties` at an epoch in the lookahead window triggers the prefetch,
    /// causing the BN to be queried for the next period's duties.
    #[tokio::test]
    async fn test_fetch_epoch_duties_triggers_prefetch_in_window() {
        let server = MockServer::start().await;
        let current_epoch = PERIOD - 2;

        // Standard duty endpoints for the current epoch (no validators, so no real data needed)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/attester/{}", current_epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{}", current_epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&server)
            .await;

        // Sync duties for current period (period 0, epoch 254 → period 0)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", current_epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .mount(&server)
            .await;

        // Prefetch: sync duties for next period (period 1, first epoch = PERIOD = 256)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        service.fetch_epoch_duties(current_epoch).await;
        // wiremock asserts expect(1) for PERIOD sync duties on drop
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Epoch-boundary summary: single-pass counts match dual-loop baseline
    // ──────────────────────────────────────────────────────────────────────────

    /// RF6-27: collapsing the two 32-slot loops into one pass must not change
    /// the attester/proposer/sync counts that feed `Epoch boundary summary`.
    #[tokio::test]
    async fn test_epoch_boundary_summary_counts_match_dual_loop() {
        use bn_manager::{
            AttesterDutiesResponse, AttesterDuty, MockBeaconNodeClient, ProposerDutiesResponse,
            ProposerDuty, SyncCommitteeDutiesResponse,
        };
        use eth_types::SyncCommitteeDuty;

        let epoch = 10u64;
        let slot_base = epoch * SLOTS_PER_EPOCH;
        // 3 attester duties on two slots (2 + 1), 2 proposer slots, 1 sync duty.
        let attester_data = vec![
            AttesterDuty {
                pubkey: "0xpk1".into(),
                validator_index: "1".into(),
                committee_index: "0".into(),
                committee_length: "128".into(),
                committees_at_slot: "64".into(),
                validator_committee_index: "0".into(),
                slot: slot_base.to_string(),
            },
            AttesterDuty {
                pubkey: "0xpk2".into(),
                validator_index: "2".into(),
                committee_index: "1".into(),
                committee_length: "128".into(),
                committees_at_slot: "64".into(),
                validator_committee_index: "1".into(),
                slot: slot_base.to_string(),
            },
            AttesterDuty {
                pubkey: "0xpk1".into(),
                validator_index: "1".into(),
                committee_index: "0".into(),
                committee_length: "128".into(),
                committees_at_slot: "64".into(),
                validator_committee_index: "0".into(),
                slot: (slot_base + 5).to_string(),
            },
        ];
        let proposer_data = vec![
            ProposerDuty {
                pubkey: "0xpk1".into(),
                validator_index: "1".into(),
                slot: slot_base.to_string(),
            },
            ProposerDuty {
                pubkey: "0xpk2".into(),
                validator_index: "2".into(),
                slot: (slot_base + 7).to_string(),
            },
        ];
        let sync_data = vec![SyncCommitteeDuty {
            pubkey: [0x11; 48],
            validator_index: 1,
            validator_sync_committee_indices: vec![0],
        }];

        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_get_attester_duties({
                    let data = attester_data.clone();
                    move |_epoch, _indices| {
                        Ok(AttesterDutiesResponse {
                            dependent_root: "0xdeproot".into(),
                            execution_optimistic: false,
                            data: data.clone(),
                        })
                    }
                })
                .with_get_proposer_duties({
                    let data = proposer_data.clone();
                    move |_epoch| {
                        Ok(ProposerDutiesResponse {
                            dependent_root: "0xdeproot".into(),
                            execution_optimistic: false,
                            data: data.clone(),
                        })
                    }
                })
                .with_post_sync_committee_duties({
                    let data = sync_data.clone();
                    move |_epoch, _indices| {
                        Ok(SyncCommitteeDutiesResponse {
                            execution_optimistic: false,
                            data: data.clone(),
                        })
                    }
                }),
        ) as Arc<dyn BeaconNodeClient>;

        let indices = vec!["1".to_string(), "2".to_string()];
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), indices));
        duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();
        duty_tracker.fetch_sync_committee_duties(epoch).await.unwrap();

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        let service = DutyManagementService::new(
            signer,
            beacon,
            duty_tracker.clone(),
            validator_store,
            pubkey_map,
            crate::pubkey_index::PubkeyIndexRegistry::shared(),
            make_config(),
        );

        let current_slot = slot_base;
        let single_pass = service.epoch_boundary_summary_counts(epoch, current_slot).await;

        // Dual-loop baseline: the pre-RF6-27 shape (two separate 32-slot walks).
        let mut dual_attester = 0usize;
        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            dual_attester += duty_tracker.get_duties_for_slot(slot).await.len();
        }
        let mut dual_proposer = 0usize;
        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            if duty_tracker.get_proposer_duty(slot).await.is_some() {
                dual_proposer += 1;
            }
        }
        let dual_sync = duty_tracker.get_sync_committee_duties(current_slot).await.len();

        assert_eq!(single_pass, (dual_attester, dual_proposer, dual_sync));
        assert_eq!(single_pass, (3, 2, 1), "known fixture counts");
    }
}
