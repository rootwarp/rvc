use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::metrics::RVC_DUTY_REORG_DETECTED_TOTAL;
use beacon::{BeaconCommitteeSubscription, ProposerPreparation};
use bn_manager::BeaconNodeClient;
use builder::legacy_proposer_ops_retired;
use duty_tracker::DutyTracker;
use eth_types::{ForkName, Slot};
use observability::logging::TruncatedPubkey;
use signer::{is_aggregator, SignerError, SignerService, ValidatorSigner};
use timing::SLOTS_PER_EPOCH;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::error::OrchestratorError;
use super::selection_proofs::{SelectionProofCache, SelectionProofError};
use super::utils::{self, TimedOutcome};
use crate::pubkey_index::{parse_pubkey_bytes, RegistryFreshness, SharedPubkeyIndexRegistry};

/// Number of epochs in a single sync committee period.
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

/// How many epochs before the end of a period to start prefetching next-period duties.
const PREFETCH_LOOKAHEAD: u64 = 2;

/// The prepare POST, as timed and as named by a timeout.
const PROPOSER_PREPARATION: &str = "proposer_preparation";

/// The committee-subscription POST, as timed and as named by a timeout.
const COMMITTEE_SUBSCRIPTION: &str = "committee_subscription";

/// The maximum number of committee subscriptions in one POST. Each consensus
/// client accepts this size.
const SUBSCRIPTION_CHUNK: usize = 512;

/// The maximum number of subscription selection proofs that sign at the same
/// time. A lower `dispatch_limits.concurrency` sets a lower cap.
const SUBSCRIPTION_SIGNS: usize = 32;

/// How a [`DutyManagementService::prepare_proposers`] call that met no error ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrepareOutcome {
    /// The epoch needs no further send: Gloas, no local key, or a POST that
    /// covered every local key.
    Complete,
    /// The keys with a validator index were POSTed; `unresolved` have none yet.
    Partial { unresolved: usize },
    /// No local key has a validator index yet, so nothing was sent.
    NoIndices,
    /// The registry was stale, or its token moved while preparing; no POST
    /// was made, or the POST may have carried indices from before a
    /// revocation.
    Stale,
}

/// Why the owner of a subscription's selection proof did not sign.
enum SubscriptionProofSkip {
    /// The store gate closed after the first check, for example while the
    /// caller waited for another owner.
    Disabled,
    Failed(SignerError),
}

/// [`PrepareOutcome::Stale`] with no POST: the indices wait for a re-check.
fn deferred_preparation(epoch: u64) -> PrepareOutcome {
    info!(
        epoch,
        "Deferring proposer preparation: validator indices are being re-checked after a beacon-node revocation"
    );
    PrepareOutcome::Stale
}

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
    /// The selection proofs that aggregation uses too.
    selection_proofs: Arc<SelectionProofCache>,
}

impl DutyManagementService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        validator_store: Arc<validator_store::ValidatorStore>,
        pubkey_map: PubkeyMap,
        pubkey_index: SharedPubkeyIndexRegistry,
        config: OrchestratorConfig,
        selection_proofs: Arc<SelectionProofCache>,
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
            selection_proofs,
        }
    }

    /// Drops the selection proofs below `slot`. See [`SelectionProofCache::evict_before`].
    pub(crate) fn evict_selection_proofs_before(&self, slot: Slot) {
        self.selection_proofs.evict_before(slot);
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

        // PTC duties — Gloas+ only. Pre-Gloas BNs reject duties/ptc (often HTTP
        // 500); skipping avoids retry-exhaustion ERROR spam. The coordinator
        // already fetches `current_epoch + 1`, so the first Gloas epoch is
        // prefetched during the last pre-Gloas epoch.
        let ptc_active = ForkName::from_epoch(epoch, &self.config.fork_schedule) >= ForkName::Gloas;
        if ptc_active && !self.duty_tracker.is_ptc_epoch_cached(epoch).await {
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

    /// Sets `proposer_root_changed` as soon as a previously cached proposer
    /// `dependent_root` changes, before the next await after the cache
    /// write, so a caller that drops the check part way still sees a change
    /// it cached.
    #[tracing::instrument(name = "orchestrator.check_reorg", level = "debug", skip_all, fields(epoch = current_epoch))]
    pub(crate) async fn check_reorg_at_epoch_boundary(
        &self,
        current_epoch: u64,
        proposer_root_changed: &AtomicBool,
    ) {
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
                    proposer_root_changed.store(true, Ordering::Release);
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

            // Same Gloas gate as fetch_epoch_duties: uncached pre-Gloas would
            // otherwise POST duties/ptc and surface BN 500s as ERROR.
            if ForkName::from_epoch(epoch, &self.config.fork_schedule) >= ForkName::Gloas {
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
    }

    /// POSTs `prepare_beacon_proposer` for the local keys whose validator
    /// index is known.
    ///
    /// [`PrepareOutcome::Complete`] at Gloas (the call is retired), with no
    /// local key, or after a POST that covered every local key. `Partial`
    /// after a POST of the keys with an index while others have none yet,
    /// and `NoIndices`, with no POST, while no key has one. A failed POST is
    /// [`OrchestratorError::Beacon`], and one cut by `timeouts.preparation`
    /// is [`OrchestratorError::OperationTimedOut`].
    ///
    /// The registry token is captured under the read lock the indices are
    /// read under. [`PrepareOutcome::Stale`], with no POST, while the
    /// registry is stale or once the token moved before the POST, and
    /// `Stale` after a POST during which it moved: that POST may carry an
    /// index from before a revocation.
    #[tracing::instrument(name = "orchestrator.prepare_proposers", level = "debug", skip_all, fields(epoch = epoch))]
    pub(crate) async fn prepare_proposers(
        &self,
        epoch: u64,
    ) -> Result<PrepareOutcome, OrchestratorError> {
        let fork = ForkName::from_epoch(epoch, &self.config.fork_schedule);
        if legacy_proposer_ops_retired(fork) {
            info!(epoch, fork = fork.as_ref(), "Skipping prepare_beacon_proposer at Gloas");
            return Ok(PrepareOutcome::Complete);
        }

        // O(validators): one registry lookup per local key — no duty-cache scan.
        // Build the preparations list under short sync locks (no await held).
        let (token, preparations, unresolved) = {
            #[cfg(test)]
            reach_prepare_point(PreparePoint::BeforeSnapshot);
            let pubkey_snapshot = self.pubkey_map.read().clone();
            let index_registry = self.pubkey_index.read();
            let token = index_registry.freshness();
            if token == RegistryFreshness::Stale {
                drop(index_registry);
                return Ok(deferred_preparation(epoch));
            }
            let mut out = Vec::with_capacity(pubkey_snapshot.len());
            let mut unresolved = 0;
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
                        unresolved += 1;
                        debug!(
                            pubkey = %format!("0x{}", hex::encode(pubkey_bytes)),
                            "No validator index found for proposer preparation"
                        );
                    }
                }
            }
            drop(index_registry);
            #[cfg(test)]
            reach_prepare_point(PreparePoint::AfterSnapshot);
            (token, out, unresolved)
        };

        if preparations.is_empty() {
            return Ok(if unresolved == 0 {
                PrepareOutcome::Complete
            } else {
                PrepareOutcome::NoIndices
            });
        }

        if self.index_freshness() != token {
            return Ok(deferred_preparation(epoch));
        }
        let count = preparations.len();
        match utils::timed(
            PROPOSER_PREPARATION,
            self.config.timeouts.preparation,
            self.beacon.prepare_beacon_proposer(&preparations),
        )
        .await
        {
            TimedOutcome::Ok(()) => {
                if self.index_freshness() != token {
                    info!(
                        epoch,
                        count,
                        "Proposer preparations sent while a beacon-node revocation moved the validator indices; sending again once they are re-checked"
                    );
                    return Ok(PrepareOutcome::Stale);
                }
                #[cfg(test)]
                reach_prepare_point(PreparePoint::AfterPostCheck);
                info!(count, "Sent proposer preparations");
                Ok(if unresolved == 0 {
                    PrepareOutcome::Complete
                } else {
                    PrepareOutcome::Partial { unresolved }
                })
            }
            TimedOutcome::Err(e) => {
                warn!(error = %e, "Failed to send proposer preparations");
                Err(OrchestratorError::Beacon(e))
            }
            TimedOutcome::Timeout => {
                warn!(
                    "Proposer preparation timed out after {}s",
                    self.config.timeouts.preparation.as_secs()
                );
                Err(OrchestratorError::OperationTimedOut { operation: PROPOSER_PREPARATION })
            }
        }
    }

    /// The registry token [`Self::prepare_proposers`] captures. The read
    /// lock is held only for this call.
    pub(crate) fn index_freshness(&self) -> RegistryFreshness {
        self.pubkey_index.read().freshness()
    }

    /// The local keys whose validator index is known: the size of the POST
    /// a [`Self::prepare_proposers`] call would make now.
    pub(crate) fn resolved_proposer_count(&self) -> usize {
        let pubkeys: Vec<[u8; 48]> = self.pubkey_map.read().keys().copied().collect();
        let index_registry = self.pubkey_index.read();
        pubkeys.iter().filter(|pubkey| index_registry.index_of(pubkey).is_some()).count()
    }

    /// Gets a selection proof for each local attester duty of `epoch` from
    /// the shared cache, and POSTs the epoch's committee subscriptions.
    ///
    /// Up to `min(32, dispatch_limits.concurrency)` duties get their proofs
    /// at the same time. Each duty checks the store gate, then the admission
    /// fence, and then gets its proof from the cache, so the concurrency does
    /// not change which duties can sign.
    ///
    /// The call reads the revocation watch of the beacon node before it reads
    /// the duties, and each duty checks that watch with its own fence. After
    /// a revocation, no later duty signs, because its duty can come from the
    /// revoked node. The duty cache applies the same rule to each read.
    ///
    /// A duty whose proof is in the cache, or in flight for aggregation, does
    /// not sign again. The cache signs only for the owner of the key, and the
    /// owner checks the store gate again just before the signer call.
    ///
    /// The subscriptions go in POSTs of 512 or fewer. The call sends each
    /// POST, also after a failed POST.
    ///
    /// `Ok` when the epoch needs no further send: each POST went out, or there
    /// is nothing to send (no own duty, or the store gate closed or the
    /// admission revoked for each one). A selection proof that fails to sign
    /// is a warn, and skips its duty. A slot below the cache's eviction cutoff
    /// skips its duty too, unless a live owner admitted before the eviction
    /// delivers its proof: the cutoff stops only a new owner. A failed POST is
    /// [`OrchestratorError::Beacon`], and one cut by `timeouts.preparation`
    /// is [`OrchestratorError::OperationTimedOut`]. After more than one failed
    /// POST, the result is the first failure.
    #[tracing::instrument(name = "orchestrator.submit_committee_subscriptions", level = "debug", skip_all, fields(epoch = epoch))]
    pub(crate) async fn submit_committee_subscriptions(
        &self,
        epoch: u64,
    ) -> Result<(), OrchestratorError> {
        let duties_watch = self.beacon.revocation_watch();
        let mut own_duties = Vec::new();
        let pubkey_snapshot = self.pubkey_map.read().clone();

        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            let duties = self.duty_tracker.get_duties_for_slot(slot).await;
            #[cfg(test)]
            AFTER_SLOT_DUTIES.with(|hook| {
                if let Some(hook) = hook.borrow_mut().as_mut() {
                    hook(slot);
                }
            });

            for duty in duties {
                // Only subscribe for our own validators (O(1) by compressed bytes).
                let Some(duty_bytes) = parse_pubkey_bytes(&duty.pubkey) else {
                    continue;
                };
                let Some(pubkey) = pubkey_snapshot.get(&duty_bytes).cloned() else {
                    continue;
                };
                own_duties.push((slot, duty_bytes, pubkey, duty));
            }
        }

        let signs = SUBSCRIPTION_SIGNS.min(self.config.dispatch_limits.concurrency as usize);
        let duties_watch = &duties_watch;
        let subscriptions: Vec<BeaconCommitteeSubscription> = stream::iter(own_duties)
            .map(|(slot, duty_bytes, pubkey, duty)| async move {
                // Same store gate as aggregate production: doppelganger-off
                // signing allows every pubkey, so `enabled = false` must skip
                // before `sign_selection_proof`.
                let pk_bytes = pubkey.to_bytes();
                if !self.validator_store.is_signing_enabled(&pk_bytes) {
                    warn!(
                        pubkey = %TruncatedPubkey::new(&duty.pubkey),
                        slot,
                        "Skipping committee subscription: validator signing is disabled"
                    );
                    return None;
                }

                let committee_length = duty.committee_length;
                let wire = &duty.raw;

                let fence = match self.beacon.duty_fence() {
                    Ok(fence)
                        if !super::slot_context::admission_blocks(
                            signer::SigningDuty::SelectionProof,
                            &[&fence, duties_watch],
                        ) =>
                    {
                        fence
                    }
                    _ => {
                        warn!(
                            slot,
                            "skipping committee subscription: beacon node admission revoked"
                        );
                        return None;
                    }
                };
                let lookup = self.selection_proofs.get_or_sign((slot, duty_bytes), || async {
                    if !self.validator_store.is_signing_enabled(&pk_bytes) {
                        return Err(SubscriptionProofSkip::Disabled);
                    }
                    super::slot_context::under_admission(
                        &fence,
                        self.signer.sign_selection_proof(
                            slot,
                            &pubkey,
                            &self.config.fork_schedule,
                            &self.config.genesis_validators_root,
                        ),
                    )
                    .await
                    .map_err(SubscriptionProofSkip::Failed)
                });
                let selection_proof = match lookup.await {
                    Ok(sig) => sig,
                    Err(SelectionProofError::Evicted { slot }) => {
                        debug!(
                            slot,
                            "subscription selection proof slot is below the eviction cutoff"
                        );
                        return None;
                    }
                    Err(SelectionProofError::Sign(SubscriptionProofSkip::Disabled)) => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(&duty.pubkey),
                            slot,
                            "Skipping committee subscription: validator signing is disabled"
                        );
                        return None;
                    }
                    Err(SelectionProofError::Sign(SubscriptionProofSkip::Failed(e))) => {
                        warn!(
                            validator_index = %duty.validator_index,
                            slot,
                            error = %e,
                            "Failed to sign selection proof for subscription"
                        );
                        return None;
                    }
                };

                let is_agg = is_aggregator(committee_length, &selection_proof.to_bytes());

                Some(BeaconCommitteeSubscription {
                    validator_index: wire.validator_index.clone(),
                    committee_index: wire.committee_index.clone(),
                    committees_at_slot: wire.committees_at_slot.clone(),
                    slot: wire.slot.clone(),
                    is_aggregator: is_agg,
                })
            })
            .buffer_unordered(signs)
            .filter_map(std::future::ready)
            .collect()
            .await;

        if subscriptions.is_empty() {
            return Ok(());
        }

        // A failed chunk does not stop the later chunks. The first failure is
        // the result, so the runner step tries again in the next slot.
        let mut outcome = Ok(());
        for chunk in subscriptions.chunks(SUBSCRIPTION_CHUNK) {
            let sent = self.post_subscriptions(epoch, chunk).await;
            outcome = outcome.and(sent);
        }
        outcome
    }

    /// One committee-subscription POST, under `timeouts.preparation`.
    async fn post_subscriptions(
        &self,
        epoch: u64,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), OrchestratorError> {
        let count = subscriptions.len();
        match utils::timed(
            COMMITTEE_SUBSCRIPTION,
            self.config.timeouts.preparation,
            self.beacon.submit_beacon_committee_subscriptions(subscriptions),
        )
        .await
        {
            TimedOutcome::Ok(()) => {
                info!(count, epoch, "Sent committee subscriptions");
                Ok(())
            }
            TimedOutcome::Err(e) => {
                warn!(epoch, error = %e, "Failed to send committee subscriptions");
                Err(OrchestratorError::Beacon(e))
            }
            TimedOutcome::Timeout => {
                warn!(
                    epoch,
                    "Committee subscription timed out after {}s",
                    self.config.timeouts.preparation.as_secs()
                );
                Err(OrchestratorError::OperationTimedOut { operation: COMMITTEE_SUBSCRIPTION })
            }
        }
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

/// A point in [`DutyManagementService::prepare_proposers`] where a test can
/// change the index registry.
#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparePoint {
    /// Before the read lock that captures the token and the indices.
    BeforeSnapshot,
    /// After that read lock ends, before the token check before the POST.
    AfterSnapshot,
    /// After the token check that follows a successful POST.
    AfterPostCheck,
}

#[cfg(test)]
type PrepareHook = Box<dyn FnMut(PreparePoint)>;

#[cfg(test)]
type SlotDutiesHook = Box<dyn FnMut(Slot)>;

#[cfg(test)]
thread_local! {
    /// Runs in [`DutyManagementService::submit_committee_subscriptions`] after
    /// the read of the duties of each slot, when a test sets it on this thread.
    static AFTER_SLOT_DUTIES: std::cell::RefCell<Option<SlotDutiesHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    static PREPARE_HOOK: std::cell::RefCell<Option<PrepareHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs the hook that [`arm_prepare_hook`] set on this thread, if one is set.
#[cfg(test)]
fn reach_prepare_point(point: PreparePoint) {
    PREPARE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(point);
        }
    });
}

/// Runs `hook` at each [`PreparePoint`] on this thread until the guard drops.
#[cfg(test)]
pub(crate) fn arm_prepare_hook(hook: impl FnMut(PreparePoint) + 'static) -> PrepareHookGuard {
    PREPARE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    PrepareHookGuard
}

/// Removes the prepare hook when it drops, also after a failed assertion.
#[cfg(test)]
pub(crate) struct PrepareHookGuard;

#[cfg(test)]
impl Drop for PrepareHookGuard {
    fn drop(&mut self) {
        PREPARE_HOOK.with(|slot| *slot.borrow_mut() = None);
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
        // Upcast: wide object only.
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
            Arc::default(),
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
        // Upcast: wide object only.
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
            Arc::default(),
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
        // Upcast: wide object only.
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
            Arc::default(),
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

    // ──────────────────────────────────────────────────────────────────────────
    // #622: gate PTC duty fetch on Gloas fork epoch
    // ──────────────────────────────────────────────────────────────────────────

    fn empty_dependent_root_response<T>() -> beacon::DependentRootResponse<Vec<T>> {
        beacon::DependentRootResponse {
            dependent_root: "0xdeproot".into(),
            execution_optimistic: false,
            data: Vec::new(),
        }
    }

    fn gloas_gated_ptc_mock() -> Arc<bn_manager::MockBeaconNodeClient> {
        Arc::new(
            bn_manager::MockBeaconNodeClient::new()
                .with_get_attester_duties(|_e, _i| Ok(empty_dependent_root_response()))
                .with_get_proposer_duties(|_e| Ok(empty_dependent_root_response()))
                .with_post_ptc_duties(|_e, _i| Ok(empty_dependent_root_response()))
                .with_post_sync_committee_duties(|_e, _i| {
                    Ok(beacon::ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: Vec::new(),
                    })
                }),
        )
    }

    fn make_config_with_gloas(gloas_epoch: u64) -> OrchestratorConfig {
        let mut schedule = (*make_fork_schedule()).clone();
        schedule.fulu_fork_epoch = 0;
        schedule.gloas_fork_epoch = gloas_epoch;
        OrchestratorConfig::new([0xaa; 32], Arc::new(schedule))
    }

    fn build_service_with_mock(
        mock: Arc<bn_manager::MockBeaconNodeClient>,
        config: OrchestratorConfig,
    ) -> DutyManagementService {
        let beacon = mock.clone() as Arc<dyn BeaconNodeClient>;
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
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
            config,
            Arc::default(),
        )
    }

    /// Pre-Gloas epochs must not POST duties/ptc (avoids BN 500 → ERROR spam).
    #[tokio::test]
    async fn test_fetch_epoch_duties_skips_ptc_before_gloas() {
        let gloas_epoch = 100u64;
        let mock = gloas_gated_ptc_mock();
        let service = build_service_with_mock(mock.clone(), make_config_with_gloas(gloas_epoch));

        for epoch in [gloas_epoch - 3, gloas_epoch - 2, gloas_epoch - 1] {
            assert!(
                ForkName::from_epoch(epoch, &service.config.fork_schedule) < ForkName::Gloas,
                "fixture epoch {epoch} must be pre-Gloas"
            );
            service.fetch_epoch_duties(epoch).await;
        }

        assert!(
            mock.post_ptc_duties_calls().is_empty(),
            "pre-Gloas fetch_epoch_duties must issue zero post_ptc_duties calls, got {:?}",
            mock.post_ptc_duties_calls()
        );
        // Attester/proposer/sync still fetched for each pre-Gloas epoch.
        assert_eq!(mock.get_attester_duties_calls().len(), 3);
        assert_eq!(mock.get_proposer_duties_calls().len(), 3);
    }

    /// Once Gloas is active, PTC duties are fetched as before.
    #[tokio::test]
    async fn test_fetch_epoch_duties_fetches_ptc_at_and_after_gloas() {
        let gloas_epoch = 100u64;
        let mock = gloas_gated_ptc_mock();
        let service = build_service_with_mock(mock.clone(), make_config_with_gloas(gloas_epoch));

        service.fetch_epoch_duties(gloas_epoch).await;
        service.fetch_epoch_duties(gloas_epoch + 1).await;

        let ptc_epochs: Vec<u64> =
            mock.post_ptc_duties_calls().into_iter().map(|(epoch, _)| epoch).collect();
        assert_eq!(
            ptc_epochs,
            vec![gloas_epoch, gloas_epoch + 1],
            "Gloas+ epochs must POST duties/ptc"
        );
    }

    /// Coordinator prefetches `current_epoch + 1`; the first Gloas epoch must
    /// still be requested during the last pre-Gloas epoch.
    #[tokio::test]
    async fn test_fetch_epoch_duties_prefetches_first_gloas_epoch() {
        let gloas_epoch = 100u64;
        let mock = gloas_gated_ptc_mock();
        let service = build_service_with_mock(mock.clone(), make_config_with_gloas(gloas_epoch));

        // Mirror coordinator post-duty: fetch current and next.
        let current = gloas_epoch - 1;
        service.fetch_epoch_duties(current).await;
        service.fetch_epoch_duties(current + 1).await;

        let ptc_epochs: Vec<u64> =
            mock.post_ptc_duties_calls().into_iter().map(|(epoch, _)| epoch).collect();
        assert_eq!(
            ptc_epochs,
            vec![gloas_epoch],
            "boundary prefetch must request only the first Gloas epoch, got {ptc_epochs:?}"
        );
    }

    /// Reorg checks must not POST duties/ptc for pre-Gloas epochs either.
    #[tokio::test]
    async fn test_check_reorg_skips_ptc_before_gloas() {
        let gloas_epoch = 100u64;
        let mock = gloas_gated_ptc_mock();
        let service = build_service_with_mock(mock.clone(), make_config_with_gloas(gloas_epoch));

        // Epoch boundary at gloas-2 checks epochs gloas-2 and gloas-1 (both pre-Gloas).
        service.check_reorg_at_epoch_boundary(gloas_epoch - 2, &AtomicBool::default()).await;

        assert!(
            mock.post_ptc_duties_calls().is_empty(),
            "pre-Gloas reorg check must issue zero post_ptc_duties calls, got {:?}",
            mock.post_ptc_duties_calls()
        );

        // Boundary into Gloas: current pre-Gloas skipped, next (Gloas) fetched.
        service.check_reorg_at_epoch_boundary(gloas_epoch - 1, &AtomicBool::default()).await;
        let ptc_epochs: Vec<u64> =
            mock.post_ptc_duties_calls().into_iter().map(|(epoch, _)| epoch).collect();
        assert_eq!(
            ptc_epochs,
            vec![gloas_epoch],
            "reorg boundary must prefetch first Gloas epoch only, got {ptc_epochs:?}"
        );
    }

    /// Unscheduled Gloas (`u64::MAX`, `ForkSchedule::unscheduled_gloas` / fork.rs:86)
    /// must never POST duties/ptc on the fetch path for ordinary epochs.
    #[tokio::test]
    async fn test_fetch_epoch_duties_skips_ptc_when_gloas_unscheduled() {
        let mock = gloas_gated_ptc_mock();
        let service = build_service_with_mock(mock.clone(), make_config_with_gloas(u64::MAX));
        assert_eq!(
            service.config.fork_schedule.gloas_fork_epoch,
            u64::MAX,
            "fixture must use the unset/default Gloas sentinel"
        );

        // Ordinary epochs only: epoch×SLOTS_PER_EPOCH overflows near u64::MAX.
        for epoch in [0u64, 10, 100, 1_000_000] {
            assert!(
                ForkName::from_epoch(epoch, &service.config.fork_schedule) < ForkName::Gloas,
                "epoch {epoch} must stay pre-Gloas when gloas_fork_epoch is u64::MAX"
            );
            service.fetch_epoch_duties(epoch).await;
        }

        assert!(
            mock.post_ptc_duties_calls().is_empty(),
            "unscheduled Gloas must issue zero post_ptc_duties calls, got {:?}",
            mock.post_ptc_duties_calls()
        );
    }

    /// Unscheduled Gloas must also skip PTC on the reorg-check path.
    #[tokio::test]
    async fn test_check_reorg_skips_ptc_when_gloas_unscheduled() {
        let mock = gloas_gated_ptc_mock();
        let service = build_service_with_mock(mock.clone(), make_config_with_gloas(u64::MAX));
        assert_eq!(service.config.fork_schedule.gloas_fork_epoch, u64::MAX);

        service.check_reorg_at_epoch_boundary(10, &AtomicBool::default()).await;
        service.check_reorg_at_epoch_boundary(1_000_000, &AtomicBool::default()).await;

        assert!(
            mock.post_ptc_duties_calls().is_empty(),
            "unscheduled Gloas reorg check must issue zero post_ptc_duties calls, got {:?}",
            mock.post_ptc_duties_calls()
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // W4-E3c R1 (Harper B5): no admitted beacon node is nothing to send
    // ──────────────────────────────────────────────────────────────────────────

    /// [`build_service_with_mock`] with `local` as an enabled local key that
    /// the signer holds, and an attester duty for it at slot 1 of each epoch.
    async fn build_subscribing_service(
        local: crypto::SecretKey,
    ) -> (DutyManagementService, Arc<bn_manager::MockBeaconNodeClient>) {
        let pubkey = local.public_key();
        let pk_bytes = pubkey.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let mock = Arc::new(
            bn_manager::MockBeaconNodeClient::new()
                .with_get_attester_duties(move |epoch, _indices| {
                    Ok(beacon::DependentRootResponse {
                        dependent_root: "0xdeproot".into(),
                        execution_optimistic: false,
                        data: vec![beacon::AttesterDuty {
                            pubkey: pk_hex.clone(),
                            validator_index: "1".to_string(),
                            committee_index: "0".to_string(),
                            committee_length: "8".to_string(),
                            committees_at_slot: "1".to_string(),
                            validator_committee_index: "0".to_string(),
                            slot: (epoch * SLOTS_PER_EPOCH + 1).to_string(),
                        }],
                    })
                })
                .with_submit_beacon_committee_subscriptions(|_subscriptions| Ok(())),
        );
        mock.track_admission();
        let beacon = mock.clone() as Arc<dyn BeaconNodeClient>;
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(1).await.expect("seed attester duties");
        let mut key_manager = KeyManager::new();
        key_manager.insert(local);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::from([(pk_bytes, pubkey)])));
        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        validator_store
            .add_validator(validator_store::ValidatorConfig::new(pk_bytes))
            .expect("add validator");
        let service = DutyManagementService::new(
            signer,
            beacon,
            duty_tracker,
            validator_store,
            pubkey_map,
            crate::pubkey_index::PubkeyIndexRegistry::shared(),
            make_config(),
            Arc::default(),
        );
        (service, mock)
    }

    /// With the admission of every beacon node revoked, the cached duty of an
    /// enabled local key is skipped before its selection proof: the call is
    /// `Ok`, with no subscription POST. Control: the same service over an
    /// admitting beacon node POSTs that duty.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_subscriptions_with_admission_revoked_send_nothing() {
        let local = crypto::SecretKey::generate();
        let pk_bytes = local.public_key().to_bytes();
        let (mut service, mock) = build_subscribing_service(local).await;
        assert!(service.validator_store.is_signing_enabled(&pk_bytes), "the key is enabled");
        assert_eq!(service.duty_tracker.get_duties_for_slot(33).await.len(), 1, "duty cached");

        let manager = bn_manager::BnManager::new(bn_manager::BnManagerConfig::new(vec![
            "http://127.0.0.1:9".to_string(),
        ]))
        .expect("bn manager");
        assert!(BeaconNodeClient::duty_fence(&manager).is_ok(), "a new manager starts admitted");
        manager.testing_revoke_admission(0);
        assert!(
            matches!(
                BeaconNodeClient::duty_fence(&manager),
                Err(bn_manager::BeaconError::NoAdmittedNode)
            ),
            "its only node is revoked"
        );
        let revoked = Arc::new(manager) as Arc<dyn BeaconNodeClient>;
        let admitting = std::mem::replace(&mut service.beacon, revoked);

        let outcome = service.submit_committee_subscriptions(1).await;

        assert!(matches!(outcome, Ok(())), "nothing to send is Ok: {outcome:?}");
        assert_eq!(service.selection_proofs.lookups(), 0, "a revoked admission makes no lookup");
        logs_assert(|lines: &[&str]| {
            let count = |text: &str| lines.iter().filter(|line| line.contains(text)).count();
            let skipped = count("skipping committee subscription: beacon node admission revoked");
            let posted = count("Sent committee subscriptions")
                + count("Failed to send committee subscriptions")
                + count("Committee subscription timed out");
            match (skipped, posted) {
                (1, 0) => Ok(()),
                other => Err(format!("(skipped, posted) = {other:?}, want (1, 0)")),
            }
        });

        service.beacon = admitting;
        let outcome = service.submit_committee_subscriptions(1).await;

        assert!(matches!(outcome, Ok(())), "control: {outcome:?}");
        assert_eq!(service.selection_proofs.lookups(), 1, "control: one lookup for the duty");
        let posts = mock
            .call_stamps()
            .iter()
            .filter(|stamp| {
                stamp.method == bn_manager::MockMethod::SubmitBeaconCommitteeSubscriptions
            })
            .count();
        assert_eq!(posts, 1, "control: an admitting beacon node gets the duty's POST");
    }

    /// W4-E8a3: the store gate runs first. A disabled key reads no admission
    /// fence and makes no cache lookup, so a ready proof or an owner in flight
    /// cannot give it a subscription (RSA N2, #1038 R1 and R2). Control: the
    /// enabled key reads one fence, makes one lookup and POSTs.
    #[tokio::test]
    async fn test_disabled_key_makes_no_selection_proof_lookup() {
        let local = crypto::SecretKey::generate();
        let pk_bytes = local.public_key().to_bytes();
        let (service, mock) = build_subscribing_service(local).await;
        service.validator_store.set_enabled(&pk_bytes, false);

        let outcome = service.submit_committee_subscriptions(1).await;

        assert!(matches!(outcome, Ok(())), "nothing to send is Ok: {outcome:?}");
        assert_eq!(mock.duty_fence_calls(), 0, "a disabled key reads no admission fence");
        assert_eq!(service.selection_proofs.lookups(), 0, "a disabled key makes no lookup");
        service.validator_store.set_enabled(&pk_bytes, true);
        let outcome = service.submit_committee_subscriptions(1).await;
        assert!(matches!(outcome, Ok(())), "control: {outcome:?}");
        assert_eq!(mock.duty_fence_calls(), 1, "control: one fence for the duty");
        assert_eq!(service.selection_proofs.lookups(), 1, "control: one lookup for the duty");
        let posts = mock
            .call_stamps()
            .iter()
            .filter(|stamp| {
                stamp.method == bn_manager::MockMethod::SubmitBeaconCommitteeSubscriptions
            })
            .count();
        assert_eq!(posts, 1, "control: the enabled key POSTs");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // W4-E8b (#881): concurrent selection proofs and chunked subscription POSTs
    // ──────────────────────────────────────────────────────────────────────────

    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    use crate::orchestrator::dispatch::DispatchLimits;

    /// The epoch of the duties in [`ManyKeys`].
    const SUBSCRIBED_EPOCH: u64 = 1;

    type SignHook = Box<dyn FnOnce() + Send>;

    /// A remote BLS backend that waits 2 ms of paused time in each sign. It
    /// records each sign when it starts, counts the signs in flight, and runs
    /// the next queued hook at the start of a sign.
    struct SlowRemote {
        proof: crypto::Signature,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
        started: parking_lot::Mutex<Vec<[u8; 48]>>,
        hooks: parking_lot::Mutex<VecDeque<SignHook>>,
    }

    impl SlowRemote {
        fn new() -> Self {
            let key = crypto::SecretKey::from_bytes(&[0x11; 32]).expect("a fixed secret key");
            Self {
                proof: key.sign(b"fixed selection proof"),
                in_flight: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                started: parking_lot::Mutex::default(),
                hooks: parking_lot::Mutex::default(),
            }
        }

        /// Runs `hook` at the start of the next sign that has no hook yet.
        fn on_sign(&self, hook: impl FnOnce() + Send + 'static) {
            self.hooks.lock().push_back(Box::new(hook));
        }

        fn started(&self) -> Vec<[u8; 48]> {
            self.started.lock().clone()
        }

        /// The highest number of signs in flight at the same time.
        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crypto::Signer for SlowRemote {
        async fn sign(
            &self,
            _signing_root: &eth_types::Root,
            pubkey: &[u8; 48],
        ) -> Result<crypto::Signature, crypto::SigningError> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            self.started.lock().push(*pubkey);
            let hook = self.hooks.lock().pop_front();
            if let Some(hook) = hook {
                hook();
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(self.proof.clone())
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            Vec::new()
        }
    }

    type Answers = Vec<Result<(), beacon::BeaconError>>;

    /// A service with `count` enabled keys that sign through one
    /// [`SlowRemote`]. Key `i` has one attester duty at slot offset `i % 32`
    /// of [`SUBSCRIBED_EPOCH`]. The beacon node records the size of each
    /// subscription POST, and `admission` is its admission generation.
    struct ManyKeys {
        service: DutyManagementService,
        remote: Arc<SlowRemote>,
        keys: Vec<[u8; 48]>,
        post_sizes: Arc<parking_lot::Mutex<Vec<usize>>>,
        admission: Arc<std::sync::atomic::AtomicU64>,
    }

    impl ManyKeys {
        /// `answers[n]` is the answer to subscription POST `n`. A POST after
        /// the list gets `Ok`.
        async fn new(count: usize, config: OrchestratorConfig, answers: Answers) -> Self {
            let pubkeys: Vec<crypto::PublicKey> =
                (0..count).map(|_| crypto::SecretKey::generate().public_key()).collect();
            let duties: Vec<beacon::AttesterDuty> = pubkeys
                .iter()
                .enumerate()
                .map(|(i, pubkey)| beacon::AttesterDuty {
                    pubkey: format!("0x{}", hex::encode(pubkey.to_bytes())),
                    validator_index: i.to_string(),
                    committee_index: "0".to_string(),
                    committee_length: "128".to_string(),
                    committees_at_slot: "1".to_string(),
                    validator_committee_index: "0".to_string(),
                    slot: (SUBSCRIBED_EPOCH * SLOTS_PER_EPOCH + i as u64 % SLOTS_PER_EPOCH)
                        .to_string(),
                })
                .collect();
            let post_sizes = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let record = Arc::clone(&post_sizes);
            let answers = parking_lot::Mutex::new(VecDeque::from(answers));
            let mock = Arc::new(
                bn_manager::MockBeaconNodeClient::new()
                    .with_get_attester_duties(move |_epoch, _indices| {
                        Ok(beacon::DependentRootResponse {
                            dependent_root: "0xdeproot".into(),
                            execution_optimistic: false,
                            data: duties.clone(),
                        })
                    })
                    .with_submit_beacon_committee_subscriptions(move |subscriptions| {
                        record.lock().push(subscriptions.len());
                        answers.lock().pop_front().unwrap_or(Ok(()))
                    }),
            );
            let admission = mock.track_admission();
            let beacon = mock as Arc<dyn BeaconNodeClient>;
            let indices = (0..count).map(|i| i.to_string()).collect();
            let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), indices));
            duty_tracker.fetch_duties_for_epoch(SUBSCRIBED_EPOCH).await.expect("seed the duties");
            let remote = Arc::new(SlowRemote::new());
            let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
            let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
            for pubkey in &pubkeys {
                composite.add_remote_key(pubkey.to_bytes(), remote.clone());
                validator_store
                    .add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()))
                    .expect("add validator");
            }
            let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
            let signer = Arc::new(
                SignerService::new(composite, slashing_db).with_enablement(always_enabled()),
            );
            let keys = pubkeys.iter().map(|pubkey| pubkey.to_bytes()).collect();
            let pubkey_map = pubkeys.into_iter().map(|pubkey| (pubkey.to_bytes(), pubkey));
            let service = DutyManagementService::new(
                signer,
                beacon,
                duty_tracker,
                validator_store,
                Arc::new(parking_lot::RwLock::new(pubkey_map.collect())),
                crate::pubkey_index::PubkeyIndexRegistry::shared(),
                config,
                Arc::default(),
            );
            Self { service, remote, keys, post_sizes, admission }
        }

        fn post_sizes(&self) -> Vec<usize> {
            self.post_sizes.lock().clone()
        }
    }

    fn refused(status: u16, message: &str) -> Result<(), beacon::BeaconError> {
        Err(beacon::BeaconError::ApiError { status, message: message.to_string() })
    }

    /// 655-AC1: 2,000 own duties and a signer that waits 2 ms for each sign.
    /// The call ends in less than 1 s of paused time and sends 4 POSTs of
    /// 512 or fewer subscriptions.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_committee_subscriptions_for_2000_keys_finish_within_one_second() {
        let f = ManyKeys::new(2_000, make_config(), Vec::new()).await;

        let start = tokio::time::Instant::now();
        let outcome = f.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "The 2,000 subscriptions must end in less than 1 s of paused time, not {elapsed:?}."
        );
        assert!(matches!(outcome, Ok(())), "The beacon node accepts each POST: {outcome:?}");
        assert_eq!(
            f.post_sizes(),
            [512, 512, 512, 464],
            "The 2,000 subscriptions must go in 4 POSTs of 512 or fewer."
        );
        assert_eq!(f.remote.started().len(), 2_000, "Each duty must sign one selection proof.");
        assert_eq!(f.remote.peak(), 32, "Not more than 32 signs must be in flight.");
    }

    /// The sign cap is the lower value of 32 and `dispatch_limits.concurrency`.
    /// 40 duties sign 4 at a time with a concurrency of 4, and 32 at a time
    /// with a concurrency of 64.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn subscription_sign_cap_is_the_lower_of_32_and_the_dispatch_concurrency() {
        for (concurrency, peak) in [(4, 4), (64, 32)] {
            let limits = DispatchLimits::validated(concurrency, 2).expect("non-zero limits");
            let config = make_config().with_dispatch_limits(limits);
            let f = ManyKeys::new(40, config, Vec::new()).await;

            let outcome = f.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;

            assert!(matches!(outcome, Ok(())), "concurrency {concurrency}: {outcome:?}");
            assert_eq!(f.remote.started().len(), 40, "concurrency {concurrency}: 40 signs");
            assert_eq!(
                f.remote.peak(),
                peak,
                "With a concurrency of {concurrency}, the peak of signs in flight must be {peak}."
            );
        }
    }

    /// The store gate and the admission fences stay in each per-duty future.
    /// Keys 0 to 3 have one duty each, in slot order.
    ///
    /// Part 1 uses the mock beacon node. Key 1 is disabled, and the first
    /// sign (key 0) moves the admission generation. The mock gives a new
    /// fence that holds after the move, but the duties were read before it:
    /// only key 0 signs. On the base code, the duty cache stops serving the
    /// duties of the later slots after the move.
    ///
    /// Part 2 uses a real `BnManager` as the beacon node of the service:
    /// - The first sign (key 0) disables key 1.
    /// - The second sign (key 2) revokes the only beacon node.
    ///
    /// Key 1 must make no cache lookup. Key 3 reads its fence after the
    /// revoke and must make no cache lookup. Only keys 0 and 2 sign.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_concurrent_subscriptions_keep_the_per_sign_fence_and_store_gate() {
        let moved = ManyKeys::new(4, make_config(), Vec::new()).await;
        moved.service.validator_store.set_enabled(&moved.keys[1], false);
        let admission = Arc::clone(&moved.admission);
        moved.remote.on_sign(move || {
            admission.fetch_add(1, Ordering::SeqCst);
        });

        let outcome = moved.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;

        assert_eq!(
            moved.remote.started(),
            [moved.keys[0]],
            "Part 1: only key 0 must sign: key 1 is disabled, and keys 2 and 3 are after the move."
        );
        assert_eq!(moved.service.selection_proofs.lookups(), 1, "Part 1: one cache lookup");
        assert!(matches!(outcome, Ok(())), "Part 1: the POST is accepted: {outcome:?}");
        assert_eq!(moved.post_sizes(), [1], "Part 1: the POST must carry only key 0.");

        let mut f = ManyKeys::new(4, make_config(), Vec::new()).await;
        let config = bn_manager::BnManagerConfig::new(vec!["http://127.0.0.1:9".to_string()]);
        let manager = Arc::new(bn_manager::BnManager::new(config).expect("bn manager"));
        assert!(BeaconNodeClient::duty_fence(manager.as_ref()).is_ok(), "the node is admitted");
        let (store, disabled) = (Arc::clone(&f.service.validator_store), f.keys[1]);
        f.remote.on_sign(move || store.set_enabled(&disabled, false));
        let revoker = Arc::clone(&manager);
        f.remote.on_sign(move || revoker.testing_revoke_admission(0));
        f.service.beacon = manager as Arc<dyn BeaconNodeClient>;

        let outcome = f.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;

        assert_eq!(
            f.remote.started(),
            [f.keys[0], f.keys[2]],
            "Part 2: only key 0 and key 2 must sign: key 1 is disabled, and key 3 is after the revoke."
        );
        assert_eq!(
            f.service.selection_proofs.lookups(),
            2,
            "Part 2: the disabled key and the key after the revoke must make no cache lookup."
        );
        assert!(
            matches!(
                outcome,
                Err(OrchestratorError::Beacon(bn_manager::BeaconError::NoAdmittedNode))
            ),
            "Part 2: the revoked beacon node refuses the POST of the two proofs: {outcome:?}"
        );
    }

    /// Keys 0 to 3 have one duty each, in slot order. The admission
    /// generation moves after the read of the first slot (key 0). Key 0 must
    /// not sign, because its duty was read before the move. The later slots
    /// have no duty that the cache serves after the move.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn duties_read_before_a_revocation_do_not_sign() {
        let f = ManyKeys::new(4, make_config(), Vec::new()).await;
        let admission = Arc::clone(&f.admission);
        AFTER_SLOT_DUTIES.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |slot| {
                if slot == SUBSCRIBED_EPOCH * SLOTS_PER_EPOCH {
                    admission.fetch_add(1, Ordering::SeqCst);
                }
            }));
        });

        let outcome = f.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;
        AFTER_SLOT_DUTIES.with(|hook| hook.borrow_mut().take());

        assert!(f.remote.started().is_empty(), "No duty read before the move must sign.");
        assert_eq!(f.service.selection_proofs.lookups(), 0, "No duty must make a cache lookup.");
        assert!(matches!(outcome, Ok(())), "Nothing to send is Ok: {outcome:?}");
        assert!(f.post_sizes().is_empty(), "The call must send no POST.");
    }

    /// `SUBSCRIPTION_CHUNK`: 512 subscriptions go in one POST, and 513 go in
    /// two POSTs.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn exactly_one_chunk_at_512() {
        for (count, sizes) in [(512, vec![512]), (513, vec![512, 1])] {
            let f = ManyKeys::new(count, make_config(), Vec::new()).await;

            let outcome = f.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;

            assert!(matches!(outcome, Ok(())), "{count} duties: {outcome:?}");
            assert_eq!(
                f.post_sizes(),
                sizes,
                "The POST sizes for {count} duties must be {sizes:?}."
            );
        }
    }

    /// 2,000 duties make 4 chunks, and the second chunk gets a 503. The call
    /// sends the other 3 chunks too, then returns the 503. The retry uses the
    /// cached proofs, and its first and fourth chunks fail: it returns the
    /// first failure.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn subscription_chunk_failure_tries_every_chunk_then_errs() {
        let answers = vec![
            Ok(()),
            refused(503, "unavailable"),
            Ok(()),
            Ok(()),
            refused(500, "first"),
            Ok(()),
            Ok(()),
            refused(503, "last"),
        ];
        let f = ManyKeys::new(2_000, make_config(), answers).await;

        let outcome = f.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;
        let first_posts = f.post_sizes();
        let retry = f.service.submit_committee_subscriptions(SUBSCRIBED_EPOCH).await;

        assert_eq!(
            first_posts,
            [512, 512, 512, 464],
            "The call must send all 4 chunks, also the 2 after the 503."
        );
        assert!(
            matches!(
                &outcome,
                Err(OrchestratorError::Beacon(beacon::BeaconError::ApiError { status: 503, message }))
                    if message == "unavailable"
            ),
            "The call must return the 503 of the second chunk: {outcome:?}"
        );
        assert_eq!(f.post_sizes().len(), 8, "The retry must send all 4 chunks again.");
        assert!(
            matches!(
                &retry,
                Err(OrchestratorError::Beacon(beacon::BeaconError::ApiError { status: 500, message }))
                    if message == "first"
            ),
            "The retry must return its first failure: {retry:?}"
        );
        assert_eq!(f.remote.started().len(), 2_000, "The retry must sign no proof again.");
    }
}
