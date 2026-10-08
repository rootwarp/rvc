use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tracing::{debug, info, info_span, warn, Instrument};

use crate::metrics::{
    orchestrator_result, RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS, RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL,
    RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL, RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS,
};
use beacon::{
    AttestationData as BeaconAttestationData, LegacyAttestation, SingleAttestation,
    VersionedAttestation,
};
use bn_manager::{AttestationSubmitter, BeaconNodeClient, Propagator};
use duty_tracker::{DutyTracker, TypedAttesterDuty};
use eth_types::{ForkName, ForkSchedule, Slot};
use observability::logging::TruncatedPubkey;
use signer::{SignerService, ValidatorSigner};
use timing::{SlotClock, SLOTS_PER_EPOCH};
use validator_store::ValidatorStore;

use super::coordinator::{AttestationResult, OrchestratorConfig, PubkeyMap};
use super::dispatch::{SlotEndDropCounter, WaveAttribution, WaveEntry, SLOT_END_PUBLISH_OVERHANG};
use super::error::OrchestratorError;
use super::slot_anchor::SlotAnchor;
use super::utils;
use super::validation::attestation_data::validate_attestation_data;

/// Decide whether an attestation duty may proceed past the doppelganger gate.
///
/// Returns `true` when the duty is allowed to be signed, `false` when it must be
/// skipped.  This is **fail-closed** (D-3 / FUP-6): the duty is skipped when
///
/// - the pubkey cannot be resolved via `find_pubkey` (case-insensitive,
///   `0x`/`0X`-tolerant) — an unresolved pubkey cannot be gate-checked, so the
///   only safe action is to skip; or
/// - the resolved validator is disabled (`is_signing_enabled` returns `false`),
///   i.e. still inside its post-import doppelganger window (M-12).
///
/// The gate decision is taken on the **infallible** `pk.to_bytes()` of the
/// already-resolved typed `PublicKey`, never by re-decoding the raw beacon
/// pubkey string.  This mirrors the sibling sync/aggregate/coordinator paths
/// and removes the previous fail-OPEN fall-through where a non-`0x`-lowercase
/// or non-decoding pubkey string skipped the gate entirely.
pub(crate) fn attestation_duty_enabled(
    duty: &TypedAttesterDuty,
    pubkey_map: &PubkeyMap,
    validator_store: &ValidatorStore,
    slot: Slot,
) -> bool {
    let Some(pk) = utils::find_pubkey(pubkey_map, &duty.pubkey) else {
        warn!(
            pubkey = %TruncatedPubkey::new(&duty.pubkey),
            slot,
            "Skipping attestation duty: pubkey did not resolve to a tracked \
             validator (D-3 fail-closed)"
        );
        return false;
    };

    let pk_bytes = pk.to_bytes();
    if !validator_store.is_signing_enabled(&pk_bytes) {
        warn!(
            pubkey = %TruncatedPubkey::new(&duty.pubkey),
            slot,
            "Skipping attestation duty: validator is inside the \
             post-import doppelganger window (M-12)"
        );
        return false;
    }

    true
}

pub(crate) struct AttestationService<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    clock: Arc<C>,
    signer: Arc<SignerService>,
    propagator: Arc<Propagator<S>>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    /// M-12 (Critical #1): per-validator enabled flag.  Duties for validators
    /// that are still inside the post-import doppelganger window
    /// (`enabled = false`) are skipped so that a freshly imported key does
    /// not attest until the window has elapsed and the background task flips
    /// the flag to `true`.
    validator_store: Arc<ValidatorStore>,
    /// Duties not pulled onto the sign pipeline before slot end.
    slot_end_drops: SlotEndDropCounter,
}

/// Attestation data for one `process_slot` call.
///
/// Not stored on the service: the next slot builds a new memo. `fork` is the
/// duty slot's fork (`slot / SLOTS_PER_EPOCH`), which is known before the
/// beacon response. `None` keys are post-Electra (one fetch for the slot);
/// `Some(committee)` keys are pre-Electra.
struct AttestationDataMemo {
    slot: Slot,
    fork: ForkName,
    /// The shared post-Electra response was for a different fork, so `entries`
    /// were refetched per committee.
    degraded: bool,
    entries: HashMap<Option<u64>, Result<Arc<BeaconAttestationData>, String>>,
}

#[derive(Clone, Copy)]
struct MemoQuery {
    key: Option<u64>,
    /// Beacon API `committee_index`. Post-Electra this is 0, not the duty's committee.
    committee_index: u64,
}

/// `None` once attestation data is shared across committees (Electra and later).
fn memo_key(fork: ForkName, committee_index: u64) -> Option<u64> {
    if utils::uses_electra_attestation_wire(fork) {
        None
    } else {
        Some(committee_index)
    }
}

fn distinct_committee_indexes(duties: &[TypedAttesterDuty]) -> Vec<u64> {
    let mut indexes = Vec::new();
    for duty in duties {
        indexes.push(duty.committee_index);
    }
    indexes.sort_unstable();
    indexes.dedup();
    indexes
}

fn memo_queries(fork: ForkName, committees: &[u64]) -> Vec<MemoQuery> {
    if utils::uses_electra_attestation_wire(fork) {
        // Beacon API: after Electra, `committee_index` must be 0. The duty
        // committee is not part of the cache key.
        vec![MemoQuery { key: None, committee_index: 0 }]
    } else {
        committees
            .iter()
            .copied()
            .map(|committee_index| MemoQuery { key: Some(committee_index), committee_index })
            .collect()
    }
}

fn response_fork(data: &BeaconAttestationData, schedule: &ForkSchedule) -> Option<ForkName> {
    let epoch = data.target.epoch.parse().ok()?;
    Some(ForkName::from_epoch(epoch, schedule))
}

impl AttestationDataMemo {
    fn get(&self, committee_index: u64) -> Result<Arc<BeaconAttestationData>, String> {
        let key = if self.degraded {
            Some(committee_index)
        } else {
            memo_key(self.fork, committee_index)
        };
        match self.entries.get(&key) {
            Some(Ok(data)) => Ok(Arc::clone(data)),
            Some(Err(error)) => Err(error.clone()),
            None => Err("Attestation data was not fetched for this duty".to_string()),
        }
    }
}

impl<C, S> AttestationService<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        clock: Arc<C>,
        signer: Arc<SignerService>,
        propagator: Arc<Propagator<S>>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
        validator_store: Arc<ValidatorStore>,
    ) -> Self {
        Self {
            clock,
            signer,
            propagator,
            beacon,
            duty_tracker,
            pubkey_map,
            config,
            validator_store,
            slot_end_drops: SlotEndDropCounter::default(),
        }
    }

    /// Duties dropped because slot end arrived before they were dispatched.
    #[cfg(test)]
    pub(crate) fn slot_end_drops(&self) -> u64 {
        self.slot_end_drops.get()
    }

    /// Processes attestation duties for `slot` until the clock's slot end.
    ///
    /// Derives `slot_end` from [`SlotAnchor`] so callers that only have a slot
    /// (pipeline fixture, coordinator tests) keep the same signature.
    pub(crate) async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        let slot_end = SlotAnchor::capture(&*self.clock, slot).slot_end();
        self.process_slot_until(slot, slot_end).await
    }

    /// Sign and publish `slot`'s attestation duties until `slot_end`.
    ///
    /// `take_until` bounds the duty input. Signs already in flight drain.
    /// Duties not yet pulled are dropped and counted. Publish is admitted only
    /// until `slot_end + 500 ms`; a submit still running then is cancelled.
    #[tracing::instrument(name = "orchestrator.process_slot", level = "debug", skip_all, fields(slot = slot))]
    pub(crate) async fn process_slot_until(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        let _timer = RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS
            .with_label_values(&[] as &[&str])
            .start_timer();

        info!(slot = slot, "Processing attestation duties for slot");

        let current_slot = self.clock.current_slot()?;

        if current_slot > slot {
            RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL.with_label_values(&[] as &[&str]).inc();
            return Err(OrchestratorError::SlotMissed { slot, current_slot });
        }

        let raw_duties =
            utils::get_duties_for_slot(&self.pubkey_map, &self.duty_tracker, slot).await?;

        // M-12 (Critical #1) / D-3: skip duties for validators still inside
        // their post-import doppelganger window, or whose pubkey cannot be
        // resolved.  The decision is fail-CLOSED: a duty is dropped unless its
        // pubkey resolves to a tracked validator whose `is_signing_enabled`
        // flag is `true`.  Keystore-loaded keys are registered in the store at
        // startup (`ServiceBuilder::register_loaded_validators`), so they
        // resolve and remain enabled; an unresolved or disabled pubkey is
        // skipped rather than passed through.  See `attestation_duty_enabled`.
        let duties: Vec<TypedAttesterDuty> = raw_duties
            .into_iter()
            .filter(|duty| {
                attestation_duty_enabled(duty, &self.pubkey_map, &self.validator_store, slot)
            })
            .collect();

        if duties.is_empty() {
            debug!(slot = slot, "No attestation duties for this slot");
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::NO_DUTIES])
                .inc();
            return Err(OrchestratorError::NoDutiesForSlot { slot });
        }

        info!(slot = slot, duty_count = duties.len(), "Found attestation duties");
        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(duties.len() as f64);

        let memo = self.load_attestation_data_memo(slot, &duties, slot_end).await;

        let duty_count = duties.len();
        let concurrency = self.config.dispatch_limits.concurrency as usize;
        let publish_concurrency = self.config.dispatch_limits.publish_concurrency as usize;
        let waves = stream::iter(duties)
            .take_until(tokio::time::sleep_until(slot_end))
            .map(|duty| self.sign_one(duty, &memo))
            .buffer_unordered(concurrency)
            .ready_chunks(concurrency)
            .map(|wave| self.publish_wave(slot, slot_end, wave))
            .buffer_unordered(publish_concurrency);
        let mut waves = std::pin::pin!(waves);
        let mut results = Vec::with_capacity(duty_count);
        while let Some(wave_results) = waves.next().await {
            results.extend(wave_results);
        }

        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(0.0);

        let dropped = (duty_count as u64).saturating_sub(results.len() as u64);
        if dropped > 0 {
            self.slot_end_drops.record(dropped);
            warn!(
                slot,
                dropped,
                duty_count,
                total_dropped = self.slot_end_drops.get(),
                "undispatched attestation duties dropped at slot end"
            );
        }

        let success_count = results.iter().filter(|r| r.success).count();
        let failure_count = results.len() - success_count;

        if failure_count > 0 || dropped > 0 {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::FAILED])
                .inc();
        } else {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::SUCCESS])
                .inc();
        }

        let target_epoch = slot / SLOTS_PER_EPOCH;
        info!(slot = slot, count = success_count, target_epoch, "Batch attestation summary");

        info!(
            slot = slot,
            total = results.len(),
            success = success_count,
            failed = failure_count,
            dropped,
            "Slot processing complete"
        );

        Ok(results)
    }

    /// Fill the per-slot memo before signing.
    ///
    /// Distinct keys run under `dispatch_limits.concurrency`, so k pre-Electra
    /// committees cost `ceil(k / concurrency)` round trips. A key that fails
    /// is stored as `Err` and fails only the duties that share that key.
    /// Each key gets at most one retry, and both attempts share
    /// `timeouts.attestation_fetch` — a second budget is not started.
    ///
    /// When the duty-slot fork says the data is shared but the response's
    /// target epoch resolves to a different fork, the shared entry is dropped
    /// and each committee is fetched on its own. Per-duty normalization still
    /// uses that response fork.
    async fn load_attestation_data_memo(
        &self,
        slot: Slot,
        duties: &[TypedAttesterDuty],
        slot_end: tokio::time::Instant,
    ) -> AttestationDataMemo {
        let fork = ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &self.config.fork_schedule);
        let committees = distinct_committee_indexes(duties);
        if tokio::time::Instant::now() >= slot_end || committees.is_empty() {
            return AttestationDataMemo { slot, fork, degraded: false, entries: HashMap::new() };
        }

        let queries = memo_queries(fork, &committees);
        let mut entries = self.fetch_memo_entries(slot, &queries).await;
        let mut degraded = false;
        if utils::uses_electra_attestation_wire(fork) {
            let disagrees =
                entries.get(&None).and_then(|result| result.as_ref().ok()).is_some_and(|data| {
                    response_fork(data, &self.config.fork_schedule)
                        .is_some_and(|response| response != fork)
                });
            if disagrees {
                degraded = true;
                let per_committee: Vec<MemoQuery> = committees
                    .iter()
                    .copied()
                    .map(|committee_index| MemoQuery {
                        key: Some(committee_index),
                        committee_index,
                    })
                    .collect();
                entries = self.fetch_memo_entries(slot, &per_committee).await;
                debug!(
                    slot,
                    memo_fork = ?fork,
                    committees = committees.len(),
                    "attestation data fork disagreed with the duty slot; fetched per committee"
                );
            }
        }

        debug!(
            slot,
            fork = ?fork,
            keys = entries.len(),
            degraded,
            "attestation data memo ready"
        );
        AttestationDataMemo { slot, fork, degraded, entries }
    }

    async fn fetch_memo_entries(
        &self,
        slot: Slot,
        queries: &[MemoQuery],
    ) -> HashMap<Option<u64>, Result<Arc<BeaconAttestationData>, String>> {
        if queries.is_empty() {
            return HashMap::new();
        }
        let concurrency = self.config.dispatch_limits.concurrency as usize;
        let fetched: Vec<_> = stream::iter(queries.iter().copied())
            .map(|query| self.fetch_memo_query(slot, query))
            .buffer_unordered(concurrency)
            .collect()
            .await;
        fetched.into_iter().collect()
    }

    async fn fetch_memo_query(
        &self,
        slot: Slot,
        query: MemoQuery,
    ) -> (Option<u64>, Result<Arc<BeaconAttestationData>, String>) {
        let result = self.fetch_attestation_data_with_retry(slot, query.committee_index).await;
        (query.key, result)
    }

    /// One attempt, and a second only when the first failed before the deadline.
    async fn fetch_attestation_data_with_retry(
        &self,
        slot: Slot,
        committee_index: u64,
    ) -> Result<Arc<BeaconAttestationData>, String> {
        let deadline = tokio::time::Instant::now() + self.config.timeouts.attestation_fetch;
        match self.fetch_attestation_data_attempt(slot, committee_index, deadline).await {
            Ok(data) => Ok(data),
            Err(first) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(first);
                }
                debug!(
                    slot,
                    committee_index,
                    error = %first,
                    "retrying attestation data fetch inside attestation_fetch"
                );
                self.fetch_attestation_data_attempt(slot, committee_index, deadline).await
            }
        }
    }

    async fn fetch_attestation_data_attempt(
        &self,
        slot: Slot,
        committee_index: u64,
        deadline: tokio::time::Instant,
    ) -> Result<Arc<BeaconAttestationData>, String> {
        if tokio::time::Instant::now() >= deadline {
            return Err("Timeout getting attestation data from beacon node".to_string());
        }
        let result = tokio::time::timeout_at(
            deadline,
            self.beacon.get_attestation_data(slot, committee_index),
        )
        .instrument(info_span!("beacon.get_attestation_data", slot, committee_index))
        .await;
        match result {
            Ok(Ok(response)) => Ok(Arc::new(response.data)),
            Ok(Err(error)) => Err(format!("Failed to get attestation data: {error}")),
            Err(_elapsed) => Err("Timeout getting attestation data from beacon node".to_string()),
        }
    }

    /// Produce and sign one duty. Publish is a later wave, not this future.
    async fn sign_one(
        &self,
        duty: TypedAttesterDuty,
        memo: &AttestationDataMemo,
    ) -> Result<WaveEntry, AttestationResult> {
        let validator_index = duty.raw.validator_index.clone();
        let pubkey = duty.pubkey.clone();
        // Written from the typed duty slot before any fallible step. Stays 0
        // only when `attest` has not yet copied it.
        let mut slot: Slot = 0;

        match self.attest(&duty, &validator_index, &mut slot, memo).await {
            Ok(attestation) => Ok(WaveEntry {
                attribution: WaveAttribution { validator_index, pubkey, slot },
                attestation,
            }),
            Err(error) => {
                let result =
                    AttestationResult { validator_index, slot, success: false, error: Some(error) };
                warn!(
                    validator_index = %result.validator_index,
                    slot = result.slot,
                    error = ?result.error,
                    "Attestation failed"
                );
                Err(result)
            }
        }
    }

    /// One array POST for a wave. Partial failures are attributed, not retried.
    ///
    /// The POST's deadline is the earlier of the `attestation_submit` timeout
    /// and `slot_end` plus 500 ms. Signs already running are not cancelled; a
    /// wave that becomes ready after that instant is not sent.
    async fn publish_wave(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
        wave: Vec<Result<WaveEntry, AttestationResult>>,
    ) -> Vec<AttestationResult> {
        let mut results = Vec::with_capacity(wave.len());
        let mut signed = Vec::new();
        for item in wave {
            match item {
                Ok(entry) => signed.push(entry),
                Err(result) => results.push(result),
            }
        }
        if signed.is_empty() {
            return results;
        }

        debug_assert!(
            wave_is_homogeneous(&signed),
            "attestation wave mixes VersionedAttestation variants at slot {slot}"
        );
        if !wave_is_homogeneous(&signed) {
            for entry in signed {
                results.push(self.failed_publish(
                    entry,
                    "mixed attestation fork in one publish wave".to_string(),
                ));
            }
            return results;
        }

        let now = tokio::time::Instant::now();
        let overhang_at = slot_end + SLOT_END_PUBLISH_OVERHANG;
        let submit_at =
            now.checked_add(self.config.timeouts.attestation_submit).unwrap_or(overhang_at);
        let deadline = overhang_at.min(submit_at);
        let bounded_by_overhang = deadline == overhang_at;
        if now >= deadline {
            let message = attestation_publish_stop_message(
                bounded_by_overhang,
                self.config.timeouts.attestation_submit,
            );
            for entry in signed {
                results.push(self.failed_publish(entry, message.clone()));
            }
            return results;
        }

        let merged = merge_wave(&signed);
        let submit_result =
            tokio::time::timeout_at(deadline, self.propagator.propagate_indexed(&merged))
                .instrument(info_span!("beacon.submit_attestation", slot, count = signed.len()))
                .await;

        match submit_result {
            Ok(Ok(outcome)) => {
                let bn = outcome.reported_by.unwrap_or_default();
                let mut rejected = HashMap::<u32, String>::new();
                for failure in outcome.failures {
                    let positioned =
                        usize::try_from(failure.index).ok().and_then(|i| signed.get(i));
                    match positioned {
                        Some(entry) => {
                            warn!(
                                validator_index = %entry.attribution.validator_index,
                                pubkey = %TruncatedPubkey::new(&entry.attribution.pubkey),
                                bn = %bn,
                                message = %failure.message,
                                "Attestation submission failed"
                            );
                            rejected.insert(failure.index, failure.message);
                        }
                        None => {
                            warn!(
                                slot,
                                index = failure.index,
                                bn = %bn,
                                message = %failure.message,
                                "Attestation submission failed for an unknown wave index"
                            );
                        }
                    }
                }
                for (index, entry) in signed.into_iter().enumerate() {
                    let index = u32::try_from(index).unwrap_or(u32::MAX);
                    if let Some(message) = rejected.remove(&index) {
                        results.push(AttestationResult {
                            validator_index: entry.attribution.validator_index,
                            slot: entry.attribution.slot,
                            success: false,
                            error: Some(message),
                        });
                    } else {
                        results.push(self.successful_publish(entry));
                    }
                }
            }
            Ok(Err(error)) => {
                let message = format!("Failed to propagate attestation: {error}");
                tracing::error!(slot, error = %message, "Attestation submission failed");
                for entry in signed {
                    results.push(self.failed_publish(entry, message.clone()));
                }
            }
            Err(_) => {
                let message = attestation_publish_stop_message(
                    bounded_by_overhang,
                    self.config.timeouts.attestation_submit,
                );
                tracing::error!(slot, bounded_by_overhang, "Attestation submission timed out");
                for entry in signed {
                    results.push(self.failed_publish(entry, message.clone()));
                }
            }
        }
        results
    }

    fn successful_publish(&self, entry: WaveEntry) -> AttestationResult {
        let result = AttestationResult {
            validator_index: entry.attribution.validator_index,
            slot: entry.attribution.slot,
            success: true,
            error: None,
        };
        // Per-validator completion is developer detail (scales with validator
        // count); the per-slot "Batch attestation summary" is the operator
        // milestone at info.
        debug!(
            validator_index = %result.validator_index,
            slot = result.slot,
            "Attestation completed successfully"
        );
        result
    }

    fn failed_publish(&self, entry: WaveEntry, error: String) -> AttestationResult {
        let result = AttestationResult {
            validator_index: entry.attribution.validator_index,
            slot: entry.attribution.slot,
            success: false,
            error: Some(error),
        };
        warn!(
            validator_index = %result.validator_index,
            slot = result.slot,
            error = ?result.error,
            "Attestation failed"
        );
        result
    }

    /// Produce and sign a single attestation duty.
    ///
    /// Returns the signed [`VersionedAttestation`] (one item). On failure
    /// returns a user-visible error string. Publish is [`Self::publish_wave`].
    ///
    /// `slot` is written from the typed duty before any fallible step.
    async fn attest(
        &self,
        duty: &TypedAttesterDuty,
        validator_index: &str,
        slot: &mut Slot,
        memo: &AttestationDataMemo,
    ) -> Result<VersionedAttestation, String> {
        *slot = duty.slot;
        debug_assert_eq!(memo.slot, *slot);

        let committee_index = duty.committee_index;

        let att_span = info_span!(
            "attestation.produce",
            slot = *slot,
            validator_index = %validator_index,
            pubkey = %TruncatedPubkey::new(&duty.pubkey),
        );

        {
            let _guard = att_span.enter();
            debug!(
                validator_index = %validator_index,
                slot = *slot,
                committee_index = committee_index,
                "Processing attestation duty"
            );
        }

        let pubkey = utils::find_pubkey(&self.pubkey_map, &duty.pubkey)
            .ok_or_else(|| format!("Public key not found: {}", duty.pubkey))?;

        // Fetched once per memo key before this sign stream. Normalization below
        // still uses the response's target epoch, not `memo.fork`.
        let beacon_attestation_data = (*memo.get(committee_index)?).clone();

        debug!(
            validator_index = %validator_index,
            slot = %beacon_attestation_data.slot,
            committee_index = %beacon_attestation_data.index,
            head = %beacon_attestation_data.beacon_block_root,
            source_epoch = %beacon_attestation_data.source.epoch,
            source_root = %beacon_attestation_data.source.root,
            target_epoch = %beacon_attestation_data.target.epoch,
            target_root = %beacon_attestation_data.target.root,
            "Attestation data fetched from BN"
        );

        // Pre-parse target epoch to derive the fork before full conversion.
        // This allows `convert_and_normalize_attestation_data` to handle the
        // EIP-7549 index-zeroing in one place for both attestation and aggregation paths.
        let target_epoch: u64 = beacon_attestation_data.target.epoch.parse().map_err(|_| {
            format!("Failed to parse target epoch: {}", beacon_attestation_data.target.epoch)
        })?;

        let fork_name = ForkName::from_epoch(target_epoch, &self.config.fork_schedule);
        let uses_electra_wire = utils::uses_electra_attestation_wire(fork_name);

        debug!(
            validator_index = %validator_index,
            fork_name = ?fork_name,
            uses_electra_wire = uses_electra_wire,
            target_epoch = target_epoch,
            "Fork derived for attestation"
        );

        // EIP-7549: Electra through Fulu zero `AttestationData.index` before
        // signing. `convert_and_normalize_attestation_data` handles this centrally
        // so both the attestation and aggregation paths stay in sync.
        let crypto_attestation_data =
            utils::convert_and_normalize_attestation_data(&beacon_attestation_data, fork_name)
                .map_err(|e| format!("Failed to convert attestation data: {}", e))?;

        debug!(
            validator_index = %validator_index,
            slot = crypto_attestation_data.slot,
            index = crypto_attestation_data.index,
            target_epoch = target_epoch,
            source_epoch = crypto_attestation_data.source.epoch,
            "Converted attestation data"
        );

        // M-2: local AttestationData sanity check before sign.
        // Re-fetch the current clock slot here so the window check uses the
        // most recent local view (≤1 ms delta from the check at process_slot).
        let current_clock_slot = match self.clock.current_slot() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    validator_index = %validator_index,
                    slot = *slot,
                    "Failed to read clock slot for AttestationData sanity check; \
                     dropping duty"
                );
                return Err(format!("Clock error during attestation validation: {e}"));
            }
        };
        if let Err(e) =
            validate_attestation_data(&crypto_attestation_data, *slot, current_clock_slot)
        {
            tracing::error!(
                error = %e,
                validator_index = %validator_index,
                pubkey = %observability::logging::TruncatedPubkey::new(&duty.pubkey),
                slot = *slot,
                "AttestationData failed sanity check (M-2); dropping duty"
            );
            return Err(format!("AttestationData sanity check failed: {e}"));
        }

        let signature = match self
            .signer
            .sign_attestation(
                &crypto_attestation_data,
                &pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            )
            .instrument(att_span.clone())
            .await
        {
            Ok(sig) => {
                let sig_bytes = sig.to_bytes();
                debug!(
                    validator_index = %validator_index,
                    signature_prefix = %format!("0x{}", hex::encode(&sig_bytes[..8])),
                    "Attestation signed successfully"
                );
                sig
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    validator_index = %validator_index,
                    slot = *slot,
                    "Attestation signing failed"
                );
                return Err(format!("Failed to sign attestation: {}", e));
            }
        };

        let attester_index = duty.validator_index;

        let sig_hex = format!("0x{}", hex::encode(signature.to_bytes()));

        // Electra+ shares SingleAttestation; EIP-7549 index-zeroing is
        // Electra..Gloas only. Variant is the resolved fork, not `>= Fulu`.
        let versioned = if uses_electra_wire {
            let mut single_data = beacon_attestation_data.clone();
            if utils::zeroes_committee_index(fork_name) {
                single_data.index = "0".to_string();
            }
            let single = SingleAttestation {
                committee_index,
                attester_index,
                data: single_data,
                signature: sig_hex,
            };
            if fork_name == ForkName::Gloas {
                VersionedAttestation::Gloas(vec![single])
            } else if fork_name == ForkName::Fulu {
                VersionedAttestation::Fulu(vec![single])
            } else {
                VersionedAttestation::Electra(vec![single])
            }
        } else {
            let aggregation_bits = match utils::make_aggregation_bits(duty) {
                Some(bits) => bits,
                None => {
                    warn!(
                        validator_index = %validator_index,
                        slot = *slot,
                        "Skipping attestation: could not produce aggregation bits"
                    );
                    return Err("could not produce aggregation bits (committee_length=0 \
                         or validator_committee_index out of range)"
                        .to_string());
                }
            };
            VersionedAttestation::PreElectra(vec![LegacyAttestation {
                aggregation_bits,
                data: beacon_attestation_data,
                signature: sig_hex,
            }])
        };

        let versioned_type = attestation_variant_name(&versioned);
        debug!(
            validator_index = %validator_index,
            versioned_type = versioned_type,
            "Signed attestation"
        );
        Ok(versioned)
    }
}

fn attestation_publish_stop_message(bounded_by_overhang: bool, submit_timeout: Duration) -> String {
    if bounded_by_overhang {
        format!(
            "Attestation publish exceeded the {} ms slot-end overhang",
            SLOT_END_PUBLISH_OVERHANG.as_millis()
        )
    } else {
        format!("Attestation submit timed out after {}s", submit_timeout.as_secs())
    }
}

fn attestation_variant_name(attestation: &VersionedAttestation) -> &'static str {
    match attestation {
        VersionedAttestation::Gloas(_) => "Gloas",
        VersionedAttestation::Fulu(_) => "Fulu",
        VersionedAttestation::Electra(_) => "Electra",
        VersionedAttestation::PreElectra(_) => "PreElectra",
    }
}

fn wave_is_homogeneous(entries: &[WaveEntry]) -> bool {
    let Some(first) = entries.first() else {
        return true;
    };
    let kind = attestation_variant_name(&first.attestation);
    entries.iter().all(|entry| attestation_variant_name(&entry.attestation) == kind)
}

/// Concatenate a homogeneous wave into one array body.
fn merge_wave(entries: &[WaveEntry]) -> VersionedAttestation {
    debug_assert!(wave_is_homogeneous(entries));
    match &entries[0].attestation {
        VersionedAttestation::PreElectra(_) => {
            let mut batch = Vec::with_capacity(entries.len());
            for entry in entries {
                if let VersionedAttestation::PreElectra(items) = &entry.attestation {
                    batch.extend(items.iter().cloned());
                }
            }
            VersionedAttestation::PreElectra(batch)
        }
        VersionedAttestation::Electra(_) => {
            VersionedAttestation::Electra(collect_singles(entries, |att| match att {
                VersionedAttestation::Electra(items) => Some(items),
                _ => None,
            }))
        }
        VersionedAttestation::Fulu(_) => {
            VersionedAttestation::Fulu(collect_singles(entries, |att| match att {
                VersionedAttestation::Fulu(items) => Some(items),
                _ => None,
            }))
        }
        VersionedAttestation::Gloas(_) => {
            VersionedAttestation::Gloas(collect_singles(entries, |att| match att {
                VersionedAttestation::Gloas(items) => Some(items),
                _ => None,
            }))
        }
    }
}

fn collect_singles(
    entries: &[WaveEntry],
    pick: impl Fn(&VersionedAttestation) -> Option<&Vec<SingleAttestation>>,
) -> Vec<SingleAttestation> {
    let mut batch = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(items) = pick(&entry.attestation) {
            batch.extend(items.iter().cloned());
        }
    }
    batch
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use beacon::AttesterDuty;
    use crypto::{PublicKey, SecretKey};
    use parking_lot::RwLock;
    use validator_store::{ValidatorConfig, ValidatorStore};

    /// Build a minimal `AttesterDuty` for the given pubkey string.
    fn duty_with_pubkey(pubkey: &str) -> AttesterDuty {
        AttesterDuty {
            pubkey: pubkey.to_string(),
            validator_index: "0".to_string(),
            committee_index: "0".to_string(),
            committee_length: "1".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "0".to_string(),
            slot: "0".to_string(),
        }
    }

    /// Build a `PubkeyMap` containing a single resolvable pubkey under its
    /// canonical `0x`-lowercase key (the form the orchestrator inserts).
    fn pubkey_map_with(pubkey: &PublicKey) -> PubkeyMap {
        let mut map: HashMap<[u8; 48], PublicKey> = HashMap::new();
        map.insert(pubkey.to_bytes(), pubkey.clone());
        Arc::new(RwLock::new(map))
    }

    fn disabled_store(pubkey: &PublicKey) -> ValidatorStore {
        let store = ValidatorStore::new([0u8; 20], 30_000_000);
        let mut config = ValidatorConfig::new(pubkey.to_bytes());
        config.enabled = false;
        store.add_validator(config).unwrap();
        store
    }

    /// FUP-6 / D-3 RED: a duty whose pubkey is uppercase-`0X`-prefixed is
    /// resolvable via `find_pubkey` (case-insensitive `CanonicalPubkey`), so the
    /// gate MUST be consulted.  The validator is disabled, so the duty must be
    /// SKIPPED (fail-closed).
    ///
    /// On `develop` the inline filter used `strip_prefix("0x")` (lowercase only)
    /// then `hex::decode`, which fails on a `0X` prefix and falls through to
    /// `true` — fail OPEN.  This test fails on `develop` and passes after the
    /// fail-closed fix.
    #[test]
    fn test_uppercase_0x_disabled_validator_is_skipped_fail_closed() {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key();

        // Duty carries the uppercase `0X` prefix — `find_pubkey` resolves it,
        // but the old lowercase-only `strip_prefix("0x")` + decode does not.
        let duty_pubkey = format!("0X{}", hex::encode(pubkey.to_bytes()).to_uppercase());
        let duty = TypedAttesterDuty::try_from(&duty_with_pubkey(&duty_pubkey)).expect("fixture");

        let pubkey_map = pubkey_map_with(&pubkey);
        let store = disabled_store(&pubkey);

        assert!(
            !attestation_duty_enabled(&duty, &pubkey_map, &store, 0),
            "uppercase-0X duty for a disabled validator must be SKIPPED (fail-closed); \
             the old lowercase-only decode falls through to enabled=true (fail-open)"
        );
    }

    /// FUP-6 / D-3 RED: a duty whose pubkey does not resolve via `find_pubkey`
    /// at all must be SKIPPED (fail-closed) — an unresolved pubkey cannot be
    /// gate-checked, so the only safe action is to skip.
    ///
    /// On `develop` an unresolved-but-decodable 48-byte pubkey reaches
    /// `is_signing_enabled` and is skipped, but a NON-decoding pubkey falls
    /// through to `true`.  This test uses a non-hex pubkey to exercise the
    /// fail-open path.
    #[test]
    fn test_unresolved_nondecoding_pubkey_is_skipped_fail_closed() {
        // Not valid hex (contains 'z') and not present in the map.
        let duty =
            TypedAttesterDuty::try_from(&duty_with_pubkey("0xzzzznotvalidhex")).expect("fixture");

        let other = SecretKey::generate().public_key();
        let pubkey_map = pubkey_map_with(&other);
        let store = disabled_store(&other);

        assert!(
            !attestation_duty_enabled(&duty, &pubkey_map, &store, 0),
            "a duty whose pubkey does not resolve via find_pubkey must be SKIPPED \
             (fail-closed); the old code falls through to enabled=true (fail-open)"
        );
    }

    /// GREEN guard: the fail-closed fix must NOT over-skip — a resolvable,
    /// enabled validator's duty (even with an uppercase `0X` prefix) is allowed.
    #[test]
    fn test_resolvable_enabled_validator_is_allowed() {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key();

        let duty_pubkey = format!("0X{}", hex::encode(pubkey.to_bytes()).to_uppercase());
        let duty = TypedAttesterDuty::try_from(&duty_with_pubkey(&duty_pubkey)).expect("fixture");

        let pubkey_map = pubkey_map_with(&pubkey);
        let store = ValidatorStore::new([0u8; 20], 30_000_000);
        store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap(); // enabled by default

        assert!(
            attestation_duty_enabled(&duty, &pubkey_map, &store, 0),
            "a resolvable, enabled validator must be allowed through the gate"
        );
    }
}

/// Concurrent dispatch coverage (RR2-03). Lives beside [`AttestationService`].
#[cfg(test)]
mod dispatch_pipeline {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use beacon::{
        AttestationData, AttestationDataResponse, AttesterDutiesResponse, AttesterDuty,
        BeaconError, Checkpoint, IndexedAttestationError, SubmitAttestationResult,
        VersionedAttestation,
    };
    use bn_manager::{
        AttestationSubmitter, BeaconNodeClient, MockBeaconNodeClient, MockMethod, Propagator,
    };
    use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
    use duty_tracker::DutyTracker;
    use eth_types::ForkSchedule;
    use signer::{always_enabled, PreReserveBarrier, SignerService};
    use slashing::SlashingDb;
    use timing::MockSlotClock;
    use tracing_test::traced_test;

    use super::super::dispatch::DispatchLimits;
    use super::AttestationService;
    use crate::orchestrator::{OrchestratorConfig, PubkeyMap};

    const SLOT: u64 = 1_600;
    const GENESIS: u64 = 1_606_824_023;

    struct LocalKey {
        pubkey: PublicKey,
        pubkey_hex_0x: String,
        index: String,
    }

    struct FixtureOpts {
        request_delay: Duration,
        /// When set, this method uses `delay` and every other role-trait call stays instant.
        only_delay: Option<(MockMethod, Duration)>,
        concurrency: u32,
        publish_concurrency: u32,
        /// Validator offset whose store flag stays disabled (doppelganger Pending).
        pending: Option<usize>,
        /// Second duty for validator 0, same slot, so two reserves share a pubkey.
        duplicate_first: bool,
        /// Replaces `OperationTimeouts::attestation_submit` when set.
        submit_timeout: Option<Duration>,
    }

    impl Default for FixtureOpts {
        fn default() -> Self {
            Self {
                request_delay: Duration::ZERO,
                only_delay: None,
                concurrency: DispatchLimits::DEFAULT_CONCURRENCY,
                publish_concurrency: DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY,
                pending: None,
                duplicate_first: false,
                submit_timeout: None,
            }
        }
    }

    struct Fixture<S: AttestationSubmitter + 'static> {
        service: AttestationService<MockSlotClock, S>,
        beacon: Arc<MockBeaconNodeClient>,
        signer: Arc<SignerService>,
        _db_dir: tempfile::TempDir,
    }

    fn fork_schedule() -> Arc<ForkSchedule> {
        Arc::new(ForkSchedule {
            genesis_fork_version: [0, 0, 0, 1],
            altair_fork_epoch: 10,
            altair_fork_version: [0, 0, 0, 2],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [0, 0, 0, 3],
            capella_fork_epoch: 30,
            capella_fork_version: [0, 0, 0, 4],
            deneb_fork_epoch: 40,
            deneb_fork_version: [0, 0, 0, 5],
            electra_fork_epoch: 50,
            electra_fork_version: [0, 0, 0, 6],
            fulu_fork_epoch: 60,
            fulu_fork_version: [0, 0, 0, 7],
            gloas_fork_epoch: 70,
            gloas_fork_version: [0, 0, 0, 8],
        })
    }

    fn attestation_data(slot: u64) -> AttestationData {
        let epoch = slot / 32;
        let root = |byte: u8| format!("0x{}", hex::encode([byte; 32]));
        AttestationData {
            slot: slot.to_string(),
            index: "0".to_string(),
            beacon_block_root: root(0x11),
            source: Checkpoint { epoch: epoch.saturating_sub(1).to_string(), root: root(0x22) },
            target: Checkpoint { epoch: epoch.to_string(), root: root(0x33) },
        }
    }

    fn duty(key: &LocalKey, committee: u64) -> AttesterDuty {
        AttesterDuty {
            pubkey: key.pubkey_hex_0x.clone(),
            validator_index: key.index.clone(),
            committee_index: committee.to_string(),
            committee_length: "1".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "0".to_string(),
            slot: SLOT.to_string(),
        }
    }

    fn keys_and_duties(
        n: usize,
        duplicate_first: bool,
    ) -> (KeyManager, Vec<LocalKey>, Vec<AttesterDuty>) {
        let mut manager = KeyManager::new();
        let mut keys = Vec::with_capacity(n);
        let mut duties = Vec::with_capacity(n + usize::from(duplicate_first));
        for offset in 0..n {
            let secret = SecretKey::generate();
            let pubkey = secret.public_key();
            let key = LocalKey {
                pubkey_hex_0x: format!("0x{}", hex::encode(pubkey.to_bytes())),
                index: (1_000 + offset).to_string(),
                pubkey,
            };
            duties.push(duty(&key, 0));
            if duplicate_first && offset == 0 {
                duties.push(duty(&key, 1));
            }
            manager.insert(secret);
            keys.push(key);
        }
        (manager, keys, duties)
    }

    fn mock_beacon(duties: Vec<AttesterDuty>, opts: &FixtureOpts) -> MockBeaconNodeClient {
        let data = attestation_data(SLOT);
        let mut beacon = MockBeaconNodeClient::new()
            .with_get_attester_duties(move |_epoch, _indices| {
                Ok(AttesterDutiesResponse {
                    dependent_root: format!("0x{}", "00".repeat(32)),
                    execution_optimistic: false,
                    data: duties.clone(),
                })
            })
            .with_get_attestation_data(move |_slot, _committee| {
                Ok(AttestationDataResponse { data: data.clone() })
            })
            .with_submit_attestation(|_| Ok(SubmitAttestationResult::Success));
        if let Some((method, delay)) = opts.only_delay {
            beacon = beacon.with_method_delay(method, delay);
        } else if !opts.request_delay.is_zero() {
            beacon = beacon.with_request_delay(opts.request_delay);
        }
        beacon
    }

    fn open_fixture(n: usize, opts: FixtureOpts) -> Fixture<MockBeaconNodeClient> {
        let (manager, keys, duties) = keys_and_duties(n, opts.duplicate_first);
        let beacon = Arc::new(mock_beacon(duties, &opts));
        finish(n, opts, manager, keys, beacon.clone(), beacon)
    }

    fn open_fixture_with_submitter<S: AttestationSubmitter + 'static>(
        n: usize,
        opts: FixtureOpts,
        submitter: Arc<S>,
    ) -> Fixture<S> {
        let (manager, keys, duties) = keys_and_duties(n, opts.duplicate_first);
        let beacon = Arc::new(mock_beacon(duties, &opts));
        finish(n, opts, manager, keys, submitter, beacon)
    }

    fn finish<S: AttestationSubmitter + 'static>(
        _n: usize,
        opts: FixtureOpts,
        manager: KeyManager,
        keys: Vec<LocalKey>,
        submitter: Arc<S>,
        beacon: Arc<MockBeaconNodeClient>,
    ) -> Fixture<S> {
        let db_dir = tempfile::tempdir().expect("slashing db dir");
        let slashing_db = Arc::new(
            SlashingDb::open(db_dir.path().join("slashing.sqlite")).expect("open slashing db"),
        );
        let signer = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(manager))),
                slashing_db,
            )
            .with_enablement(always_enabled()),
        );
        let mut map = std::collections::HashMap::new();
        let store = Arc::new(validator_store::ValidatorStore::new([0xaa; 20], 30_000_000));
        for (offset, key) in keys.iter().enumerate() {
            let bytes = key.pubkey.to_bytes();
            map.insert(bytes, key.pubkey.clone());
            store
                .add_validator(validator_store::ValidatorConfig::new(bytes))
                .expect("register validator");
            if opts.pending == Some(offset) {
                store.set_enabled(&bytes, false);
            }
        }
        let indices: Vec<String> = keys.iter().map(|key| key.index.clone()).collect();
        let duty_tracker =
            Arc::new(DutyTracker::new(Arc::clone(&beacon) as Arc<dyn BeaconNodeClient>, indices));
        let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), 32));
        clock.set_slot(SLOT);
        let limits = DispatchLimits::validated(opts.concurrency, opts.publish_concurrency)
            .expect("test limits are non-zero");
        let mut config =
            OrchestratorConfig::new([0xaa; 32], fork_schedule()).with_dispatch_limits(limits);
        if let Some(attestation_submit) = opts.submit_timeout {
            config = config.with_timeouts(bn_manager::OperationTimeouts {
                attestation_submit,
                ..bn_manager::OperationTimeouts::default()
            });
        }
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(map));
        let service = AttestationService::new(
            clock,
            Arc::clone(&signer),
            Arc::new(Propagator::new(submitter)),
            beacon.clone(),
            duty_tracker,
            pubkey_map,
            config,
            store,
        );
        Fixture { service, beacon, signer, _db_dir: db_dir }
    }

    struct SleepBarrier(Duration);

    #[async_trait]
    impl PreReserveBarrier for SleepBarrier {
        async fn wait(&self) {
            tokio::time::sleep(self.0).await;
        }
    }

    struct OverlapBarrier {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        entries: AtomicUsize,
    }

    impl OverlapBarrier {
        fn new() -> Self {
            Self {
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                entries: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl PreReserveBarrier for OverlapBarrier {
        async fn wait(&self) {
            self.entries.fetch_add(1, Ordering::SeqCst);
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct PartialSubmitter {
        calls: AtomicUsize,
        seen: Mutex<Vec<VersionedAttestation>>,
    }

    impl PartialSubmitter {
        fn new() -> Self {
            Self { calls: AtomicUsize::new(0), seen: Mutex::new(Vec::new()) }
        }
    }

    impl AttestationSubmitter for PartialSubmitter {
        fn submit_attestation<'a>(
            &'a self,
            _attestations: &'a VersionedAttestation,
        ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
        {
            Box::pin(async { Ok(SubmitAttestationResult::Success) })
        }

        fn submit_attestation_attributed<'a>(
            &'a self,
            attestations: &'a VersionedAttestation,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<(Option<String>, SubmitAttestationResult), BeaconError>>
                    + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().expect("seen lock").push(attestations.clone());
            // Index 0 is always in range. `ready_chunks` may publish a short
            // wave as soon as one sign is ready, so a fixed index of 1 would
            // miss a one-item wave.
            Box::pin(async {
                Ok((
                    Some("http://bn-partial.example:5052".to_string()),
                    SubmitAttestationResult::PartialFailure {
                        failures: vec![IndexedAttestationError {
                            index: 0,
                            message: "invalid signature".to_string(),
                        }],
                    },
                ))
            })
        }
    }

    fn sign_request_window(beacon: &MockBeaconNodeClient) -> (usize, Duration) {
        let mut stamps = Vec::new();
        for stamp in beacon.call_stamps() {
            if stamp.method == MockMethod::GetAttestationData {
                stamps.push(stamp.at);
            }
        }
        let count = stamps.len();
        let window = match (stamps.iter().min(), stamps.iter().max()) {
            (Some(first), Some(last)) => last.saturating_duration_since(*first),
            _ => Duration::ZERO,
        };
        (count, window)
    }

    /// N = 64 Electra duties, 50 ms mock RTT, paused clock. The slot shares one
    /// attestation-data fetch (committee index 0), issued inside that RTT.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn attestation_dispatch_issues_all_sign_requests_within_one_rtt() {
        const N: usize = 64;
        let fixture = open_fixture(
            N,
            FixtureOpts {
                request_delay: Duration::from_millis(50),
                concurrency: 64,
                publish_concurrency: 2,
                ..FixtureOpts::default()
            },
        );
        let results = fixture.service.process_slot(SLOT).await.expect("process_slot");
        assert_eq!(results.len(), N);
        assert!(
            results.iter().all(|result| result.success),
            "every duty should publish: {results:?}"
        );
        let (count, window) = sign_request_window(&fixture.beacon);
        assert_eq!(count, 1, "Electra slot shares one get_attestation_data");
        assert_eq!(fixture.beacon.get_attestation_data_calls(), vec![(SLOT, 0)]);
        assert!(
            window <= Duration::from_millis(50),
            "the shared fetch must be issued within one 50 ms RTT, spread was {window:?}"
        );
    }

    /// `slot_end` already passed: nothing is signed, the drop counter matches
    /// the duty count, and a warn is emitted.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[traced_test]
    async fn undispatched_duties_are_dropped_and_counted_at_slot_end() {
        const N: usize = 5;
        let fixture = open_fixture(N, FixtureOpts::default());
        let slot_end = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1)).await;
        let results =
            fixture.service.process_slot_until(SLOT, slot_end).await.expect("slot already ended");
        assert!(results.is_empty(), "no duty is dispatched after slot end");
        assert_eq!(fixture.service.slot_end_drops(), N as u64);
        assert!(fixture.beacon.get_attestation_data_calls().is_empty());
        assert!(fixture.beacon.submit_attestation_calls().is_empty());
        assert!(logs_contain("undispatched attestation duties dropped at slot end"));
    }

    /// Signs already inside `buffer_unordered` finish after `take_until` stops
    /// pulling new duties. Attestation data is fetched before that stream, so
    /// the hold is the pre-reserve barrier rather than the beacon fetch.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn in_flight_signs_complete_when_slot_end_stops_new_dispatch() {
        const N: usize = 8;
        let fixture = open_fixture(
            N,
            FixtureOpts { concurrency: 4, publish_concurrency: 2, ..FixtureOpts::default() },
        );
        fixture
            .signer
            .set_pre_reserve_barrier(Some(Arc::new(SleepBarrier(Duration::from_millis(50)))));
        let slot_end = tokio::time::Instant::now() + Duration::from_millis(25);
        let results = fixture.service.process_slot_until(SLOT, slot_end).await.expect("drain");
        assert_eq!(results.len(), 4, "the in-flight wave completes");
        assert!(results.iter().all(|result| result.success), "{results:?}");
        assert_eq!(fixture.beacon.get_attestation_data_calls(), vec![(SLOT, 0)]);
        assert_eq!(fixture.service.slot_end_drops(), 4);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn same_pubkey_reserves_do_not_overlap_under_concurrency() {
        let barrier = Arc::new(OverlapBarrier::new());
        let fixture = open_fixture(
            1,
            FixtureOpts { duplicate_first: true, concurrency: 4, ..FixtureOpts::default() },
        );
        fixture
            .signer
            .set_pre_reserve_barrier(Some(Arc::clone(&barrier) as Arc<dyn PreReserveBarrier>));
        let results = fixture.service.process_slot(SLOT).await.expect("process_slot");
        assert_eq!(results.len(), 2, "both duties for the pubkey are attempted");
        assert_eq!(barrier.entries.load(Ordering::SeqCst), 2, "both reserves reached pre-reserve");
        assert_eq!(
            barrier.max_in_flight.load(Ordering::SeqCst),
            1,
            "per-pubkey reserves must not overlap"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn doppelganger_pending_validator_does_not_sign_under_concurrency() {
        let fixture = open_fixture(
            4,
            FixtureOpts { pending: Some(1), concurrency: 4, ..FixtureOpts::default() },
        );
        let results = fixture.service.process_slot(SLOT).await.expect("process_slot");
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|result| result.success), "{results:?}");
        assert!(results.iter().all(|result| result.validator_index != "1001"));
        assert_eq!(fixture.beacon.get_attestation_data_calls(), vec![(SLOT, 0)]);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[traced_test]
    async fn partial_failure_attributes_validator_and_beacon_without_retry() {
        let submitter = Arc::new(PartialSubmitter::new());
        let fixture = open_fixture_with_submitter(
            3,
            FixtureOpts { concurrency: 8, ..FixtureOpts::default() },
            Arc::clone(&submitter),
        );
        let results = fixture.service.process_slot(SLOT).await.expect("process_slot");
        let calls = submitter.calls.load(Ordering::SeqCst);
        let seen = submitter.seen.lock().expect("seen lock").clone();
        assert_eq!(calls, seen.len(), "each wave is posted once; a rejection is not retried");
        assert!(calls >= 1, "at least one array POST");

        let mut posted = Vec::new();
        let mut failed_indices = Vec::new();
        for batch in &seen {
            let VersionedAttestation::Electra(items) = batch else {
                panic!("wave must be Electra, got {batch:?}");
            };
            assert!(!items.is_empty(), "a wave POST is non-empty");
            failed_indices.push(items[0].attester_index.to_string());
            posted.extend(items.iter().map(|item| item.attester_index.to_string()));
        }
        let mut unique = posted.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(posted.len(), 3, "every duty is in exactly one POST");
        assert_eq!(unique.len(), 3, "a rejected attestation is not posted again");

        let failed: Vec<_> = results.iter().filter(|result| !result.success).collect();
        assert_eq!(failed.len(), failed_indices.len());
        for index in &failed_indices {
            assert!(
                failed.iter().any(|result| {
                    result.validator_index == *index
                        && result
                            .error
                            .as_deref()
                            .is_some_and(|message| message.contains("invalid signature"))
                }),
                "index {index} missing from {failed:?}"
            );
            assert!(logs_contain(index), "log must name validator {index}");
        }
        assert!(logs_contain("http://bn-partial.example:5052"));
        assert!(logs_contain("invalid signature"));
        assert_eq!(results.len(), 3);
        assert_eq!(
            results.iter().filter(|result| result.success).count(),
            3 - failed_indices.len()
        );
    }

    /// A publish started near `slot_end` is cut at `slot_end + 500 ms`.
    /// The submit timeout alone (2 s here) would finish about 1.5 s into S+1.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn delayed_publish_stops_at_slot_end_overhang() {
        const N: usize = 4;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_millis(50);
        let fixture = open_fixture(
            N,
            FixtureOpts {
                only_delay: Some((MockMethod::SubmitAttestation, Duration::from_secs(2))),
                concurrency: 4,
                publish_concurrency: 1,
                submit_timeout: Some(Duration::from_secs(2)),
                ..FixtureOpts::default()
            },
        );
        let results = fixture.service.process_slot_until(SLOT, slot_end).await.expect("drain");
        let finished = tokio::time::Instant::now();
        let overhang_at = slot_end + Duration::from_millis(500);
        assert_eq!(results.len(), N, "in-flight signs still produce a result");
        assert!(
            results.iter().all(|result| {
                !result.success
                    && result
                        .error
                        .as_deref()
                        .is_some_and(|message| message.contains("slot-end overhang"))
            }),
            "{results:?}"
        );
        assert!(
            finished <= overhang_at,
            "drain ran until {finished:?}, past overhang {overhang_at:?}"
        );
        assert!(
            finished.saturating_duration_since(started) < Duration::from_secs(2),
            "the 2 s submit timeout must not extend the phase, elapsed {:?}",
            finished.saturating_duration_since(started)
        );
        let submits: Vec<_> = fixture
            .beacon
            .call_stamps()
            .into_iter()
            .filter(|stamp| stamp.method == MockMethod::SubmitAttestation)
            .collect();
        assert!(!submits.is_empty(), "the final publish starts, then the overhang budget stops it");
        assert!(
            submits.iter().all(|stamp| stamp.at <= overhang_at),
            "a publish must not be admitted after the overhang: {submits:?}"
        );
        assert!(
            fixture.beacon.submit_attestation_calls().is_empty(),
            "the 2 s POST must be cancelled before it completes"
        );
    }
}
