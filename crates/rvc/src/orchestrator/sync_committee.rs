use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tracing::{debug, info, info_span, warn, Instrument};

use crate::metrics::{
    sync_committee_skip_phase, sync_committee_skip_reason, RVC_SYNC_COMMITTEE_SKIPPED_TOTAL,
};
use bn_manager::BeaconNodeClient;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{
    is_sync_committee_aggregator, subcommittee_index, ContributionAndProof, Root,
    SignedContributionAndProof, Slot, SyncCommitteeContribution, SyncCommitteeDuty,
    SYNC_COMMITTEE_SIZE, SYNC_COMMITTEE_SUBNET_COUNT,
};
use observability::logging::TruncatedRoot;
use signer::ValidatorSigner;
use validator_store::ValidatorStore;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::dispatch::{
    sign_with_phase2_permit, Phase2SignError, Phase2SignerPermits, SlotEndDropCounter,
    SLOT_END_PUBLISH_OVERHANG,
};
use super::slot_context::SlotContext;
use super::utils;

/// Aggregation bits for one sync subcommittee: 512/4 bits, 16 bytes.
const SYNC_SUBCOMMITTEE_BITFIELD_BYTES: usize =
    (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT / 8) as usize;

/// BLS signature length on the contribution wire.
const BLS_SIGNATURE_BYTES: usize = 96;

pub(crate) struct SyncCommitteeService {
    signer: Arc<dyn ValidatorSigner>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    /// D-3: per-validator doppelganger gate.  Mirrors the M-12 check already
    /// present in attestation.rs so that sync messages and contributions
    /// are also suppressed during the post-import doppelganger window.
    validator_store: Arc<ValidatorStore>,
    /// Items `take_until(slot_end)` did not yield.
    ///
    /// Sync-message dispatch records one per duty. Contribution dispatch
    /// records one per duty and subcommittee. This counter adds those two
    /// counts, so one increment is not always one subcommittee and not always
    /// one duty. Cumulative for this service. An in-flight fetch or signature
    /// is not a drop. This is a log field and a test accessor, not a
    /// Prometheus metric.
    slot_end_drops: SlotEndDropCounter,
}

impl SyncCommitteeService {
    pub(crate) fn new(
        signer: Arc<dyn ValidatorSigner>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
        validator_store: Arc<ValidatorStore>,
    ) -> Self {
        Self {
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            config,
            validator_store,
            slot_end_drops: SlotEndDropCounter::default(),
        }
    }

    /// Sync-message duties plus contribution items dropped at slot end.
    ///
    /// The two phases share the counter and do not use the same unit. See
    /// the `slot_end_drops` field.
    #[cfg(test)]
    pub(crate) fn slot_end_drops(&self) -> u64 {
        self.slot_end_drops.get()
    }

    fn sync_admission_closed(&self, ctx: &SlotContext, duty: signer::SigningDuty) -> bool {
        let own = self.beacon.duty_fence().unwrap_or_else(|_| beacon::DutyFence::closed());
        super::slot_context::admission_blocks(duty, &[&own, &ctx.fence])
    }

    fn skip_sync_revoked(&self, slot: Slot, phase: &'static str) {
        warn!(slot, "skipping sync committee duty: beacon node admission revoked");
        RVC_SYNC_COMMITTEE_SKIPPED_TOTAL
            .with_label_values(&[phase, sync_committee_skip_reason::BN_REVOKED])
            .inc();
    }

    #[tracing::instrument(name = "orchestrator.produce_sync_messages", level = "debug", skip_all, fields(slot = slot))]
    pub(crate) async fn maybe_produce_sync_messages(
        &self,
        slot: Slot,
        _epoch: u64,
        ctx: &SlotContext,
        slot_end: tokio::time::Instant,
    ) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
            return;
        }
        if self.sync_admission_closed(ctx, signer::SigningDuty::SyncCommitteeMessage) {
            self.skip_sync_revoked(slot, sync_committee_skip_phase::MESSAGES);
            return;
        }

        // H-5: use the head_root captured once at phase 2 instead of
        // fetching independently. If the BN failed during capture_head, skip
        // rather than falling back to a fresh (potentially drifted) fetch.
        let head_root = match ctx.head_root {
            Some(root) => root,
            None => {
                warn!(
                    slot,
                    "Skipping sync committee messages: head_root unavailable in slot context"
                );
                RVC_SYNC_COMMITTEE_SKIPPED_TOTAL
                    .with_label_values(&[
                        sync_committee_skip_phase::MESSAGES,
                        sync_committee_skip_reason::NO_HEAD_ROOT,
                    ])
                    .inc();
                return;
            }
        };

        // Same shape as attestation dispatch: `take_until` stops pulling new
        // duties at slot end, signs already in `buffer_unordered` drain, and
        // each ready chunk is one `submit_sync_committee_messages` call.
        // Sync messages are non-slashable, so this path does not touch SQLite.
        let pairs: Vec<_> = matching_duties.into_iter().zip(matching_pubkeys).collect();
        let duty_count = pairs.len();
        let concurrency = self.config.dispatch_limits.concurrency as usize;
        let publish_concurrency = self.config.dispatch_limits.publish_concurrency as usize;
        let waves = stream::iter(pairs)
            .take_until(tokio::time::sleep_until(slot_end))
            .map(|(duty, pubkey)| self.sign_sync_message(slot, head_root, duty, pubkey, ctx))
            .buffer_unordered(concurrency)
            .ready_chunks(concurrency)
            .map(|wave| self.publish_sync_wave(slot, slot_end, wave))
            .buffer_unordered(publish_concurrency);
        let mut waves = std::pin::pin!(waves);
        let mut dispatched = 0usize;
        while let Some(attempted) = waves.next().await {
            dispatched += attempted;
        }

        let dropped = duty_count.saturating_sub(dispatched);
        if dropped > 0 {
            self.slot_end_drops.record(dropped as u64);
            warn!(
                slot,
                dropped,
                duty_count,
                total_dropped = self.slot_end_drops.get(),
                "undispatched sync committee duties dropped at slot end"
            );
        }
    }

    /// Sign one sync-committee message. Publish is a later wave, not this future.
    async fn sign_sync_message(
        &self,
        slot: Slot,
        head_root: eth_types::Root,
        duty: SyncCommitteeDuty,
        pubkey: PublicKey,
        ctx: &SlotContext,
    ) -> Result<beacon::SyncCommitteeMessage, ()> {
        if self.sync_admission_closed(ctx, signer::SigningDuty::SyncCommitteeMessage) {
            return Err(());
        }
        let fence = self.beacon.duty_fence().unwrap_or_else(|_| beacon::DutyFence::closed());
        match super::slot_context::under_admission(
            &fence,
            self.signer.sign_sync_committee_message(
                &head_root,
                slot,
                &pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            ),
        )
        .await
        {
            Ok(sig) => Ok(beacon::SyncCommitteeMessage {
                slot,
                beacon_block_root: head_root,
                validator_index: duty.validator_index,
                signature: sig.to_bytes().to_vec(),
            }),
            Err(e) => {
                warn!(
                    slot,
                    validator_index = duty.validator_index,
                    error = %e,
                    "Failed to sign sync committee message"
                );
                Err(())
            }
        }
    }

    /// One batch POST for a wave of signed sync messages.
    ///
    /// The POST's deadline is the earlier of the `sync_message` timeout and
    /// `slot_end` plus 500 ms. Signs already running are not cancelled; a
    /// wave that becomes ready after that instant is not sent. Returns how
    /// many duties this wave attempted, including sign failures.
    async fn publish_sync_wave(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
        wave: Vec<Result<beacon::SyncCommitteeMessage, ()>>,
    ) -> usize {
        let attempted = wave.len();
        let messages: Vec<_> = wave.into_iter().flatten().collect();
        if messages.is_empty() {
            return attempted;
        }

        let now = tokio::time::Instant::now();
        let overhang_at = slot_end + SLOT_END_PUBLISH_OVERHANG;
        let submit_at = now.checked_add(self.config.timeouts.sync_message).unwrap_or(overhang_at);
        let deadline = overhang_at.min(submit_at);
        let bounded_by_overhang = deadline == overhang_at;
        if now >= deadline {
            warn_sync_publish_stopped(slot, bounded_by_overhang, self.config.timeouts.sync_message);
            return attempted;
        }

        let count = messages.len();
        let submit_result = tokio::time::timeout_at(
            deadline,
            self.beacon.submit_sync_committee_messages(&messages),
        )
        .instrument(info_span!("beacon.submit_sync_committee_messages", slot, count))
        .await;

        match submit_result {
            Ok(Ok(_)) => info!(slot, count, "Submitted sync committee messages"),
            Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit sync committee messages"),
            Err(_) => {
                warn_sync_publish_stopped(
                    slot,
                    bounded_by_overhang,
                    self.config.timeouts.sync_message,
                );
            }
        }
        attempted
    }

    /// Tests call this so a pipeline keeps its own cap. The coordinator calls
    /// [`Self::produce_sync_contributions`] with the shared phase-2 permits.
    #[cfg(test)]
    pub(crate) async fn maybe_produce_sync_contributions(
        &self,
        slot: Slot,
        epoch: u64,
        ctx: &SlotContext,
        slot_end: tokio::time::Instant,
    ) {
        let permits = Phase2SignerPermits::new(self.config.dispatch_limits.concurrency as usize);
        self.produce_sync_contributions(slot, epoch, ctx, slot_end, &permits).await
    }

    /// Produce sync contributions under a caller-owned phase-2 cap.
    ///
    /// The coordinator passes one [`Phase2SignerPermits`] shared with aggregation.
    /// Selection proofs and contribution-and-proof signatures each take one
    /// permit for the signer call. The contribution fetch does not hold one.
    #[tracing::instrument(name = "orchestrator.produce_sync_contributions", level = "debug", skip_all, fields(slot = slot))]
    pub(crate) async fn produce_sync_contributions(
        &self,
        slot: Slot,
        _epoch: u64,
        ctx: &SlotContext,
        slot_end: tokio::time::Instant,
        permits: &Phase2SignerPermits,
    ) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
            return;
        }
        if self.sync_admission_closed(ctx, signer::SigningDuty::SyncCommitteeSelectionProof) {
            self.skip_sync_revoked(slot, sync_committee_skip_phase::CONTRIBUTIONS);
            return;
        }

        // H-5: use the head_root captured once at phase 2 instead of
        // fetching independently. If the BN failed during capture_head, skip
        // rather than falling back to a fresh (potentially drifted) fetch.
        let head_root = match ctx.head_root {
            Some(root) => root,
            None => {
                warn!(
                    slot,
                    "Skipping sync committee contributions: head_root unavailable in slot context"
                );
                RVC_SYNC_COMMITTEE_SKIPPED_TOTAL
                    .with_label_values(&[
                        sync_committee_skip_phase::CONTRIBUTIONS,
                        sync_committee_skip_reason::NO_HEAD_ROOT,
                    ])
                    .inc();
                return;
            }
        };

        // One item per duty and distinct subcommittee. `take_until` stops
        // pulling new items at slot end. A fetch, a signature, or a publish
        // already running gets a fresh `now` plus `sync_contribution`. Only
        // the slot end + 500 ms cap is shared across those steps.
        let mut items = Vec::new();
        for (duty, pubkey) in matching_duties.into_iter().zip(matching_pubkeys) {
            let subcommittees: BTreeSet<u64> = duty
                .validator_sync_committee_indices
                .iter()
                .copied()
                .map(subcommittee_index)
                .collect();
            for subcommittee in subcommittees {
                items.push((duty.clone(), pubkey.clone(), subcommittee));
            }
        }
        let item_count = items.len();
        let concurrency = self.config.dispatch_limits.concurrency as usize;
        let publish_concurrency = self.config.dispatch_limits.publish_concurrency as usize;
        let waves = stream::iter(items)
            .take_until(tokio::time::sleep_until(slot_end))
            .map(|(duty, pubkey, subcommittee)| {
                self.produce_one_contribution(
                    slot,
                    head_root,
                    slot_end,
                    duty,
                    pubkey,
                    subcommittee,
                    ctx,
                    permits,
                )
            })
            .buffer_unordered(concurrency)
            .ready_chunks(concurrency)
            .map(|wave| self.publish_contribution_wave(slot, slot_end, wave))
            .buffer_unordered(publish_concurrency);
        let mut waves = std::pin::pin!(waves);
        let mut dispatched = 0usize;
        while let Some(attempted) = waves.next().await {
            dispatched += attempted;
        }

        let dropped = item_count.saturating_sub(dispatched);
        if dropped > 0 {
            self.slot_end_drops.record(dropped as u64);
            warn!(
                slot,
                dropped,
                item_count,
                total_dropped = self.slot_end_drops.get(),
                "undispatched sync contribution subcommittees dropped at slot end"
            );
        }
    }

    /// Selection proof, contribution fetch, and contribution-and-proof signature
    /// for one subcommittee. Publish is a later wave.
    ///
    /// A subcommittee index outside `0..4` returns before any signature.
    /// The selection proof and the contribution-and-proof signature both stop
    /// at [`contribution_deadline`]. Each sign acquires one phase-2 permit
    /// inside that deadline and inside the admission scope. The contribution
    /// body is checked before `sign_contribution_and_proof`. A deadline that
    /// has already passed does not call the signer or the beacon node.
    #[allow(clippy::too_many_arguments)]
    async fn produce_one_contribution(
        &self,
        slot: Slot,
        head_root: Root,
        slot_end: tokio::time::Instant,
        duty: SyncCommitteeDuty,
        pubkey: PublicKey,
        subcommittee_index: u64,
        ctx: &SlotContext,
        permits: &Phase2SignerPermits,
    ) -> Option<SignedContributionAndProof> {
        if subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
            debug!(
                slot,
                subcommittee_index,
                validator_index = duty.validator_index,
                "sync subcommittee index is outside 0..4"
            );
            return None;
        }
        if self.sync_admission_closed(ctx, signer::SigningDuty::SyncCommitteeSelectionProof) {
            return None;
        }
        let fence = self.beacon.duty_fence().unwrap_or_else(|_| beacon::DutyFence::closed());

        let selection_proof = match sign_contribution_phase2(
            permits,
            slot_end,
            self.config.timeouts.sync_contribution,
            &fence,
            super::slot_context::under_admission(
                &fence,
                self.signer.sign_sync_committee_selection_proof(
                    slot,
                    subcommittee_index,
                    &pubkey,
                    &self.config.fork_schedule,
                    &self.config.genesis_validators_root,
                ),
            ),
        )
        .await
        {
            Ok(sig) => sig,
            Err(ContributionSignStop::Stopped { bounded_by_overhang }) => {
                warn_contribution_stopped(
                    slot,
                    bounded_by_overhang,
                    self.config.timeouts.sync_contribution,
                );
                return None;
            }
            Err(ContributionSignStop::Revoked) => {
                warn!(
                    slot,
                    "skipping sync contribution: beacon node admission revoked before sign"
                );
                return None;
            }
            Err(ContributionSignStop::Failed(e)) => {
                warn!(
                    slot,
                    subcommittee_index,
                    validator_index = duty.validator_index,
                    error = %e,
                    "Failed to sign sync committee selection proof"
                );
                return None;
            }
        };

        if !is_sync_committee_aggregator(&selection_proof.to_bytes()) {
            debug!(
                slot,
                subcommittee_index,
                validator_index = duty.validator_index,
                "Not selected as sync committee aggregator"
            );
            return None;
        }

        debug!(
            slot,
            subcommittee_index,
            validator_index = duty.validator_index,
            "Selected as sync committee aggregator"
        );

        let (deadline, bounded_by_overhang) =
            contribution_deadline(slot_end, self.config.timeouts.sync_contribution);
        if tokio::time::Instant::now() >= deadline {
            warn_contribution_stopped(
                slot,
                bounded_by_overhang,
                self.config.timeouts.sync_contribution,
            );
            return None;
        }

        let head_root_hex = format!("0x{}", hex::encode(head_root));
        let contribution = match tokio::time::timeout_at(
            deadline,
            self.beacon.get_sync_committee_contribution(slot, subcommittee_index, &head_root_hex),
        )
        .await
        {
            Ok(Ok(resp)) => resp.data,
            Ok(Err(e)) => {
                warn!(
                    slot,
                    subcommittee_index,
                    error = %e,
                    "Failed to get sync committee contribution"
                );
                return None;
            }
            Err(_) => {
                warn_contribution_stopped(
                    slot,
                    bounded_by_overhang,
                    self.config.timeouts.sync_contribution,
                );
                return None;
            }
        };

        if !contribution_matches(&contribution, slot, head_root, subcommittee_index) {
            warn!(
                slot,
                subcommittee_index,
                contribution_slot = contribution.slot,
                "sync contribution does not match the duty; rejecting the body"
            );
            return None;
        }

        let proof = ContributionAndProof {
            aggregator_index: duty.validator_index,
            contribution,
            selection_proof: selection_proof.to_bytes().to_vec(),
        };
        if !fence.holds() {
            warn!(slot, "skipping sync contribution: beacon node admission revoked before sign");
            return None;
        }
        let sig = match sign_contribution_phase2(
            permits,
            slot_end,
            self.config.timeouts.sync_contribution,
            &fence,
            super::slot_context::under_admission(
                &fence,
                self.signer.sign_contribution_and_proof(
                    &proof,
                    &pubkey,
                    &self.config.fork_schedule,
                    &self.config.genesis_validators_root,
                ),
            ),
        )
        .await
        {
            Ok(sig) => sig,
            Err(ContributionSignStop::Stopped { bounded_by_overhang }) => {
                warn_contribution_stopped(
                    slot,
                    bounded_by_overhang,
                    self.config.timeouts.sync_contribution,
                );
                return None;
            }
            Err(ContributionSignStop::Revoked) => {
                warn!(
                    slot,
                    "skipping sync contribution: beacon node admission revoked before sign"
                );
                return None;
            }
            Err(ContributionSignStop::Failed(e)) => {
                warn!(
                    slot,
                    subcommittee_index,
                    validator_index = duty.validator_index,
                    error = %e,
                    "Failed to sign contribution and proof"
                );
                return None;
            }
        };
        Some(SignedContributionAndProof { message: proof, signature: sig.to_bytes().to_vec() })
    }

    /// One batch POST for a wave of signed contribution and proofs.
    ///
    /// The POST stops at the earlier of the `sync_contribution` timeout and
    /// `slot_end` plus 500 ms. A wave that is ready after that instant is not
    /// sent. Returns how many subcommittees this wave attempted.
    async fn publish_contribution_wave(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
        wave: Vec<Option<SignedContributionAndProof>>,
    ) -> usize {
        let attempted = wave.len();
        let proofs: Vec<_> = wave.into_iter().flatten().collect();
        if proofs.is_empty() {
            return attempted;
        }
        let (deadline, bounded_by_overhang) =
            contribution_deadline(slot_end, self.config.timeouts.sync_contribution);
        if tokio::time::Instant::now() >= deadline {
            warn_contribution_stopped(
                slot,
                bounded_by_overhang,
                self.config.timeouts.sync_contribution,
            );
            return attempted;
        }
        let count = proofs.len();
        match tokio::time::timeout_at(deadline, self.beacon.submit_contribution_and_proofs(&proofs))
            .await
        {
            Ok(Ok(_)) => info!(slot, count, "Submitted sync committee contribution and proofs"),
            Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit contribution and proofs"),
            Err(_) => warn_contribution_stopped(
                slot,
                bounded_by_overhang,
                self.config.timeouts.sync_contribution,
            ),
        }
        attempted
    }

    fn filter_sync_duties(
        &self,
        duties: &[SyncCommitteeDuty],
    ) -> (Vec<SyncCommitteeDuty>, Vec<PublicKey>) {
        let mut matching_duties = Vec::new();
        let mut matching_pubkeys = Vec::new();

        for duty in duties {
            if let Some(pk) = utils::find_pubkey_bytes(&self.pubkey_map, &duty.pubkey) {
                // D-3: per-validator doppelganger gate (mirrors attestation.rs M-12 check).
                // `pk` is the already-resolved typed PublicKey — use its infallible
                // `to_bytes()` instead of re-decoding the hex string (no fail-open).
                let pk_bytes = pk.to_bytes();
                if !self.validator_store.is_signing_enabled(&pk_bytes) {
                    warn!(
                        pubkey = %TruncatedRoot::new(&duty.pubkey),
                        "Skipping sync committee duty: validator is inside the \
                         post-import doppelganger window (D-3)"
                    );
                    continue;
                }
                matching_duties.push(duty.clone());
                matching_pubkeys.push(pk);
            }
        }

        (matching_duties, matching_pubkeys)
    }
}

/// Earlier of a fresh `now + timeout` and slot end plus 500 ms.
///
/// Each caller computes its own deadline. A step that starts later has a
/// later `now`, so its timeout instant is later. Only the slot end + 500 ms
/// cap is shared. `checked_add` that cannot represent slot end plus 500 ms
/// uses `now` as that overhang instant. `checked_add` that cannot represent
/// `now` plus the timeout uses the overhang instant. A deadline at or before
/// `now` is already due, and the caller does not send.
pub(crate) fn contribution_deadline(
    slot_end: tokio::time::Instant,
    timeout: Duration,
) -> (tokio::time::Instant, bool) {
    let now = tokio::time::Instant::now();
    let overhang_at = slot_end.checked_add(SLOT_END_PUBLISH_OVERHANG).unwrap_or(now);
    let submit_at = now.checked_add(timeout).unwrap_or(overhang_at);
    let deadline = overhang_at.min(submit_at);
    (deadline, deadline == overhang_at)
}

enum SignStop<E> {
    Stopped { bounded_by_overhang: bool },
    Failed(E),
}

enum ContributionSignStop<E> {
    Stopped { bounded_by_overhang: bool },
    Revoked,
    Failed(E),
}

/// Sign inside the contribution deadline and the shared phase-2 cap.
///
/// The permit wait sits inside [`sign_before_deadline`], so time spent queued
/// for a phase-2 permit counts against the sync contribution timeout. That
/// timeout still drops a slow signer. A cancelled wait is the same stop as a
/// deadline that has already passed. The signer future is polled only after a
/// permit is held and the fence still holds. The caller installs admission.
async fn sign_contribution_phase2<E, Fut>(
    permits: &Phase2SignerPermits,
    slot_end: tokio::time::Instant,
    timeout: Duration,
    fence: &beacon::DutyFence,
    sign: Fut,
) -> Result<crypto::Signature, ContributionSignStop<E>>
where
    Fut: Future<Output = Result<crypto::Signature, E>>,
{
    let (deadline, bounded_by_overhang) = contribution_deadline(slot_end, timeout);
    match sign_before_deadline(
        slot_end,
        timeout,
        sign_with_phase2_permit(permits, deadline, fence, sign),
    )
    .await
    {
        Ok(signature) => Ok(signature),
        Err(SignStop::Stopped { bounded_by_overhang }) => {
            Err(ContributionSignStop::Stopped { bounded_by_overhang })
        }
        Err(SignStop::Failed(Phase2SignError::Cancelled)) => {
            Err(ContributionSignStop::Stopped { bounded_by_overhang })
        }
        Err(SignStop::Failed(Phase2SignError::Revoked)) => Err(ContributionSignStop::Revoked),
        Err(SignStop::Failed(Phase2SignError::Failed(error))) => {
            Err(ContributionSignStop::Failed(error))
        }
    }
}

/// Signs `sign` only when [`contribution_deadline`] is still ahead.
///
/// The future is not polled when the deadline is already due: `timeout_at`
/// on a past instant still polls its inner future once. A running sign is
/// dropped at the deadline, so a slow remote signer cannot stretch the phase.
async fn sign_before_deadline<E, Fut>(
    slot_end: tokio::time::Instant,
    timeout: Duration,
    sign: Fut,
) -> Result<crypto::Signature, SignStop<E>>
where
    Fut: Future<Output = Result<crypto::Signature, E>>,
{
    let (deadline, bounded_by_overhang) = contribution_deadline(slot_end, timeout);
    if tokio::time::Instant::now() >= deadline {
        return Err(SignStop::Stopped { bounded_by_overhang });
    }
    match tokio::time::timeout_at(deadline, sign).await {
        Ok(Ok(signature)) => Ok(signature),
        Ok(Err(error)) => Err(SignStop::Failed(error)),
        Err(_) => Err(SignStop::Stopped { bounded_by_overhang }),
    }
}

/// The contribution body matches the duty slot, the phase-2 head, and the
/// subcommittee that was requested. The bitfield is 16 bytes with at least
/// one participant bit, and the signature is 96 bytes. A mismatch rejects
/// the body before it is signed.
fn contribution_matches(
    contribution: &SyncCommitteeContribution,
    slot: Slot,
    head: Root,
    subcommittee: u64,
) -> bool {
    contribution.slot == slot
        && contribution.beacon_block_root == head
        && contribution.subcommittee_index == subcommittee
        && contribution.aggregation_bits.len() == SYNC_SUBCOMMITTEE_BITFIELD_BYTES
        && contribution.aggregation_bits.iter().any(|byte| *byte != 0)
        && contribution.signature.len() == BLS_SIGNATURE_BYTES
}

fn warn_contribution_stopped(slot: Slot, bounded_by_overhang: bool, submit_timeout: Duration) {
    if bounded_by_overhang {
        warn!(
            slot,
            "sync contribution exceeded the {} ms slot-end overhang",
            SLOT_END_PUBLISH_OVERHANG.as_millis()
        );
    } else {
        warn!(slot, "sync contribution timed out after {}s", submit_timeout.as_secs());
    }
}

fn warn_sync_publish_stopped(slot: Slot, bounded_by_overhang: bool, submit_timeout: Duration) {
    if bounded_by_overhang {
        warn!(
            slot,
            "Sync committee message publish exceeded the {} ms slot-end overhang",
            SLOT_END_PUBLISH_OVERHANG.as_millis()
        );
    } else {
        warn!(slot, "Sync committee message submit timed out after {}s", submit_timeout.as_secs());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use crate::metrics::{
        sync_committee_skip_phase, sync_committee_skip_reason, RVC_SYNC_COMMITTEE_SKIPPED_TOTAL,
    };
    use async_trait::async_trait;
    use beacon::{DataResponse, ExecutionOptimisticResponse};
    use bn_manager::{BeaconNodeClient, MockBeaconNodeClient, MockMethod};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use duty_tracker::DutyTracker;
    use eth_types::{ForkSchedule, Root, SyncCommitteeDuty};
    use signer::{always_enabled, SignerService};
    use slashing::SlashingDb;
    use validator_store::{ValidatorConfig, ValidatorStore};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn create_test_fork_schedule() -> Arc<ForkSchedule> {
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
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [0, 0, 0, 8],
        })
    }

    fn create_test_config() -> OrchestratorConfig {
        OrchestratorConfig::new([0u8; 32], create_test_fork_schedule())
    }

    /// Far enough ahead that `take_until(slot_end)` does not drop duties.
    fn ample_slot_end() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(60)
    }

    // -----------------------------------------------------------------------
    // Shared mock builders (RF4-24) — preserve Toctou / Contrib / Isolation behaviors.
    // -----------------------------------------------------------------------

    /// TOCTOU mock: counts get_block_root, captures submitted message roots, serves duties.
    fn toctou_beacon(
        get_block_root_call_count: Arc<AtomicUsize>,
        submitted_roots: Arc<Mutex<Vec<Root>>>,
        r_from_bn_hex: String,
        duty_pubkey: [u8; 48],
    ) -> MockBeaconNodeClient {
        let count = Arc::clone(&get_block_root_call_count);
        let roots = Arc::clone(&submitted_roots);
        MockBeaconNodeClient::new()
            .with_slot_aware_block_root(0, &[], move |queried| {
                count.fetch_add(1, Ordering::SeqCst);
                match queried {
                    None => r_from_bn_hex.clone(),
                    Some(_) => r_from_bn_hex.clone(),
                }
            })
            .with_post_sync_committee_duties(move |_epoch, _indices| {
                Ok(ExecutionOptimisticResponse {
                    execution_optimistic: false,
                    data: vec![SyncCommitteeDuty {
                        pubkey: duty_pubkey,
                        validator_index: 1,
                        validator_sync_committee_indices: vec![0],
                    }],
                })
            })
            .with_submit_sync_committee_messages(move |messages| {
                let mut guard = roots.lock().unwrap();
                for msg in messages {
                    guard.push(msg.beacon_block_root);
                }
                Ok(())
            })
            .with_get_sync_committee_contribution(move |slot, subcommittee, root| {
                Ok(DataResponse { data: contribution_body(slot, decode_root(&root), subcommittee) })
            })
            .with_submit_contribution_and_proofs({
                let roots = Arc::clone(&submitted_roots);
                move |proofs| {
                    let mut guard = roots.lock().unwrap();
                    for proof in proofs {
                        guard.push(proof.message.contribution.beacon_block_root);
                    }
                    Ok(())
                }
            })
    }

    fn decode_root(hex_root: &str) -> Root {
        let bytes =
            hex::decode(hex_root.strip_prefix("0x").unwrap_or(hex_root)).unwrap_or_default();
        let mut root = [0u8; 32];
        if bytes.len() == 32 {
            root.copy_from_slice(&bytes);
        }
        root
    }

    /// Contrib-gate mock: counts get_sync_committee_contribution fetches.
    fn contrib_gate_beacon(
        contrib_fetch_calls: Arc<AtomicUsize>,
        duty_pubkey: [u8; 48],
    ) -> MockBeaconNodeClient {
        let calls = Arc::clone(&contrib_fetch_calls);
        MockBeaconNodeClient::new()
            .with_post_sync_committee_duties(move |_epoch, _indices| {
                Ok(ExecutionOptimisticResponse {
                    execution_optimistic: false,
                    data: vec![SyncCommitteeDuty {
                        pubkey: duty_pubkey,
                        validator_index: 1,
                        validator_sync_committee_indices: vec![0],
                    }],
                })
            })
            .with_get_sync_committee_contribution(move |slot, subcommittee_index, _root| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(DataResponse {
                    data: eth_types::SyncCommitteeContribution {
                        slot,
                        beacon_block_root: [0xAA; 32],
                        subcommittee_index,
                        aggregation_bits: vec![0xff; 16],
                        signature: vec![0u8; 96],
                    },
                })
            })
            .with_submit_contribution_and_proofs(|_proofs| Ok(()))
    }

    /// Multi-validator isolation mock for H-6.
    fn isolation_beacon(
        duties: Vec<SyncCommitteeDuty>,
        submitted_message_indices: Arc<Mutex<Vec<u64>>>,
        contrib_fetch_calls: Arc<AtomicUsize>,
        submitted_proof_count: Arc<AtomicUsize>,
    ) -> MockBeaconNodeClient {
        let indices = Arc::clone(&submitted_message_indices);
        let contrib = Arc::clone(&contrib_fetch_calls);
        let proofs = Arc::clone(&submitted_proof_count);
        MockBeaconNodeClient::new()
            .with_post_sync_committee_duties(move |_epoch, _indices| {
                Ok(ExecutionOptimisticResponse {
                    execution_optimistic: false,
                    data: duties.clone(),
                })
            })
            .with_submit_sync_committee_messages(move |messages| {
                let mut guard = indices.lock().unwrap();
                for msg in messages {
                    guard.push(msg.validator_index);
                }
                Ok(())
            })
            .with_get_sync_committee_contribution(move |slot, subcommittee_index, _root| {
                contrib.fetch_add(1, Ordering::SeqCst);
                Ok(DataResponse {
                    data: eth_types::SyncCommitteeContribution {
                        slot,
                        beacon_block_root: [0xAA; 32],
                        subcommittee_index,
                        aggregation_bits: vec![0xff; 16],
                        signature: vec![0u8; 96],
                    },
                })
            })
            .with_submit_contribution_and_proofs(move |ps| {
                proofs.fetch_add(ps.len(), Ordering::SeqCst);
                Ok(())
            })
    }

    // -----------------------------------------------------------------------
    // Setup helper: SyncCommitteeService with a real BLS key and shared mock.
    // -----------------------------------------------------------------------
    async fn setup_service(
        beacon: Arc<dyn BeaconNodeClient>,
        pk_hex: String,
        pk: crypto::PublicKey,
        sk: SecretKey,
    ) -> SyncCommitteeService {
        setup_service_with_store(
            beacon,
            pk_hex,
            pk,
            sk,
            Arc::new(ValidatorStore::new([0u8; 20], 0)),
        )
        .await
    }

    async fn setup_service_with_store(
        beacon: Arc<dyn BeaconNodeClient>,
        _pk_hex: String,
        pk: crypto::PublicKey,
        sk: SecretKey,
        validator_store: Arc<ValidatorStore>,
    ) -> SyncCommitteeService {
        // D-3 fail-closed: register the loaded validator (enabled) unless the
        // test already tracks it (e.g. as disabled for the doppelganger-window
        // path). Mirrors startup registration so the per-validator gate permits
        // signing for keys the VC actually loaded.
        if !validator_store.has_validator(&pk.to_bytes()) {
            validator_store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
        }
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        // Upcast: wide object only.
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        // Pre-populate sync committee duties for period 0 (epoch 0 / 256 = 0)
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            validator_store,
        )
    }

    // -----------------------------------------------------------------------
    // RED → GREEN: H-5 TOCTOU fix
    //
    // A buggy implementation fetches head_root independently in each phase.
    // When head advances between t=slot/3 and t=2*slot/3 the two phases would
    // sign with different roots. The fix: both phases read from SlotContext.
    //
    // RED: current code calls get_block_root("head") in each phase → counter > 0
    //      and submitted message has r_from_bn, not r_captured.
    // GREEN: fixed code reads ctx.head_root → counter stays 0,
    //        submitted message has r_captured.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_messages_and_contributions_share_head_root() {
        let config = create_test_config();
        let (sk, pk) = find_aggregator_for(0, &[0], &config.fork_schedule, [0u8; 32]);
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        // R_captured: the root pinned at slot-start in SlotContext.
        let r_captured: Root = [0xAA; 32];
        // R_from_bn: what the BN would return for head queries — intentionally different.
        let r_from_bn: Root = [0xBB; 32];
        let r_from_bn_hex = format!("0x{}", hex::encode(r_from_bn));

        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(toctou_beacon(
            get_block_root_call_count.clone(),
            submitted_roots.clone(),
            r_from_bn_hex,
            pk.to_bytes(),
        ));

        let service = setup_service(beacon, pk_hex, pk, sk).await;

        // SlotContext constructed once at slot start — this is the fix's contract.
        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some(r_captured),
            fence: beacon::DutyFence::open(),
        };

        // Run both sync-committee phases with the same context.
        service.maybe_produce_sync_messages(0, 0, &ctx, ample_slot_end()).await;
        service.maybe_produce_sync_contributions(0, 0, &ctx, ample_slot_end()).await;

        // Neither phase must call get_block_root: head_root is sourced from SlotContext.
        assert_eq!(
            get_block_root_call_count.load(Ordering::SeqCst),
            0,
            "H-5: neither sync-committee phase must call get_block_root; \
             head_root must come from SlotContext, not a fresh BN fetch"
        );

        // The messages phase must submit messages with the captured root, not the BN root.
        let roots = submitted_roots.lock().unwrap();
        assert!(
            roots.len() >= 2,
            "messages and at least one contribution must be published with the captured head"
        );
        for root in roots.iter() {
            assert_eq!(
                *root, r_captured,
                "beacon_block_root must equal SlotContext.head_root (r_captured=0xaa…), \
                 not the BN's head root (r_from_bn=0xbb…)"
            );
        }
    }

    fn skip_count(phase: &str) -> u64 {
        RVC_SYNC_COMMITTEE_SKIPPED_TOTAL
            .with_label_values(&[phase, sync_committee_skip_reason::NO_HEAD_ROOT])
            .get()
    }

    /// ARCH-3e: both skip sites increment the labelled skip counter when
    /// phase-2 `head_root` is missing.
    #[tokio::test]
    async fn test_sync_skip_counter_increments_for_messages_and_contributions() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(toctou_beacon(
            get_block_root_call_count.clone(),
            submitted_roots.clone(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            pk.to_bytes(),
        ));

        let service = setup_service(beacon, pk_hex, pk, sk).await;
        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: None,
            fence: beacon::DutyFence::open(),
        };

        let before_messages = skip_count(sync_committee_skip_phase::MESSAGES);
        let before_contributions = skip_count(sync_committee_skip_phase::CONTRIBUTIONS);

        service.maybe_produce_sync_messages(0, 0, &ctx, ample_slot_end()).await;
        service.maybe_produce_sync_contributions(0, 0, &ctx, ample_slot_end()).await;

        assert_eq!(
            skip_count(sync_committee_skip_phase::MESSAGES),
            before_messages + 1,
            "messages skip must increment rvc_sync_committee_skipped_total{{phase=messages,reason=no_head_root}}"
        );
        assert_eq!(
            skip_count(sync_committee_skip_phase::CONTRIBUTIONS),
            before_contributions + 1,
            "contributions skip must increment rvc_sync_committee_skipped_total{{phase=contributions,reason=no_head_root}}"
        );
        assert_eq!(
            get_block_root_call_count.load(Ordering::SeqCst),
            0,
            "neither skip path may fall back to a BN fetch"
        );
        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "no messages must be submitted when head_root is None"
        );
    }

    // -----------------------------------------------------------------------
    // None head_root: messages phase skips gracefully without any BN call.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_messages_skip_when_head_root_none() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(toctou_beacon(
            get_block_root_call_count.clone(),
            submitted_roots.clone(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            pk.to_bytes(),
        ));

        let service = setup_service(beacon, pk_hex, pk, sk).await;

        // head_root = None simulates a BN failure during SlotContext::capture_head.
        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: None,
            fence: beacon::DutyFence::open(),
        };

        service.maybe_produce_sync_messages(0, 0, &ctx, ample_slot_end()).await;

        assert_eq!(
            get_block_root_call_count.load(Ordering::SeqCst),
            0,
            "messages phase must not fall back to a BN fetch when head_root is None"
        );
        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "no messages must be submitted when head_root is None"
        );
    }

    // -----------------------------------------------------------------------
    // None head_root: contributions phase skips gracefully without any BN call.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_contributions_skip_when_head_root_none() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(toctou_beacon(
            get_block_root_call_count.clone(),
            submitted_roots.clone(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            pk.to_bytes(),
        ));

        let service = setup_service(beacon, pk_hex, pk, sk).await;

        // head_root = None simulates a BN failure during SlotContext::capture_head.
        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: None,
            fence: beacon::DutyFence::open(),
        };

        service.maybe_produce_sync_contributions(0, 0, &ctx, ample_slot_end()).await;

        assert_eq!(
            get_block_root_call_count.load(Ordering::SeqCst),
            0,
            "contributions phase must not fall back to a BN fetch when head_root is None"
        );
    }

    // -----------------------------------------------------------------------
    // D-3: sync message path skips validators whose is_signing_enabled=false.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_sync_message_skipped_when_validator_disabled() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let pk_bytes: [u8; 48] = pk.to_bytes();

        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));
        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(toctou_beacon(
            get_block_root_call_count.clone(),
            submitted_roots.clone(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            pk_bytes,
        ));

        // Set up a store where the validator is disabled (doppelganger window).
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut config = ValidatorConfig::new(pk_bytes);
        config.enabled = false;
        store.add_validator(config).unwrap();

        let service = setup_service_with_store(beacon, pk_hex, pk, sk, store).await;

        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some([0xAA; 32]),
            fence: beacon::DutyFence::open(),
        };
        service.maybe_produce_sync_messages(0, 0, &ctx, ample_slot_end()).await;

        // No messages must be submitted for a disabled validator.
        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "D-3: sync committee message must not be produced when is_signing_enabled=false"
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn sync_messages_from_a_head_captured_before_revocation_are_not_signed() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(toctou_beacon(
            Arc::new(AtomicUsize::new(0)),
            submitted_roots.clone(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            pk.to_bytes(),
        ));
        let service = setup_service(beacon, pk_hex, pk, sk).await;
        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some([0xAA; 32]),
            fence: beacon::DutyFence::closed(),
        };
        service.maybe_produce_sync_messages(0, 0, &ctx, ample_slot_end()).await;
        assert!(submitted_roots.lock().unwrap().is_empty(), "a revoked head is not signed");
        assert!(logs_contain("beacon node admission revoked"));
    }

    // -----------------------------------------------------------------------
    // D-3: sync contribution path skips validators whose is_signing_enabled=false.
    //
    // ContribGateBeacon: a beacon that returns a valid contribution and tracks
    // how many times `get_sync_committee_contribution` is called.  If the D-3
    // gate fires correctly (filter_sync_duties skips the disabled validator),
    // the loop body is never entered and the contribution endpoint is never
    // reached.  If the gate is absent (RED state), the loop runs, the selection
    // proof is signed, and — because we arrange for the key to be deterministically
    // selected as a sync committee aggregator — `get_sync_committee_contribution`
    // is called, incrementing the counter.
    // -----------------------------------------------------------------------

    /// Returns a `(SecretKey, PublicKey)` pair that is deterministically
    /// selected as a sync committee aggregator for slot=0 / subcommittee=0
    /// with the test fork schedule (genesis_fork_version=[0,0,0,1],
    /// genesis_validators_root=[0u8;32]).
    ///
    /// The selection criterion is `sha256(bls_sig_bytes)[0..8] as u64 % 8 == 0`.
    /// Expected to terminate in ~8 iterations on average.
    fn find_aggregator_sk() -> (SecretKey, crypto::PublicKey) {
        use eth_types::{
            ForkName, SyncAggregatorSelectionData, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        };

        let fork_schedule = create_test_fork_schedule();
        let genesis_validators_root: eth_types::Root = [0u8; 32];

        // Slot 0 falls in epoch 0, which is Phase0 (altair_fork_epoch = 10).
        let fork_name = ForkName::from_epoch(0, &fork_schedule);
        let fork_version = fork_name.fork_version(&fork_schedule);
        let domain = crypto::compute_domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            fork_version,
            genesis_validators_root,
        );
        let selection_data = SyncAggregatorSelectionData { slot: 0, subcommittee_index: 0 };
        let signing_root = crypto::compute_signing_root(&selection_data, domain);

        loop {
            let sk = SecretKey::generate();
            let pk = sk.public_key();
            // `LocalSigner::sign` calls `sk.sign(signing_root)` internally.
            // Mirror that directly: `SecretKey::sign(&self, message: &[u8])`.
            let sig = sk.sign(&signing_root);
            let sig_bytes = sig.to_bytes();
            if is_sync_committee_aggregator(&sig_bytes) {
                return (sk, pk);
            }
        }
    }

    #[tokio::test]
    async fn test_sync_contribution_skipped_when_validator_disabled() {
        // Find a BLS key that is deterministically selected as a sync committee
        // aggregator for slot=0 / subcommittee=0.  This ensures the test is
        // meaningful in RED state: when the D-3 gate is absent, the selection
        // proof is signed, `is_sync_committee_aggregator` returns true, and
        // `get_sync_committee_contribution` is reached — incrementing the counter.
        let (sk, pk) = find_aggregator_sk();
        let _pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let pk_bytes: [u8; 48] = pk.to_bytes();

        let contrib_fetch_calls = Arc::new(AtomicUsize::new(0));
        let beacon: Arc<dyn BeaconNodeClient> =
            Arc::new(contrib_gate_beacon(contrib_fetch_calls.clone(), pk_bytes));

        // Validator is disabled (inside post-import doppelganger window).
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut config = ValidatorConfig::new(pk_bytes);
        config.enabled = false;
        store.add_validator(config).unwrap();

        // Build the service with this beacon and the disabled-validator store.
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        // Upcast: wide object only.
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        let service = SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            store,
        );

        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some([0xAA; 32]),
            fence: beacon::DutyFence::open(),
        };
        service.maybe_produce_sync_contributions(0, 0, &ctx, ample_slot_end()).await;

        // In GREEN: filter_sync_duties returns [] because the validator is
        // disabled → the loop body is never entered → get_sync_committee_contribution
        // is NEVER called → count stays 0.
        //
        // In RED (gate removed): the validator passes the filter → selection
        // proof is signed → is_sync_committee_aggregator returns true (the key
        // was chosen to guarantee this) → get_sync_committee_contribution IS called
        // → count > 0 → assertion fails.
        assert_eq!(
            contrib_fetch_calls.load(Ordering::SeqCst),
            0,
            "D-3: get_sync_committee_contribution must not be called for a disabled \
             validator (is_signing_enabled=false)"
        );
    }

    // -----------------------------------------------------------------------
    // H-6 (RF2-01 port): multi-validator sign-failure isolation.
    //
    // Ported from the deleted `sync-service` twin suite
    // (`test_one_signer_failure_does_not_abort_others` and related). One
    // validator's KeyNotFound must not abort the slot: other validators still
    // produce, and the phase returns (does not panic / propagate).
    // -----------------------------------------------------------------------

    /// H-6: three validators A/B/C on the messages path; B's secret key is absent
    /// from the KeyManager (KeyNotFound). A and C must still submit; the phase
    /// must complete without aborting the remaining validators.
    #[tokio::test]
    async fn test_h6_one_signer_failure_does_not_abort_sync_messages() {
        let sk_a = SecretKey::generate();
        let sk_b = SecretKey::generate();
        let sk_c = SecretKey::generate();
        let pk_a = sk_a.public_key();
        let pk_b = sk_b.public_key();
        let pk_c = sk_c.public_key();
        let _hex_a = format!("0x{}", hex::encode(pk_a.to_bytes()));
        let _hex_b = format!("0x{}", hex::encode(pk_b.to_bytes()));
        let _hex_c = format!("0x{}", hex::encode(pk_c.to_bytes()));

        let duties = vec![
            SyncCommitteeDuty {
                pubkey: pk_a.to_bytes(),
                validator_index: 10,
                validator_sync_committee_indices: vec![0],
            },
            SyncCommitteeDuty {
                pubkey: pk_b.to_bytes(),
                validator_index: 11,
                validator_sync_committee_indices: vec![1],
            },
            SyncCommitteeDuty {
                pubkey: pk_c.to_bytes(),
                validator_index: 12,
                validator_sync_committee_indices: vec![2],
            },
        ];

        let submitted_message_indices = Arc::new(Mutex::new(Vec::<u64>::new()));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(isolation_beacon(
            duties,
            submitted_message_indices.clone(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        ));

        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        for pk in [&pk_a, &pk_b, &pk_c] {
            store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
        }

        // KeyManager holds A and C only — B signs with KeyNotFound.
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk_a);
        key_manager.insert(sk_c);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        // Upcast: wide object only.
        let duty_tracker =
            Arc::new(DutyTracker::new(beacon.clone(), vec!["10".into(), "11".into(), "12".into()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk_a.to_bytes(), pk_a);
        map.insert(pk_b.to_bytes(), pk_b);
        map.insert(pk_c.to_bytes(), pk_c);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        let service = SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            store,
        );

        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some([0xAA; 32]),
            fence: beacon::DutyFence::open(),
        };
        // Must complete without panic / hang — isolation property.
        service.maybe_produce_sync_messages(0, 0, &ctx, ample_slot_end()).await;

        let mut indices = submitted_message_indices.lock().unwrap().clone();
        indices.sort_unstable();
        assert_eq!(
            indices,
            vec![10, 12],
            "H-6: A and C must submit messages; B (KeyNotFound) must be skipped"
        );
    }

    /// H-6: three aggregator-eligible validators on the contributions path; B's
    /// secret key is absent. Selection-proof signing fails for B with continue;
    /// A and C must still fetch contributions and submit proofs.
    #[tokio::test]
    async fn test_h6_one_signer_failure_does_not_abort_sync_contributions() {
        let (sk_a, pk_a) = find_aggregator_sk();
        let sk_b = SecretKey::generate();
        let pk_b = sk_b.public_key();
        let (sk_c, pk_c) = find_aggregator_sk();
        let _hex_a = format!("0x{}", hex::encode(pk_a.to_bytes()));
        let _hex_b = format!("0x{}", hex::encode(pk_b.to_bytes()));
        let _hex_c = format!("0x{}", hex::encode(pk_c.to_bytes()));

        // Distinct subcommittees (pos 0 / 128 / 256 → subnet 0 / 1 / 2). For A
        // and C we still need aggregator selection on their subcommittee.
        // find_aggregator_sk is for subcommittee 0 only — put A and C on
        // subcommittee 0 (indices 0 and 1) and B on the same path so B's
        // selection-proof KeyNotFound is the isolation fault.
        let duties = vec![
            SyncCommitteeDuty {
                pubkey: pk_a.to_bytes(),
                validator_index: 10,
                validator_sync_committee_indices: vec![0],
            },
            SyncCommitteeDuty {
                pubkey: pk_b.to_bytes(),
                validator_index: 11,
                validator_sync_committee_indices: vec![1],
            },
            SyncCommitteeDuty {
                pubkey: pk_c.to_bytes(),
                validator_index: 12,
                validator_sync_committee_indices: vec![2],
            },
        ];

        let submitted_message_indices = Arc::new(Mutex::new(Vec::<u64>::new()));
        let contrib_fetch_calls = Arc::new(AtomicUsize::new(0));
        let submitted_proof_count = Arc::new(AtomicUsize::new(0));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(isolation_beacon(
            duties,
            submitted_message_indices,
            contrib_fetch_calls.clone(),
            submitted_proof_count.clone(),
        ));

        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        for pk in [&pk_a, &pk_b, &pk_c] {
            store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
        }

        // KeyManager holds A and C only — B's selection proof fails KeyNotFound.
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk_a);
        key_manager.insert(sk_c);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        // Upcast: wide object only.
        let duty_tracker =
            Arc::new(DutyTracker::new(beacon.clone(), vec!["10".into(), "11".into(), "12".into()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk_a.to_bytes(), pk_a);
        map.insert(pk_b.to_bytes(), pk_b);
        map.insert(pk_c.to_bytes(), pk_c);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        let service = SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            store,
        );

        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some([0xAA; 32]),
            fence: beacon::DutyFence::open(),
        };
        service.maybe_produce_sync_contributions(0, 0, &ctx, ample_slot_end()).await;

        // A and C are aggregators for subcommittee 0 → two contribution fetches
        // and two submitted proofs. B skipped after selection-proof KeyNotFound.
        assert_eq!(
            contrib_fetch_calls.load(Ordering::SeqCst),
            2,
            "H-6: contribution fetch must run for A and C only"
        );
        assert_eq!(
            submitted_proof_count.load(Ordering::SeqCst),
            2,
            "H-6: proofs from A and C must be submitted; B must not abort the loop"
        );
    }

    /// ARCH-3c: a spec-conformant BN 404s the current slot. After t=0
    /// `capture_parent` (slot-1) and phase-2 `capture_head`, messages must
    /// still be produced — do not leave `head_root` stuck at the t=0 404.
    #[tokio::test]
    async fn test_sync_messages_are_produced_when_bn_404s_the_current_slot() {
        let slot: Slot = 1000;
        let epoch = slot / 32;
        let parent_hex =
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let expected_parent = {
            let mut r = [0u8; 32];
            r.fill(0x11);
            r
        };

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let submitted = Arc::new(Mutex::new(Vec::<Root>::new()));
        let submitted_for_hook = Arc::clone(&submitted);
        let duty_pk = pk.to_bytes();
        let parent_for_stub = parent_hex.clone();

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_slot_aware_block_root(slot, &[], move |queried| match queried {
                    None => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                    Some(_) => parent_for_stub.clone(),
                })
                .with_post_sync_committee_duties(move |_epoch, _indices| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                })
                .with_submit_sync_committee_messages(move |messages| {
                    submitted_for_hook
                        .lock()
                        .unwrap()
                        .extend(messages.iter().map(|m| m.beacon_block_root));
                    Ok(())
                }),
        );

        let service = setup_service(beacon.clone(), pk_hex, pk, sk).await;

        // Coordinator sequence: parent at t=0, head at phase 2, then messages.
        let mut ctx = SlotContext::capture_parent(beacon.as_ref(), slot, epoch).await;
        assert!(ctx.head_root.is_none(), "t=0 capture_parent must not populate head_root");
        assert_eq!(ctx.parent_root, Some(expected_parent));

        ctx.apply_phase2_head(beacon.as_ref()).await;
        assert!(
            ctx.head_root.is_some(),
            "phase-2 capture_head must supply a head even when the current slot 404s"
        );

        service.maybe_produce_sync_messages(slot, epoch, &ctx, ample_slot_end()).await;
        let roots = submitted.lock().unwrap();
        assert!(
            !roots.is_empty(),
            "sync messages must be produced after phase-2 capture when the current slot 404s"
        );
        for root in roots.iter() {
            assert_eq!(
                *root, expected_parent,
                "messages must sign the captured head (parent when slot N has no block)"
            );
        }
    }

    /// `slot_end` already passed: nothing is signed or published, and the drop
    /// counter matches the duty count.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn undispatched_sync_duties_are_dropped_at_slot_end() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let submitted = Arc::new(Mutex::new(0usize));
        let submitted_for_hook = Arc::clone(&submitted);
        let duty_pk = pk.to_bytes();
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties(move |_epoch, _indices| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                })
                .with_submit_sync_committee_messages(move |messages| {
                    *submitted_for_hook.lock().unwrap() += messages.len();
                    Ok(())
                }),
        );
        let service = setup_service(beacon, pk_hex, pk, sk).await;
        let slot_end = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1)).await;
        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some([0xAA; 32]),
            fence: beacon::DutyFence::open(),
        };
        service.maybe_produce_sync_messages(0, 0, &ctx, slot_end).await;
        assert_eq!(*submitted.lock().unwrap(), 0, "no sync message is published after slot end");
        assert_eq!(service.slot_end_drops(), 1);
    }

    /// A publish started near `slot_end` is cut at `slot_end + 500 ms`.
    /// The `sync_message` timeout alone (2 s) would finish well into S+1.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn delayed_sync_publish_stops_at_slot_end_overhang() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let duty_pk = pk.to_bytes();
        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties(move |_epoch, _indices| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                })
                .with_submit_sync_committee_messages(|_| Ok(()))
                .with_method_delay(MockMethod::SubmitSyncCommitteeMessages, Duration::from_secs(2)),
        );
        let service =
            setup_service(Arc::clone(&beacon) as Arc<dyn BeaconNodeClient>, pk_hex, pk, sk).await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_millis(50);
        let ctx = SlotContext {
            slot: 0,
            epoch: 0,
            parent_root: None,
            expected_parents: None,
            head_root: Some([0xAA; 32]),
            fence: beacon::DutyFence::open(),
        };
        service.maybe_produce_sync_messages(0, 0, &ctx, slot_end).await;
        let finished = tokio::time::Instant::now();
        let overhang_at = slot_end + Duration::from_millis(500);
        assert!(
            finished <= overhang_at,
            "drain ran until {finished:?}, past overhang {overhang_at:?}"
        );
        assert!(
            finished.saturating_duration_since(started) < Duration::from_secs(2),
            "the 2 s sync_message timeout must not extend the phase, elapsed {:?}",
            finished.saturating_duration_since(started)
        );
        let submits: Vec<_> = beacon
            .call_stamps()
            .into_iter()
            .filter(|stamp| stamp.method == MockMethod::SubmitSyncCommitteeMessages)
            .collect();
        assert!(!submits.is_empty(), "the publish starts, then the overhang budget stops it");
        assert!(
            submits.iter().all(|stamp| stamp.at <= overhang_at),
            "a publish must not be admitted after the overhang: {submits:?}"
        );
        assert!(
            beacon.submit_sync_committee_messages_calls().is_empty(),
            "the 2 s POST must be cancelled before it completes"
        );
        assert!(
            beacon.submit_sync_committee_messages_completions().is_empty(),
            "a POST cancelled during the delay must not record a completion"
        );
    }

    /// Sync messages are non-slashable. Holding the slashing connection must
    /// not stop the phase from publishing.
    #[test]
    fn sync_messages_publish_while_slashing_db_conn_is_held() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (service, submitted, db) = rt.block_on(async {
            let sk = SecretKey::generate();
            let pk = sk.public_key();
            let submitted = Arc::new(Mutex::new(0usize));
            let submitted_for_hook = Arc::clone(&submitted);
            let duty_pk = pk.to_bytes();
            let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_sync_committee_duties(move |_epoch, _indices| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    })
                    .with_submit_sync_committee_messages(move |messages| {
                        *submitted_for_hook.lock().unwrap() += messages.len();
                        Ok(())
                    }),
            );
            let db = Arc::new(SlashingDb::open_in_memory().unwrap());
            let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
            store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
            let mut key_manager = KeyManager::new();
            key_manager.insert(sk);
            let signer = Arc::new(
                SignerService::new(
                    Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                    Arc::clone(&db),
                )
                .with_enablement(always_enabled()),
            );
            // Upcast: wide object only.
            let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
            duty_tracker.fetch_sync_committee_duties(0).await.unwrap();
            let mut map = HashMap::new();
            map.insert(pk.to_bytes(), pk);
            let service = SyncCommitteeService::new(
                signer,
                beacon,
                duty_tracker,
                Arc::new(parking_lot::RwLock::new(map)),
                create_test_config(),
                store,
            );
            (service, submitted, db)
        });

        let held = db
            .stage_block("0xdeadbeef01", 1, Some("0xhold".into()), &[0u8; 32])
            .expect("stage_block holds the slashing connection");

        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let published = rt.block_on(async move {
                let ctx = SlotContext {
                    slot: 0,
                    epoch: 0,
                    parent_root: None,
                    expected_parents: None,
                    head_root: Some([0xAA; 32]),
                    fence: beacon::DutyFence::open(),
                };
                let slot_end = tokio::time::Instant::now() + Duration::from_secs(30);
                service.maybe_produce_sync_messages(0, 0, &ctx, slot_end).await;
                *submitted.lock().unwrap()
            });
            tx.send(published).expect("publish result");
        });

        let published = rx.recv_timeout(Duration::from_secs(15)).unwrap_or_else(|_| {
            panic!("sync phase blocked while the slashing connection was held")
        });
        assert!(published > 0, "sync phase must publish while the slashing connection is held");
        worker.join().expect("sync worker");
        drop(held);
    }

    // ContributionAndProof signing roots for a fixed container.
    // eth-ssz-specs==0.1.0, consensus-specs v1.7.0-beta.2,
    // scripts/gen_signing_roots.py --contribution-out. Domain bytes are parsed
    // from altair beacon-chain.md (0x09000000). Fork versions match
    // create_test_fork_schedule with gloas_fork_epoch = 70. GVR is zero.
    // Aggregator 1, block root 0xcd*32, subcommittee 0, aggregation bits
    // 0xff*16, contribution signature 0x01*96, selection proof 0x22*96.
    const KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_DENEB: &str =
        "ddd35a153f5dd348cbdd029415b8008c6221f3f6bbdc767414d40dd4b671b589";
    const KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_ELECTRA: &str =
        "ab397acee848a543560c83257138e54ac18922d8de86cdb20e2ac7c5fe26ce04";
    const KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_FULU: &str =
        "08ba8ee46f0256737998aa09f04e3cbe0733d43f21ecfda18fa1c0caf9dcb3ac";
    const KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_GLOAS: &str =
        "b8a7f216721d67ec098c3dec0027fed747ef77ba5d4df8f5a7e76a6f29ed99c9";

    fn contribution_kat(name: &str) -> &'static str {
        match name {
            "deneb" => KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_DENEB,
            "electra" => KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_ELECTRA,
            "fulu" => KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_FULU,
            "gloas" => KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_GLOAS,
            other => panic!("no contribution KAT for {other}"),
        }
    }

    fn fixed_contribution_and_proof(slot: Slot) -> eth_types::ContributionAndProof {
        eth_types::ContributionAndProof {
            aggregator_index: 1,
            contribution: contribution_body(slot, [0xcd; 32], 0),
            selection_proof: vec![0x22; 96],
        }
    }

    fn contribution_body(
        slot: Slot,
        head: Root,
        subcommittee: u64,
    ) -> eth_types::SyncCommitteeContribution {
        eth_types::SyncCommitteeContribution {
            slot,
            beacon_block_root: head,
            subcommittee_index: subcommittee,
            aggregation_bits: vec![0xff; 16],
            signature: vec![1u8; 96],
        }
    }

    fn find_aggregator_for(
        slot: Slot,
        subcommittees: &[u64],
        schedule: &ForkSchedule,
        genesis: Root,
    ) -> (SecretKey, crypto::PublicKey) {
        use eth_types::{
            is_sync_committee_aggregator, ForkName, SyncAggregatorSelectionData,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        };
        let fork = ForkName::from_epoch(slot / 32, schedule);
        let domain = crypto::compute_domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            fork.fork_version(schedule),
            genesis,
        );
        loop {
            let sk = SecretKey::generate();
            let selected = subcommittees.iter().all(|subcommittee| {
                let data = SyncAggregatorSelectionData { slot, subcommittee_index: *subcommittee };
                let signing_root = crypto::compute_signing_root(&data, domain);
                is_sync_committee_aggregator(&sk.sign(&signing_root).to_bytes())
            });
            if selected {
                let pk = sk.public_key();
                return (sk, pk);
            }
        }
    }

    async fn service_with_config(
        beacon: Arc<dyn BeaconNodeClient>,
        pk: crypto::PublicKey,
        sk: SecretKey,
        config: OrchestratorConfig,
    ) -> SyncCommitteeService {
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let signer = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                Arc::new(SlashingDb::open_in_memory().unwrap()),
            )
            .with_enablement(always_enabled()),
        );
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk);
        SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            config,
            store,
        )
    }

    fn head_ctx(slot: Slot, head: Root) -> SlotContext {
        SlotContext {
            slot,
            epoch: slot / 32,
            parent_root: None,
            expected_parents: None,
            head_root: Some(head),
            fence: beacon::DutyFence::open(),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn contribution_intake_stops_at_slot_end_while_one_get_is_in_flight() {
        let slot = 0;
        let head = [0xAA; 32];
        let config = create_test_config().with_dispatch_limits(
            crate::orchestrator::dispatch::DispatchLimits::validated(1, 1).unwrap(),
        );
        let (sk, pk) = find_aggregator_for(slot, &[0, 1, 2], &config.fork_schedule, [0u8; 32]);
        let gets = Arc::new(AtomicUsize::new(0));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_method_delay(
                    MockMethod::GetSyncCommitteeContribution,
                    Duration::from_millis(300),
                )
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0, 128, 256],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution({
                    let gets = Arc::clone(&gets);
                    move |requested, subcommittee, _| {
                        gets.fetch_add(1, Ordering::SeqCst);
                        Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                    }
                })
                .with_submit_contribution_and_proofs(|_| Ok(())),
        );
        let service = service_with_config(beacon, pk, sk, config).await;
        let slot_end = tokio::time::Instant::now() + Duration::from_millis(200);
        service.maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), slot_end).await;
        assert_eq!(gets.load(Ordering::SeqCst), 1, "only the in-flight subcommittee is fetched");
        assert_eq!(service.slot_end_drops(), 2);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn past_slot_end_publishes_nothing_and_counts_the_drop() {
        let slot = 0;
        let head = [0xAA; 32];
        let config = create_test_config();
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let submits = Arc::new(AtomicUsize::new(0));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution(|requested, subcommittee, _| {
                    Ok(DataResponse {
                        data: contribution_body(requested, [0xAA; 32], subcommittee),
                    })
                })
                .with_submit_contribution_and_proofs({
                    let submits = Arc::clone(&submits);
                    move |proofs| {
                        submits.fetch_add(proofs.len(), Ordering::SeqCst);
                        Ok(())
                    }
                }),
        );
        let service = service_with_config(beacon, pk, sk, config).await;
        let slot_end = tokio::time::Instant::now() - Duration::from_millis(600);
        service.maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), slot_end).await;
        assert_eq!(submits.load(Ordering::SeqCst), 0);
        assert_eq!(service.slot_end_drops(), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn zero_sync_contribution_timeout_does_not_fetch_or_publish() {
        let slot = 0;
        let head = [0xAA; 32];
        let mut config = create_test_config();
        config.timeouts.sync_contribution = Duration::ZERO;
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let gets = Arc::new(AtomicUsize::new(0));
        let submits = Arc::new(AtomicUsize::new(0));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution({
                    let gets = Arc::clone(&gets);
                    move |requested, subcommittee, _| {
                        gets.fetch_add(1, Ordering::SeqCst);
                        Ok(DataResponse {
                            data: contribution_body(requested, [0xAA; 32], subcommittee),
                        })
                    }
                })
                .with_submit_contribution_and_proofs({
                    let submits = Arc::clone(&submits);
                    move |proofs| {
                        submits.fetch_add(proofs.len(), Ordering::SeqCst);
                        Ok(())
                    }
                }),
        );
        let service = service_with_config(beacon, pk, sk, config).await;
        let started = tokio::time::Instant::now();
        service
            .maybe_produce_sync_contributions(
                slot,
                0,
                &head_ctx(slot, head),
                started + Duration::from_secs(30),
            )
            .await;
        assert_eq!(gets.load(Ordering::SeqCst), 0);
        assert_eq!(submits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn hung_contribution_submit_stops_at_the_slot_end_overhang() {
        let slot = 0;
        let head = [0xAA; 32];
        let mut config = create_test_config();
        config.timeouts.sync_contribution = Duration::from_secs(10);
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let submits = Arc::new(AtomicUsize::new(0));
        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_method_delay(MockMethod::SubmitContributionAndProofs, Duration::from_secs(10))
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution(|requested, subcommittee, _| {
                    Ok(DataResponse {
                        data: contribution_body(requested, [0xAA; 32], subcommittee),
                    })
                })
                .with_submit_contribution_and_proofs({
                    let submits = Arc::clone(&submits);
                    move |proofs| {
                        submits.fetch_add(proofs.len(), Ordering::SeqCst);
                        Ok(())
                    }
                }),
        );
        let service =
            service_with_config(Arc::clone(&beacon) as Arc<dyn BeaconNodeClient>, pk, sk, config)
                .await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_secs(2);
        service.maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), slot_end).await;
        let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
        assert!(elapsed <= Duration::from_millis(2_600), "elapsed {elapsed:?}");
        let arrivals: Vec<_> = beacon
            .call_stamps()
            .into_iter()
            .filter(|stamp| stamp.method == MockMethod::SubmitContributionAndProofs)
            .collect();
        assert_eq!(arrivals.len(), 1, "the POST is started; skipping it is not this stop");
        assert!(arrivals[0].at <= slot_end + Duration::from_millis(500));
        assert_eq!(submits.load(Ordering::SeqCst), 0, "a cancelled submit is not a publish");
    }

    /// A contribution GET that outlives slot end is cut at slot end plus 500 ms.
    /// The 10 s `sync_contribution` timeout does not extend it.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn hung_contribution_get_stops_at_the_slot_end_overhang() {
        let slot = 0;
        let head = [0xAA; 32];
        let mut config = create_test_config();
        config.timeouts.sync_contribution = Duration::from_secs(10);
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_method_delay(
                    MockMethod::GetSyncCommitteeContribution,
                    Duration::from_secs(10),
                )
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution(move |requested, subcommittee, _| {
                    Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                })
                .with_submit_contribution_and_proofs(|_| Ok(())),
        );
        let service =
            service_with_config(Arc::clone(&beacon) as Arc<dyn BeaconNodeClient>, pk, sk, config)
                .await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_secs(2);
        service.maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), slot_end).await;
        let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
        assert!(elapsed <= Duration::from_millis(2_500), "elapsed {elapsed:?}");
        let arrivals: Vec<_> = beacon
            .call_stamps()
            .into_iter()
            .filter(|stamp| stamp.method == MockMethod::GetSyncCommitteeContribution)
            .collect();
        assert_eq!(arrivals.len(), 1, "the GET starts, then the overhang cuts it");
        assert!(arrivals[0].at < slot_end + Duration::from_millis(500));
        let posts: Vec<_> = beacon
            .call_stamps()
            .into_iter()
            .filter(|stamp| stamp.method == MockMethod::SubmitContributionAndProofs)
            .collect();
        assert!(posts.is_empty(), "a cancelled GET does not publish");
    }

    #[tokio::test]
    async fn duplicate_subcommittee_indices_are_fetched_and_signed_once() {
        let slot = 0;
        let head = [0xAA; 32];
        let config = create_test_config();
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let gets = Arc::new(AtomicUsize::new(0));
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0, 0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution({
                    let gets = Arc::clone(&gets);
                    move |requested, subcommittee, _| {
                        gets.fetch_add(1, Ordering::SeqCst);
                        Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                    }
                })
                .with_submit_contribution_and_proofs({
                    let proofs = Arc::clone(&proofs);
                    move |batch| {
                        proofs.lock().unwrap().extend(batch.iter().cloned());
                        Ok(())
                    }
                }),
        );
        let service = service_with_config(beacon, pk, sk, config).await;
        service
            .maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), ample_slot_end())
            .await;
        assert_eq!(gets.load(Ordering::SeqCst), 1);
        let published = proofs.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].message.contribution.subcommittee_index, 0);
        assert_eq!(published[0].signature.len(), 96);
    }

    #[tokio::test]
    async fn subcommittee_index_at_or_above_four_is_not_signed() {
        let slot = 0;
        let head = [0xAA; 32];
        let config = create_test_config();
        let (sk, pk) = find_aggregator_for(slot, &[0, 4], &config.fork_schedule, [0u8; 32]);
        let gets = Arc::new(Mutex::new(Vec::new()));
        let proofs = Arc::new(Mutex::new(Vec::new()));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0, 512],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution({
                    let gets = Arc::clone(&gets);
                    move |requested, subcommittee, _| {
                        gets.lock().unwrap().push(subcommittee);
                        Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                    }
                })
                .with_submit_contribution_and_proofs({
                    let proofs = Arc::clone(&proofs);
                    move |batch| {
                        proofs.lock().unwrap().extend(batch.iter().cloned());
                        Ok(())
                    }
                }),
        );
        let service = service_with_config(beacon, pk, sk, config).await;
        service
            .maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), ample_slot_end())
            .await;
        assert_eq!(*gets.lock().unwrap(), vec![0]);
        let published = proofs.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].message.contribution.subcommittee_index, 0);
    }

    #[tokio::test]
    async fn a_mismatched_contribution_is_not_published_and_a_sibling_is() {
        let slot = 0;
        let head = [0xAA; 32];
        let config = create_test_config();
        let bad_bodies = [
            contribution_body(slot + 1, head, 1),
            contribution_body(slot, [0xBB; 32], 1),
            contribution_body(slot, head, 9),
            eth_types::SyncCommitteeContribution {
                aggregation_bits: vec![0xff, 0x01],
                ..contribution_body(slot, head, 1)
            },
            eth_types::SyncCommitteeContribution {
                signature: vec![1u8; 95],
                ..contribution_body(slot, head, 1)
            },
        ];
        for bad in bad_bodies {
            let (sk, pk) = find_aggregator_for(slot, &[0, 1], &config.fork_schedule, [0u8; 32]);
            let proofs = Arc::new(Mutex::new(Vec::new()));
            let bad = bad.clone();
            let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_sync_committee_duties({
                        let duty_pk = pk.to_bytes();
                        move |_epoch, _| {
                            Ok(ExecutionOptimisticResponse {
                                execution_optimistic: false,
                                data: vec![SyncCommitteeDuty {
                                    pubkey: duty_pk,
                                    validator_index: 1,
                                    validator_sync_committee_indices: vec![0, 128],
                                }],
                            })
                        }
                    })
                    .with_get_sync_committee_contribution({
                        let bad = bad.clone();
                        move |requested, subcommittee, _| {
                            let data = if subcommittee == 0 {
                                contribution_body(requested, head, 0)
                            } else {
                                bad.clone()
                            };
                            Ok(DataResponse { data })
                        }
                    })
                    .with_submit_contribution_and_proofs({
                        let proofs = Arc::clone(&proofs);
                        move |batch| {
                            proofs.lock().unwrap().extend(batch.iter().cloned());
                            Ok(())
                        }
                    }),
            );
            let service = service_with_config(beacon, pk, sk, config.clone()).await;
            service
                .maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), ample_slot_end())
                .await;
            let published = proofs.lock().unwrap().clone();
            assert_eq!(published.len(), 1, "bad body {bad:?} must not be published");
            assert_eq!(published[0].message.contribution.slot, slot);
            assert_eq!(published[0].message.contribution.beacon_block_root, head);
            assert_eq!(published[0].message.contribution.subcommittee_index, 0);
            assert_eq!(published[0].message.contribution.aggregation_bits.len(), 16);
            assert_eq!(published[0].signature.len(), 96);
            assert!(published[0].signature.iter().any(|byte| *byte != 0));
        }
    }

    #[test]
    fn test_contribution_and_proof_signing_root() {
        let mut schedule = (*create_test_fork_schedule()).clone();
        schedule.gloas_fork_epoch = 70;
        let ctx =
            crypto::SigningCtx { fork_schedule: &schedule, genesis_validators_root: [0u8; 32] };
        let cases = [
            (1280u64, "deneb", KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_DENEB),
            (1600, "electra", KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_ELECTRA),
            (1920, "fulu", KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_FULU),
            (2240, "gloas", KAT_CONTRIBUTION_AND_PROOF_SIGNING_ROOT_GLOAS),
        ];
        for (slot, name, kat) in cases {
            let fixture = fixed_contribution_and_proof(slot);
            let got =
                crypto::signing_root_for(&crypto::DutyRef::ContributionAndProof(&fixture), &ctx);
            assert_eq!(hex::encode(got), kat, "{name}");
            assert_eq!(kat, contribution_kat(name), "{name}");
        }
    }

    #[tokio::test]
    async fn each_fork_publishes_the_slot_and_rejects_a_mismatched_slot() {
        let epochs = [(40u64, "deneb"), (50, "electra"), (60, "fulu"), (70, "gloas")];
        for (epoch, name) in epochs {
            let slot = epoch * 32;
            let head = [0xCD; 32];
            let mut schedule = (*create_test_fork_schedule()).clone();
            schedule.gloas_fork_epoch = 70;
            let schedule = Arc::new(schedule);
            let mut config = OrchestratorConfig::new([0u8; 32], Arc::clone(&schedule));
            config.timeouts.sync_contribution = Duration::from_secs(3);
            let (sk, pk) = find_aggregator_for(slot, &[0], &schedule, [0u8; 32]);
            let proofs = Arc::new(Mutex::new(Vec::new()));
            let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_sync_committee_duties({
                        let duty_pk = pk.to_bytes();
                        move |_epoch, _| {
                            Ok(ExecutionOptimisticResponse {
                                execution_optimistic: false,
                                data: vec![SyncCommitteeDuty {
                                    pubkey: duty_pk,
                                    validator_index: 1,
                                    validator_sync_committee_indices: vec![0],
                                }],
                            })
                        }
                    })
                    .with_get_sync_committee_contribution(move |requested, subcommittee, root| {
                        assert_eq!(root, format!("0x{}", hex::encode(head)));
                        Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                    })
                    .with_submit_contribution_and_proofs({
                        let proofs = Arc::clone(&proofs);
                        move |batch| {
                            proofs.lock().unwrap().extend(batch.iter().cloned());
                            Ok(())
                        }
                    }),
            );
            let pk_verify = pk.clone();
            let service = service_with_config(beacon, pk, sk, config.clone()).await;
            service
                .maybe_produce_sync_contributions(
                    slot,
                    epoch,
                    &head_ctx(slot, head),
                    ample_slot_end(),
                )
                .await;
            let published = proofs.lock().unwrap().clone();
            assert_eq!(published.len(), 1, "{name}");
            assert_eq!(published[0].message.contribution.slot, slot, "{name}");
            assert_eq!(published[0].message.contribution.beacon_block_root, head, "{name}");
            assert_eq!(published[0].signature.len(), 96, "{name}");
            assert!(published[0].signature.iter().any(|byte| *byte != 0), "{name}");
            assert_eq!(eth_types::ForkName::from_epoch(epoch, &schedule).as_ref(), name);
            let ctx = crypto::SigningCtx {
                fork_schedule: schedule.as_ref(),
                genesis_validators_root: [0u8; 32],
            };
            let fixture = fixed_contribution_and_proof(slot);
            let anchored =
                crypto::signing_root_for(&crypto::DutyRef::ContributionAndProof(&fixture), &ctx);
            assert_eq!(hex::encode(anchored), contribution_kat(name), "{name}");
            // The published selection proof is a fresh key, so its signing root
            // is not the fixed KAT. This only checks the signature matches that
            // message; the root oracle is `contribution_kat`.
            let expected = crypto::signing_root_for(
                &crypto::DutyRef::ContributionAndProof(&published[0].message),
                &ctx,
            );
            let signature =
                crypto::Signature::from_bytes(&published[0].signature).expect("signature bytes");
            signature.verify(&pk_verify, &expected).expect(name);
            let wrong_domain = crypto::signing_root_with_fork_version(
                &published[0].message,
                eth_types::DOMAIN_CONTRIBUTION_AND_PROOF,
                [0, 0, 0, 1],
                [0u8; 32],
            );
            assert!(signature.verify(&pk_verify, &wrong_domain).is_err(), "{name}");

            let (sk, pk) = find_aggregator_for(slot, &[0], &schedule, [0u8; 32]);
            let submits = Arc::new(AtomicUsize::new(0));
            let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_sync_committee_duties({
                        let duty_pk = pk.to_bytes();
                        move |_epoch, _| {
                            Ok(ExecutionOptimisticResponse {
                                execution_optimistic: false,
                                data: vec![SyncCommitteeDuty {
                                    pubkey: duty_pk,
                                    validator_index: 1,
                                    validator_sync_committee_indices: vec![0],
                                }],
                            })
                        }
                    })
                    .with_get_sync_committee_contribution(move |requested, subcommittee, _| {
                        Ok(DataResponse {
                            data: contribution_body(requested + 1, head, subcommittee),
                        })
                    })
                    .with_submit_contribution_and_proofs({
                        let submits = Arc::clone(&submits);
                        move |batch| {
                            submits.fetch_add(batch.len(), Ordering::SeqCst);
                            Ok(())
                        }
                    }),
            );
            let service = service_with_config(beacon, pk, sk, config).await;
            service
                .maybe_produce_sync_contributions(
                    slot,
                    epoch,
                    &head_ctx(slot, head),
                    ample_slot_end(),
                )
                .await;
            assert_eq!(submits.load(Ordering::SeqCst), 0, "{name}");
        }
    }

    #[tokio::test]
    async fn an_empty_aggregation_bitfield_is_not_signed() {
        let slot = 0;
        let head = [0xAA; 32];
        let config = create_test_config();
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let gets = Arc::new(AtomicUsize::new(0));
        let submits = Arc::new(AtomicUsize::new(0));
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution({
                    let gets = Arc::clone(&gets);
                    move |requested, subcommittee, _| {
                        gets.fetch_add(1, Ordering::SeqCst);
                        let mut body = contribution_body(requested, head, subcommittee);
                        body.aggregation_bits = vec![0u8; 16];
                        Ok(DataResponse { data: body })
                    }
                })
                .with_submit_contribution_and_proofs({
                    let submits = Arc::clone(&submits);
                    move |batch| {
                        submits.fetch_add(batch.len(), Ordering::SeqCst);
                        Ok(())
                    }
                }),
        );
        let selection_calls = Arc::new(AtomicUsize::new(0));
        let contribution_calls = Arc::new(AtomicUsize::new(0));
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let inner = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                Arc::new(SlashingDb::open_in_memory().unwrap()),
            )
            .with_enablement(always_enabled()),
        );
        let signer = Arc::new(SlowSigner {
            inner,
            delay_selection: false,
            delay_contribution: false,
            delay: Duration::ZERO,
            selection_calls: Arc::clone(&selection_calls),
            contribution_calls: Arc::clone(&contribution_calls),
            selection_finished: Arc::new(AtomicUsize::new(0)),
            contribution_finished: Arc::new(AtomicUsize::new(0)),
        });
        let service = service_with_signer(beacon, pk, signer, config).await;
        service
            .maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), ample_slot_end())
            .await;
        assert_eq!(gets.load(Ordering::SeqCst), 1);
        assert_eq!(submits.load(Ordering::SeqCst), 0);
        assert_eq!(selection_calls.load(Ordering::SeqCst), 1, "the selection proof still runs");
        assert_eq!(
            contribution_calls.load(Ordering::SeqCst),
            0,
            "an empty aggregation bitfield is not passed to sign_contribution_and_proof"
        );
    }

    struct SlowSigner {
        inner: Arc<SignerService>,
        delay_selection: bool,
        delay_contribution: bool,
        delay: Duration,
        selection_calls: Arc<AtomicUsize>,
        contribution_calls: Arc<AtomicUsize>,
        /// Incremented after the selection sleep, so a cancelled sleep stays at 0.
        selection_finished: Arc<AtomicUsize>,
        /// Incremented after the contribution sleep, so a cancelled sleep stays at 0.
        contribution_finished: Arc<AtomicUsize>,
    }

    macro_rules! slow_fwd {
        ($($name:ident($($arg:ident: $ty:ty),* $(,)?));* $(;)?) => {
            #[async_trait]
            impl ValidatorSigner for SlowSigner {
                $(
                    async fn $name(&self, $($arg: $ty),*) -> Result<crypto::Signature, signer::SignerError> {
                        slow_fwd!(@arm $name, self, $($arg),*);
                        self.inner.$name($($arg),*).await
                    }
                )*
            }
        };
        (@arm sign_sync_committee_selection_proof, $self:ident, $($arg:ident),*) => {
            $self.selection_calls.fetch_add(1, Ordering::SeqCst);
            if $self.delay_selection {
                tokio::time::sleep($self.delay).await;
            }
            $self.selection_finished.fetch_add(1, Ordering::SeqCst);
        };
        (@arm sign_contribution_and_proof, $self:ident, $($arg:ident),*) => {
            $self.contribution_calls.fetch_add(1, Ordering::SeqCst);
            if $self.delay_contribution {
                tokio::time::sleep($self.delay).await;
            }
            $self.contribution_finished.fetch_add(1, Ordering::SeqCst);
        };
        (@arm $name:ident, $self:ident, $($arg:ident),*) => {};
    }

    slow_fwd! {
        sign_attestation(data: &eth_types::AttestationData, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_block(block_root: &Root, slot: Slot, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_block_header(header: &signer::BeaconBlockHeaderFields, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_randao_reveal(epoch: eth_types::Epoch, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_sync_committee_message(beacon_block_root: &Root, slot: Slot, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_selection_proof(slot: Slot, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_aggregate_and_proof(aggregate_and_proof: &eth_types::AggregateAndProof, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_electra_aggregate_and_proof(aggregate_and_proof: &eth_types::ElectraAggregateAndProof, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_voluntary_exit(voluntary_exit: &eth_types::VoluntaryExit, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_builder_registration(registration: &eth_types::ValidatorRegistrationV1, pubkey: &crypto::PublicKey, fork_version: [u8; 4]);
        sign_sync_committee_selection_proof(slot: Slot, subcommittee_index: u64, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_contribution_and_proof(contribution_and_proof: &eth_types::ContributionAndProof, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_payload_attestation(data: &eth_types::PayloadAttestationData, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_execution_payload_envelope_root(object_root: &Root, slot: Slot, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
        sign_aggregate_and_proof_root(object_root: &Root, slot: Slot, pubkey: &crypto::PublicKey, fork_schedule: &eth_types::ForkSchedule, genesis_validators_root: &Root);
    }

    async fn service_with_signer(
        beacon: Arc<dyn BeaconNodeClient>,
        pk: crypto::PublicKey,
        signer: Arc<dyn ValidatorSigner>,
        config: OrchestratorConfig,
    ) -> SyncCommitteeService {
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk);
        SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            config,
            store,
        )
    }

    enum SlowCase {
        Selection,
        Contribution,
        AlreadyPast,
    }

    async fn slow_signer_stops(case: SlowCase) {
        let slot = 0;
        let head = [0xAA; 32];
        let mut config = create_test_config();
        config.timeouts.sync_contribution = Duration::from_secs(10);
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let selection_calls = Arc::new(AtomicUsize::new(0));
        let contribution_calls = Arc::new(AtomicUsize::new(0));
        let gets = Arc::new(AtomicUsize::new(0));
        let submits = Arc::new(AtomicUsize::new(0));
        let (delay_selection, delay_contribution) = match case {
            SlowCase::Selection => (true, false),
            SlowCase::Contribution => (false, true),
            SlowCase::AlreadyPast => (true, true),
        };
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let inner = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                Arc::new(SlashingDb::open_in_memory().unwrap()),
            )
            .with_enablement(always_enabled()),
        );
        let signer = Arc::new(SlowSigner {
            inner,
            delay_selection,
            delay_contribution,
            delay: Duration::from_secs(10),
            selection_calls: Arc::clone(&selection_calls),
            contribution_calls: Arc::clone(&contribution_calls),
            selection_finished: Arc::new(AtomicUsize::new(0)),
            contribution_finished: Arc::new(AtomicUsize::new(0)),
        });
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution({
                    let gets = Arc::clone(&gets);
                    move |requested, subcommittee, _| {
                        gets.fetch_add(1, Ordering::SeqCst);
                        Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                    }
                })
                .with_submit_contribution_and_proofs({
                    let submits = Arc::clone(&submits);
                    move |batch| {
                        submits.fetch_add(batch.len(), Ordering::SeqCst);
                        Ok(())
                    }
                }),
        );
        let service = service_with_signer(beacon, pk, signer, config).await;
        if matches!(case, SlowCase::AlreadyPast) {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let started = tokio::time::Instant::now();
        let slot_end = if matches!(case, SlowCase::AlreadyPast) {
            started - Duration::from_secs(1)
        } else {
            started + Duration::from_millis(200)
        };
        service.maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), slot_end).await;
        let elapsed = started.elapsed();
        // Slot end is 200 ms ahead and the cap is that instant plus 500 ms.
        assert!(elapsed <= Duration::from_millis(700), "signer stretched the phase to {elapsed:?}");
        assert_eq!(submits.load(Ordering::SeqCst), 0);
        match case {
            SlowCase::Selection => {
                assert_eq!(selection_calls.load(Ordering::SeqCst), 1);
                assert_eq!(contribution_calls.load(Ordering::SeqCst), 0);
                assert_eq!(gets.load(Ordering::SeqCst), 0);
            }
            SlowCase::Contribution => {
                assert_eq!(selection_calls.load(Ordering::SeqCst), 1);
                assert_eq!(contribution_calls.load(Ordering::SeqCst), 1);
                assert_eq!(gets.load(Ordering::SeqCst), 1);
            }
            SlowCase::AlreadyPast => {
                assert_eq!(selection_calls.load(Ordering::SeqCst), 0);
                assert_eq!(contribution_calls.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_slow_contribution_signer_stops_at_the_slot_end_overhang() {
        slow_signer_stops(SlowCase::Selection).await;
        slow_signer_stops(SlowCase::Contribution).await;
        slow_signer_stops(SlowCase::AlreadyPast).await;
    }

    /// Contribution body is fetched, then admission is revoked. The contribution
    /// signer must not be entered. A holding fence still signs, and that sign
    /// is inside the admission scope.
    #[tokio::test]
    async fn sync_contribution_fetched_before_revocation_is_not_signed() {
        let slot = 0;
        let head = [0xAA; 32];
        let config = create_test_config();
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let selection_calls = Arc::new(AtomicUsize::new(0));
        let contribution_calls = Arc::new(AtomicUsize::new(0));
        let submits = Arc::new(AtomicUsize::new(0));
        let beacon = MockBeaconNodeClient::new();
        let generation = beacon.track_admission();
        let beacon = Arc::new(
            beacon
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution({
                    let generation = Arc::clone(&generation);
                    move |requested, subcommittee, _| {
                        generation.fetch_add(1, Ordering::Release);
                        Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                    }
                })
                .with_submit_contribution_and_proofs({
                    let submits = Arc::clone(&submits);
                    move |batch| {
                        submits.fetch_add(batch.len(), Ordering::SeqCst);
                        Ok(())
                    }
                }),
        );
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let inner = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                Arc::new(SlashingDb::open_in_memory().unwrap()),
            )
            .with_enablement(always_enabled()),
        );
        let signer = Arc::new(SlowSigner {
            inner,
            delay_selection: false,
            delay_contribution: false,
            delay: Duration::ZERO,
            selection_calls: Arc::clone(&selection_calls),
            contribution_calls: Arc::clone(&contribution_calls),
            selection_finished: Arc::new(AtomicUsize::new(0)),
            contribution_finished: Arc::new(AtomicUsize::new(0)),
        });
        let service = service_with_signer(beacon, pk, signer, config.clone()).await;
        service
            .maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), ample_slot_end())
            .await;
        assert_eq!(
            selection_calls.load(Ordering::SeqCst),
            1,
            "selection proof runs before the fetch"
        );
        assert_eq!(
            contribution_calls.load(Ordering::SeqCst),
            0,
            "removing the pre-sign fence check enters sign_contribution_and_proof"
        );
        assert_eq!(submits.load(Ordering::SeqCst), 0);

        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let submits = Arc::new(AtomicUsize::new(0));
        let beacon = MockBeaconNodeClient::new();
        let _generation = beacon.track_admission();
        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            beacon
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution(move |requested, subcommittee, _| {
                    Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                })
                .with_submit_contribution_and_proofs({
                    let submits = Arc::clone(&submits);
                    move |batch| {
                        submits.fetch_add(batch.len(), Ordering::SeqCst);
                        Ok(())
                    }
                }),
        );
        let service = service_with_config(beacon, pk, sk, config).await;
        signer::require_beacon_admission_scope(async {
            service
                .maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), ample_slot_end())
                .await;
        })
        .await;
        assert_eq!(
            submits.load(Ordering::SeqCst),
            1,
            "a holding fence signs the contribution only inside the admission scope"
        );
    }

    /// Selection or contribution sign whose sleep ends on slot end + 500 ms.
    ///
    /// The sleep duration is that overhang. `timeout_at` polls the signer
    /// first, so the sign returns `Ok` at the overhang instead of being
    /// cancelled. The next step's fresh deadline is that same overhang.
    async fn sign_finishes_on_the_overhang(
        delay_selection: bool,
        delay_contribution: bool,
    ) -> (Arc<MockBeaconNodeClient>, usize, usize) {
        let slot = 0;
        let head = [0xAA; 32];
        let mut config = create_test_config();
        config.timeouts.sync_contribution = Duration::from_secs(10);
        let (sk, pk) = find_aggregator_for(slot, &[0], &config.fork_schedule, [0u8; 32]);
        let selection_finished = Arc::new(AtomicUsize::new(0));
        let contribution_finished = Arc::new(AtomicUsize::new(0));
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let inner = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                Arc::new(SlashingDb::open_in_memory().unwrap()),
            )
            .with_enablement(always_enabled()),
        );
        let signer = Arc::new(SlowSigner {
            inner,
            delay_selection,
            delay_contribution,
            delay: Duration::from_millis(700),
            selection_calls: Arc::new(AtomicUsize::new(0)),
            contribution_calls: Arc::new(AtomicUsize::new(0)),
            selection_finished: Arc::clone(&selection_finished),
            contribution_finished: Arc::clone(&contribution_finished),
        });
        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties({
                    let duty_pk = pk.to_bytes();
                    move |_epoch, _| {
                        Ok(ExecutionOptimisticResponse {
                            execution_optimistic: false,
                            data: vec![SyncCommitteeDuty {
                                pubkey: duty_pk,
                                validator_index: 1,
                                validator_sync_committee_indices: vec![0],
                            }],
                        })
                    }
                })
                .with_get_sync_committee_contribution(move |requested, subcommittee, _| {
                    Ok(DataResponse { data: contribution_body(requested, head, subcommittee) })
                })
                .with_submit_contribution_and_proofs(|_| Ok(())),
        );
        let service = service_with_signer(
            Arc::clone(&beacon) as Arc<dyn BeaconNodeClient>,
            pk,
            signer,
            config,
        )
        .await;
        let slot_end = tokio::time::Instant::now() + Duration::from_millis(200);
        service.maybe_produce_sync_contributions(slot, 0, &head_ctx(slot, head), slot_end).await;
        (
            beacon,
            selection_finished.load(Ordering::SeqCst),
            contribution_finished.load(Ordering::SeqCst),
        )
    }

    fn arrivals(beacon: &MockBeaconNodeClient, method: MockMethod) -> usize {
        beacon.call_stamps().into_iter().filter(|stamp| stamp.method == method).count()
    }

    /// The selection proof returns at slot end + 500 ms. The contribution GET
    /// is not sent. Removing the pre-GET deadline check polls the GET once.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_produce_ready_at_the_deadline_is_not_fetched() {
        let (beacon, selection_finished, contribution_finished) =
            sign_finishes_on_the_overhang(true, false).await;
        assert_eq!(selection_finished, 1, "the selection proof completed on the overhang");
        assert_eq!(contribution_finished, 0);
        assert_eq!(arrivals(&beacon, MockMethod::GetSyncCommitteeContribution), 0);
        assert_eq!(arrivals(&beacon, MockMethod::SubmitContributionAndProofs), 0);
    }

    /// The contribution signature returns at slot end + 500 ms. The POST is
    /// not sent. Removing the pre-POST deadline check polls the POST once.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_wave_ready_at_the_deadline_is_not_posted() {
        let (beacon, selection_finished, contribution_finished) =
            sign_finishes_on_the_overhang(false, true).await;
        assert_eq!(selection_finished, 1);
        assert_eq!(
            contribution_finished, 1,
            "the contribution signature completed on the overhang"
        );
        assert_eq!(arrivals(&beacon, MockMethod::GetSyncCommitteeContribution), 1);
        assert_eq!(arrivals(&beacon, MockMethod::SubmitContributionAndProofs), 0);
    }

    /// `timeout_at` on a past instant still polls its future once. The
    /// pre-check is what keeps an already-due sign off the signer.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn sign_before_deadline_is_not_called_when_already_due() {
        let polled = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&polled);
        let slot_end = tokio::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let outcome = sign_before_deadline(slot_end, Duration::from_secs(10), async move {
            flag.fetch_add(1, Ordering::SeqCst);
            Err::<crypto::Signature, ()>(())
        })
        .await;
        assert!(matches!(outcome, Err(SignStop::Stopped { bounded_by_overhang: true })));
        assert_eq!(polled.load(Ordering::SeqCst), 0, "a past deadline does not poll the signer");
    }
}
