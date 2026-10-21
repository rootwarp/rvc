use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tracing::{debug, info, info_span, warn, Instrument, Span};

use crate::metrics::{attestation_status, RVC_AGGREGATIONS_TOTAL};
use beacon::{VersionedAggregateAttestation, VersionedSignedAggregateAndProof};
use bn_manager::AttestationApi;
use crypto::PublicKey;
use duty_tracker::{DutyTracker, TypedAttesterDuty};
use eth_types::{
    AggregateAndProof, ElectraAggregateAndProof, ForkName, SignedAggregateAndProof,
    SignedElectraAggregateAndProof, Slot, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE,
};
use observability::logging::TruncatedPubkey;
use signer::{is_aggregator, ValidatorSigner};
use ssz08::Encode;
use tree_hash::TreeHash;
use validator_store::ValidatorStore;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::dispatch::{
    sign_with_phase2_permit, Phase2SignError, Phase2SignerPermits, SlotEndDropCounter,
    SLOT_END_PUBLISH_OVERHANG,
};
use super::utils::{self, TimedOutcome};

pub(crate) struct AggregationService {
    signer: Arc<dyn ValidatorSigner>,
    beacon: Arc<dyn AttestationApi>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    /// D-3: per-validator doppelganger gate.  Mirrors the M-12 check already
    /// present in attestation.rs so that aggregation and selection proofs
    /// are also suppressed during the post-import doppelganger window.
    validator_store: Arc<ValidatorStore>,
    /// Aggregator duties not pulled onto the sign pipeline before slot end.
    slot_end_drops: SlotEndDropCounter,
}

/// Signed aggregate produced for one aggregator duty (fork-discriminated).
enum ProducedAggregate {
    PreElectra(SignedAggregateAndProof),
    Electra(SignedElectraAggregateAndProof),
    Gloas(SignedElectraAggregateAndProof),
}

/// Selects the pre-refactor log message set for aggregate submission.
enum AggregateSubmitLabel {
    PreElectra,
    Electra,
    Gloas,
}

/// Result of attempting aggregation for a single attester duty.
///
/// `None` means the duty was skipped before selection (disabled / not
/// selected). `Some` means the validator was selected as aggregator; `proof`
/// is `None` when a later step failed after selection (source_validators still
/// records the validator_index — matches pre-refactor behaviour).
struct AggregateDutyOutcome {
    /// Parsed at the duty cache. Primary key for `source_validators`.
    validator_index: u64,
    /// Wire decimal recorded on the submit span. Tie-break for the sort.
    raw_validator_index: String,
    proof: Option<ProducedAggregate>,
}

/// Why an aggregate body was not the one this duty requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateMismatch {
    Slot,
    DataRoot,
    DataIndex,
    CommitteeIndex,
    AttesterBits,
    Fork,
    Oversized,
}

impl AggregateMismatch {
    fn as_str(self) -> &'static str {
        match self {
            Self::Slot => "slot",
            Self::DataRoot => "data_root",
            Self::DataIndex => "data_index",
            Self::CommitteeIndex => "committee_index",
            Self::AttesterBits => "attester_bits",
            Self::Fork => "fork",
            Self::Oversized => "oversized",
        }
    }
}

/// The aggregate body is the one `get_aggregate_attestation` was asked for.
///
/// The root is `AttestationData::tree_hash_root` of the body that would be
/// signed. Electra and Fulu also require `data.index == 0` (EIP-7549). Before
/// Electra, `data.index` must be the duty's committee index. At Gloas the
/// index stays in the root (payload empty or full). The duty's
/// `committee_length` must be `1..=MAX_VALIDATORS_PER_COMMITTEE` on every
/// fork. A mismatch is returned before any `sign_*aggregate_and_proof*` call.
fn aggregate_matches(
    aggregate: &VersionedAggregateAttestation,
    slot: Slot,
    att_data_root: tree_hash::Hash256,
    committee_index: u64,
    committee_length: u64,
    fork: ForkName,
) -> Result<(), AggregateMismatch> {
    if !aggregate_fork_matches(aggregate, fork) {
        return Err(AggregateMismatch::Fork);
    }
    let (data, aggregation_bits, signature, committee_bits) = match aggregate {
        VersionedAggregateAttestation::PreElectra(body) => {
            (&body.data, body.aggregation_bits.as_slice(), body.signature.as_slice(), None)
        }
        VersionedAggregateAttestation::Electra(body)
        | VersionedAggregateAttestation::Fulu(body)
        | VersionedAggregateAttestation::Gloas(body) => (
            &body.data,
            body.aggregation_bits.as_slice(),
            body.signature.as_slice(),
            Some(body.committee_bits.as_slice()),
        ),
    };
    if signature.len() != 96 {
        return Err(AggregateMismatch::Oversized);
    }
    // `committee_length` is an unbounded duty field. The Electra bitlist limit
    // is larger than 2048, so a matching over-long list would otherwise be signed.
    if !(1..=MAX_VALIDATORS_PER_COMMITTEE).contains(&committee_length) {
        return Err(AggregateMismatch::AttesterBits);
    }
    let max_bits = if utils::uses_electra_attestation_wire(fork) {
        MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT
    } else {
        MAX_VALIDATORS_PER_COMMITTEE
    };
    attester_bits_ok(aggregation_bits, max_bits, committee_length)?;
    if data.slot != slot {
        return Err(AggregateMismatch::Slot);
    }
    if let Some(bits) = committee_bits {
        committee_index_ok(bits, committee_index)?;
    }
    if utils::zeroes_committee_index(fork) {
        if data.index != 0 {
            return Err(AggregateMismatch::DataIndex);
        }
    } else if !utils::uses_electra_attestation_wire(fork) && data.index != committee_index {
        return Err(AggregateMismatch::DataIndex);
    }
    if data.tree_hash_root() != att_data_root {
        return Err(AggregateMismatch::DataRoot);
    }
    Ok(())
}

/// Fork variant accepted for `fork`.
///
/// An Electra body is accepted on every fork that uses the Electra wire,
/// including Fulu and Gloas. A beacon node without aggregate v2 returns that
/// variant from the v1 fallback. Fulu stays exact. Gloas stays open-ended.
fn aggregate_fork_matches(aggregate: &VersionedAggregateAttestation, fork: ForkName) -> bool {
    match aggregate {
        VersionedAggregateAttestation::PreElectra(_) => fork < ForkName::Electra,
        VersionedAggregateAttestation::Electra(_) => utils::uses_electra_attestation_wire(fork),
        VersionedAggregateAttestation::Fulu(_) => fork == ForkName::Fulu,
        VersionedAggregateAttestation::Gloas(_) => fork >= ForkName::Gloas,
    }
}

/// SSZ `Bitlist` bytes for this duty.
///
/// The byte cap and the bit cap each reject an oversized buffer before the
/// committee-length compare. A buffer inside the spec whose bit length
/// is not `committee_length` is [`AggregateMismatch::AttesterBits`].
/// `committee_length` must be `1..=MAX_VALIDATORS_PER_COMMITTEE` on every fork.
fn attester_bits_ok(
    bytes: &[u8],
    max_bits: u64,
    committee_length: u64,
) -> Result<(), AggregateMismatch> {
    let max_len = (max_bits / 8 + 1) as usize;
    if bytes.len() > max_len {
        return Err(AggregateMismatch::Oversized);
    }
    if bytes.is_empty() {
        return Err(AggregateMismatch::AttesterBits);
    }
    let last = *bytes.last().expect("length checked");
    if last == 0 {
        return Err(AggregateMismatch::AttesterBits);
    }
    let sentinel_bit = 7 - last.leading_zeros() as usize;
    let bit_length = (bytes.len() - 1) * 8 + sentinel_bit;
    if bit_length as u64 > max_bits {
        return Err(AggregateMismatch::Oversized);
    }
    if !(1..=MAX_VALIDATORS_PER_COMMITTEE).contains(&committee_length)
        || bit_length as u64 != committee_length
    {
        return Err(AggregateMismatch::AttesterBits);
    }
    let mut saw_participant = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let bits = if index + 1 == bytes.len() { byte & !(1 << sentinel_bit) } else { byte };
        if bits != 0 {
            saw_participant = true;
            break;
        }
    }
    if saw_participant {
        Ok(())
    } else {
        Err(AggregateMismatch::AttesterBits)
    }
}

/// Electra+ `committee_bits` is `Bitvector[MAX_COMMITTEES_PER_SLOT]` with
/// exactly the requested committee set.
fn committee_index_ok(bits: &[u8], committee_index: u64) -> Result<(), AggregateMismatch> {
    if bits.len() > (MAX_COMMITTEES_PER_SLOT as usize).div_ceil(8) {
        return Err(AggregateMismatch::Oversized);
    }
    if bits.len() != (MAX_COMMITTEES_PER_SLOT as usize).div_ceil(8)
        || committee_index >= MAX_COMMITTEES_PER_SLOT
    {
        return Err(AggregateMismatch::CommitteeIndex);
    }
    let mut matched = false;
    for (index, byte) in bits.iter().copied().enumerate() {
        for bit in 0..8 {
            if byte & (1 << bit) == 0 {
                continue;
            }
            let set = (index * 8 + bit) as u64;
            if matched || set != committee_index {
                return Err(AggregateMismatch::CommitteeIndex);
            }
            matched = true;
        }
    }
    if matched {
        Ok(())
    } else {
        Err(AggregateMismatch::CommitteeIndex)
    }
}

impl AggregationService {
    pub(crate) fn new(
        signer: Arc<dyn ValidatorSigner>,
        beacon: Arc<dyn AttestationApi>,
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

    /// Duties dropped because slot end arrived before they were dispatched.
    #[cfg(test)]
    pub(crate) fn slot_end_drops(&self) -> u64 {
        self.slot_end_drops.get()
    }

    /// Produce aggregate-and-proofs for `slot`.
    ///
    /// `take_until(slot_end)` stops pulling new duties. Signs already inside
    /// `buffer_unordered` drain. Each ready chunk is one submit. A publish is
    /// admitted only until `slot_end` plus [`SLOT_END_PUBLISH_OVERHANG`].
    /// Aggregates are non-slashable: this path does not touch SQLite.
    /// `source_validators` is sorted before recording because wave completion
    /// order is not the duty order. The span is on [`Self::produce_aggregations`].
    ///
    /// Tests call this so a pipeline keeps its own cap. The coordinator calls
    /// [`Self::produce_aggregations`] with the shared phase-2 permits.
    #[cfg(test)]
    pub(crate) async fn maybe_produce_aggregations(
        &self,
        slot: Slot,
        epoch: u64,
        slot_end: tokio::time::Instant,
    ) {
        let permits = Phase2SignerPermits::new(self.config.dispatch_limits.concurrency as usize);
        self.produce_aggregations(slot, epoch, slot_end, &permits).await
    }

    /// Produce aggregate-and-proofs under a caller-owned phase-2 cap.
    ///
    /// The coordinator passes one [`Phase2SignerPermits`] shared with sync
    /// contributions. A caller outside that phase builds its own, sized to
    /// the same knob.
    #[tracing::instrument(name = "orchestrator.produce_aggregations", level = "debug", skip_all, fields(slot = slot, epoch = epoch))]
    pub(crate) async fn produce_aggregations(
        &self,
        slot: Slot,
        epoch: u64,
        slot_end: tokio::time::Instant,
        permits: &Phase2SignerPermits,
    ) {
        let duties =
            match utils::get_duties_for_slot(&self.pubkey_map, &self.duty_tracker, slot).await {
                Ok(d) => d,
                Err(_) => return,
            };

        if duties.is_empty() {
            return;
        }

        let fork_name = ForkName::from_epoch(epoch, &self.config.fork_schedule);
        let uses_electra_wire = utils::uses_electra_attestation_wire(fork_name);
        let fork_label: &'static str = if fork_name == ForkName::Gloas {
            "gloas"
        } else if fork_name == ForkName::Fulu {
            "fulu"
        } else if uses_electra_wire {
            "electra"
        } else {
            "pre_electra"
        };

        // Same shape as attestation and sync dispatch. Aggregates stay
        // non-slashable: no slashing DB access on this path.
        let duty_count = duties.len();
        let concurrency = self.config.dispatch_limits.concurrency as usize;
        let publish_concurrency = self.config.dispatch_limits.publish_concurrency as usize;
        let sign_deadline = slot_end.checked_add(SLOT_END_PUBLISH_OVERHANG).unwrap_or(slot_end);
        let waves = stream::iter(duties)
            .take_until(tokio::time::sleep_until(slot_end))
            .map(|duty| {
                let agg_span = info_span!(
                    "aggregation.produce",
                    slot = slot,
                    validator_index = %duty.validator_index,
                    pubkey = %TruncatedPubkey::new(&duty.pubkey),
                    aggregation.fork = fork_label,
                );
                self.produce_one_aggregate(duty, slot, fork_name, agg_span, permits, sign_deadline)
            })
            .buffer_unordered(concurrency)
            .ready_chunks(concurrency)
            .map(|wave| self.publish_aggregate_wave(slot, slot_end, fork_name, wave))
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
                "undispatched aggregation duties dropped at slot end"
            );
        }
    }

    /// Select-as-aggregator path for a single duty: selection proof through
    /// signed aggregate-and-proof. Returns `None` when the duty is skipped
    /// before selection; `Some` once selected (proof may still be `None`).
    async fn produce_one_aggregate(
        &self,
        duty: TypedAttesterDuty,
        slot: Slot,
        fork_name: ForkName,
        agg_span: Span,
        permits: &Phase2SignerPermits,
        sign_deadline: tokio::time::Instant,
    ) -> Option<AggregateDutyOutcome> {
        let committee_length = duty.committee_length;

        let pubkey = utils::find_pubkey(&self.pubkey_map, &duty.pubkey)?;

        // D-3: per-validator doppelganger gate (mirrors attestation.rs M-12 check).
        // `pubkey` is the already-resolved typed PublicKey — use its infallible
        // `to_bytes()` instead of re-decoding the hex string (no fail-open).
        {
            let pk_bytes = pubkey.to_bytes();
            if !self.validator_store.is_signing_enabled(&pk_bytes) {
                warn!(
                    pubkey = %TruncatedPubkey::new(&duty.pubkey),
                    slot,
                    "Skipping aggregation duty: validator is inside the \
                     post-import doppelganger window (D-3)"
                );
                return None;
            }
        }

        let fence = match self.beacon.admission_duty_fence() {
            Ok(fence)
                if !super::slot_context::admission_blocks(
                    signer::SigningDuty::SelectionProof,
                    &[&fence],
                ) =>
            {
                fence
            }
            _ => {
                warn!(slot, "skipping aggregation: beacon node admission revoked");
                return None;
            }
        };
        let selection_proof = match sign_with_phase2_permit(
            permits,
            sign_deadline,
            &fence,
            super::slot_context::under_admission(
                &fence,
                self.signer
                    .sign_selection_proof(
                        slot,
                        &pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .instrument(agg_span.clone()),
            ),
        )
        .await
        {
            Ok(sig) => sig,
            Err(Phase2SignError::Cancelled) => {
                warn!(
                    slot,
                    validator_index = %duty.validator_index,
                    "phase-2 signer permit wait cancelled before selection proof"
                );
                return None;
            }
            Err(Phase2SignError::Revoked) => {
                warn!(slot, "skipping aggregation: beacon node admission revoked");
                return None;
            }
            Err(Phase2SignError::Failed(e)) => {
                warn!(
                    slot,
                    validator_index = %duty.validator_index,
                    error = %e,
                    "Failed to sign selection proof for aggregation"
                );
                return None;
            }
        };

        if !is_aggregator(committee_length, &selection_proof.to_bytes()) {
            debug!(
                slot,
                validator_index = %duty.validator_index,
                "Not selected as attestation aggregator"
            );
            return None;
        }

        info!(
            slot,
            validator_index = %duty.validator_index,
            "Selected as attestation aggregator"
        );

        let proof = self
            .fetch_sign_aggregate(
                &duty,
                slot,
                fork_name,
                &pubkey,
                selection_proof.to_bytes().to_vec(),
                agg_span,
                &fence,
                permits,
                sign_deadline,
            )
            .await;

        Some(AggregateDutyOutcome {
            validator_index: duty.validator_index,
            raw_validator_index: duty.raw.validator_index.clone(),
            proof,
        })
    }

    /// Fetch attestation data + aggregate, then sign_and_wrap for the fork.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_sign_aggregate(
        &self,
        duty: &TypedAttesterDuty,
        slot: Slot,
        fork_name: ForkName,
        pubkey: &PublicKey,
        selection_proof: Vec<u8>,
        agg_span: Span,
        fence: &beacon::DutyFence,
        permits: &Phase2SignerPermits,
        sign_deadline: tokio::time::Instant,
    ) -> Option<ProducedAggregate> {
        let uses_electra_wire = utils::uses_electra_attestation_wire(fork_name);
        let committee_index = duty.committee_index;

        let attestation_data_response = match utils::timed(
            "aggregate_attestation_data",
            self.config.timeouts.aggregate_fetch,
            self.beacon.get_attestation_data(slot, committee_index),
        )
        .instrument(agg_span.clone())
        .await
        {
            TimedOutcome::Ok(resp) => resp,
            TimedOutcome::Err(e) => {
                warn!(
                    slot,
                    validator_index = %duty.validator_index,
                    error = %e,
                    "Failed to get attestation data for aggregation"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            TimedOutcome::Timeout => {
                warn!(
                    slot,
                    validator_index = %duty.validator_index,
                    "Attestation data fetch timed out for aggregation"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
        };

        // EIP-7549: Electra through Fulu zero `AttestationData.index` before
        // the aggregate-query tree-hash. Gloas preserves the BN value.
        // Pre-Electra forks keep the index intact.
        let crypto_attestation_data = match utils::convert_and_normalize_attestation_data(
            &attestation_data_response.data,
            fork_name,
        ) {
            Ok(data) => data,
            Err(e) => {
                warn!(
                    slot,
                    validator_index = %duty.validator_index,
                    error = %e,
                    "Failed to convert attestation data for aggregation"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
        };

        let att_data_root = crypto_attestation_data.tree_hash_root();
        let att_data_root_hex = format!("0x{}", hex::encode(att_data_root.0));

        // Fetch the aggregate attestation
        // Electra: pass committee_index for per-committee aggregation
        let electra_committee_index = uses_electra_wire.then_some(committee_index);
        let aggregate = match utils::timed(
            "aggregate_attestation_fetch",
            self.config.timeouts.aggregate_fetch,
            self.beacon.get_aggregate_attestation(
                slot,
                &att_data_root_hex,
                electra_committee_index,
                fork_name,
            ),
        )
        .instrument(agg_span.clone())
        .await
        {
            TimedOutcome::Ok(resp) => resp,
            TimedOutcome::Err(e) => {
                warn!(
                    slot,
                    validator_index = %duty.validator_index,
                    error = %e,
                    "Failed to get aggregate attestation"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            TimedOutcome::Timeout => {
                warn!(
                    slot,
                    validator_index = %duty.validator_index,
                    "Aggregate attestation fetch timed out"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
        };

        if let Err(mismatch) = aggregate_matches(
            &aggregate,
            slot,
            att_data_root,
            committee_index,
            duty.committee_length,
            fork_name,
        ) {
            warn!(
                slot,
                validator_index = %duty.validator_index,
                mismatch = mismatch.as_str(),
                "aggregate response does not match the request; not signing"
            );
            RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
            return None;
        }

        let aggregator_index = duty.validator_index;

        if uses_electra_wire {
            let electra_agg = match aggregate {
                VersionedAggregateAttestation::Electra(a)
                | VersionedAggregateAttestation::Fulu(a)
                | VersionedAggregateAttestation::Gloas(a) => a,
                VersionedAggregateAttestation::PreElectra(_) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        "Expected Electra aggregate but got pre-Electra"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    return None;
                }
            };
            let message = ElectraAggregateAndProof {
                aggregator_index,
                aggregate: electra_agg,
                selection_proof,
            };
            // Inherit-intentionally: Gloas and later use the island root, not tree_hash 0.9.
            if fork_name >= ForkName::Gloas {
                let signed = self
                    .sign_and_wrap_gloas(
                        slot,
                        duty.raw.validator_index.as_str(),
                        pubkey,
                        message,
                        agg_span,
                        fence,
                        permits,
                        sign_deadline,
                    )
                    .await?;
                Some(ProducedAggregate::Gloas(signed))
            } else {
                let signed = self
                    .sign_and_wrap_electra(
                        slot,
                        duty.raw.validator_index.as_str(),
                        pubkey,
                        message,
                        agg_span,
                        fence,
                        permits,
                        sign_deadline,
                    )
                    .await?;
                Some(ProducedAggregate::Electra(signed))
            }
        } else {
            let pre_electra_agg = match aggregate {
                VersionedAggregateAttestation::PreElectra(a) => a,
                VersionedAggregateAttestation::Electra(_)
                | VersionedAggregateAttestation::Fulu(_)
                | VersionedAggregateAttestation::Gloas(_) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        "Expected pre-Electra aggregate but got Electra"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    return None;
                }
            };
            let message =
                AggregateAndProof { aggregator_index, aggregate: pre_electra_agg, selection_proof };
            let signed = self
                .sign_and_wrap_pre_electra(
                    slot,
                    duty.raw.validator_index.as_str(),
                    pubkey,
                    message,
                    agg_span,
                    fence,
                    permits,
                    sign_deadline,
                )
                .await?;
            Some(ProducedAggregate::PreElectra(signed))
        }
    }

    /// Tree-hash guard + sign + wrap for pre-Electra aggregate-and-proof.
    ///
    /// Explicit (non-generic) twin of [`Self::sign_and_wrap_electra`]: the two
    /// signer methods and log strings differ; a generic over proof type would
    /// contort more than it saves.
    #[allow(clippy::too_many_arguments)]
    async fn sign_and_wrap_pre_electra(
        &self,
        slot: Slot,
        validator_index: &str,
        pubkey: &PublicKey,
        message: AggregateAndProof,
        agg_span: Span,
        fence: &beacon::DutyFence,
        permits: &Phase2SignerPermits,
        sign_deadline: tokio::time::Instant,
    ) -> Option<SignedAggregateAndProof> {
        if let Err(e) = message.try_tree_hash_root() {
            warn!(
                slot,
                validator_index = %validator_index,
                error = %e,
                "Skipping aggregate with invalid aggregation bits"
            );
            RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
            return None;
        }
        let signature = match sign_with_phase2_permit(
            permits,
            sign_deadline,
            fence,
            super::slot_context::under_admission(
                fence,
                self.signer
                    .sign_aggregate_and_proof(
                        &message,
                        pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .instrument(agg_span),
            ),
        )
        .await
        {
            Ok(sig) => sig,
            Err(Phase2SignError::Cancelled) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    "phase-2 signer permit wait cancelled before aggregate and proof"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            Err(Phase2SignError::Revoked) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    "skipping aggregate: beacon node admission revoked before sign"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            Err(Phase2SignError::Failed(e)) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    error = %e,
                    "Failed to sign aggregate and proof"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
        };
        Some(SignedAggregateAndProof { message, signature: signature.to_bytes().to_vec() })
    }

    /// Tree-hash guard + sign + wrap for Electra/Fulu aggregate-and-proof.
    #[allow(clippy::too_many_arguments)]
    async fn sign_and_wrap_electra(
        &self,
        slot: Slot,
        validator_index: &str,
        pubkey: &PublicKey,
        message: ElectraAggregateAndProof,
        agg_span: Span,
        fence: &beacon::DutyFence,
        permits: &Phase2SignerPermits,
        sign_deadline: tokio::time::Instant,
    ) -> Option<SignedElectraAggregateAndProof> {
        if let Err(e) = message.try_tree_hash_root() {
            warn!(
                slot,
                validator_index = %validator_index,
                error = %e,
                "Skipping aggregate with invalid aggregation bits"
            );
            RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
            return None;
        }
        let signature = match sign_with_phase2_permit(
            permits,
            sign_deadline,
            fence,
            super::slot_context::under_admission(
                fence,
                self.signer
                    .sign_electra_aggregate_and_proof(
                        &message,
                        pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .instrument(agg_span),
            ),
        )
        .await
        {
            Ok(sig) => sig,
            Err(Phase2SignError::Cancelled) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    "phase-2 signer permit wait cancelled before Electra aggregate and proof"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            Err(Phase2SignError::Revoked) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    "skipping aggregate: beacon node admission revoked before sign"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            Err(Phase2SignError::Failed(e)) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    error = %e,
                    "Failed to sign Electra aggregate and proof"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
        };
        Some(SignedElectraAggregateAndProof { message, signature: signature.to_bytes().to_vec() })
    }

    /// Island root + sign + wrap for Gloas aggregate-and-proof.
    ///
    /// Pre-Gloas `try_tree_hash_root` is intentionally not used: the island
    /// decode is the validity gate. A [`rvc_gloas::GloasError`] skips the
    /// duty with a failure increment and no signer call.
    #[allow(clippy::too_many_arguments)]
    async fn sign_and_wrap_gloas(
        &self,
        slot: Slot,
        validator_index: &str,
        pubkey: &PublicKey,
        message: ElectraAggregateAndProof,
        agg_span: Span,
        fence: &beacon::DutyFence,
        permits: &Phase2SignerPermits,
        sign_deadline: tokio::time::Instant,
    ) -> Option<SignedElectraAggregateAndProof> {
        let ssz = match encode_electra_aggregate_and_proof(&message) {
            Ok(ssz) => ssz,
            Err(e) => {
                skip_gloas_aggregate(slot, validator_index, "encode", &e);
                return None;
            }
        };
        let object_root = match rvc_gloas::gloas_aggregate_and_proof_root(&ssz) {
            Ok(root) => root,
            Err(e) => {
                skip_gloas_aggregate(slot, validator_index, "island_root", &e);
                return None;
            }
        };
        let sign_slot = message.aggregate.data.slot;
        let signature = match sign_with_phase2_permit(
            permits,
            sign_deadline,
            fence,
            super::slot_context::under_admission(
                fence,
                self.signer
                    .sign_aggregate_and_proof_root(
                        &object_root,
                        sign_slot,
                        pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .instrument(agg_span),
            ),
        )
        .await
        {
            Ok(sig) => sig,
            Err(Phase2SignError::Cancelled) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    "phase-2 signer permit wait cancelled before Gloas aggregate and proof"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            Err(Phase2SignError::Revoked) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    "skipping aggregate: beacon node admission revoked before sign"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
            Err(Phase2SignError::Failed(e)) => {
                warn!(
                    slot,
                    validator_index = %validator_index,
                    error = %e,
                    "Failed to sign Gloas aggregate and proof"
                );
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                return None;
            }
        };
        Some(SignedElectraAggregateAndProof { message, signature: signature.to_bytes().to_vec() })
    }

    /// One batch POST for a wave of signed aggregates.
    ///
    /// `source_validators` is sorted before the submit span records it (H-25).
    /// The POST's deadline is the earlier of the `aggregate_submit` timeout and
    /// `slot_end` plus 500 ms. Signs already running are not cancelled; a wave
    /// that becomes ready after that instant is not sent. Returns how many
    /// duties this wave attempted, including skips and sign failures.
    async fn publish_aggregate_wave(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
        fork_name: ForkName,
        wave: Vec<Option<AggregateDutyOutcome>>,
    ) -> usize {
        let attempted = wave.len();
        let outcomes: Vec<AggregateDutyOutcome> = wave.into_iter().flatten().collect();
        if outcomes.is_empty() {
            return attempted;
        }

        let mut source_validators: Vec<(u64, String)> = outcomes
            .iter()
            .map(|outcome| (outcome.validator_index, outcome.raw_validator_index.clone()))
            .collect();
        sort_source_validators(&mut source_validators);
        let source_validators: Vec<String> =
            source_validators.into_iter().map(|(_, raw)| raw).collect();

        let mut pre_electra_aggregates: Vec<SignedAggregateAndProof> = Vec::new();
        let mut electra_aggregates: Vec<SignedElectraAggregateAndProof> = Vec::new();
        for outcome in outcomes {
            match outcome.proof {
                Some(ProducedAggregate::PreElectra(proof)) => pre_electra_aggregates.push(proof),
                Some(ProducedAggregate::Electra(proof) | ProducedAggregate::Gloas(proof)) => {
                    electra_aggregates.push(proof)
                }
                None => {}
            }
        }

        if !pre_electra_aggregates.is_empty() {
            let versioned = VersionedSignedAggregateAndProof::PreElectra(pre_electra_aggregates);
            self.submit_versioned(
                slot,
                slot_end,
                versioned,
                &source_validators,
                AggregateSubmitLabel::PreElectra,
            )
            .await;
        }

        if !electra_aggregates.is_empty() {
            // Exact fork, not `>= Fulu`: Gloas must submit Eth-Consensus-Version: gloas.
            // Fulu keeps the Electra submit-label so its log literals stay byte-identical.
            let (versioned, label) = if fork_name == ForkName::Gloas {
                (
                    VersionedSignedAggregateAndProof::Gloas(electra_aggregates),
                    AggregateSubmitLabel::Gloas,
                )
            } else if fork_name == ForkName::Fulu {
                (
                    VersionedSignedAggregateAndProof::Fulu(electra_aggregates),
                    AggregateSubmitLabel::Electra,
                )
            } else {
                (
                    VersionedSignedAggregateAndProof::Electra(electra_aggregates),
                    AggregateSubmitLabel::Electra,
                )
            };
            self.submit_versioned(slot, slot_end, versioned, &source_validators, label).await;
        }
        attempted
    }

    /// Submit a versioned batch of signed aggregates; shared by pre-Electra and
    /// Electra/Fulu/Gloas. Log messages stay as static literals (byte-identical
    /// to the pre-refactor paths) via [`AggregateSubmitLabel`].
    async fn submit_versioned(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
        versioned: VersionedSignedAggregateAndProof,
        source_validators: &[String],
        label: AggregateSubmitLabel,
    ) {
        let count = match &versioned {
            VersionedSignedAggregateAndProof::PreElectra(v) => v.len(),
            VersionedSignedAggregateAndProof::Electra(v)
            | VersionedSignedAggregateAndProof::Fulu(v)
            | VersionedSignedAggregateAndProof::Gloas(v) => v.len(),
        };
        let source_validators_str = source_validators.join(",");
        // The span field below is this string. Tests read the thread-local
        // because a parallel `set_default` rebuilds callsite interest and can
        // drop the `info` span after the value was already chosen.
        #[cfg(test)]
        record_source_validators_for_test(&source_validators_str);

        let submit_span = info_span!(
            "aggregation.submit",
            slot = slot,
            aggregation.count = count,
            aggregation.source_validators = %source_validators_str,
        );

        let now = tokio::time::Instant::now();
        let overhang_at = slot_end + SLOT_END_PUBLISH_OVERHANG;
        let submit_at =
            now.checked_add(self.config.timeouts.aggregate_submit).unwrap_or(overhang_at);
        let deadline = overhang_at.min(submit_at);
        let bounded_by_overhang = deadline == overhang_at;
        if now >= deadline {
            drop(submit_span);
            warn_aggregate_publish_stopped(
                slot,
                label,
                bounded_by_overhang,
                self.config.timeouts.aggregate_submit,
            );
            RVC_AGGREGATIONS_TOTAL
                .with_label_values(&[attestation_status::FAILED])
                .inc_by(count as u64);
            return;
        }

        let submit_result =
            tokio::time::timeout_at(deadline, self.beacon.submit_aggregate_and_proofs(&versioned))
                .instrument(submit_span)
                .await;

        match submit_result {
            Ok(Ok(())) => {
                match label {
                    AggregateSubmitLabel::PreElectra => {
                        info!(slot, count, "Submitted aggregate and proofs");
                    }
                    AggregateSubmitLabel::Electra => {
                        info!(slot, count, "Submitted Electra aggregate and proofs");
                    }
                    AggregateSubmitLabel::Gloas => {
                        info!(slot, count, "Submitted Gloas aggregate and proofs");
                    }
                }
                RVC_AGGREGATIONS_TOTAL
                    .with_label_values(&[attestation_status::SUCCESS])
                    .inc_by(count as u64);
            }
            Ok(Err(e)) => {
                match label {
                    AggregateSubmitLabel::PreElectra => {
                        warn!(slot, error = %e, "Failed to submit aggregate and proofs");
                    }
                    AggregateSubmitLabel::Electra => {
                        warn!(slot, error = %e, "Failed to submit Electra aggregate and proofs");
                    }
                    AggregateSubmitLabel::Gloas => {
                        warn!(slot, error = %e, "Failed to submit Gloas aggregate and proofs");
                    }
                }
                RVC_AGGREGATIONS_TOTAL
                    .with_label_values(&[attestation_status::FAILED])
                    .inc_by(count as u64);
            }
            Err(_) => {
                warn_aggregate_publish_stopped(
                    slot,
                    label,
                    bounded_by_overhang,
                    self.config.timeouts.aggregate_submit,
                );
                RVC_AGGREGATIONS_TOTAL
                    .with_label_values(&[attestation_status::FAILED])
                    .inc_by(count as u64);
            }
        }
    }
}

/// Decimal validator indices, so `2` stays before `10`.
///
/// The typed index is the primary key. The wire string breaks ties, matching
/// the order a successful parse of that string used to produce. Wave
/// completion order is not this order. H-25 records the sorted list.
fn sort_source_validators(indices: &mut [(u64, String)]) {
    indices.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
}

fn warn_aggregate_publish_stopped(
    slot: Slot,
    label: AggregateSubmitLabel,
    bounded_by_overhang: bool,
    submit_timeout: Duration,
) {
    if bounded_by_overhang {
        let overhang_ms = SLOT_END_PUBLISH_OVERHANG.as_millis();
        match label {
            AggregateSubmitLabel::PreElectra => {
                warn!(
                    slot,
                    "Aggregate and proofs publish exceeded the {} ms slot-end overhang",
                    overhang_ms
                );
            }
            AggregateSubmitLabel::Electra => {
                warn!(
                    slot,
                    "Electra aggregate and proofs publish exceeded the {} ms slot-end overhang",
                    overhang_ms
                );
            }
            AggregateSubmitLabel::Gloas => {
                warn!(
                    slot,
                    "Gloas aggregate and proofs publish exceeded the {} ms slot-end overhang",
                    overhang_ms
                );
            }
        }
    } else {
        match label {
            AggregateSubmitLabel::PreElectra => {
                warn!(
                    slot,
                    "Aggregate and proofs submit timed out after {}s",
                    submit_timeout.as_secs()
                );
            }
            AggregateSubmitLabel::Electra => {
                warn!(
                    slot,
                    "Electra aggregate and proofs submit timed out after {}s",
                    submit_timeout.as_secs()
                );
            }
            AggregateSubmitLabel::Gloas => {
                warn!(
                    slot,
                    "Gloas aggregate and proofs submit timed out after {}s",
                    submit_timeout.as_secs()
                );
            }
        }
    }
}

fn skip_gloas_aggregate(
    slot: Slot,
    validator_index: &str,
    stage: &'static str,
    error: &rvc_gloas::GloasError,
) {
    warn!(
        slot,
        validator_index = %validator_index,
        stage,
        error = %error,
        "Skipping Gloas aggregate"
    );
    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
}

fn encode_electra_aggregate_and_proof(
    message: &ElectraAggregateAndProof,
) -> Result<Vec<u8>, rvc_gloas::GloasError> {
    const COMMITTEE_BITS_LEN: usize = (MAX_COMMITTEES_PER_SLOT as usize).div_ceil(8);
    if message.selection_proof.len() != 96 || message.aggregate.signature.len() != 96 {
        return Err(rvc_gloas::GloasError::InvalidBody {
            reason: "bls signature fields must be 96 bytes".to_string(),
        });
    }
    if message.aggregate.committee_bits.len() != COMMITTEE_BITS_LEN {
        return Err(rvc_gloas::GloasError::InvalidBody {
            reason: "committee_bits must be Bitvector[MAX_COMMITTEES_PER_SLOT]".to_string(),
        });
    }
    eth_types::try_electra_aggregation_bits(&message.aggregate.aggregation_bits).map_err(|e| {
        rvc_gloas::GloasError::InvalidBody { reason: format!("aggregation_bits: {e:?}") }
    })?;
    Ok(Encode::as_ssz_bytes(message))
}

/// Slot end far enough that tests which do not exercise the bound still drain.
#[cfg(test)]
pub(crate) fn ample_slot_end() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(3_600)
}

// Values passed to `aggregation.source_validators`, in submit order.
// Libtest reuses threads, so callers clear this before a run.
#[cfg(test)]
thread_local! {
    static RECORDED_SOURCE_VALIDATORS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_source_validators_for_test(value: &str) {
    RECORDED_SOURCE_VALIDATORS.with(|slot| slot.borrow_mut().push(value.to_string()));
}

#[cfg(test)]
fn take_recorded_source_validators() -> Vec<String> {
    RECORDED_SOURCE_VALIDATORS.with(|slot| {
        let mut values = slot.borrow_mut();
        std::mem::take(&mut *values)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use async_trait::async_trait;
    use beacon::{
        AttestationDataResponse, BeaconCommitteeSubscription, BeaconError, DataResponse,
        DependentRootResponse, SubmitAttestationResult, VersionedAggregateAttestation,
        VersionedAttestation, VersionedSignedAggregateAndProof,
    };
    use bn_manager::{AttestationApi, MockBeaconNodeClient};
    use crypto::{
        signing_root_for, CompositeSigner, DutyRef, KeyManager, LocalSigner, PublicKey, SecretKey,
        Signature, SigningCtx,
    };
    use duty_tracker::DutyTracker;
    use eth_types::{
        Attestation as EthAttestation, AttestationData, Checkpoint, ElectraAggregateAndProof,
        ElectraAttestation, Epoch, ForkName, ForkSchedule, Root, Slot, MAX_COMMITTEES_PER_SLOT,
        MAX_VALIDATORS_PER_COMMITTEE, SLOTS_PER_EPOCH,
    };
    use signer::{
        always_enabled, SignerError, SignerService, StubValidatorSigner, ValidatorSigner,
    };
    use slashing::SlashingDb;
    use ssz08::{Decode, Encode};
    use tree_hash::TreeHash;
    use validator_store::{ValidatorConfig, ValidatorStore};

    use tracing_subscriber::layer::SubscriberExt;

    use super::utils;
    use super::{AggregationService, OrchestratorConfig};
    use crate::metrics::{attestation_status, RVC_AGGREGATIONS_TOTAL};

    /// Process-wide aggregations-failed counter; serialize exact-delta assertions.
    async fn agg_fail_metric_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await
    }

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

    fn electra_attestation(slot: Slot) -> ElectraAttestation {
        ElectraAttestation {
            aggregation_bits: vec![0xff, 0x01],
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: [0x11; 32],
                source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [0u8; 32] },
                target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [0u8; 32] },
            },
            signature: vec![0xab; 96],
            committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn pre_electra_attestation(slot: Slot) -> EthAttestation {
        EthAttestation {
            aggregation_bits: vec![0xff, 0x01],
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: [0x11; 32],
                source: Checkpoint { epoch: 0, root: [0u8; 32] },
                target: Checkpoint { epoch: 0, root: [0u8; 32] },
            },
            signature: vec![0xab; 96],
        }
    }

    /// Shared mock that records submit_aggregate_and_proofs calls (RF4-24).
    fn tracking_beacon(
        duty_pubkey: String,
        submit_agg_calls: Arc<AtomicUsize>,
        duty_slot: Slot,
        aggregate: VersionedAggregateAttestation,
    ) -> MockBeaconNodeClient {
        capturing_tracking_beacon(
            duty_pubkey,
            submit_agg_calls,
            duty_slot,
            aggregate,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        )
    }

    /// Same fixture as [`tracking_beacon`], plus the fork passed to the fetch
    /// and the submitted proof batch.
    fn capturing_tracking_beacon(
        duty_pubkey: String,
        submit_agg_calls: Arc<AtomicUsize>,
        duty_slot: Slot,
        aggregate: VersionedAggregateAttestation,
        fetched_forks: Arc<Mutex<Vec<ForkName>>>,
        submitted: Arc<Mutex<Vec<VersionedSignedAggregateAndProof>>>,
    ) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new()
            .with_slot_aware_block_root(0, &[], |_queried| {
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()
            })
            .with_get_attester_duties(move |_epoch, _indices| {
                Ok(DependentRootResponse {
                    dependent_root: "0xaabb".to_string(),
                    execution_optimistic: false,
                    data: vec![beacon::AttesterDuty {
                        pubkey: duty_pubkey.clone(),
                        validator_index: "1".to_string(),
                        committee_index: "0".to_string(),
                        committee_length: "8".to_string(), // small → always aggregator
                        committees_at_slot: "1".to_string(),
                        validator_committee_index: "0".to_string(),
                        slot: duty_slot.to_string(),
                    }],
                })
            })
            .with_get_attestation_data(|slot, _committee_index| {
                Ok(DataResponse {
                    data: beacon::AttestationData {
                        slot: slot.to_string(),
                        index: "0".to_string(),
                        beacon_block_root:
                            "0x1111111111111111111111111111111111111111111111111111111111111111"
                                .to_string(),
                        source: beacon::Checkpoint {
                            epoch: "0".to_string(),
                            root:
                                "0x0000000000000000000000000000000000000000000000000000000000000000"
                                    .to_string(),
                        },
                        target: beacon::Checkpoint {
                            epoch: "0".to_string(),
                            root:
                                "0x0000000000000000000000000000000000000000000000000000000000000000"
                                    .to_string(),
                        },
                    },
                })
            })
            .with_get_aggregate_attestation(move |slot, _root, _idx, fork| {
                fetched_forks.lock().unwrap().push(fork);
                let mut agg = aggregate.clone();
                let data = request_shaped_data(slot);
                match &mut agg {
                    VersionedAggregateAttestation::PreElectra(a) => a.data = data,
                    VersionedAggregateAttestation::Electra(a)
                    | VersionedAggregateAttestation::Fulu(a)
                    | VersionedAggregateAttestation::Gloas(a) => a.data = data,
                }
                Ok(agg)
            })
            .with_submit_aggregate_and_proofs(move |proofs| {
                submitted.lock().unwrap().push(proofs);
                submit_agg_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
    }

    struct AggEnv {
        config: OrchestratorConfig,
        slot: Slot,
        aggregate: VersionedAggregateAttestation,
    }

    async fn setup_agg_service(
        duty_pubkey: String,
        pk: crypto::PublicKey,
        signer: Arc<dyn ValidatorSigner>,
        validator_store: Arc<ValidatorStore>,
        submit_agg_calls: Arc<AtomicUsize>,
        env: AggEnv,
    ) -> AggregationService {
        let epoch = env.slot / SLOTS_PER_EPOCH;
        let beacon = Arc::new(tracking_beacon(
            duty_pubkey.clone(),
            submit_agg_calls,
            env.slot,
            env.aggregate,
        ));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        AggregationService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            env.config,
            validator_store,
        )
    }

    fn local_signer_service(sk: SecretKey) -> Arc<dyn ValidatorSigner> {
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()))
    }

    fn enabled_store(pk_bytes: [u8; 48]) -> Arc<ValidatorStore> {
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        store.add_validator(ValidatorConfig::new(pk_bytes)).unwrap();
        store
    }

    struct RecordingSigner {
        inner: StubValidatorSigner,
        calls: Mutex<Vec<&'static str>>,
        selection_proof: Option<Signature>,
    }

    impl RecordingSigner {
        fn new() -> Self {
            Self {
                inner: StubValidatorSigner::new(),
                calls: Mutex::new(Vec::new()),
                selection_proof: None,
            }
        }

        fn record(&self, name: &'static str) {
            self.calls.lock().unwrap().push(name);
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    macro_rules! rec_fwd {
        ($($name:ident($($arg:ident: $ty:ty),* $(,)?));* $(;)?) => {
            #[async_trait]
            impl ValidatorSigner for RecordingSigner {
                $(
                    async fn $name(
                        &self,
                        $($arg: $ty),*
                    ) -> Result<Signature, SignerError> {
                        self.record(stringify!($name));
                        if stringify!($name) == "sign_selection_proof" {
                            if let Some(proof) = &self.selection_proof {
                                return Ok(proof.clone());
                            }
                        }
                        self.inner.$name($($arg),*).await
                    }
                )*
            }
        };
    }

    rec_fwd! {
        sign_attestation(data: &AttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_block(block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_block_header(header: &signer::BeaconBlockHeaderFields, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_randao_reveal(epoch: Epoch, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_sync_committee_message(beacon_block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_selection_proof(slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_aggregate_and_proof(aggregate_and_proof: &eth_types::AggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_electra_aggregate_and_proof(aggregate_and_proof: &ElectraAggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_voluntary_exit(voluntary_exit: &eth_types::VoluntaryExit, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_builder_registration(registration: &eth_types::ValidatorRegistrationV1, pubkey: &PublicKey, fork_version: [u8; 4]);
        sign_sync_committee_selection_proof(slot: Slot, subcommittee_index: u64, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_contribution_and_proof(contribution_and_proof: &eth_types::ContributionAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_payload_attestation(data: &eth_types::PayloadAttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_execution_payload_envelope_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_aggregate_and_proof_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    }

    // -----------------------------------------------------------------------
    // D-3: aggregation path skips validators whose is_signing_enabled=false.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_aggregation_skipped_when_validator_disabled() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let pk_bytes: [u8; 48] = pk.to_bytes();

        // Set up a store where the validator is disabled (doppelganger window).
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut config = ValidatorConfig::new(pk_bytes);
        config.enabled = false;
        store.add_validator(config).unwrap();

        let submit_calls = Arc::new(AtomicUsize::new(0));

        let service = setup_agg_service(
            pk_hex,
            pk,
            local_signer_service(sk),
            store,
            submit_calls.clone(),
            AggEnv {
                config: create_test_config(),
                slot: 0,
                aggregate: VersionedAggregateAttestation::PreElectra(pre_electra_attestation(0)),
            },
        )
        .await;

        // Epoch 0 / slot 0 — the duty tracker has the duty for slot 0.
        service.maybe_produce_aggregations(0, 0, super::ample_slot_end()).await;

        // No aggregation must be submitted for a disabled validator.
        assert_eq!(
            submit_calls.load(Ordering::SeqCst),
            0,
            "D-3: aggregate_and_proofs must not be submitted when is_signing_enabled=false"
        );
    }

    fn make_beacon_attestation_data(index: &str) -> beacon::AttestationData {
        beacon::AttestationData {
            slot: "500".to_string(),
            index: index.to_string(),
            beacon_block_root: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "15".to_string(),
                root: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "16".to_string(),
                root: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            },
        }
    }

    /// Builds an `eth_types::AttestationData` directly for root comparison.
    fn make_crypto_attestation_data(index: u64) -> AttestationData {
        AttestationData {
            slot: 500,
            index,
            beacon_block_root: [0xaa; 32],
            source: Checkpoint { epoch: 15, root: [0xbb; 32] },
            target: Checkpoint { epoch: 16, root: [0xcc; 32] },
        }
    }

    /// H-2 regression test: Electra aggregator must zero `index` before
    /// computing `tree_hash_root` (EIP-7549).
    ///
    /// Pre-fix: `aggregation.rs` called `tree_hash_root()` with the BN-supplied
    /// committee index intact, producing a root the BN doesn't recognise (→ 404).
    /// Post-fix: `convert_and_normalize_attestation_data` zeros the index first.
    #[test]
    fn test_electra_aggregator_root_zero_index() {
        let beacon_data = make_beacon_attestation_data("5");

        // Simulate the aggregation path: convert + normalize for Electra
        let normalized =
            utils::convert_and_normalize_attestation_data(&beacon_data, ForkName::Electra)
                .expect("conversion must succeed");

        let agg_root = normalized.tree_hash_root();

        // Expected: root computed with index explicitly set to 0
        let expected = make_crypto_attestation_data(0).tree_hash_root();

        assert_eq!(
            agg_root, expected,
            "Electra aggregator root must equal the root with index=0 (EIP-7549)"
        );

        // Guard: root with the original index differs (validates the test is meaningful)
        let wrong_root = make_crypto_attestation_data(5).tree_hash_root();
        assert_ne!(
            agg_root, wrong_root,
            "Root with original index must differ (test fixture must use non-zero index)"
        );
    }

    /// Regression guard: pre-Electra forks must NOT zero the committee index.
    ///
    /// Zeroing the index for Phase0..Deneb would change the attestation data
    /// root and break all pre-Electra aggregator duties.
    #[test]
    fn test_pre_electra_aggregator_root_keeps_index() {
        let beacon_data = make_beacon_attestation_data("5");

        // Simulate the aggregation path for Deneb (last pre-Electra fork)
        let normalized =
            utils::convert_and_normalize_attestation_data(&beacon_data, ForkName::Deneb)
                .expect("conversion must succeed");

        let agg_root = normalized.tree_hash_root();

        // Expected: root computed with the original index (5), NOT zeroed
        let expected = make_crypto_attestation_data(5).tree_hash_root();

        assert_eq!(
            agg_root, expected,
            "Pre-Electra aggregator root must be computed with original index (no EIP-7549 zeroing)"
        );

        // Guard: zero-index root differs from the preserved-index root
        let zero_root = make_crypto_attestation_data(0).tree_hash_root();
        assert_ne!(agg_root, zero_root, "Pre-Electra root must differ from the zero-index root");
    }

    fn parse_hex(hex: &str) -> Vec<u8> {
        assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
        assert_eq!(hex.len() % 2, 0, "SPEC_* hex must have even length, got {}", hex.len());
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| {
                let s = core::str::from_utf8(chunk).expect("hex digits are utf8");
                u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s}: {e}"))
            })
            .collect()
    }

    fn parse_root(hex: &str) -> Root {
        assert_eq!(hex.len(), 64, "KAT hex must be 64 chars, got {} ({hex:?})", hex.len());
        parse_hex(hex).try_into().expect("64 hex chars decode to 32 bytes")
    }

    fn gloas_kat_schedule() -> ForkSchedule {
        let mut schedule = (*create_test_fork_schedule()).clone();
        schedule.gloas_fork_epoch = 0;
        schedule.gloas_fork_version = [0x07, 0x00, 0x00, 0x01];
        schedule
    }

    fn gloas_config(gloas_epoch: u64) -> OrchestratorConfig {
        let mut schedule = (*create_test_fork_schedule()).clone();
        schedule.gloas_fork_epoch = gloas_epoch;
        OrchestratorConfig::new([0u8; 32], Arc::new(schedule))
    }

    #[test]
    fn test_gloas_aggregate_and_proof_signing_root() {
        let spec_ssz = parse_hex(rvc_gloas::test_fixtures::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ);
        let object_root = rvc_gloas::gloas_aggregate_and_proof_root(&spec_ssz)
            .expect("spec AggregateAndProof SSZ");
        assert_eq!(
            object_root,
            parse_root(rvc_gloas::test_fixtures::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT)
        );

        let mainnet_ssz =
            parse_hex(rvc_gloas::test_fixtures::SPEC_GLOAS_AGGREGATE_AND_PROOF_SSZ_MAINNET);
        let mainnet_root = rvc_gloas::gloas_aggregate_and_proof_root(&mainnet_ssz)
            .expect("mainnet spec AggregateAndProof SSZ");
        assert_eq!(
            mainnet_root,
            parse_root(rvc_gloas::test_fixtures::SPEC_GLOAS_AGGREGATE_AND_PROOF_ROOT_MAINNET)
        );
        match ElectraAggregateAndProof::from_ssz_bytes(&mainnet_ssz) {
            Ok(proof) => {
                let encoded = Encode::as_ssz_bytes(&proof);
                assert_eq!(
                    rvc_gloas::gloas_aggregate_and_proof_root(&encoded)
                        .expect("6.9a re-encode of mainnet SPEC"),
                    mainnet_root
                );
            }
            Err(_) => {
                // Mainnet SPEC SSZ is Gloas progressive; Electra decode may fail.
                // Production 6.9a encode of a mainnet-shaped Electra container
                // must still be island-decodable (SPEC root is a different object).
                let encoded = Encode::as_ssz_bytes(&ElectraAggregateAndProof {
                    aggregator_index: 1,
                    aggregate: electra_attestation(1),
                    selection_proof: vec![0xbb; 96],
                });
                rvc_gloas::gloas_aggregate_and_proof_root(&encoded)
                    .expect("6.9a-encoded ElectraAggregateAndProof must be island-decodable");
            }
        }

        let schedule = gloas_kat_schedule();
        let ctx = SigningCtx { fork_schedule: &schedule, genesis_validators_root: [0u8; 32] };
        let got =
            signing_root_for(&DutyRef::AggregateAndProofRoot { root: &object_root, slot: 1 }, &ctx);
        assert_eq!(got, parse_root(rvc_gloas::KAT_GLOAS_AGGREGATE_AND_PROOF_SIGNING_ROOT));
    }

    #[tokio::test]
    async fn test_gloas_aggregate_uses_root_signer_not_electra() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let rec = Arc::new(RecordingSigner::new());
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let gloas_epoch = 70;
        let slot = gloas_epoch * SLOTS_PER_EPOCH;
        let service = setup_agg_service(
            pk_hex,
            pk,
            rec.clone(),
            enabled_store(pk_bytes),
            submit_calls,
            AggEnv {
                config: gloas_config(gloas_epoch),
                slot,
                aggregate: VersionedAggregateAttestation::Gloas(electra_attestation(slot)),
            },
        )
        .await;

        service.maybe_produce_aggregations(slot, gloas_epoch, super::ample_slot_end()).await;

        let calls = rec.calls();
        assert!(
            calls.contains(&"sign_aggregate_and_proof_root"),
            "Gloas aggregate must sign the island root; calls={calls:?}"
        );
        assert!(
            !calls.contains(&"sign_electra_aggregate_and_proof"),
            "Gloas aggregate must not call sign_electra_aggregate_and_proof; calls={calls:?}"
        );
    }

    #[tokio::test]
    async fn test_fulu_aggregate_still_uses_electra_signer() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let rec = Arc::new(RecordingSigner::new());
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let fulu_epoch = 60;
        let slot = fulu_epoch * SLOTS_PER_EPOCH;
        let service = setup_agg_service(
            pk_hex,
            pk,
            rec.clone(),
            enabled_store(pk_bytes),
            submit_calls,
            AggEnv {
                config: create_test_config(),
                slot,
                aggregate: VersionedAggregateAttestation::Fulu(electra_attestation(slot)),
            },
        )
        .await;

        service.maybe_produce_aggregations(slot, fulu_epoch, super::ample_slot_end()).await;

        let calls = rec.calls();
        assert!(
            calls.contains(&"sign_electra_aggregate_and_proof"),
            "Fulu aggregate must still call sign_electra_aggregate_and_proof; calls={calls:?}"
        );
        assert!(
            !calls.contains(&"sign_aggregate_and_proof_root"),
            "Fulu aggregate must not call sign_aggregate_and_proof_root; calls={calls:?}"
        );
    }

    /// Aggregate body is fetched, then admission is revoked, then the signer
    /// must not see the aggregate. The selection proof already ran.
    #[tokio::test]
    async fn aggregate_fetched_before_revocation_is_not_signed() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let rec = Arc::new(RecordingSigner::new());
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let fulu_epoch = 60;
        let slot = fulu_epoch * SLOTS_PER_EPOCH;
        let beacon = Arc::new(tracking_beacon(
            pk_hex.clone(),
            Arc::clone(&submit_calls),
            slot,
            VersionedAggregateAttestation::Fulu(electra_attestation(slot)),
        ));
        beacon.revoke_after_aggregate();
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(fulu_epoch).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk_bytes, pk);
        let service = AggregationService::new(
            rec.clone(),
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            create_test_config(),
            enabled_store(pk_bytes),
        );
        service.maybe_produce_aggregations(slot, fulu_epoch, super::ample_slot_end()).await;
        let calls = rec.calls();
        assert!(
            calls.contains(&"sign_selection_proof"),
            "selection proof is signed before the aggregate fetch; calls={calls:?}"
        );
        assert!(
            !calls.contains(&"sign_electra_aggregate_and_proof"),
            "aggregate captured before revocation must not be signed; calls={calls:?}"
        );
    }

    /// Pre-Electra aggregate body is fetched, then admission is revoked.
    /// `sign_aggregate_and_proof` must not run. A holding fence still signs,
    /// and that sign goes through the admission scope.
    #[tokio::test]
    async fn pre_electra_aggregate_fetched_before_revocation_is_not_signed() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let rec = Arc::new(RecordingSigner::new());
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let slot = 0u64;
        let beacon = Arc::new(tracking_beacon(
            pk_hex.clone(),
            Arc::clone(&submit_calls),
            slot,
            VersionedAggregateAttestation::PreElectra(pre_electra_attestation(slot)),
        ));
        beacon.revoke_after_aggregate();
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(0).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk_bytes, pk);
        let service = AggregationService::new(
            rec.clone(),
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            create_test_config(),
            enabled_store(pk_bytes),
        );
        service.maybe_produce_aggregations(slot, 0, super::ample_slot_end()).await;
        let calls = rec.calls();
        assert!(
            calls.contains(&"sign_selection_proof"),
            "selection proof is signed before the aggregate fetch; calls={calls:?}"
        );
        assert!(
            !calls.contains(&"sign_aggregate_and_proof"),
            "pre-Electra aggregate captured before revocation must not be signed; calls={calls:?}"
        );
        assert_eq!(submit_calls.load(Ordering::SeqCst), 0);

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let beacon = tracking_beacon(
            pk_hex,
            Arc::clone(&submit_calls),
            slot,
            VersionedAggregateAttestation::PreElectra(pre_electra_attestation(slot)),
        );
        let _generation = beacon.track_admission();
        let beacon = Arc::new(beacon);
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(0).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk_bytes, pk.clone());
        let service = AggregationService::new(
            local_signer_service(sk),
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            create_test_config(),
            enabled_store(pk_bytes),
        );
        signer::require_beacon_admission_scope(async {
            service.maybe_produce_aggregations(slot, 0, super::ample_slot_end()).await;
        })
        .await;
        assert_eq!(
            submit_calls.load(Ordering::SeqCst),
            1,
            "a holding fence signs the pre-Electra aggregate only inside the admission scope"
        );
    }

    /// A short `committee_bits` vector is rejected by the request check.
    /// The island encode is a different reject; a short selection proof is.
    #[tokio::test(flavor = "current_thread")]
    async fn short_committee_bits_fail_the_request_check() {
        let _guard = agg_fail_metric_lock().await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let rec = Arc::new(RecordingSigner::new());
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let gloas_epoch = 70;
        let slot = gloas_epoch * SLOTS_PER_EPOCH;
        let mut bad = electra_attestation(slot);
        bad.committee_bits = vec![0x01, 0x00, 0x00];
        let failed_before =
            RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();

        let service = setup_agg_service(
            pk_hex,
            pk,
            rec.clone(),
            enabled_store(pk_bytes),
            submit_calls.clone(),
            AggEnv {
                config: gloas_config(gloas_epoch),
                slot,
                aggregate: VersionedAggregateAttestation::Gloas(bad),
            },
        )
        .await;

        let logs = Arc::new(Mutex::new(String::new()));
        let subscriber =
            tracing_subscriber::registry().with(MismatchLog { buf: Arc::clone(&logs) });
        let _log = tracing::subscriber::set_default(subscriber);
        service.maybe_produce_aggregations(slot, gloas_epoch, super::ample_slot_end()).await;
        drop(_log);
        let text = logs.lock().expect("mismatch log").clone();
        assert!(
            text.contains("mismatch=committee_index"),
            "short committee bits must fail the request check; log={text}"
        );

        let calls = rec.calls();
        assert!(
            !calls.contains(&"sign_aggregate_and_proof_root"),
            "short committee bits must not reach the island signer; calls={calls:?}"
        );
        assert!(
            !calls.contains(&"sign_electra_aggregate_and_proof"),
            "a request-check reject must not fall back to Electra signing; calls={calls:?}"
        );
        let failed_after =
            RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();
        assert_eq!(
            failed_after.saturating_sub(failed_before),
            1,
            "a request-check reject must increment RVC_AGGREGATIONS_TOTAL failed"
        );
        assert_eq!(
            submit_calls.load(Ordering::SeqCst),
            0,
            "a request-check reject must not submit"
        );
    }

    /// Empty, sentinel-less, and over-long bitlists fail the request check.
    #[tokio::test(flavor = "current_thread")]
    async fn invalid_aggregation_bits_fail_the_request_check() {
        let _guard = agg_fail_metric_lock().await;
        const OVER_LEN: usize = 16_386;
        for (label, bits, mismatch) in [
            ("empty", vec![], "attester_bits"),
            ("no-sentinel", vec![0x00], "attester_bits"),
            ("over-length", vec![0xff; OVER_LEN], "oversized"),
        ] {
            let sk = SecretKey::generate();
            let pk = sk.public_key();
            let pk_bytes = pk.to_bytes();
            let pk_hex = format!("0x{}", hex::encode(pk_bytes));
            let rec = Arc::new(RecordingSigner::new());
            let submit_calls = Arc::new(AtomicUsize::new(0));
            let gloas_epoch = 70;
            let slot = gloas_epoch * SLOTS_PER_EPOCH;
            let mut bad = electra_attestation(slot);
            bad.aggregation_bits = bits;
            let failed_before =
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();

            let service = setup_agg_service(
                pk_hex,
                pk,
                rec.clone(),
                enabled_store(pk_bytes),
                submit_calls.clone(),
                AggEnv {
                    config: gloas_config(gloas_epoch),
                    slot,
                    aggregate: VersionedAggregateAttestation::Gloas(bad),
                },
            )
            .await;

            let logs = Arc::new(Mutex::new(String::new()));
            let subscriber =
                tracing_subscriber::registry().with(MismatchLog { buf: Arc::clone(&logs) });
            let _log = tracing::subscriber::set_default(subscriber);
            service.maybe_produce_aggregations(slot, gloas_epoch, super::ample_slot_end()).await;
            drop(_log);
            let text = logs.lock().expect("mismatch log").clone();
            assert!(
                text.contains(&format!("mismatch={mismatch}")),
                "{label}: expected mismatch={mismatch}; log={text}"
            );

            let calls = rec.calls();
            assert!(
                !calls.contains(&"sign_aggregate_and_proof_root"),
                "{label}: must not reach the island signer; calls={calls:?}"
            );
            assert!(
                !calls.contains(&"sign_electra_aggregate_and_proof"),
                "{label}: must not fall back to Electra signing; calls={calls:?}"
            );
            let failed_after =
                RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();
            assert_eq!(
                failed_after.saturating_sub(failed_before),
                1,
                "{label}: must increment RVC_AGGREGATIONS_TOTAL failed"
            );
            assert_eq!(submit_calls.load(Ordering::SeqCst), 0, "{label}: must not submit");
        }
    }

    async fn produce_captured(
        config: OrchestratorConfig,
        epoch: u64,
        aggregate: VersionedAggregateAttestation,
    ) -> (Vec<ForkName>, Vec<VersionedSignedAggregateAndProof>) {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let slot = epoch * SLOTS_PER_EPOCH;
        let fetched = Arc::new(Mutex::new(Vec::new()));
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let beacon = Arc::new(capturing_tracking_beacon(
            pk_hex,
            Arc::new(AtomicUsize::new(0)),
            slot,
            aggregate,
            fetched.clone(),
            submitted.clone(),
        ));
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let service = AggregationService::new(
            local_signer_service(sk),
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            config,
            enabled_store(pk_bytes),
        );
        service.maybe_produce_aggregations(slot, epoch, super::ample_slot_end()).await;
        let forks = fetched.lock().unwrap().clone();
        let proofs = submitted.lock().unwrap().clone();
        (forks, proofs)
    }

    #[tokio::test]
    async fn gloas_aggregate_is_fetched_and_dispatched_end_to_end() {
        let gloas_epoch = 70;
        let slot = gloas_epoch * SLOTS_PER_EPOCH;
        let mut aggregate = electra_attestation(slot);
        aggregate.signature = vec![0xcd; 96];
        let (forks, submitted) = produce_captured(
            gloas_config(gloas_epoch),
            gloas_epoch,
            VersionedAggregateAttestation::Gloas(aggregate),
        )
        .await;

        assert_eq!(forks, vec![ForkName::Gloas], "fetch must see the slot's Gloas fork");
        assert_eq!(submitted.len(), 1, "Gloas aggregate must be submitted once");
        match &submitted[0] {
            VersionedSignedAggregateAndProof::Gloas(proofs) => {
                assert_eq!(proofs.len(), 1);
                assert_eq!(proofs[0].message.aggregate.signature, vec![0xcd; 96]);
                assert_eq!(proofs[0].message.aggregate.data.slot, slot);
            }
            other => panic!("fetched Gloas aggregate must be dispatched as Gloas, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_fork_passed_to_the_fetch_is_the_fork_resolved_for_the_slot() {
        let fulu_epoch = 60;
        let fulu_slot = fulu_epoch * SLOTS_PER_EPOCH;
        let (fulu_forks, _) = produce_captured(
            create_test_config(),
            fulu_epoch,
            VersionedAggregateAttestation::Fulu(electra_attestation(fulu_slot)),
        )
        .await;
        assert_eq!(
            fulu_forks,
            vec![ForkName::Fulu],
            "Fulu slot must not pass Phase0, Electra, or a stale head fork"
        );

        let gloas_epoch = 70;
        let gloas_slot = gloas_epoch * SLOTS_PER_EPOCH;
        let (gloas_forks, _) = produce_captured(
            gloas_config(gloas_epoch),
            gloas_epoch,
            VersionedAggregateAttestation::Gloas(electra_attestation(gloas_slot)),
        )
        .await;
        assert_eq!(
            gloas_forks,
            vec![ForkName::Gloas],
            "Gloas slot must not keep the previous Fulu fork"
        );
    }

    /// H-25: one wave can contain indices in duty order `10,2,1,3`.
    ///
    /// `ready_chunks` flushes when the sign stream is pending, so staggered
    /// sleeps would publish one index at a time. A shared delay makes the four
    /// selection proofs ready in one poll; the recorded attribute is still the
    /// numeric order, and a second run records the same string.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn source_validators_is_sorted_before_recording() {
        use std::time::Duration;

        use crate::orchestrator::dispatch::DispatchLimits;

        let indices = ["10", "2", "1", "3"];
        let mut keys = Vec::new();
        let mut delays = HashMap::new();
        let mut duties = Vec::new();
        for index in indices {
            let secret = SecretKey::generate();
            let pubkey = secret.public_key();
            let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
            delays.insert(pubkey.to_bytes(), Duration::from_millis(5));
            duties.push(beacon::AttesterDuty {
                pubkey: pubkey_hex,
                validator_index: index.to_string(),
                committee_index: "0".to_string(),
                committee_length: "8".to_string(),
                committees_at_slot: "1".to_string(),
                validator_committee_index: "0".to_string(),
                slot: "0".to_string(),
            });
            keys.push(pubkey);
        }

        let duty_rows = duties.clone();
        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_get_attester_duties(move |_epoch, _indices| {
                    Ok(DependentRootResponse {
                        dependent_root: "0xaabb".to_string(),
                        execution_optimistic: false,
                        data: duty_rows.clone(),
                    })
                })
                .with_get_attestation_data(|slot, _committee_index| {
                    Ok(DataResponse {
                        data: beacon::AttestationData {
                            slot: slot.to_string(),
                            index: "0".to_string(),
                            beacon_block_root:
                                "0x1111111111111111111111111111111111111111111111111111111111111111"
                                    .to_string(),
                            source: beacon::Checkpoint {
                                epoch: "0".to_string(),
                                root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                                    .to_string(),
                            },
                            target: beacon::Checkpoint {
                                epoch: "0".to_string(),
                                root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                                    .to_string(),
                            },
                        },
                    })
                })
                .with_get_aggregate_attestation(move |slot, _root, _idx, _fork| {
                    Ok(VersionedAggregateAttestation::PreElectra(pre_electra_attestation(slot)))
                })
                .with_submit_aggregate_and_proofs(|_| Ok(())),
        );

        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut map = HashMap::new();
        for pubkey in &keys {
            let bytes = pubkey.to_bytes();
            store.add_validator(ValidatorConfig::new(bytes)).unwrap();
            map.insert(bytes, pubkey.clone());
        }
        let tracked: Vec<String> = indices.iter().map(|index| (*index).to_string()).collect();
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), tracked));
        duty_tracker.fetch_duties_for_epoch(0).await.unwrap();

        let signer = Arc::new(DelayingSigner { inner: StubValidatorSigner::new(), delays });
        let config = create_test_config().with_dispatch_limits(
            DispatchLimits::validated(4, 1).expect("concurrency is non-zero"),
        );
        let service = AggregationService::new(
            signer,
            beacon.clone(),
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            config,
            store,
        );

        super::take_recorded_source_validators();
        let slot_end = super::ample_slot_end();
        service.maybe_produce_aggregations(0, 0, slot_end).await;
        service.maybe_produce_aggregations(0, 0, slot_end).await;

        let recorded = super::take_recorded_source_validators();
        assert_eq!(
            beacon.submit_aggregate_and_proofs_calls().len(),
            2,
            "one aggregate submit per run"
        );
        assert_eq!(recorded.len(), 2, "one source_validators value per run, got {recorded:?}");
        assert_eq!(recorded[0], recorded[1], "source_validators must be stable across runs");
        assert_eq!(
            recorded[0], "1,2,3,10",
            "validator indices are sorted numerically before recording, got {}",
            recorded[0]
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn undispatched_aggregation_duties_are_dropped_at_slot_end() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let service = setup_agg_service(
            pk_hex,
            pk.clone(),
            local_signer_service(sk),
            enabled_store(pk.to_bytes()),
            submit_calls.clone(),
            AggEnv {
                config: create_test_config(),
                slot: 0,
                aggregate: VersionedAggregateAttestation::PreElectra(pre_electra_attestation(0)),
            },
        )
        .await;
        let slot_end = tokio::time::Instant::now();
        tokio::time::advance(std::time::Duration::from_millis(1)).await;
        service.maybe_produce_aggregations(0, 0, slot_end).await;
        assert_eq!(submit_calls.load(Ordering::SeqCst), 0, "nothing is published after slot end");
        assert_eq!(service.slot_end_drops(), 1);
    }

    /// A publish started near `slot_end` is cut at `slot_end + 500 ms`.
    /// The `aggregate_submit` timeout alone (2 s) would finish well into S+1.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn delayed_aggregate_publish_stops_at_slot_end_overhang() {
        use std::time::Duration;

        use bn_manager::MockMethod;

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let submit_calls = Arc::new(AtomicUsize::new(0));
        let beacon = Arc::new(
            tracking_beacon(
                pk_hex.clone(),
                Arc::clone(&submit_calls),
                0,
                VersionedAggregateAttestation::PreElectra(pre_electra_attestation(0)),
            )
            .with_method_delay(MockMethod::SubmitAggregateAndProofs, Duration::from_secs(2)),
        );
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(0).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk.clone());
        let config = create_test_config().with_timeouts(bn_manager::OperationTimeouts {
            aggregate_submit: Duration::from_secs(2),
            ..bn_manager::OperationTimeouts::default()
        });
        let service = AggregationService::new(
            local_signer_service(sk),
            beacon.clone(),
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            config,
            enabled_store(pk.to_bytes()),
        );

        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_millis(50);
        service.maybe_produce_aggregations(0, 0, slot_end).await;
        let finished = tokio::time::Instant::now();
        let overhang_at = slot_end + Duration::from_millis(500);
        assert!(
            finished <= overhang_at,
            "drain ran until {finished:?}, past overhang {overhang_at:?}"
        );
        assert!(
            finished.saturating_duration_since(started) < Duration::from_secs(2),
            "the 2 s aggregate_submit timeout must not extend the phase, elapsed {:?}",
            finished.saturating_duration_since(started)
        );
        let submits: Vec<_> = beacon
            .call_stamps()
            .into_iter()
            .filter(|stamp| stamp.method == MockMethod::SubmitAggregateAndProofs)
            .collect();
        assert!(!submits.is_empty(), "the publish starts, then the overhang budget stops it");
        assert!(
            submits.iter().all(|stamp| stamp.at <= overhang_at),
            "a publish must not be admitted after the overhang: {submits:?}"
        );
        assert_eq!(submit_calls.load(Ordering::SeqCst), 0, "the 2 s POST must be cancelled");
        assert!(
            beacon.submit_aggregate_and_proofs_completions().is_empty(),
            "a POST cancelled during the delay must not record a completion"
        );
        assert_eq!(service.slot_end_drops(), 0, "the in-flight duty is dispatched");
    }

    /// Beacon stand-in that implements [`AttestationApi`] and nothing else.
    ///
    /// Construction is the proof: a `BeaconNodeClient` constructor cannot name
    /// this type.
    struct AttestationOnlyMock;

    #[async_trait]
    impl AttestationApi for AttestationOnlyMock {
        async fn get_attestation_data(
            &self,
            _slot: u64,
            _committee_index: u64,
        ) -> Result<AttestationDataResponse, BeaconError> {
            Err(BeaconError::HttpError("attestation-only mock".into()))
        }

        async fn submit_attestation(
            &self,
            _attestations: &VersionedAttestation,
        ) -> Result<SubmitAttestationResult, BeaconError> {
            Err(BeaconError::HttpError("attestation-only mock".into()))
        }

        async fn get_aggregate_attestation(
            &self,
            _slot: u64,
            _attestation_data_root: &str,
            _committee_index: Option<u64>,
            _fork: ForkName,
        ) -> Result<VersionedAggregateAttestation, BeaconError> {
            Err(BeaconError::HttpError("attestation-only mock".into()))
        }

        async fn submit_aggregate_and_proofs(
            &self,
            _proofs: &VersionedSignedAggregateAndProof,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("attestation-only mock".into()))
        }

        async fn submit_beacon_committee_subscriptions(
            &self,
            _subscriptions: &[BeaconCommitteeSubscription],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("attestation-only mock".into()))
        }
    }

    /// An attestation-only client must construct [`AggregationService`].
    #[test]
    fn attestation_only_mock_satisfies_aggregation_service() {
        let beacon = Arc::new(AttestationOnlyMock);
        let duty_tracker =
            Arc::new(DutyTracker::new(Arc::new(MockBeaconNodeClient::new()), Vec::new()));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let service = AggregationService::new(
            Arc::new(StubValidatorSigner::new()),
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            store,
        );
        assert_eq!(service.slot_end_drops(), 0);
    }

    struct DelayingSigner {
        inner: StubValidatorSigner,
        delays: HashMap<[u8; 48], std::time::Duration>,
    }

    macro_rules! delay_fwd {
        ($($name:ident($($arg:ident: $ty:ty),* $(,)?));* $(;)?) => {
            #[async_trait]
            impl ValidatorSigner for DelayingSigner {
                $(
                    async fn $name(
                        &self,
                        $($arg: $ty),*
                    ) -> Result<Signature, SignerError> {
                        delay_fwd!(@maybe_delay $name, self, $($arg),*);
                        self.inner.$name($($arg),*).await
                    }
                )*
            }
        };
        (@maybe_delay sign_selection_proof, $self:ident, $slot:ident, $pubkey:ident, $($rest:ident),*) => {
            if let Some(delay) = $self.delays.get(&$pubkey.to_bytes()) {
                tokio::time::sleep(*delay).await;
            }
        };
        (@maybe_delay $name:ident, $self:ident, $($arg:ident),*) => {};
    }

    delay_fwd! {
        sign_attestation(data: &AttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_block(block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_block_header(header: &signer::BeaconBlockHeaderFields, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_randao_reveal(epoch: Epoch, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_sync_committee_message(beacon_block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_selection_proof(slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_aggregate_and_proof(aggregate_and_proof: &eth_types::AggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_electra_aggregate_and_proof(aggregate_and_proof: &ElectraAggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_voluntary_exit(voluntary_exit: &eth_types::VoluntaryExit, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_builder_registration(registration: &eth_types::ValidatorRegistrationV1, pubkey: &PublicKey, fork_version: [u8; 4]);
        sign_sync_committee_selection_proof(slot: Slot, subcommittee_index: u64, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_contribution_and_proof(contribution_and_proof: &eth_types::ContributionAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_payload_attestation(data: &eth_types::PayloadAttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_execution_payload_envelope_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
        sign_aggregate_and_proof_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root);
    }

    fn request_shaped_data(slot: Slot) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 0, root: [0u8; 32] },
            target: Checkpoint { epoch: 0, root: [0u8; 32] },
        }
    }

    fn matching_electra_body(slot: Slot) -> ElectraAttestation {
        let mut body = electra_attestation(slot);
        body.data = request_shaped_data(slot);
        body.aggregation_bits = vec![0xff, 0x01];
        body.committee_bits = vec![0x01, 0, 0, 0, 0, 0, 0, 0];
        body.signature = vec![0xab; 96];
        body
    }

    fn beacon_request_data(slot: Slot) -> beacon::AttestationData {
        beacon::AttestationData {
            slot: slot.to_string(),
            index: "0".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "0".to_string(),
                root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "0".to_string(),
                root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            },
        }
    }

    struct SignCase {
        epoch: u64,
        committee_index: &'static str,
        committee_length: &'static str,
        aggregate: VersionedAggregateAttestation,
        config: OrchestratorConfig,
        /// When set, `sign_selection_proof` returns this signature so a long
        /// committee can still be selected as aggregator.
        selection_proof: Option<Signature>,
    }

    async fn sign_electra_aggregate(
        aggregate: VersionedAggregateAttestation,
    ) -> (Vec<&'static str>, usize) {
        sign_case(SignCase {
            epoch: 50,
            committee_index: "0",
            committee_length: "8",
            aggregate,
            config: create_test_config(),
            selection_proof: None,
        })
        .await
    }

    async fn sign_case(case: SignCase) -> (Vec<&'static str>, usize) {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let mut recorder = RecordingSigner::new();
        recorder.selection_proof = case.selection_proof.clone();
        let rec = Arc::new(recorder);
        let submits = Arc::new(AtomicUsize::new(0));
        let slot = case.epoch * SLOTS_PER_EPOCH;
        let epoch = case.epoch;
        let committee_index = case.committee_index.to_string();
        let committee_length = case.committee_length.to_string();
        let aggregate = case.aggregate;
        let config = case.config;
        let submit_count = Arc::clone(&submits);
        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_get_attester_duties(move |_epoch, _indices| {
                    Ok(DependentRootResponse {
                        dependent_root: "0xaabb".to_string(),
                        execution_optimistic: false,
                        data: vec![beacon::AttesterDuty {
                            pubkey: pk_hex.clone(),
                            validator_index: "1".to_string(),
                            committee_index: committee_index.clone(),
                            committee_length: committee_length.clone(),
                            committees_at_slot: "1".to_string(),
                            validator_committee_index: "0".to_string(),
                            slot: slot.to_string(),
                        }],
                    })
                })
                .with_get_attestation_data(move |queried, _committee| {
                    Ok(DataResponse { data: beacon_request_data(queried) })
                })
                .with_get_aggregate_attestation(move |_slot, _root, _idx, _fork| {
                    Ok(aggregate.clone())
                })
                .with_submit_aggregate_and_proofs(move |_proofs| {
                    submit_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
        );
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk_bytes, pk);
        let service = AggregationService::new(
            rec.clone(),
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            config,
            enabled_store(pk_bytes),
        );
        service.maybe_produce_aggregations(slot, epoch, super::ample_slot_end()).await;
        (rec.calls(), submits.load(Ordering::SeqCst))
    }

    struct MismatchLog {
        buf: Arc<Mutex<String>>,
    }

    struct MismatchVisitor<'a>(&'a mut String);

    impl tracing::field::Visit for MismatchVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={value}", field.name());
        }
    }

    impl<S> tracing_subscriber::Layer<S> for MismatchLog
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut line = String::new();
            event.record(&mut MismatchVisitor(&mut line));
            let mut buf = self.buf.lock().expect("mismatch log");
            buf.push_str(&line);
            buf.push('\n');
        }
    }

    fn aggregate_sign_count(calls: &[&str]) -> usize {
        calls.iter().filter(|name| name.contains("aggregate_and_proof")).count()
    }

    /// A real selection proof that `is_aggregator` accepts for this committee.
    fn aggregator_proof(committee_length: u64) -> Signature {
        let mut n = 0u32;
        loop {
            let signature = signer::mock_sig(&n.to_le_bytes());
            if signer::is_aggregator(committee_length, &signature.to_bytes()) {
                return signature;
            }
            n += 1;
            assert!(n < 10_000, "no aggregator proof for committee {committee_length}");
        }
    }

    /// SSZ bitlist with `bit_length` participant bits and a trailing sentinel.
    fn bitlist(bit_length: usize) -> Vec<u8> {
        assert!(bit_length > 0);
        let len = bit_length / 8 + 1;
        let sentinel_bit = bit_length % 8;
        let mut bytes = vec![0xff; len];
        let low = if sentinel_bit == 0 { 0 } else { (1u8 << sentinel_bit) - 1 };
        bytes[len - 1] = low | (1u8 << sentinel_bit);
        bytes
    }

    async fn expect_mismatch(label: &str, case: SignCase, mismatch: &str) {
        let logs = Arc::new(Mutex::new(String::new()));
        let subscriber =
            tracing_subscriber::registry().with(MismatchLog { buf: Arc::clone(&logs) });
        let _guard = tracing::subscriber::set_default(subscriber);
        let (calls, submits) = sign_case(case).await;
        drop(_guard);
        assert_eq!(
            aggregate_sign_count(&calls),
            0,
            "{label}: aggregate must not be signed; calls={calls:?}"
        );
        assert_eq!(submits, 0, "{label}: aggregate must not be published");
        let text = logs.lock().expect("mismatch log").clone();
        assert!(
            text.contains(&format!("mismatch={mismatch}")),
            "{label}: expected mismatch={mismatch}; log={text}"
        );
    }

    #[test]
    fn aggregate_fork_matches_rejects_each_loosened_arm() {
        let slot = 0;
        let pre = VersionedAggregateAttestation::PreElectra(pre_electra_attestation(slot));
        let electra = VersionedAggregateAttestation::Electra(electra_attestation(slot));
        let fulu = VersionedAggregateAttestation::Fulu(electra_attestation(slot));
        let gloas = VersionedAggregateAttestation::Gloas(electra_attestation(slot));
        assert!(super::aggregate_fork_matches(&pre, ForkName::Deneb));
        assert!(!super::aggregate_fork_matches(&pre, ForkName::Electra));
        assert!(!super::aggregate_fork_matches(&electra, ForkName::Deneb));
        assert!(super::aggregate_fork_matches(&electra, ForkName::Electra));
        assert!(super::aggregate_fork_matches(&electra, ForkName::Fulu));
        assert!(super::aggregate_fork_matches(&electra, ForkName::Gloas));
        assert!(!super::aggregate_fork_matches(&fulu, ForkName::Electra));
        assert!(super::aggregate_fork_matches(&fulu, ForkName::Fulu));
        assert!(!super::aggregate_fork_matches(&fulu, ForkName::Gloas));
        assert!(!super::aggregate_fork_matches(&gloas, ForkName::Electra));
        assert!(!super::aggregate_fork_matches(&gloas, ForkName::Fulu));
        assert!(super::aggregate_fork_matches(&gloas, ForkName::Gloas));
    }

    #[test]
    fn gloas_island_encode_rejects_a_short_selection_proof() {
        let message = ElectraAggregateAndProof {
            aggregator_index: 1,
            aggregate: matching_electra_body(0),
            selection_proof: vec![0x11; 95],
        };
        let err = super::encode_electra_aggregate_and_proof(&message).expect_err("95-byte proof");
        assert!(err.to_string().contains("96"), "{err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_mismatched_aggregate_is_not_signed() {
        let _guard = agg_fail_metric_lock().await;
        let electra_epoch = 50u64;
        let slot = electra_epoch * SLOTS_PER_EPOCH;
        let cases: &[(&str, VersionedAggregateAttestation)] = &[
            ("slot", {
                let mut body = matching_electra_body(slot);
                body.data.slot = slot + 1;
                VersionedAggregateAttestation::Electra(body)
            }),
            ("data_root", {
                let mut body = matching_electra_body(slot);
                body.data.beacon_block_root = [0x22; 32];
                VersionedAggregateAttestation::Electra(body)
            }),
            ("committee_index", {
                let mut body = matching_electra_body(slot);
                body.committee_bits = vec![0x02, 0, 0, 0, 0, 0, 0, 0];
                VersionedAggregateAttestation::Electra(body)
            }),
            ("multiple_committee_bits", {
                let mut body = matching_electra_body(slot);
                body.committee_bits = vec![0x03, 0, 0, 0, 0, 0, 0, 0];
                VersionedAggregateAttestation::Electra(body)
            }),
            ("attester_bits", {
                let mut body = matching_electra_body(slot);
                body.aggregation_bits = vec![0x01];
                VersionedAggregateAttestation::Electra(body)
            }),
            ("fork", {
                let body = matching_electra_body(slot);
                VersionedAggregateAttestation::Fulu(body)
            }),
            ("signature_95", {
                let mut body = matching_electra_body(slot);
                body.signature = vec![0xab; 95];
                VersionedAggregateAttestation::Electra(body)
            }),
            ("signature_97", {
                let mut body = matching_electra_body(slot);
                body.signature = vec![0xab; 97];
                VersionedAggregateAttestation::Electra(body)
            }),
            ("short_committee_bits", {
                let mut body = matching_electra_body(slot);
                body.committee_bits = vec![0x01];
                VersionedAggregateAttestation::Electra(body)
            }),
            ("oversized", {
                let mut body = matching_electra_body(slot);
                body.aggregation_bits = vec![0xff; 16_386];
                VersionedAggregateAttestation::Electra(body)
            }),
            // 31 participant bits (`0xffffffff`) against a committee of 8.
            ("committee_length", {
                let mut body = matching_electra_body(slot);
                body.aggregation_bits = vec![0xff, 0xff, 0xff, 0xff];
                VersionedAggregateAttestation::Electra(body)
            }),
            // EIP-7549: a non-zero index must not be signed on a zeroed copy's root.
            ("data_index", {
                let mut body = matching_electra_body(slot);
                body.data.index = 1;
                VersionedAggregateAttestation::Electra(body)
            }),
        ];
        for (label, aggregate) in cases {
            let logs = Arc::new(Mutex::new(String::new()));
            let subscriber =
                tracing_subscriber::registry().with(MismatchLog { buf: Arc::clone(&logs) });
            let _guard = tracing::subscriber::set_default(subscriber);
            let (calls, submits) = sign_electra_aggregate(aggregate.clone()).await;
            drop(_guard);
            assert_eq!(
                aggregate_sign_count(&calls),
                0,
                "{label}: aggregate must not be signed; calls={calls:?}"
            );
            assert_eq!(submits, 0, "{label}: aggregate must not be published");
            let expected = match *label {
                "committee_length" => "attester_bits",
                "multiple_committee_bits" | "short_committee_bits" => "committee_index",
                "signature_95" | "signature_97" => "oversized",
                other => other,
            };
            let text = logs.lock().expect("mismatch log").clone();
            assert!(
                text.contains(&format!("mismatch={expected}")),
                "{label}: expected mismatch={expected}; log={text}"
            );
        }
    }

    /// Fulu and Gloas accept the Electra body a v1 aggregate fallback returns.
    #[tokio::test]
    async fn electra_variant_from_v1_fallback_is_signed_on_fulu_and_gloas() {
        let fulu_epoch = 60u64;
        let fulu_slot = fulu_epoch * SLOTS_PER_EPOCH;
        let (fulu_calls, fulu_submits) = sign_case(SignCase {
            epoch: fulu_epoch,
            committee_index: "0",
            committee_length: "8",
            aggregate: VersionedAggregateAttestation::Electra(matching_electra_body(fulu_slot)),
            config: create_test_config(),
            selection_proof: None,
        })
        .await;
        assert_eq!(
            fulu_calls.iter().filter(|name| **name == "sign_electra_aggregate_and_proof").count(),
            1,
            "Fulu v1 Electra body must be signed; calls={fulu_calls:?}"
        );
        assert_eq!(fulu_submits, 1);

        let gloas_epoch = 70u64;
        let gloas_slot = gloas_epoch * SLOTS_PER_EPOCH;
        let (gloas_calls, gloas_submits) = sign_case(SignCase {
            epoch: gloas_epoch,
            committee_index: "0",
            committee_length: "8",
            aggregate: VersionedAggregateAttestation::Electra(matching_electra_body(gloas_slot)),
            config: gloas_config(gloas_epoch),
            selection_proof: None,
        })
        .await;
        assert_eq!(
            gloas_calls.iter().filter(|name| **name == "sign_aggregate_and_proof_root").count(),
            1,
            "Gloas v1 Electra body must be signed on the island path; calls={gloas_calls:?}"
        );
        assert_eq!(gloas_submits, 1);
    }

    /// Pre-Electra roots can match on the wrong committee. The duty index binds.
    #[tokio::test(flavor = "current_thread")]
    async fn pre_electra_data_index_must_match_the_duty_committee() {
        let _metrics = agg_fail_metric_lock().await;
        let logs = Arc::new(Mutex::new(String::new()));
        let subscriber =
            tracing_subscriber::registry().with(MismatchLog { buf: Arc::clone(&logs) });
        let _guard = tracing::subscriber::set_default(subscriber);
        let slot = 0u64;
        let mut body = pre_electra_attestation(slot);
        body.data = request_shaped_data(slot);
        let (calls, submits) = sign_case(SignCase {
            epoch: 0,
            committee_index: "1",
            committee_length: "8",
            aggregate: VersionedAggregateAttestation::PreElectra(body),
            config: create_test_config(),
            selection_proof: None,
        })
        .await;
        drop(_guard);
        assert_eq!(
            aggregate_sign_count(&calls),
            0,
            "index 0 must not be signed for committee 1; calls={calls:?}"
        );
        assert_eq!(submits, 0);
        let text = logs.lock().expect("mismatch log").clone();
        assert!(
            text.contains("mismatch=data_index"),
            "pre-Electra index check must be the one that fired; log={text}"
        );
    }

    /// Variants the later wrap would still sign. Only `aggregate_fork_matches` rejects them.
    #[tokio::test(flavor = "current_thread")]
    async fn cross_fork_aggregates_fail_the_early_fork_check() {
        let _guard = agg_fail_metric_lock().await;
        let electra_epoch = 50u64;
        let electra_slot = electra_epoch * SLOTS_PER_EPOCH;
        let fulu_epoch = 60u64;
        let fulu_slot = fulu_epoch * SLOTS_PER_EPOCH;
        let gloas_epoch = 70u64;
        let gloas_slot = gloas_epoch * SLOTS_PER_EPOCH;
        let cases = [
            (
                "fulu_on_electra",
                electra_epoch,
                create_test_config(),
                VersionedAggregateAttestation::Fulu(matching_electra_body(electra_slot)),
            ),
            (
                "gloas_on_electra",
                electra_epoch,
                create_test_config(),
                VersionedAggregateAttestation::Gloas(matching_electra_body(electra_slot)),
            ),
            (
                "gloas_on_fulu",
                fulu_epoch,
                create_test_config(),
                VersionedAggregateAttestation::Gloas(matching_electra_body(fulu_slot)),
            ),
            (
                "fulu_on_gloas",
                gloas_epoch,
                gloas_config(gloas_epoch),
                VersionedAggregateAttestation::Fulu(matching_electra_body(gloas_slot)),
            ),
        ];
        for (label, epoch, config, aggregate) in cases {
            expect_mismatch(
                label,
                SignCase {
                    epoch,
                    committee_index: "0",
                    committee_length: "8",
                    aggregate,
                    config,
                    selection_proof: None,
                },
                "fork",
            )
            .await;
        }
    }

    /// Byte cap and bit cap each fire on their own boundary. Electra's limit is
    /// above the pre-Electra maximum, so a 2049-bit list is not oversized there.
    #[tokio::test(flavor = "current_thread")]
    async fn attester_bit_caps_reject_each_boundary() {
        let _guard = agg_fail_metric_lock().await;
        let pre_max = MAX_VALIDATORS_PER_COMMITTEE as usize;
        let electra_max = pre_max * MAX_COMMITTEES_PER_SLOT as usize;

        let mut at_pre_limit = pre_electra_attestation(0);
        at_pre_limit.data = request_shaped_data(0);
        at_pre_limit.aggregation_bits = bitlist(pre_max);
        expect_mismatch(
            "pre_at_bit_limit",
            SignCase {
                epoch: 0,
                committee_index: "0",
                committee_length: "8",
                aggregate: VersionedAggregateAttestation::PreElectra(at_pre_limit),
                config: create_test_config(),
                selection_proof: None,
            },
            "attester_bits",
        )
        .await;

        let mut over_pre_bits = pre_electra_attestation(0);
        over_pre_bits.data = request_shaped_data(0);
        over_pre_bits.aggregation_bits = bitlist(pre_max + 1);
        expect_mismatch(
            "pre_bit_cap",
            SignCase {
                epoch: 0,
                committee_index: "0",
                committee_length: "8",
                aggregate: VersionedAggregateAttestation::PreElectra(over_pre_bits),
                config: create_test_config(),
                selection_proof: None,
            },
            "oversized",
        )
        .await;

        let mut over_pre_bytes = pre_electra_attestation(0);
        over_pre_bytes.data = request_shaped_data(0);
        over_pre_bytes.aggregation_bits = vec![0u8; pre_max / 8 + 2];
        expect_mismatch(
            "pre_byte_cap",
            SignCase {
                epoch: 0,
                committee_index: "0",
                committee_length: "8",
                aggregate: VersionedAggregateAttestation::PreElectra(over_pre_bytes),
                config: create_test_config(),
                selection_proof: None,
            },
            "oversized",
        )
        .await;

        let electra_epoch = 50u64;
        let electra_slot = electra_epoch * SLOTS_PER_EPOCH;
        let mut electra_above_pre = matching_electra_body(electra_slot);
        electra_above_pre.aggregation_bits = bitlist(pre_max + 1);
        expect_mismatch(
            "electra_above_pre_electra_max",
            SignCase {
                epoch: electra_epoch,
                committee_index: "0",
                committee_length: "8",
                aggregate: VersionedAggregateAttestation::Electra(electra_above_pre),
                config: create_test_config(),
                selection_proof: None,
            },
            "attester_bits",
        )
        .await;

        let mut electra_over_bits = matching_electra_body(electra_slot);
        electra_over_bits.aggregation_bits = bitlist(electra_max + 1);
        expect_mismatch(
            "electra_bit_cap",
            SignCase {
                epoch: electra_epoch,
                committee_index: "0",
                committee_length: "8",
                aggregate: VersionedAggregateAttestation::Electra(electra_over_bits),
                config: create_test_config(),
                selection_proof: None,
            },
            "oversized",
        )
        .await;

        let mut electra_over_bytes = matching_electra_body(electra_slot);
        electra_over_bytes.aggregation_bits = vec![0u8; electra_max / 8 + 2];
        expect_mismatch(
            "electra_byte_cap",
            SignCase {
                epoch: electra_epoch,
                committee_index: "0",
                committee_length: "8",
                aggregate: VersionedAggregateAttestation::Electra(electra_over_bytes),
                config: create_test_config(),
                selection_proof: None,
            },
            "oversized",
        )
        .await;
    }

    /// The only phase-2 permit is already held. The selection-proof wait hits
    /// its deadline and the signer is not called.
    #[tokio::test(start_paused = true)]
    async fn cancel_during_phase2_permit_wait_does_not_sign() {
        use std::time::Duration;

        use crate::orchestrator::dispatch::Phase2SignerPermits;

        let permits = Phase2SignerPermits::new(1);
        let held = permits
            .acquire_until(tokio::time::Instant::now() + Duration::from_secs(30))
            .await
            .expect("the test holds the only permit");
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk_hex = format!("0x{}", hex::encode(pk_bytes));
        let rec = Arc::new(RecordingSigner::new());
        let submits = Arc::new(AtomicUsize::new(0));
        let slot = 50 * SLOTS_PER_EPOCH;
        let submit_count = Arc::clone(&submits);
        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_get_attester_duties(move |_epoch, _indices| {
                    Ok(DependentRootResponse {
                        dependent_root: "0xaabb".to_string(),
                        execution_optimistic: false,
                        data: vec![beacon::AttesterDuty {
                            pubkey: pk_hex.clone(),
                            validator_index: "1".to_string(),
                            committee_index: "0".to_string(),
                            committee_length: "8".to_string(),
                            committees_at_slot: "1".to_string(),
                            validator_committee_index: "0".to_string(),
                            slot: slot.to_string(),
                        }],
                    })
                })
                .with_get_attestation_data(move |queried, _committee| {
                    Ok(DataResponse { data: beacon_request_data(queried) })
                })
                .with_get_aggregate_attestation(move |_slot, _root, _idx, _fork| {
                    Ok(VersionedAggregateAttestation::Electra(matching_electra_body(slot)))
                })
                .with_submit_aggregate_and_proofs(move |_proofs| {
                    submit_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
        );
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(50).await.unwrap();
        let mut map = HashMap::new();
        map.insert(pk_bytes, pk);
        let service = AggregationService::new(
            rec.clone(),
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            create_test_config(),
            enabled_store(pk_bytes),
        );
        let slot_end = tokio::time::Instant::now() + Duration::from_millis(20);
        let run = service.produce_aggregations(slot, 50, slot_end, &permits);
        tokio::pin!(run);
        // Park on the permit before slot end, so intake does not drop the duty.
        for _ in 0..32 {
            tokio::select! {
                biased;
                _ = &mut run => panic!("phase finished while the only permit is held"),
                _ = tokio::task::yield_now() => {}
            }
        }
        let mut advanced = Duration::ZERO;
        loop {
            tokio::select! {
                biased;
                _ = &mut run => {
                    assert!(
                        advanced >= Duration::from_millis(520),
                        "the permit wait returned before its deadline ({advanced:?})"
                    );
                    break;
                }
                _ = tokio::task::yield_now() => {
                    if advanced < Duration::from_millis(600) {
                        tokio::time::advance(Duration::from_millis(10)).await;
                        advanced += Duration::from_millis(10);
                    } else {
                        panic!("permit wait did not cancel after the deadline");
                    }
                }
            }
        }
        drop(held);
        let calls = rec.calls();
        assert_eq!(calls, Vec::<&str>::new(), "a cancelled permit wait must not sign: {calls:?}");
        assert_eq!(submits.load(Ordering::SeqCst), 0);
    }

    /// A duty committee length outside `1..=2048` is rejected before signing,
    /// including when the bitlist matches that length and fits the Electra spec max.
    #[tokio::test(flavor = "current_thread")]
    async fn committee_length_above_2048_is_not_signed_on_electra_or_fulu() {
        let _metrics = agg_fail_metric_lock().await;
        for (label, epoch) in [("electra", 50u64), ("fulu", 60u64)] {
            let slot = epoch * SLOTS_PER_EPOCH;
            let mut body = matching_electra_body(slot);
            body.aggregation_bits = bitlist(2049);
            let aggregate = if epoch == 50 {
                VersionedAggregateAttestation::Electra(body)
            } else {
                VersionedAggregateAttestation::Fulu(body)
            };
            expect_mismatch(
                label,
                SignCase {
                    epoch,
                    committee_index: "0",
                    committee_length: "2049",
                    aggregate,
                    config: create_test_config(),
                    selection_proof: Some(aggregator_proof(2049)),
                },
                "attester_bits",
            )
            .await;
        }
    }

    /// Fulu zeroes `data.index`. A non-zero index is `data_index`, not a root miss.
    #[tokio::test(flavor = "current_thread")]
    async fn fulu_data_index_must_be_zero() {
        let _metrics = agg_fail_metric_lock().await;
        let fulu_epoch = 60u64;
        let slot = fulu_epoch * SLOTS_PER_EPOCH;
        let mut body = matching_electra_body(slot);
        body.data.index = 1;
        expect_mismatch(
            "fulu_data_index",
            SignCase {
                epoch: fulu_epoch,
                committee_index: "0",
                committee_length: "8",
                aggregate: VersionedAggregateAttestation::Fulu(body),
                config: create_test_config(),
                selection_proof: None,
            },
            "data_index",
        )
        .await;
    }

    /// The final Electra sign's permit wait expires. That counts as failed,
    /// and it is not a slot-end intake drop.
    #[tokio::test(start_paused = true)]
    async fn expired_final_sign_permit_wait_counts_as_failed() {
        use std::time::Duration;

        use crate::orchestrator::dispatch::Phase2SignerPermits;

        let _metrics = agg_fail_metric_lock().await;
        let permits = Phase2SignerPermits::new(1);
        let held = permits
            .acquire_until(tokio::time::Instant::now() + Duration::from_secs(30))
            .await
            .expect("the test holds the only permit");
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let rec = Arc::new(RecordingSigner::new());
        let beacon = Arc::new(MockBeaconNodeClient::new());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        let mut map = HashMap::new();
        map.insert(pk_bytes, pk.clone());
        let service = AggregationService::new(
            rec.clone(),
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            create_test_config(),
            enabled_store(pk_bytes),
        );
        let slot = 50 * SLOTS_PER_EPOCH;
        let message = ElectraAggregateAndProof {
            aggregator_index: 1,
            aggregate: matching_electra_body(slot),
            selection_proof: vec![0xcd; 96],
        };
        let failed_before =
            RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();
        let drops_before = service.slot_end_drops.get();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(40);
        let fence = beacon::DutyFence::open();
        let run = service.sign_and_wrap_electra(
            slot,
            "1",
            &pk,
            message,
            tracing::Span::none(),
            &fence,
            &permits,
            deadline,
        );
        tokio::pin!(run);
        tokio::select! {
            biased;
            _ = &mut run => panic!("the final sign finished while the only permit is held"),
            _ = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_millis(40)).await;
        let signed = (&mut run).await;
        drop(held);
        assert!(signed.is_none(), "an expired final-sign wait must not return a signature");
        let calls = rec.calls();
        assert!(
            !calls.contains(&"sign_electra_aggregate_and_proof"),
            "an expired final-sign wait must not sign; calls={calls:?}"
        );
        let failed_after =
            RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();
        assert_eq!(
            failed_after.saturating_sub(failed_before),
            1,
            "an expired final-sign wait must increment RVC_AGGREGATIONS_TOTAL failed"
        );
        assert_eq!(
            service.slot_end_drops.get(),
            drops_before,
            "an expired final-sign wait is not a slot-end intake drop"
        );
    }

    #[tokio::test]
    async fn a_matching_electra_aggregate_is_signed_once() {
        let slot = 50 * SLOTS_PER_EPOCH;
        let (calls, submits) = sign_electra_aggregate(VersionedAggregateAttestation::Electra(
            matching_electra_body(slot),
        ))
        .await;
        assert_eq!(
            calls.iter().filter(|name| **name == "sign_electra_aggregate_and_proof").count(),
            1,
            "a matching Electra aggregate is signed once; calls={calls:?}"
        );
        assert_eq!(submits, 1, "a matching Electra aggregate is published once");
    }
}
