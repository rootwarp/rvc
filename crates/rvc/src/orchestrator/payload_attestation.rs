use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tracing::{debug, info, info_span, warn, Instrument};

use crate::metrics::{
    attestation_status, payload_attestation_skip_reason, ptc_duty_outcome,
    RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL, RVC_PTC_ATTESTATIONS_TOTAL, RVC_PTC_DUTIES_TOTAL,
};
use bn_manager::BeaconNodeClient;
use crypto::PublicKey;
use duty_tracker::{DutyTracker, TypedPtcDuty};
use eth_types::{PayloadAttestationData, PayloadAttestationMessage, Slot};
use observability::logging::TruncatedPubkey;
use signer::{SignerService, ValidatorSigner};
use validator_store::ValidatorStore;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::dispatch::{SlotEndDropCounter, SLOT_END_PUBLISH_OVERHANG};
use super::utils;

pub(crate) struct PayloadAttestationService {
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    validator_store: Arc<ValidatorStore>,
    /// PTC duties not pulled onto the sign pipeline before slot end.
    slot_end_drops: SlotEndDropCounter,
}

impl PayloadAttestationService {
    pub(crate) fn new(
        signer: Arc<SignerService>,
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

    /// Duties dropped because slot end arrived before they were dispatched.
    #[cfg(test)]
    pub(crate) fn slot_end_drops(&self) -> u64 {
        self.slot_end_drops.get()
    }

    /// Fetch payload attestation data once per slot and sign/submit for every
    /// local PTC duty. HTTP 204 (`Ok(None)`) skips with no signatures.
    ///
    /// Signing uses the same dispatch limits as attestation, sync messages,
    /// and aggregation: `take_until(slot_end)` stops pulling new duties. Duty
    /// fetch, payload-data fetch, and the sign/publish drain are each capped
    /// by the earlier of `slot_end` plus 500 ms and `attestation_submit`. The
    /// phase may therefore overhang into the next slot by up to 500 ms; a
    /// stalled BN or signer cannot hold the coordinator `join!` beyond that.
    /// `scheduled` means the duty was signed. `dropped` is recorded at most
    /// once per duty and can follow a successful sign when publish fails or
    /// is cut off. Each ready chunk is one `submit_payload_attestations`
    /// submission (fanned out to the configured BNs). Payload attestations
    /// are non-slashable, so this path does not touch the slashing database.
    #[tracing::instrument(
        name = "orchestrator.produce_payload_attestations",
        level = "debug",
        skip_all,
        fields(slot = slot)
    )]
    pub(crate) async fn maybe_produce_payload_attestations(
        &self,
        slot: Slot,
        epoch: u64,
        slot_end: tokio::time::Instant,
    ) {
        let submit_timeout = self.config.timeouts.attestation_submit;

        // Same lazy-fetch as attester `process_slot`, but never start a cold
        // duties/ptc POST after slot end — that fetch can take seconds and the
        // slot loop join!s this phase with attestation/aggregation.
        if !self.duty_tracker.is_ptc_epoch_cached(epoch).await {
            if tokio::time::Instant::now() >= slot_end {
                warn!(slot, epoch, "Skipping PTC duty fetch: slot already ended");
                return;
            }
            let deadline = ptc_hard_deadline(slot_end, submit_timeout);
            match tokio::time::timeout_at(
                deadline,
                self.duty_tracker.fetch_ptc_duties_for_epoch(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    warn!(slot, epoch, error = %e, "Failed to fetch PTC duties");
                    return;
                }
                Err(_) => {
                    warn!(slot, epoch, "PTC duty fetch exceeded the phase deadline");
                    return;
                }
            }
        }

        let duties = self.duty_tracker.get_ptc_duties_for_slot(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_ptc_duties(&duties);
        let (matching_duties, matching_pubkeys) =
            dedup_ptc_duties(matching_duties, matching_pubkeys);
        if matching_duties.is_empty() {
            return;
        }

        if tokio::time::Instant::now() >= slot_end {
            self.record_slot_end_drops(slot, matching_duties.len(), matching_duties.len());
            return;
        }

        // VC is the single observer: one fetch, identical bytes to every signer.
        let deadline = ptc_hard_deadline(slot_end, submit_timeout);
        let data =
            match tokio::time::timeout_at(deadline, self.beacon.get_payload_attestation_data(slot))
                .await
            {
                Ok(Ok(Some(resp))) => resp.data,
                Ok(Ok(None)) => {
                    debug!(slot, "Skipping payload attestations: no data (HTTP 204)");
                    RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL
                        .with_label_values(&[payload_attestation_skip_reason::NO_DATA])
                        .inc();
                    inc_ptc_duty_by(
                        ptc_duty_outcome::SKIPPED_NO_DATA,
                        matching_duties.len() as u64,
                    );
                    return;
                }
                Ok(Err(e)) => {
                    warn!(slot, error = %e, "Failed to get payload attestation data");
                    inc_ptc_duty_by(ptc_duty_outcome::DROPPED, matching_duties.len() as u64);
                    return;
                }
                Err(_) => {
                    warn!(slot, "Payload attestation data fetch exceeded the phase deadline");
                    inc_ptc_duty_by(ptc_duty_outcome::DROPPED, matching_duties.len() as u64);
                    return;
                }
            };

        if data.slot != slot {
            warn!(slot, data_slot = data.slot, "Rejecting payload attestation data: slot mismatch");
            inc_ptc_duty_by(ptc_duty_outcome::DROPPED, matching_duties.len() as u64);
            return;
        }

        // Same shape as sync-message dispatch. A slow sign stays inside
        // `buffer_unordered`; `ready_chunks` posts the signatures that are
        // already ready so one validator does not hold the others' pool POST.
        // The drain is hard-capped at `phase_deadline`. Publish awaits the
        // POST without a second timeout — the drain cancel is the sole
        // deadline. `dropped` is recorded at most once per duty and can
        // follow a successful sign when publish fails or is cut off.
        let pairs: Vec<_> = matching_duties
            .into_iter()
            .zip(matching_pubkeys)
            .enumerate()
            .map(|(idx, (duty, pubkey))| (idx, duty, pubkey))
            .collect();
        let duty_count = pairs.len();
        let outcomes = PtcDutyOutcomes::new(duty_count);
        let concurrency = self.config.dispatch_limits.concurrency as usize;
        let publish_concurrency = self.config.dispatch_limits.publish_concurrency as usize;
        let phase_deadline = ptc_hard_deadline(slot_end, submit_timeout);
        // The flag is set only when slot end completes and stops the input.
        // Dropping the stream because the submit cap fired leaves it false.
        let take_until_stopped = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&take_until_stopped);
        let stop_pulling = async move {
            tokio::time::sleep_until(slot_end).await;
            stop_flag.store(true, Ordering::Release);
        };
        let waves = stream::iter(pairs)
            .take_until(stop_pulling)
            .map(|(idx, duty, pubkey)| {
                self.sign_payload_attestation_one(slot, &data, duty, pubkey, idx, &outcomes)
            })
            .buffer_unordered(concurrency)
            .ready_chunks(concurrency)
            .map(|wave| {
                self.publish_payload_attestation_wave(
                    slot,
                    slot_end,
                    phase_deadline,
                    wave,
                    &outcomes,
                )
            })
            .buffer_unordered(publish_concurrency);
        let drain = async {
            let mut waves = std::pin::pin!(waves);
            while waves.next().await.is_some() {}
        };
        let drain_timed_out = tokio::time::timeout_at(phase_deadline, drain).await.is_err();
        if drain_timed_out {
            warn!(slot, "Payload attestation sign/publish drain exceeded the phase deadline");
        }
        // Which cap armed `phase_deadline` is not the log reason. A backlog
        // `take_until` dropped at slot end stays a slot-end drop when the
        // drain finishes inside an earlier submit cap.
        let reason = pending_drop_reason(PtcDrainEvidence {
            take_until_stopped: take_until_stopped.load(Ordering::Acquire),
            drain_timed_out,
            timeout_was_overhang: phase_deadline == slot_end + SLOT_END_PUBLISH_OVERHANG,
        });
        outcomes.finalize_remainder(slot, &self.slot_end_drops, duty_count, reason, submit_timeout);
    }

    fn record_slot_end_drops(&self, slot: Slot, dropped: usize, duty_count: usize) {
        self.slot_end_drops.record(dropped as u64);
        inc_ptc_duty_by(ptc_duty_outcome::DROPPED, dropped as u64);
        warn!(
            slot,
            dropped,
            duty_count,
            total_dropped = self.slot_end_drops.get(),
            "undispatched payload attestation duties dropped at slot end"
        );
    }

    /// Sign one payload attestation. Publish is a later wave, not this future.
    ///
    /// H6: a signer error is `Err` for this duty only. The outcome is recorded
    /// here once; a later phase-deadline cancel must not count it again.
    async fn sign_payload_attestation_one(
        &self,
        slot: Slot,
        data: &PayloadAttestationData,
        duty: TypedPtcDuty,
        pubkey: PublicKey,
        duty_idx: usize,
        outcomes: &PtcDutyOutcomes,
    ) -> (usize, Result<PayloadAttestationMessage, ()>) {
        let validator_index = duty.validator_index;
        match self
            .signer
            .sign_payload_attestation(
                data,
                &pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            )
            .await
        {
            Ok(sig) => {
                outcomes.mark_signed(duty_idx);
                (
                    duty_idx,
                    Ok(PayloadAttestationMessage {
                        validator_index,
                        data: data.clone(),
                        signature: sig.to_bytes().to_vec(),
                    }),
                )
            }
            Err(e) => {
                warn!(
                    slot,
                    validator_index,
                    error = %e,
                    "Failed to sign payload attestation"
                );
                outcomes.finalize_sign_failure(duty_idx);
                (duty_idx, Err(()))
            }
        }
    }

    /// One batch POST for a wave of signed payload attestations.
    ///
    /// Admission stops at `phase_deadline` (the earlier of `slot_end` plus
    /// 500 ms and the submit cap from drain start). The POST itself is not
    /// wrapped in a second timeout — the parent drain cancel is the deadline
    /// — so a cut-off in-flight POST is finalized once via
    /// [`PtcDutyOutcomes::finalize_remainder`]. Only `Ok` signatures are posted.
    async fn publish_payload_attestation_wave(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
        phase_deadline: tokio::time::Instant,
        wave: Vec<(usize, Result<PayloadAttestationMessage, ()>)>,
        outcomes: &PtcDutyOutcomes,
    ) {
        let mut messages = Vec::new();
        let mut signed_indices = Vec::new();
        for (idx, result) in wave {
            if let Ok(message) = result {
                signed_indices.push(idx);
                messages.push(message);
            }
        }
        if messages.is_empty() {
            return;
        }

        let bounded_by_overhang = phase_deadline == slot_end + SLOT_END_PUBLISH_OVERHANG;
        if tokio::time::Instant::now() >= phase_deadline {
            warn_ptc_publish_stopped(
                slot,
                bounded_by_overhang,
                self.config.timeouts.attestation_submit,
            );
            outcomes.finalize_publish_failure(&signed_indices);
            return;
        }

        let count = messages.len();
        let submit_result = self
            .beacon
            .submit_payload_attestations(&messages)
            .instrument(info_span!("beacon.submit_payload_attestations", slot, count))
            .await;

        match submit_result {
            Ok(()) => {
                info!(slot, count, "Submitted payload attestations");
                outcomes.finalize_publish_success(&signed_indices);
            }
            Err(e) => {
                warn!(slot, error = %e, "Failed to submit payload attestations");
                outcomes.finalize_publish_failure(&signed_indices);
            }
        }
    }

    fn filter_ptc_duties(&self, duties: &[TypedPtcDuty]) -> (Vec<TypedPtcDuty>, Vec<PublicKey>) {
        let mut matching_duties = Vec::new();
        let mut matching_pubkeys = Vec::new();

        for duty in duties {
            if let Some(pk) = utils::find_pubkey(&self.pubkey_map, &duty.pubkey) {
                let pk_bytes = pk.to_bytes();
                if !self.validator_store.is_signing_enabled(&pk_bytes) {
                    warn!(
                        pubkey = %TruncatedPubkey::new(&duty.pubkey),
                        "Skipping payload attestation duty: validator is inside the \
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

    #[cfg(test)]
    pub(crate) fn slashing_db(&self) -> &slashing::SlashingDb {
        self.signer.slashing_db()
    }
}

/// What the sign/publish drain actually observed. The cap that armed
/// `phase_deadline` is not itself a reason.
struct PtcDrainEvidence {
    /// `take_until(slot_end)` completed and stopped pulling new duties.
    take_until_stopped: bool,
    /// `timeout_at(phase_deadline)` fired.
    drain_timed_out: bool,
    /// The armed deadline was `slot_end + 500 ms` rather than `attestation_submit`.
    /// Read only when `drain_timed_out` is set.
    timeout_was_overhang: bool,
}

/// Log line for duties still pending after the drain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PtcPendingDropReason {
    /// Slot end stopped the input, or the overhang timeout fired.
    SlotEnd,
    /// The `attestation_submit` timeout fired and `take_until` did not.
    SubmitDeadline,
}

/// Choose the pending-duty log from what cut the duties.
///
/// `take_until` can drop a backlog while `attestation_submit` is the earlier
/// armed cap and the drain still finishes inside it. That backlog is a
/// slot-end drop. The submit line is used only when that timeout fired and
/// slot end did not stop the input.
fn pending_drop_reason(evidence: PtcDrainEvidence) -> PtcPendingDropReason {
    if evidence.take_until_stopped {
        PtcPendingDropReason::SlotEnd
    } else if evidence.drain_timed_out && !evidence.timeout_was_overhang {
        PtcPendingDropReason::SubmitDeadline
    } else {
        PtcPendingDropReason::SlotEnd
    }
}

/// Earlier of `slot_end + 500 ms` and `now + attestation_submit`.
fn ptc_hard_deadline(
    slot_end: tokio::time::Instant,
    submit_timeout: Duration,
) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    let overhang_at = slot_end + SLOT_END_PUBLISH_OVERHANG;
    let submit_at = now.checked_add(submit_timeout).unwrap_or(overhang_at);
    overhang_at.min(submit_at)
}

/// Keep the first duty for each parsed `(pubkey_bytes, slot)` pair from the BN.
fn dedup_ptc_duties(
    duties: Vec<TypedPtcDuty>,
    pubkeys: Vec<PublicKey>,
) -> (Vec<TypedPtcDuty>, Vec<PublicKey>) {
    let mut seen = HashSet::new();
    let mut out_duties = Vec::with_capacity(duties.len());
    let mut out_pubkeys = Vec::with_capacity(pubkeys.len());
    for (duty, pubkey) in duties.into_iter().zip(pubkeys) {
        if seen.insert((pubkey.to_bytes(), duty.slot)) {
            out_duties.push(duty);
            out_pubkeys.push(pubkey);
        }
    }
    (out_duties, out_pubkeys)
}

/// Per-duty phase. `dropped` is recorded at most once and can follow a
/// successful sign when publish fails or is cut off.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PtcDutyPhase {
    /// Not signed yet (or sign cancelled before completion).
    Pending,
    /// Signed; `scheduled` already counted. Awaiting publish finalization.
    Signed,
    /// Terminal: sign failure, publish success/failure, or undispatched drop.
    Done,
}

struct PtcDutyOutcomes {
    phases: Mutex<Vec<PtcDutyPhase>>,
}

impl PtcDutyOutcomes {
    fn new(n: usize) -> Self {
        Self { phases: Mutex::new(vec![PtcDutyPhase::Pending; n]) }
    }

    fn mark_signed(&self, idx: usize) {
        let mut phases = self.phases.lock().expect("ptc duty outcomes");
        if phases[idx] != PtcDutyPhase::Pending {
            return;
        }
        phases[idx] = PtcDutyPhase::Signed;
        drop(phases);
        inc_ptc_duty(ptc_duty_outcome::SCHEDULED);
    }

    fn finalize_sign_failure(&self, idx: usize) {
        let mut phases = self.phases.lock().expect("ptc duty outcomes");
        if phases[idx] != PtcDutyPhase::Pending {
            return;
        }
        phases[idx] = PtcDutyPhase::Done;
        drop(phases);
        inc_ptc_duty(ptc_duty_outcome::DROPPED);
    }

    fn finalize_publish_success(&self, indices: &[usize]) {
        let mut phases = self.phases.lock().expect("ptc duty outcomes");
        let mut n = 0u64;
        for &idx in indices {
            if phases[idx] == PtcDutyPhase::Signed {
                phases[idx] = PtcDutyPhase::Done;
                n += 1;
            }
        }
        drop(phases);
        if n > 0 {
            inc_ptc_attestation_by(attestation_status::SUCCESS, n);
        }
    }

    fn finalize_publish_failure(&self, indices: &[usize]) {
        let mut phases = self.phases.lock().expect("ptc duty outcomes");
        let mut n = 0u64;
        for &idx in indices {
            if phases[idx] == PtcDutyPhase::Signed {
                phases[idx] = PtcDutyPhase::Done;
                n += 1;
            }
        }
        drop(phases);
        if n > 0 {
            inc_ptc_attestation_by(attestation_status::FAILED, n);
            inc_ptc_duty_by(ptc_duty_outcome::DROPPED, n);
        }
    }

    /// After the drain: pending duties were never finalized (sign cancelled or
    /// never started); signed-but-unpublished duties are a cut-off POST.
    ///
    /// `reason` is what cut the pending duties, not which cap was smaller
    /// when the deadline was armed. Metric totals do not depend on it.
    fn finalize_remainder(
        &self,
        slot: Slot,
        counter: &SlotEndDropCounter,
        duty_count: usize,
        reason: PtcPendingDropReason,
        submit_timeout: Duration,
    ) {
        let mut phases = self.phases.lock().expect("ptc duty outcomes");
        let mut pending = 0usize;
        let mut cut_off = 0usize;
        for phase in phases.iter_mut() {
            match *phase {
                PtcDutyPhase::Pending => {
                    *phase = PtcDutyPhase::Done;
                    pending += 1;
                }
                PtcDutyPhase::Signed => {
                    *phase = PtcDutyPhase::Done;
                    cut_off += 1;
                }
                PtcDutyPhase::Done => {}
            }
        }
        drop(phases);

        if pending > 0 {
            counter.record(pending as u64);
            inc_ptc_duty_by(ptc_duty_outcome::DROPPED, pending as u64);
            match reason {
                PtcPendingDropReason::SlotEnd => {
                    warn!(
                        slot,
                        dropped = pending,
                        duty_count,
                        total_dropped = counter.get(),
                        "undispatched payload attestation duties dropped at slot end"
                    );
                }
                PtcPendingDropReason::SubmitDeadline => {
                    warn!(
                        slot,
                        dropped = pending,
                        duty_count,
                        total_dropped = counter.get(),
                        timeout_secs = submit_timeout.as_secs(),
                        "undispatched payload attestation duties dropped by attestation_submit deadline"
                    );
                }
            }
        }
        if cut_off > 0 {
            inc_ptc_attestation_by(attestation_status::FAILED, cut_off as u64);
            inc_ptc_duty_by(ptc_duty_outcome::DROPPED, cut_off as u64);
            warn!(slot, count = cut_off, "Payload attestation publish cut by the phase deadline");
        }
    }
}

fn inc_ptc_duty(outcome: &str) {
    #[cfg(test)]
    if !ptc_counter_lock::enabled() {
        return;
    }
    RVC_PTC_DUTIES_TOTAL.with_label_values(&[outcome]).inc();
}

fn inc_ptc_duty_by(outcome: &str, n: u64) {
    #[cfg(test)]
    if !ptc_counter_lock::enabled() {
        return;
    }
    RVC_PTC_DUTIES_TOTAL.with_label_values(&[outcome]).inc_by(n);
}

fn inc_ptc_attestation_by(status: &str, n: u64) {
    #[cfg(test)]
    if !ptc_counter_lock::enabled() {
        return;
    }
    RVC_PTC_ATTESTATIONS_TOTAL.with_label_values(&[status]).inc_by(n);
}

fn warn_ptc_publish_stopped(slot: Slot, bounded_by_overhang: bool, submit_timeout: Duration) {
    if bounded_by_overhang {
        warn!(
            slot,
            "Payload attestation publish exceeded the {} ms slot-end overhang",
            SLOT_END_PUBLISH_OVERHANG.as_millis()
        );
    } else {
        warn!(slot, "Payload attestation submit timed out after {}s", submit_timeout.as_secs());
    }
}

/// Serializes PTC counter delta tests without blocking other PTC callers.
#[cfg(test)]
mod ptc_counter_lock {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;

    tokio::task_local! {
        static HELD: ();
    }

    static DELTA_TESTS: AtomicUsize = AtomicUsize::new(0);

    fn mutex() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    pub fn enabled() -> bool {
        if DELTA_TESTS.load(Ordering::SeqCst) == 0 {
            true
        } else {
            HELD.try_with(|_| ()).is_ok()
        }
    }

    pub async fn with_held<Fut: Future>(fut: Fut) -> Fut::Output {
        DELTA_TESTS.fetch_add(1, Ordering::SeqCst);
        let _guard = mutex().lock().await;
        let out = HELD.scope((), fut).await;
        DELTA_TESTS.fetch_sub(1, Ordering::SeqCst);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use crate::metrics::{
        attestation_status, payload_attestation_skip_reason, ptc_duty_outcome,
        RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL, RVC_PTC_ATTESTATIONS_TOTAL, RVC_PTC_DUTIES_TOTAL,
    };
    use crate::orchestrator::dispatch::DispatchLimits;
    use async_trait::async_trait;
    use beacon::PayloadAttestationDataResponse;
    use bn_manager::{
        BeaconError, BeaconNodeClient, MockBeaconNodeClient, MockMethod, OperationTimeouts,
        PtcDutiesResponse, PtcDuty,
    };
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey, Signer, SigningError};
    use duty_tracker::DutyTracker;
    use eth_types::{ForkSchedule, PayloadAttestationData, PayloadAttestationMessage, Root};
    use signer::{always_enabled, SignerService};
    use slashing::SlashingDb;
    use tracing_test::traced_test;
    use validator_store::{ValidatorConfig, ValidatorStore};

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

    fn ptc_data(slot: Slot) -> PayloadAttestationData {
        PayloadAttestationData {
            beacon_block_root: [0xAA; 32],
            slot,
            payload_present: true,
            blob_data_available: false,
        }
    }

    fn ptc_duty(slot: Slot, validator_index: u64, pk: &PublicKey) -> PtcDuty {
        PtcDuty {
            pubkey: format!("0x{}", hex::encode(pk.to_bytes())),
            validator_index: validator_index.to_string(),
            slot: slot.to_string(),
        }
    }

    fn ptc_response(duties: Vec<PtcDuty>) -> PtcDutiesResponse {
        PtcDutiesResponse {
            dependent_root: "0xdeproot".to_string(),
            execution_optimistic: false,
            data: duties,
        }
    }

    struct TestKeys {
        sk: SecretKey,
        pk: PublicKey,
        index: u64,
    }

    fn test_key(index: u64) -> TestKeys {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        TestKeys { sk, pk, index }
    }

    async fn setup_service(
        beacon: Arc<dyn BeaconNodeClient>,
        keys: Vec<TestKeys>,
        omit_secret_for: &[u64],
    ) -> PayloadAttestationService {
        setup_service_with(beacon, keys, omit_secret_for, create_test_config(), None).await
    }

    async fn setup_service_with(
        beacon: Arc<dyn BeaconNodeClient>,
        keys: Vec<TestKeys>,
        omit_secret_for: &[u64],
        config: OrchestratorConfig,
        sign_backend: Option<Arc<dyn Signer>>,
    ) -> PayloadAttestationService {
        build_service(beacon, keys, omit_secret_for, config, sign_backend, true).await
    }

    /// Like [`setup_service_with`], but leaves the PTC epoch cache cold so the
    /// phase's duty-fetch path runs.
    async fn setup_service_cold_cache(
        beacon: Arc<dyn BeaconNodeClient>,
        keys: Vec<TestKeys>,
        config: OrchestratorConfig,
    ) -> PayloadAttestationService {
        build_service(beacon, keys, &[], config, None, false).await
    }

    async fn build_service(
        beacon: Arc<dyn BeaconNodeClient>,
        keys: Vec<TestKeys>,
        omit_secret_for: &[u64],
        config: OrchestratorConfig,
        sign_backend: Option<Arc<dyn Signer>>,
        warm_ptc_cache: bool,
    ) -> PayloadAttestationService {
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut key_manager = KeyManager::new();
        let mut map = HashMap::new();
        let mut indices = Vec::new();
        for k in keys {
            store.add_validator(ValidatorConfig::new(k.pk.to_bytes())).unwrap();
            if !omit_secret_for.contains(&k.index) {
                key_manager.insert(k.sk);
            }
            map.insert(k.pk.to_bytes(), k.pk);
            indices.push(k.index.to_string());
        }
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let mut signer =
            SignerService::new(composite, slashing_db).with_enablement(always_enabled());
        if let Some(backend) = sign_backend {
            signer = signer.with_sign_backend(backend);
        }
        let signer = Arc::new(signer);
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), indices.clone()));
        if warm_ptc_cache {
            duty_tracker.fetch_ptc_duties(0, &indices).await.unwrap();
        }
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));
        PayloadAttestationService::new(signer, beacon, duty_tracker, pubkey_map, config, store)
    }

    /// BLS backend that records how many `sign` calls overlap.
    type SignFinishLog = Arc<Mutex<Vec<([u8; 48], tokio::time::Instant)>>>;

    struct TrackingSigner {
        key: SecretKey,
        delays: HashMap<[u8; 48], Duration>,
        default_delay: Duration,
        in_flight: Arc<AtomicUsize>,
        max_in_flight: Arc<AtomicUsize>,
        fail: Vec<[u8; 48]>,
        finished: SignFinishLog,
    }

    #[async_trait]
    impl Signer for TrackingSigner {
        async fn sign(
            &self,
            signing_root: &Root,
            pubkey: &[u8; 48],
        ) -> Result<crypto::Signature, SigningError> {
            if self.fail.iter().any(|failed| failed == pubkey) {
                return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
            }
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            let delay = self.delays.get(pubkey).copied().unwrap_or(self.default_delay);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let signature = self.key.sign(signing_root);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            self.finished.lock().unwrap().push((*pubkey, tokio::time::Instant::now()));
            Ok(signature)
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            Vec::new()
        }
    }

    fn skip_count() -> u64 {
        RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL
            .with_label_values(&[payload_attestation_skip_reason::NO_DATA])
            .get()
    }

    fn ptc_duty_count(outcome: &str) -> u64 {
        RVC_PTC_DUTIES_TOTAL.with_label_values(&[outcome]).get()
    }

    fn ptc_attestation_count(status: &str) -> u64 {
        RVC_PTC_ATTESTATIONS_TOTAL.with_label_values(&[status]).get()
    }

    #[tokio::test]
    async fn test_payload_attestation_204_skips_without_signature_or_submission() {
        super::ptc_counter_lock::with_held(async {
            let k = test_key(10);
            let submitted: Arc<Mutex<Vec<PayloadAttestationMessage>>> =
                Arc::new(Mutex::new(Vec::new()));
            let fetch_count = Arc::new(AtomicUsize::new(0));
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &k.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data({
                        let fetch_count = fetch_count.clone();
                        move |_slot| {
                            fetch_count.fetch_add(1, Ordering::SeqCst);
                            Ok(None)
                        }
                    })
                    .with_submit_payload_attestations({
                        let submitted = submitted.clone();
                        move |msgs| {
                            submitted.lock().unwrap().extend(msgs);
                            Ok(())
                        }
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
            let service = setup_service(beacon, vec![k], &[]).await;

            let before = skip_count();
            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(fetch_count.load(Ordering::SeqCst), 1, "204 path must still fetch once");
            assert!(
                submitted.lock().unwrap().is_empty(),
                "204 must not submit payload attestations"
            );
            assert_eq!(
                skip_count(),
                before + 1,
                "204 must increment rvc_payload_attestation_skipped_total{{reason=no_data}}"
            );
            assert!(
                mock.submit_payload_attestations_calls().is_empty(),
                "204 must not call submit_payload_attestations"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_one_signer_failure_does_not_abort_remaining_ptc_validators() {
        super::ptc_counter_lock::with_held(async {
            let a = test_key(10);
            let b = test_key(11);
            let c = test_key(12);
            let submitted_indices: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
            let data = ptc_data(0);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duties = vec![
                            ptc_duty(0, 10, &a.pk),
                            ptc_duty(0, 11, &b.pk),
                            ptc_duty(0, 12, &c.pk),
                        ];
                        move |_epoch, _indices| Ok(ptc_response(duties.clone()))
                    })
                    .with_get_payload_attestation_data({
                        let data = data.clone();
                        move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                    })
                    .with_submit_payload_attestations({
                        let submitted_indices = submitted_indices.clone();
                        move |msgs| {
                            submitted_indices
                                .lock()
                                .unwrap()
                                .extend(msgs.iter().map(|m| m.validator_index));
                            Ok(())
                        }
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
            let service = setup_service(beacon, vec![a, b, c], &[11]).await;

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            let mut indices = submitted_indices.lock().unwrap().clone();
            indices.sort_unstable();
            assert_eq!(
                indices,
                vec![10, 12],
                "H6: A and C must submit; B (KeyNotFound) must be skipped"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_payload_attestation_data_fetched_once_identical_bytes_to_every_signer() {
        super::ptc_counter_lock::with_held(async {
            let a = test_key(10);
            let b = test_key(11);
            let fetch_count = Arc::new(AtomicUsize::new(0));
            let expected = ptc_data(0);
            let submitted: Arc<Mutex<Vec<PayloadAttestationMessage>>> =
                Arc::new(Mutex::new(Vec::new()));
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duties = vec![ptc_duty(0, 10, &a.pk), ptc_duty(0, 11, &b.pk)];
                        move |_epoch, _indices| Ok(ptc_response(duties.clone()))
                    })
                    .with_get_payload_attestation_data({
                        let fetch_count = fetch_count.clone();
                        let expected = expected.clone();
                        move |_slot| {
                            let n = fetch_count.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(
                                n, 0,
                                "payload attestation data must be fetched once per slot"
                            );
                            Ok(Some(PayloadAttestationDataResponse { data: expected.clone() }))
                        }
                    })
                    .with_submit_payload_attestations({
                        let submitted = submitted.clone();
                        move |msgs| {
                            submitted.lock().unwrap().extend(msgs);
                            Ok(())
                        }
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
            let service = setup_service(beacon, vec![a, b], &[]).await;

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
            assert_eq!(mock.get_payload_attestation_data_calls(), vec![0]);
            let messages = submitted.lock().unwrap().clone();
            assert_eq!(messages.len(), 2);
            for msg in &messages {
                assert_eq!(
                    msg.data, expected,
                    "identical PayloadAttestationData bytes must go to every signer"
                );
            }
            assert_eq!(messages[0].data, messages[1].data);
        })
        .await;
    }

    #[tokio::test]
    async fn test_ptc_success_increments_only_after_pool_post() {
        super::ptc_counter_lock::with_held(async {
            let k = test_key(10);
            let success_at_post = Arc::new(AtomicU64::new(0));
            let data = ptc_data(0);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &k.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data({
                        let data = data.clone();
                        move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                    })
                    .with_submit_payload_attestations({
                        let success_at_post = success_at_post.clone();
                        move |msgs| {
                            assert_eq!(msgs.len(), 1, "success path posts one payload attestation");
                            success_at_post.store(
                                ptc_attestation_count(attestation_status::SUCCESS),
                                Ordering::SeqCst,
                            );
                            Ok(())
                        }
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
            let service = setup_service(beacon, vec![k], &[]).await;

            let before_success = ptc_attestation_count(attestation_status::SUCCESS);
            let before_failed = ptc_attestation_count(attestation_status::FAILED);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let before_skipped = ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA);
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(
                success_at_post.load(Ordering::SeqCst),
                before_success,
                "rvc_ptc_attestations_total{{status=success}} must not increment until pool POST returns"
            );
            assert_eq!(
                ptc_attestation_count(attestation_status::SUCCESS),
                before_success + 1,
                "success increments after pool POST"
            );
            assert_eq!(
                ptc_attestation_count(attestation_status::FAILED),
                before_failed,
                "successful pool POST must not increment failed"
            );
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::SCHEDULED),
                before_scheduled + 1,
                "signed PTC duty counts as scheduled"
            );
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA), before_skipped);
            assert_eq!(ptc_duty_count(ptc_duty_outcome::DROPPED), before_dropped);
            assert_eq!(mock.submit_payload_attestations_calls().len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn test_ptc_204_counts_as_skipped_not_failed() {
        super::ptc_counter_lock::with_held(async {
            let k = test_key(10);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &k.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data(move |_slot| Ok(None))
                    .with_submit_payload_attestations(|_msgs| {
                        panic!("204 must not POST pool/payload_attestations")
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock;
            let service = setup_service(beacon, vec![k], &[]).await;

            let before_skipped = ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let before_success = ptc_attestation_count(attestation_status::SUCCESS);
            let before_failed = ptc_attestation_count(attestation_status::FAILED);

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA),
                before_skipped + 1,
                "204 must increment rvc_ptc_duties_total{{outcome=skipped_no_data}}"
            );
            assert_eq!(
                ptc_attestation_count(attestation_status::FAILED),
                before_failed,
                "204 must not count as a failed PTC attestation"
            );
            assert_eq!(ptc_attestation_count(attestation_status::SUCCESS), before_success);
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SCHEDULED), before_scheduled);
            assert_eq!(ptc_duty_count(ptc_duty_outcome::DROPPED), before_dropped);
        })
        .await;
    }

    #[tokio::test]
    async fn test_ptc_duty_dropped_when_signer_rejects_increments_dropped() {
        super::ptc_counter_lock::with_held(async {
            let k = test_key(10);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &k.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data({
                        let data = ptc_data(0);
                        move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                    })
                    .with_submit_payload_attestations(|_msgs| {
                        panic!("signer reject must not POST pool/payload_attestations")
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock;
            let service = setup_service(beacon, vec![k], &[10]).await;

            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let before_skipped = ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA);
            let before_success = ptc_attestation_count(attestation_status::SUCCESS);
            let before_failed = ptc_attestation_count(attestation_status::FAILED);

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped + 1,
                "signer reject must increment rvc_ptc_duties_total{{outcome=dropped}}"
            );
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SCHEDULED), before_scheduled);
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA), before_skipped);
            assert_eq!(ptc_attestation_count(attestation_status::SUCCESS), before_success);
            assert_eq!(ptc_attestation_count(attestation_status::FAILED), before_failed);
        })
        .await;
    }

    #[tokio::test]
    async fn test_ptc_get_data_error_increments_dropped() {
        super::ptc_counter_lock::with_held(async {
            let k = test_key(10);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &k.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data(|_slot| {
                        Err(BeaconError::HttpError("bn down".to_string()))
                    })
                    .with_submit_payload_attestations(|_msgs| {
                        panic!("GET error must not POST pool/payload_attestations")
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock;
            let service = setup_service(beacon, vec![k], &[]).await;

            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let before_skipped = ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA);
            let before_success = ptc_attestation_count(attestation_status::SUCCESS);
            let before_failed = ptc_attestation_count(attestation_status::FAILED);

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped + 1,
                "GET error must increment rvc_ptc_duties_total{{outcome=dropped}}"
            );
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SCHEDULED), before_scheduled);
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SKIPPED_NO_DATA), before_skipped);
            assert_eq!(ptc_attestation_count(attestation_status::SUCCESS), before_success);
            assert_eq!(ptc_attestation_count(attestation_status::FAILED), before_failed);
        })
        .await;
    }

    #[tokio::test]
    async fn test_ptc_pool_post_error_increments_failed() {
        super::ptc_counter_lock::with_held(async {
            let k = test_key(10);
            let data = ptc_data(0);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &k.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data({
                        let data = data.clone();
                        move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                    })
                    .with_submit_payload_attestations(|_msgs| {
                        Err(BeaconError::HttpError("pool rejected".to_string()))
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock;
            let service = setup_service(beacon, vec![k], &[]).await;

            let before_failed = ptc_attestation_count(attestation_status::FAILED);
            let before_success = ptc_attestation_count(attestation_status::SUCCESS);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(
                ptc_attestation_count(attestation_status::FAILED),
                before_failed + 1,
                "failed pool POST must increment rvc_ptc_attestations_total{{status=failed}}"
            );
            assert_eq!(ptc_attestation_count(attestation_status::SUCCESS), before_success);
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::SCHEDULED),
                before_scheduled + 1,
                "signed duty is still scheduled when pool POST fails"
            );
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped + 1,
                "publish failure must also increment rvc_ptc_duties_total{{outcome=dropped}}"
            );
        })
        .await;
    }

    type SubmitLog = Arc<Mutex<Vec<(tokio::time::Instant, Vec<u64>)>>>;

    fn ptc_beacon(duties: Vec<PtcDuty>, submitted: SubmitLog) -> Arc<MockBeaconNodeClient> {
        let data = ptc_data(0);
        Arc::new(
            MockBeaconNodeClient::new()
                .with_post_ptc_duties(move |_epoch, _indices| Ok(ptc_response(duties.clone())))
                .with_get_payload_attestation_data({
                    let data = data.clone();
                    move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                })
                .with_submit_payload_attestations(move |msgs| {
                    submitted.lock().unwrap().push((
                        tokio::time::Instant::now(),
                        msgs.iter().map(|msg| msg.validator_index).collect(),
                    ));
                    Ok(())
                }),
        )
    }

    /// Signs for distinct validators overlap, and never exceed dispatch concurrency.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ptc_signs_overlap_within_dispatch_concurrency() {
        const N: u64 = 6;
        const CONCURRENCY: u32 = 2;
        let keys: Vec<TestKeys> = (0..N).map(test_key).collect();
        let duties = keys.iter().map(|key| ptc_duty(0, key.index, &key.pk)).collect();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: HashMap::new(),
            default_delay: Duration::from_millis(40),
            in_flight: Arc::clone(&in_flight),
            max_in_flight: Arc::clone(&max_in_flight),
            fail: Vec::new(),
            finished: Arc::new(Mutex::new(Vec::new())),
        });
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(CONCURRENCY, 1).expect("non-zero"));
        let service =
            setup_service_with(mock, keys, &[], config, Some(backend as Arc<dyn Signer>)).await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        let mut indices: Vec<u64> =
            submitted.lock().unwrap().iter().flat_map(|(_, batch)| batch.clone()).collect();
        indices.sort_unstable();
        assert_eq!(indices, (0..N).collect::<Vec<_>>(), "every validator is submitted once");
        let max = max_in_flight.load(Ordering::SeqCst);
        assert!(max > 1, "PTC signs must overlap, max_in_flight={max}");
        assert!(
            max <= CONCURRENCY as usize,
            "PTC sign concurrency must stay within dispatch limit {CONCURRENCY}, max_in_flight={max}"
        );
    }

    /// A slow signer must not hold the other validators' payload-attestation POST.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn slow_ptc_signer_does_not_block_other_messages() {
        let slow = test_key(10);
        let fast_a = test_key(11);
        let fast_b = test_key(12);
        let slow_pk = slow.pk.to_bytes();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(Mutex::new(Vec::new()));
        let mut delays = HashMap::new();
        delays.insert(slow_pk, Duration::from_millis(200));
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays,
            default_delay: Duration::ZERO,
            in_flight: Arc::clone(&in_flight),
            max_in_flight: Arc::clone(&max_in_flight),
            fail: Vec::new(),
            finished: Arc::clone(&finished),
        });
        let duties = vec![
            ptc_duty(0, slow.index, &slow.pk),
            ptc_duty(0, fast_a.index, &fast_a.pk),
            ptc_duty(0, fast_b.index, &fast_b.pk),
        ];
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(3, 2).expect("non-zero"));
        let service = setup_service_with(
            mock,
            vec![slow, fast_a, fast_b],
            &[],
            config,
            Some(backend as Arc<dyn Signer>),
        )
        .await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        let submits = submitted.lock().unwrap().clone();
        let finished = finished.lock().unwrap().clone();
        let slow_done = finished
            .iter()
            .find(|(pubkey, _)| *pubkey == slow_pk)
            .map(|(_, at)| *at)
            .expect("slow validator signed");
        let fast_submit =
            submits.iter().find(|(_, indices)| indices.contains(&11) || indices.contains(&12));
        let Some((submitted_at, _)) = fast_submit else {
            panic!("fast validators were not submitted: {submits:?}");
        };
        assert!(
            *submitted_at < slow_done,
            "fast payload attestations must be posted before the slow signer finishes; \
             submitted_at={submitted_at:?} slow_done={slow_done:?} submits={submits:?}"
        );
    }

    /// No duties: do not fetch payload-attestation data and do not sign or post.
    #[tokio::test]
    async fn empty_ptc_duty_set_does_not_sign_or_submit() {
        let mock = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_ptc_duties(|_epoch, _indices| Ok(ptc_response(Vec::new())))
                .with_get_payload_attestation_data(|_slot| {
                    panic!("empty PTC duties must not fetch payload attestation data")
                })
                .with_submit_payload_attestations(|_| {
                    panic!("empty PTC duties must not submit payload attestations")
                }),
        );
        let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
        let service = setup_service(beacon, Vec::new(), &[]).await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        assert!(mock.get_payload_attestation_data_calls().is_empty());
        assert!(mock.submit_payload_attestations_calls().is_empty());
        assert_eq!(service.slot_end_drops(), 0);
    }

    /// One signer fails immediately. The other validators are still posted, and
    /// a fast success is not held behind a slow success.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn partial_ptc_failure_does_not_drop_other_messages() {
        let slow = test_key(10);
        let failed = test_key(11);
        let fast = test_key(12);
        let slow_pk = slow.pk.to_bytes();
        let failed_pk = failed.pk.to_bytes();
        let finished = Arc::new(Mutex::new(Vec::new()));
        let mut delays = HashMap::new();
        delays.insert(slow_pk, Duration::from_millis(200));
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays,
            default_delay: Duration::ZERO,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: vec![failed_pk],
            finished: Arc::clone(&finished),
        });
        let duties = vec![
            ptc_duty(0, slow.index, &slow.pk),
            ptc_duty(0, failed.index, &failed.pk),
            ptc_duty(0, fast.index, &fast.pk),
        ];
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(3, 2).expect("non-zero"));
        let service = setup_service_with(
            mock,
            vec![slow, failed, fast],
            &[],
            config,
            Some(backend as Arc<dyn Signer>),
        )
        .await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        let submits = submitted.lock().unwrap().clone();
        let mut indices: Vec<u64> = submits.iter().flat_map(|(_, batch)| batch.clone()).collect();
        indices.sort_unstable();
        assert_eq!(indices, vec![10, 12], "failed validator 11 must be omitted; 10 and 12 posted");
        assert!(
            submits.iter().all(|(_, batch)| !batch.contains(&11)),
            "a sign failure must not appear in a pool POST: {submits:?}"
        );
        let slow_done = finished
            .lock()
            .unwrap()
            .iter()
            .find(|(pubkey, _)| *pubkey == slow_pk)
            .map(|(_, at)| *at)
            .expect("slow validator signed");
        let fast_at = submits
            .iter()
            .find(|(_, batch)| batch.contains(&12))
            .map(|(at, _)| *at)
            .expect("fast validator posted");
        assert!(
            fast_at < slow_done,
            "validator 12 must be posted while validator 10 is still signing"
        );
    }

    /// `slot_end` already passed: nothing is fetched, signed, or published.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn undispatched_ptc_duties_are_dropped_at_slot_end() {
        super::ptc_counter_lock::with_held(async {
            let key = test_key(10);
            let duties = vec![ptc_duty(0, key.index, &key.pk)];
            let submitted = Arc::new(Mutex::new(Vec::new()));
            let mock = ptc_beacon(duties, Arc::clone(&submitted));
            let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
            let service = setup_service(beacon, vec![key], &[]).await;
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let slot_end = tokio::time::Instant::now();
            tokio::time::advance(Duration::from_millis(1)).await;

            service.maybe_produce_payload_attestations(0, 0, slot_end).await;

            assert!(
                mock.get_payload_attestation_data_calls().is_empty(),
                "a slot that has already ended must not fetch payload attestation data"
            );
            assert!(mock.submit_payload_attestations_calls().is_empty());
            assert!(submitted.lock().unwrap().is_empty());
            assert_eq!(service.slot_end_drops(), 1);
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped + 1,
                "slot-end drops must increment rvc_ptc_duties_total{{outcome=dropped}}"
            );
        })
        .await;
    }

    /// Signs already inside `buffer_unordered` finish after `take_until` stops
    /// pulling new duties. Later duties are dropped.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn in_flight_ptc_signs_complete_when_slot_end_stops_new_dispatch() {
        const N: u64 = 8;
        const CONCURRENCY: u32 = 4;
        let keys: Vec<TestKeys> = (0..N).map(test_key).collect();
        let duties = keys.iter().map(|key| ptc_duty(0, key.index, &key.pk)).collect();
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: HashMap::new(),
            default_delay: Duration::from_millis(50),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::new(Mutex::new(Vec::new())),
        });
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(CONCURRENCY, 2).expect("non-zero"));
        let service =
            setup_service_with(mock.clone(), keys, &[], config, Some(backend as Arc<dyn Signer>))
                .await;
        let slot_end = tokio::time::Instant::now() + Duration::from_millis(25);

        service.maybe_produce_payload_attestations(0, 0, slot_end).await;

        let indices: Vec<u64> =
            submitted.lock().unwrap().iter().flat_map(|(_, batch)| batch.clone()).collect();
        assert_eq!(indices.len(), CONCURRENCY as usize, "the in-flight wave completes");
        assert_eq!(mock.get_payload_attestation_data_calls(), vec![0]);
        assert_eq!(service.slot_end_drops(), N - u64::from(CONCURRENCY));
    }

    /// Codex mislabel: slot end at 25 ms, signs finish at 50 ms, submit cap at
    /// 100 ms. `take_until` drops the backlog and the drain finishes before
    /// the submit cap fires, so the log must not blame `attestation_submit`.
    /// A mutant that always logs the slot-end line still fails
    /// `undispatched_ptc_duties_dropped_by_submit_deadline_say_so`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[traced_test]
    async fn slot_end_backlog_is_not_logged_as_attestation_submit_deadline() {
        const N: u64 = 8;
        const CONCURRENCY: u32 = 4;
        let keys: Vec<TestKeys> = (0..N).map(test_key).collect();
        let duties = keys.iter().map(|key| ptc_duty(0, key.index, &key.pk)).collect();
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: HashMap::new(),
            default_delay: Duration::from_millis(50),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::new(Mutex::new(Vec::new())),
        });
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(CONCURRENCY, 2).expect("non-zero"))
            .with_timeouts(OperationTimeouts {
                attestation_submit: Duration::from_millis(100),
                ..OperationTimeouts::default()
            });
        let service =
            setup_service_with(mock, keys, &[], config, Some(backend as Arc<dyn Signer>)).await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_millis(25);

        service.maybe_produce_payload_attestations(0, 0, slot_end).await;

        let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
        assert!(
            elapsed >= Duration::from_millis(50) && elapsed < Duration::from_millis(100),
            "in-flight signs finish at 50 ms, before the 100 ms submit cap; elapsed {elapsed:?}"
        );
        let posted: usize = submitted.lock().unwrap().iter().map(|(_, batch)| batch.len()).sum();
        assert_eq!(posted, CONCURRENCY as usize, "the in-flight wave completes");
        assert_eq!(service.slot_end_drops(), N - u64::from(CONCURRENCY));
        assert!(
            logs_contain("undispatched payload attestation duties dropped at slot end"),
            "take_until dropped the backlog"
        );
        assert!(
            !logs_contain(
                "undispatched payload attestation duties dropped by attestation_submit deadline"
            ),
            "the submit cap was armed but never fired"
        );
    }

    /// Submit-cap timeout with slot end still far away. The log names
    /// `attestation_submit`. Always logging the slot-end reason fails this.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[traced_test]
    async fn undispatched_ptc_duties_dropped_by_submit_deadline_say_so() {
        let key = test_key(10);
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: HashMap::new(),
            default_delay: Duration::from_secs(30),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::new(Mutex::new(Vec::new())),
        });
        let duties = vec![ptc_duty(0, key.index, &key.pk)];
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config().with_timeouts(OperationTimeouts {
            attestation_submit: Duration::from_millis(100),
            ..OperationTimeouts::default()
        });
        let service =
            setup_service_with(mock, vec![key], &[], config, Some(backend as Arc<dyn Signer>))
                .await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_secs(60);

        service.maybe_produce_payload_attestations(0, 0, slot_end).await;

        let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
        assert!(
            elapsed <= Duration::from_millis(100),
            "drain must stop at the 100 ms submit cap, elapsed {elapsed:?}"
        );
        assert!(submitted.lock().unwrap().is_empty());
        assert_eq!(service.slot_end_drops(), 1, "pending duties are still counted");
        assert!(
            logs_contain(
                "undispatched payload attestation duties dropped by attestation_submit deadline"
            ),
            "the submit timeout fired and take_until did not stop the input"
        );
        assert!(
            !logs_contain("undispatched payload attestation duties dropped at slot end"),
            "slot end is still 60 s away"
        );
    }

    #[test]
    fn pending_drop_reason_follows_the_cut_not_the_armed_cap() {
        assert_eq!(
            pending_drop_reason(PtcDrainEvidence {
                take_until_stopped: true,
                drain_timed_out: false,
                timeout_was_overhang: false,
            }),
            PtcPendingDropReason::SlotEnd,
            "submit cap armed, drain finished early: backlog is slot end"
        );
        assert_eq!(
            pending_drop_reason(PtcDrainEvidence {
                take_until_stopped: false,
                drain_timed_out: true,
                timeout_was_overhang: false,
            }),
            PtcPendingDropReason::SubmitDeadline,
        );
        assert_eq!(
            pending_drop_reason(PtcDrainEvidence {
                take_until_stopped: false,
                drain_timed_out: true,
                timeout_was_overhang: true,
            }),
            PtcPendingDropReason::SlotEnd,
            "overhang timeout keeps the slot-end line"
        );
        assert_eq!(
            pending_drop_reason(PtcDrainEvidence {
                take_until_stopped: true,
                drain_timed_out: true,
                timeout_was_overhang: false,
            }),
            PtcPendingDropReason::SlotEnd,
            "take_until stopping the input wins over a later submit timeout"
        );
    }

    /// A publish started near `slot_end` is cut at `slot_end + 500 ms`.
    /// The `attestation_submit` timeout alone (2 s) would finish well into S+1.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn delayed_ptc_publish_stops_at_slot_end_overhang() {
        let key = test_key(10);
        let duty = ptc_duty(0, key.index, &key.pk);
        let data = ptc_data(0);
        let mock = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_ptc_duties({
                    let duty = duty.clone();
                    move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                })
                .with_get_payload_attestation_data({
                    let data = data.clone();
                    move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                })
                .with_submit_payload_attestations(|_| Ok(()))
                .with_method_delay(MockMethod::SubmitPayloadAttestations, Duration::from_secs(2)),
        );
        let config = create_test_config().with_timeouts(OperationTimeouts {
            attestation_submit: Duration::from_secs(2),
            ..OperationTimeouts::default()
        });
        let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
        let service = setup_service_with(beacon, vec![key], &[], config, None).await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_millis(50);

        service.maybe_produce_payload_attestations(0, 0, slot_end).await;

        let finished = tokio::time::Instant::now();
        let overhang_at = slot_end + Duration::from_millis(500);
        assert!(
            finished <= overhang_at,
            "drain ran until {finished:?}, past overhang {overhang_at:?}"
        );
        assert!(
            finished.saturating_duration_since(started) < Duration::from_secs(2),
            "the 2 s attestation_submit timeout must not extend the phase, elapsed {:?}",
            finished.saturating_duration_since(started)
        );
        let submits: Vec<_> = mock
            .call_stamps()
            .into_iter()
            .filter(|stamp| stamp.method == MockMethod::SubmitPayloadAttestations)
            .collect();
        assert!(!submits.is_empty(), "the publish starts, then the overhang budget stops it");
        assert!(
            submits.iter().all(|stamp| stamp.at <= overhang_at),
            "a publish must not be admitted after the overhang: {submits:?}"
        );
        assert!(
            mock.submit_payload_attestations_calls().is_empty(),
            "the 2 s POST must be cancelled before it completes"
        );
        assert_eq!(service.slot_end_drops(), 0, "the in-flight duty is dispatched");
    }

    /// Payload attestation stays non-slashable under concurrent signs: no
    /// attestation or block row, and each duty is posted once.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn concurrent_ptc_signs_write_no_slashing_rows_and_do_not_double_post() {
        const N: u64 = 4;
        let keys: Vec<TestKeys> = (0..N).map(test_key).collect();
        let pubkeys: Vec<[u8; 48]> = keys.iter().map(|key| key.pk.to_bytes()).collect();
        let duties = keys.iter().map(|key| ptc_duty(0, key.index, &key.pk)).collect();
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(N as u32, 2).expect("non-zero"));
        let service = setup_service_with(mock, keys, &[], config, None).await;
        for pubkey in &pubkeys {
            assert_eq!(slashing_rows(service.slashing_db(), pubkey), 0);
        }

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        for pubkey in &pubkeys {
            assert_eq!(
                slashing_rows(service.slashing_db(), pubkey),
                0,
                "concurrent PTC signs must not write a slashing row"
            );
        }
        let mut indices: Vec<u64> =
            submitted.lock().unwrap().iter().flat_map(|(_, batch)| batch.clone()).collect();
        let posted = indices.len();
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(posted, N as usize, "each duty is posted once");
        assert_eq!(indices, (0..N).collect::<Vec<_>>());
    }

    /// PTC signing does not take the slashing connection. Holding it must not
    /// stop the phase from publishing.
    #[test]
    fn ptc_publish_while_slashing_db_conn_is_held() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (service, submitted, db) = rt.block_on(async {
            let key = test_key(10);
            let duty = ptc_duty(0, key.index, &key.pk);
            let submitted = Arc::new(Mutex::new(0usize));
            let submitted_for_hook = Arc::clone(&submitted);
            let data = ptc_data(0);
            let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = duty.clone();
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data({
                        let data = data.clone();
                        move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                    })
                    .with_submit_payload_attestations(move |messages| {
                        *submitted_for_hook.lock().unwrap() += messages.len();
                        Ok(())
                    }),
            );
            let db = Arc::new(SlashingDb::open_in_memory().unwrap());
            let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
            store.add_validator(ValidatorConfig::new(key.pk.to_bytes())).unwrap();
            let mut key_manager = KeyManager::new();
            key_manager.insert(key.sk);
            let signer = Arc::new(
                SignerService::new(
                    Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                    Arc::clone(&db),
                )
                .with_enablement(always_enabled()),
            );
            let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["10".to_string()]));
            duty_tracker.fetch_ptc_duties(0, &["10".to_string()]).await.unwrap();
            let mut map = HashMap::new();
            map.insert(key.pk.to_bytes(), key.pk);
            let service = PayloadAttestationService::new(
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
                let slot_end = tokio::time::Instant::now() + Duration::from_secs(30);
                service.maybe_produce_payload_attestations(0, 0, slot_end).await;
                *submitted.lock().unwrap()
            });
            tx.send(published).expect("publish result");
        });

        let published = rx
            .recv_timeout(Duration::from_secs(15))
            .unwrap_or_else(|_| panic!("PTC phase blocked while the slashing connection was held"));
        assert!(published > 0, "PTC phase must publish while the slashing connection is held");
        worker.join().expect("PTC worker");
        drop(held);
    }

    fn slashing_rows(db: &SlashingDb, pubkey: &[u8; 48]) -> usize {
        let hex = hex::encode(pubkey);
        db.get_attestations(&hex).expect("attestations").len()
            + db.get_blocks(&hex).expect("blocks").len()
    }

    /// Publish deadline is the earlier of `attestation_submit` and overhang.
    /// A mutant that ignores `submit_at` would wait for the ample overhang.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ptc_publish_deadline_honors_attestation_submit() {
        let key = test_key(10);
        let duty = ptc_duty(0, key.index, &key.pk);
        let data = ptc_data(0);
        let mock = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_ptc_duties({
                    let duty = duty.clone();
                    move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                })
                .with_get_payload_attestation_data({
                    let data = data.clone();
                    move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                })
                .with_submit_payload_attestations(|_| Ok(()))
                .with_method_delay(MockMethod::SubmitPayloadAttestations, Duration::from_secs(2)),
        );
        let config = create_test_config().with_timeouts(OperationTimeouts {
            attestation_submit: Duration::from_millis(100),
            ..OperationTimeouts::default()
        });
        let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
        let service = setup_service_with(beacon, vec![key], &[], config, None).await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_secs(60);

        service.maybe_produce_payload_attestations(0, 0, slot_end).await;

        let finished = tokio::time::Instant::now();
        let elapsed = finished.saturating_duration_since(started);
        assert!(
            elapsed <= Duration::from_millis(100),
            "publish must stop at attestation_submit (100ms), elapsed {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "ignoring submit_at would wait for the 60s overhang, elapsed {elapsed:?}"
        );
        assert!(
            mock.submit_payload_attestations_calls().is_empty(),
            "the 2 s POST must be cancelled at the submit deadline"
        );
    }

    /// A wave that becomes ready exactly at `slot_end + 500 ms` is not admitted.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ptc_publish_refused_exactly_at_slot_end_overhang() {
        let key = test_key(10);
        let key_pk = key.pk.to_bytes();
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: {
                let mut delays = HashMap::new();
                delays.insert(key_pk, Duration::from_millis(550));
                delays
            },
            default_delay: Duration::ZERO,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::new(Mutex::new(Vec::new())),
        });
        let duties = vec![ptc_duty(0, key.index, &key.pk)];
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let service = setup_service_with(
            mock.clone(),
            vec![key],
            &[],
            create_test_config(),
            Some(backend as Arc<dyn Signer>),
        )
        .await;
        let started = tokio::time::Instant::now();
        let slot_end = started + Duration::from_millis(50);

        service.maybe_produce_payload_attestations(0, 0, slot_end).await;

        let overhang_at = slot_end + Duration::from_millis(500);
        assert_eq!(
            tokio::time::Instant::now(),
            overhang_at,
            "sign finishes exactly at the overhang boundary"
        );
        assert!(
            submitted.lock().unwrap().is_empty(),
            "publish at exactly slot_end+500ms must be refused"
        );
        assert!(mock.submit_payload_attestations_calls().is_empty());
    }

    /// `ready_chunks(concurrency)` posts exact wave sizes. Sign delays are
    /// staggered across waves (pairs share a delay) so a mutant that removes
    /// `ready_chunks` publishes one-by-one as each sign finishes and fails the
    /// exact `[2, 2, 2]` size assertion.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ptc_ready_chunks_respect_dispatch_concurrency() {
        const N: u64 = 6;
        const CONCURRENCY: u32 = 2;
        let keys: Vec<TestKeys> = (0..N).map(test_key).collect();
        let duties = keys.iter().map(|key| ptc_duty(0, key.index, &key.pk)).collect();
        // Within each ready_chunks wave the two in-flight signs share a delay so
        // they complete together; successive waves are staggered so removing the
        // chunk cap yields observable size-1 POSTs instead of coalesced pairs.
        let mut delays = HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            let wave = i / CONCURRENCY as usize;
            delays.insert(key.pk.to_bytes(), Duration::from_millis(20 * (wave as u64 + 1)));
        }
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays,
            default_delay: Duration::from_millis(20),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::new(Mutex::new(Vec::new())),
        });
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(CONCURRENCY, 1).expect("non-zero"));
        let service =
            setup_service_with(mock, keys, &[], config, Some(backend as Arc<dyn Signer>)).await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        let submits = submitted.lock().unwrap().clone();
        let sizes: Vec<usize> = submits.iter().map(|(_, batch)| batch.len()).collect();
        assert_eq!(
            sizes,
            vec![CONCURRENCY as usize; (N / u64::from(CONCURRENCY)) as usize],
            "ready_chunks({CONCURRENCY}) must post exact wave sizes, got {sizes:?}"
        );
        let posted: usize = sizes.iter().sum();
        assert_eq!(posted, N as usize);
    }

    /// Each distinct PTC duty is signed exactly once under concurrent dispatch.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn each_ptc_duty_is_signed_exactly_once() {
        const N: u64 = 5;
        let keys: Vec<TestKeys> = (0..N).map(test_key).collect();
        let pubkeys: Vec<[u8; 48]> = keys.iter().map(|key| key.pk.to_bytes()).collect();
        let duties = keys.iter().map(|key| ptc_duty(0, key.index, &key.pk)).collect();
        let finished = Arc::new(Mutex::new(Vec::new()));
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: HashMap::new(),
            default_delay: Duration::from_millis(10),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::clone(&finished),
        });
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let config = create_test_config()
            .with_dispatch_limits(DispatchLimits::validated(3, 2).expect("non-zero"));
        let service =
            setup_service_with(mock, keys, &[], config, Some(backend as Arc<dyn Signer>)).await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        let signed: Vec<[u8; 48]> = finished.lock().unwrap().iter().map(|(pk, _)| *pk).collect();
        assert_eq!(signed.len(), N as usize, "exactly one sign call per duty");
        let mut unique = signed.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), N as usize, "no pubkey is signed twice");
        for pk in &pubkeys {
            assert_eq!(
                signed.iter().filter(|signed_pk| *signed_pk == pk).count(),
                1,
                "pubkey {} must be signed exactly once",
                hex::encode(pk)
            );
        }
    }

    /// A stalled signer cannot hold the phase past the hard deadline.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stalled_ptc_signer_returns_by_phase_deadline() {
        super::ptc_counter_lock::with_held(async {
            let key = test_key(10);
            let backend = Arc::new(TrackingSigner {
                key: SecretKey::generate(),
                delays: HashMap::new(),
                default_delay: Duration::from_secs(30),
                in_flight: Arc::new(AtomicUsize::new(0)),
                max_in_flight: Arc::new(AtomicUsize::new(0)),
                fail: Vec::new(),
                finished: Arc::new(Mutex::new(Vec::new())),
            });
            let duties = vec![ptc_duty(0, key.index, &key.pk)];
            let submitted = Arc::new(Mutex::new(Vec::new()));
            let mock = ptc_beacon(duties, Arc::clone(&submitted));
            let config = create_test_config().with_timeouts(OperationTimeouts {
                attestation_submit: Duration::from_secs(2),
                ..OperationTimeouts::default()
            });
            let service = setup_service_with(
                mock,
                vec![key],
                &[],
                config,
                Some(backend as Arc<dyn Signer>),
            )
            .await;
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let started = tokio::time::Instant::now();
            let slot_end = started + Duration::from_millis(50);

            service.maybe_produce_payload_attestations(0, 0, slot_end).await;

            let finished = tokio::time::Instant::now();
            let deadline = slot_end + Duration::from_millis(500);
            assert!(
                finished <= deadline,
                "stalled signer must not hold past slot_end+500ms; finished={finished:?} deadline={deadline:?}"
            );
            assert!(
                finished.saturating_duration_since(started) < Duration::from_secs(2),
                "phase must also respect attestation_submit"
            );
            assert!(submitted.lock().unwrap().is_empty());
            assert_eq!(service.slot_end_drops(), 1);
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped + 1,
                "cancelled stall must count as dropped"
            );
        })
        .await;
    }

    /// Duplicate `(pubkey, slot)` rows from the BN are signed and posted once.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn duplicate_ptc_duties_from_bn_are_deduped() {
        let key = test_key(10);
        let key_pk = key.pk.to_bytes();
        let finished = Arc::new(Mutex::new(Vec::new()));
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: HashMap::new(),
            default_delay: Duration::ZERO,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::clone(&finished),
        });
        // Same pubkey+slot twice (distinct validator_index strings on the wire).
        let duties = vec![ptc_duty(0, 10, &key.pk), ptc_duty(0, 10, &key.pk)];
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let service = setup_service_with(
            mock,
            vec![key],
            &[],
            create_test_config(),
            Some(backend as Arc<dyn Signer>),
        )
        .await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        let signed = finished.lock().unwrap().clone();
        assert_eq!(signed.len(), 1, "duplicate BN duties must yield one sign");
        assert_eq!(signed[0].0, key_pk);
        let indices: Vec<u64> =
            submitted.lock().unwrap().iter().flat_map(|(_, batch)| batch.clone()).collect();
        assert_eq!(indices, vec![10], "duplicate BN duties must yield one pool submission");
    }

    /// Dedup keys on parsed pubkey bytes, not the raw BN string.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn duplicate_ptc_duties_with_mixed_case_and_0x_are_deduped() {
        let key = test_key(10);
        let key_pk = key.pk.to_bytes();
        let hex = hex::encode(key_pk);
        let finished = Arc::new(Mutex::new(Vec::new()));
        let backend = Arc::new(TrackingSigner {
            key: SecretKey::generate(),
            delays: HashMap::new(),
            default_delay: Duration::ZERO,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            fail: Vec::new(),
            finished: Arc::clone(&finished),
        });
        // Distinct validator_index values: a mutant that dedups on index
        // (instead of parsed pubkey bytes) would keep all three rows.
        let duties = vec![
            PtcDuty {
                pubkey: format!("0x{hex}"),
                validator_index: "10".to_string(),
                slot: "0".to_string(),
            },
            PtcDuty {
                pubkey: format!("0x{}", hex.to_uppercase()),
                validator_index: "11".to_string(),
                slot: "0".to_string(),
            },
            PtcDuty {
                pubkey: hex.clone(),
                validator_index: "12".to_string(),
                slot: "0".to_string(),
            },
        ];
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let mock = ptc_beacon(duties, Arc::clone(&submitted));
        let service = setup_service_with(
            mock,
            vec![key],
            &[],
            create_test_config(),
            Some(backend as Arc<dyn Signer>),
        )
        .await;

        service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

        let signed = finished.lock().unwrap().clone();
        assert_eq!(signed.len(), 1, "mixed-case / 0x variants must yield one sign");
        assert_eq!(signed[0].0, key_pk);
        let indices: Vec<u64> =
            submitted.lock().unwrap().iter().flat_map(|(_, batch)| batch.clone()).collect();
        assert_eq!(
            indices,
            vec![10],
            "first (pubkey_bytes, slot) wins; distinct validator_index must not defeat dedup"
        );
    }

    /// Payload attestation data for the wrong slot is rejected before signing.
    #[tokio::test]
    async fn ptc_rejects_payload_data_with_mismatched_slot() {
        super::ptc_counter_lock::with_held(async {
            let key = test_key(10);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &key.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data({
                        // Requested slot is 0; BN returns data for slot 7.
                        let data = ptc_data(7);
                        move |_slot| Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                    })
                    .with_submit_payload_attestations(|_| {
                        panic!("slot-mismatched payload data must not be submitted")
                    }),
            );
            let beacon: Arc<dyn BeaconNodeClient> = mock;
            let service = setup_service(beacon, vec![key], &[]).await;
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);

            service.maybe_produce_payload_attestations(0, 0, ample_slot_end()).await;

            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped + 1,
                "slot mismatch must increment rvc_ptc_duties_total{{outcome=dropped}}"
            );
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SCHEDULED), before_scheduled);
        })
        .await;
    }

    struct DelayedFailSigner {
        key: SecretKey,
        fail: [u8; 48],
        delay: Duration,
    }

    #[async_trait]
    impl Signer for DelayedFailSigner {
        async fn sign(
            &self,
            signing_root: &Root,
            pubkey: &[u8; 48],
        ) -> Result<crypto::Signature, SigningError> {
            tokio::time::sleep(self.delay).await;
            if *pubkey == self.fail {
                return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
            }
            Ok(self.key.sign(signing_root))
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            Vec::new()
        }
    }

    /// A signer error inside a wave whose POST is cut by the phase drain must
    /// not be double-counted, and the cut-off signed duty must count as failed.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn signer_error_and_cut_off_publish_count_each_duty_once() {
        super::ptc_counter_lock::with_held(async {
            let ok = test_key(10);
            let bad = test_key(11);
            let backend = Arc::new(DelayedFailSigner {
                key: SecretKey::generate(),
                fail: bad.pk.to_bytes(),
                delay: Duration::from_millis(100),
            });
            let duties = vec![ptc_duty(0, ok.index, &ok.pk), ptc_duty(0, bad.index, &bad.pk)];
            let data = ptc_data(0);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties(move |_e, _i| Ok(ptc_response(duties.clone())))
                    .with_get_payload_attestation_data(move |_s| {
                        Ok(Some(PayloadAttestationDataResponse { data: data.clone() }))
                    })
                    .with_submit_payload_attestations(|_| Ok(()))
                    .with_method_delay(
                        MockMethod::SubmitPayloadAttestations,
                        Duration::from_secs(5),
                    ),
            );
            let config = create_test_config()
                .with_dispatch_limits(DispatchLimits::validated(2, 1).expect("non-zero"))
                .with_timeouts(OperationTimeouts {
                    attestation_submit: Duration::from_secs(1),
                    ..OperationTimeouts::default()
                });
            let beacon: Arc<dyn BeaconNodeClient> = mock;
            let service = setup_service_with(
                beacon,
                vec![ok, bad],
                &[],
                config,
                Some(backend as Arc<dyn Signer>),
            )
            .await;
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let before_failed = ptc_attestation_count(attestation_status::FAILED);
            let before_success = ptc_attestation_count(attestation_status::SUCCESS);
            let slot_end = tokio::time::Instant::now() + Duration::from_secs(60);

            service.maybe_produce_payload_attestations(0, 0, slot_end).await;

            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED) - before_dropped,
                2,
                "exactly one dropped outcome per duty"
            );
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::SCHEDULED) - before_scheduled,
                1,
                "the successful sign is scheduled once"
            );
            assert_eq!(
                ptc_attestation_count(attestation_status::FAILED) - before_failed,
                1,
                "the cut-off POST counts as attestations failed"
            );
            assert_eq!(ptc_attestation_count(attestation_status::SUCCESS), before_success);
            assert_eq!(service.slot_end_drops(), 0, "both duties were pulled onto the pipeline");
        })
        .await;
    }

    /// Cold duty fetch is capped by the phase deadline and records no per-duty drop.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stalled_ptc_duty_fetch_returns_by_phase_deadline() {
        super::ptc_counter_lock::with_held(async {
            let key = test_key(10);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &key.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_method_delay(MockMethod::PostPtcDuties, Duration::from_secs(30))
                    .with_get_payload_attestation_data(|_slot| {
                        panic!("stalled duty fetch must not reach payload data")
                    })
                    .with_submit_payload_attestations(|_| {
                        panic!("stalled duty fetch must not submit")
                    }),
            );
            let config = create_test_config().with_timeouts(OperationTimeouts {
                attestation_submit: Duration::from_millis(200),
                ..OperationTimeouts::default()
            });
            let service = setup_service_cold_cache(mock, vec![key], config).await;
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let started = tokio::time::Instant::now();
            let slot_end = started + Duration::from_secs(60);

            service.maybe_produce_payload_attestations(0, 0, slot_end).await;

            let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
            assert!(
                elapsed <= Duration::from_millis(200),
                "duty fetch must stop at attestation_submit, elapsed {elapsed:?}"
            );
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped,
                "a failed duty fetch has no duty list to attribute"
            );
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SCHEDULED), before_scheduled);
            assert_eq!(service.slot_end_drops(), 0);
        })
        .await;
    }

    /// Payload-data fetch is capped by the phase deadline and counts matching duties dropped.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stalled_ptc_payload_data_fetch_returns_by_phase_deadline() {
        super::ptc_counter_lock::with_held(async {
            let key = test_key(10);
            let mock = Arc::new(
                MockBeaconNodeClient::new()
                    .with_post_ptc_duties({
                        let duty = ptc_duty(0, 10, &key.pk);
                        move |_epoch, _indices| Ok(ptc_response(vec![duty.clone()]))
                    })
                    .with_get_payload_attestation_data(|_slot| {
                        Ok(Some(PayloadAttestationDataResponse { data: ptc_data(0) }))
                    })
                    .with_method_delay(
                        MockMethod::GetPayloadAttestationData,
                        Duration::from_secs(30),
                    )
                    .with_submit_payload_attestations(|_| {
                        panic!("stalled payload-data fetch must not submit")
                    }),
            );
            let config = create_test_config().with_timeouts(OperationTimeouts {
                attestation_submit: Duration::from_millis(200),
                ..OperationTimeouts::default()
            });
            let beacon: Arc<dyn BeaconNodeClient> = mock;
            let service = setup_service_with(beacon, vec![key], &[], config, None).await;
            let before_dropped = ptc_duty_count(ptc_duty_outcome::DROPPED);
            let before_scheduled = ptc_duty_count(ptc_duty_outcome::SCHEDULED);
            let started = tokio::time::Instant::now();
            let slot_end = started + Duration::from_secs(60);

            service.maybe_produce_payload_attestations(0, 0, slot_end).await;

            let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
            assert!(
                elapsed <= Duration::from_millis(200),
                "payload-data fetch must stop at attestation_submit, elapsed {elapsed:?}"
            );
            assert_eq!(
                ptc_duty_count(ptc_duty_outcome::DROPPED),
                before_dropped + 1,
                "timed-out payload-data fetch drops the matching duties"
            );
            assert_eq!(ptc_duty_count(ptc_duty_outcome::SCHEDULED), before_scheduled);
        })
        .await;
    }
}
