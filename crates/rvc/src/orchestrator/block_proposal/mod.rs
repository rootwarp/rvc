//! Block-proposal phase methods for [`DutyOrchestrator`].
//!
//! # Relocation (RF6-28 / F121)
//!
//! These methods previously lived in `coordinator/mod.rs`. They remain an
//! inherent `impl DutyOrchestrator` block (second impl on the same type) so
//! this is a **pure move**: no new trait, no injected seam, no constructor or
//! field-type changes. Field visibility is `pub(crate)` only where a sibling
//! module must read them — the construction path is unchanged.
//!
//! # Future `BlockProposalService` (go/no-go)
//!
//! A full service extraction is **out of scope** here and would be a separate
//! issue. Sketch for that follow-up:
//!
//! | Would take (owned / `Arc` clones) | Seam to inject |
//! |----------------------------------|----------------|
//! | `BlockService<SignerService, B>` | already a service — move ownership out of orchestrator |
//! | `Arc<DutyTracker>` | proposer-duty lookup |
//! | `PubkeyMap` | resolve BN duty pubkey → local key |
//! | `Arc<ValidatorStore>` | D-3 doppelganger / `is_signing_enabled` |
//! | `Arc<CircuitBreakerState>` + metrics helper | builder miss/success accounting |
//! | `OrchestratorConfig` timeouts | produce+publish timeout envelope |
//!
//! Call site today is a single phase in the slot loop
//! (`maybe_propose_block(slot, epoch, &ctx)`). A service would expose that same
//! entry point; the orchestrator would hold `block_proposal: BlockProposalService`
//! instead of calling an inherent method. Do **not** introduce the service until
//! a second caller or a test-double seam justifies the plumbing cost.

use tracing::{error, info, warn};

use block_service::metrics::{proposal_outcome, RVC_PROPOSALS_TOTAL};
use block_service::BeaconBlockClient;
use bn_manager::AttestationSubmitter;
use eth_types::Slot;
use metrics::definitions::{
    RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL, RVC_BUILDER_CONSECUTIVE_MISSES,
    RVC_BUILDER_EPOCH_MISSES,
};
use timing::SlotClock;

use super::coordinator::DutyOrchestrator;
use super::slot_context::SlotContext;
use super::utils;

fn inc_proposal_outcome(outcome: &str) {
    #[cfg(test)]
    if !proposal_counter_lock::enabled() {
        return;
    }
    RVC_PROPOSALS_TOTAL.with_label_values(&[outcome]).inc();
}

/// Serializes proposal-outcome counter delta tests without blocking other callers.
#[cfg(test)]
mod proposal_counter_lock {
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

impl<C, S, B> DutyOrchestrator<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    pub(crate) fn update_circuit_breaker_metrics(&self) {
        RVC_BUILDER_CONSECUTIVE_MISSES.set(self.circuit_breaker.consecutive_misses() as i64);
        RVC_BUILDER_EPOCH_MISSES.set(self.circuit_breaker.epoch_misses() as i64);
    }

    #[tracing::instrument(name = "orchestrator.maybe_propose_block", level = "debug", skip_all, fields(slot = slot, epoch = epoch))]
    pub(crate) async fn maybe_propose_block(&self, slot: Slot, epoch: u64, ctx: &SlotContext) {
        let proposer_duty = match self.duty_tracker.get_proposer_duty(slot).await {
            Some(duty) => duty,
            None => return,
        };

        // Check if the proposer is one of our validators
        let pubkey = match utils::find_pubkey(&self.pubkey_map, &proposer_duty.pubkey) {
            Some(pk) => pk,
            None => return,
        };

        // D-3: per-validator doppelganger gate (mirrors attestation.rs M-12 check).
        // Skip block proposal for validators still inside the post-import
        // doppelganger window (`enabled = false`).
        {
            let pk_bytes = pubkey.to_bytes();
            if !self.validator_store.is_signing_enabled(&pk_bytes) {
                warn!(
                    slot,
                    pubkey = %observability::logging::TruncatedPubkey::new(&proposer_duty.pubkey),
                    "Skipping block proposal: validator is inside the \
                     post-import doppelganger window (D-3)"
                );
                return;
            }
        }

        // H-4: parse validator_index for proposer_index validation (returned as String by the BN type)
        let expected_proposer_index: u64 = match proposer_duty.validator_index.parse() {
            Ok(v) => v,
            Err(_) => {
                error!(slot, raw = %proposer_duty.validator_index,
                    "Cannot parse proposer duty validator_index as u64 — dropping duty");
                return;
            }
        };

        info!(slot, validator_index = %proposer_duty.validator_index, "Proposing block");

        // Wrap with combined produce + publish timeout
        match tokio::time::timeout(
            self.config.timeouts.block_production + self.config.timeouts.block_publication,
            self.block_service.propose_block(
                slot,
                &pubkey,
                expected_proposer_index,
                ctx.parent_root,
            ),
        )
        .await
        {
            Ok(Ok(result)) => {
                let was_tripped = self.circuit_breaker.is_tripped();
                self.circuit_breaker.record_success();
                self.update_circuit_breaker_metrics();
                if was_tripped && !self.circuit_breaker.is_tripped() {
                    info!(slot, "Builder circuit breaker reset after successful proposal");
                }
                inc_proposal_outcome(proposal_outcome::SUCCESS);
                info!(
                    slot,
                    blinded = result.is_blinded,
                    consensus_version = %result.consensus_version,
                    "Block proposed successfully"
                );
            }
            Ok(Err(e)) => {
                // H-3: only record a miss when the failure originated from the
                // builder path.  Signer errors, BN errors on the local-only
                // path (boost = 0), and validation failures must not trip the
                // builder circuit breaker.
                let is_builder_failure = matches!(
                    e,
                    block_service::BlockServiceError::BuilderFailure(_)
                        | block_service::BlockServiceError::BuilderOnly(_)
                );
                if is_builder_failure {
                    let was_tripped = self.circuit_breaker.is_tripped();
                    self.circuit_breaker.record_miss();
                    self.update_circuit_breaker_metrics();
                    if !was_tripped && self.circuit_breaker.is_tripped() {
                        RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL.inc();
                        warn!(slot, "Builder circuit breaker tripped");
                    }
                }
                inc_proposal_outcome(proposal_outcome::FAILED);
                error!(
                    slot,
                    epoch,
                    error = %e,
                    "Failed to propose block"
                );
            }
            Err(_) => {
                // Outer timeout: we cannot determine whether the builder relay
                // was involved.  Do not record a miss — a transient BN or
                // network slowdown that fires the outer timeout should not
                // disable MEV for a full epoch (H-3).
                inc_proposal_outcome(proposal_outcome::FAILED);
                error!(
                    slot,
                    epoch,
                    "Block proposal timed out after {}s",
                    (self.config.timeouts.block_production
                        + self.config.timeouts.block_publication)
                        .as_secs()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
