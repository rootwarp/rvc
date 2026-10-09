//! Main duty orchestrator implementation.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, field, info, info_span, warn, Instrument};

use async_trait::async_trait;
use block_service::{BeaconBlockClient, BlockService, BuilderConfig, BuilderConfigProvider};
use bn_manager::{AttestationSubmitter, BeaconNodeClient, OperationTimeouts, Propagator};
use builder::{legacy_proposer_ops_retired, BuilderService, UpcomingProposal};
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{ForkName, ForkSchedule, Root, Slot};
use metrics::definitions::{
    slot_phase_cache, slot_phase_late, slot_phase_offset, RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS,
    RVC_SLOT_PHASE_LATE_TOTAL, RVC_SLOT_PHASE_OFFSET_MS, RVC_SLOT_REPLAY_SKIPPED_TOTAL,
};

use crate::metrics::{
    attestation_status, pre_proposal_cold_fetch, RVC_ATTESTATIONS_TOTAL, RVC_FORK_CURRENT_ID,
    RVC_FORK_NEXT_ACTIVATION_EPOCH, RVC_PRE_PROPOSAL_COLD_FETCH_DURATION_SECONDS,
    RVC_PRE_PROPOSAL_COLD_FETCH_TOTAL,
};
use signer::{CircuitBreakerState, SignerService, ValidatorSigner};
use timing::{due_ms, DeadlineBps, DeadlineSchedule, SlotClock, SLOTS_PER_EPOCH};

use super::aggregation::AggregationService;
use super::attestation::AttestationService;
use super::dispatch::DispatchLimits;
use super::duty_management::DutyManagementService;
use super::error::OrchestratorError;
use super::head_events::HeadEventGate;
use super::payload_attestation::PayloadAttestationService;
use super::slot_anchor::SlotAnchor;
use super::slot_context::SlotContext;
use super::sync_committee::SyncCommitteeService;
use super::utils::{self, TimedOutcome};
use crate::pubkey_index::SharedPubkeyIndexRegistry;

/// Shared, dynamically-updatable public key map.
///
/// Keyed by compressed BLS pubkey bytes (`[u8; 48]`) so hot-path lookups are
/// O(1) without hex normalization. Wrapped in `Arc<RwLock>` so the keymanager
/// API can insert/remove keys at runtime while the orchestrator reads them
/// each slot.
pub type PubkeyMap = Arc<parking_lot::RwLock<HashMap<[u8; 48], PublicKey>>>;

/// Aggregate pre-proposal budget (A-5 warm default): parent-root capture
/// including the ARCH-3d walk-back. Cold-cache duty fetch (ARCH-3j) shares
/// this envelope.
pub const DEFAULT_PRE_PROPOSAL_DEADLINE: Duration = Duration::from_millis(1000);

/// Hard cap for a proposer-only fetch when the duty cache is cold (A-5 / C6).
pub const COLD_PROPOSER_FETCH_DEADLINE: Duration = Duration::from_millis(500);

/// Configuration for the duty orchestrator.
#[derive(Clone)]
pub struct OrchestratorConfig {
    pub genesis_validators_root: Root,
    pub fork_schedule: Arc<ForkSchedule>,
    pub shutdown_timeout: Duration,
    pub timeouts: OperationTimeouts,
    /// Single timeout around pre-proposal capture (not per-request).
    pub pre_proposal_deadline: Duration,
    /// Proposer-only fetch deadline when the epoch cache is cold (ARCH-3j).
    pub cold_proposer_fetch_deadline: Duration,
    /// Pre-Gloas and Gloas deadline sets. Selected once per slot via
    /// [`ForkName::from_epoch`]; wait sites consume the resolved [`DeadlineBps`].
    pub deadline_schedule: DeadlineSchedule,
    /// Sign-request and publish-wave concurrency for attestation, sync messages,
    /// and aggregates.
    pub dispatch_limits: DispatchLimits,
}

impl OrchestratorConfig {
    pub fn new(genesis_validators_root: Root, fork_schedule: Arc<ForkSchedule>) -> Self {
        Self {
            genesis_validators_root,
            fork_schedule,
            shutdown_timeout: Duration::from_secs(30),
            timeouts: OperationTimeouts::default(),
            pre_proposal_deadline: DEFAULT_PRE_PROPOSAL_DEADLINE,
            cold_proposer_fetch_deadline: COLD_PROPOSER_FETCH_DEADLINE,
            deadline_schedule: DeadlineSchedule {
                pre_gloas: DeadlineBps::default(),
                // All six Gloas members required: serde defaults fill omitted TOML
                // keys, so "missing" is a compile error here, not a startup error.
                gloas: DeadlineBps {
                    attestation: 2500,
                    aggregate: 5000,
                    sync_message: 2500,
                    contribution: 5000,
                    payload: 5000,
                    payload_attestation: 7500,
                },
            },
            dispatch_limits: DispatchLimits::validated(
                DispatchLimits::DEFAULT_CONCURRENCY,
                DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY,
            )
            .expect("default dispatch limits are non-zero"),
        }
    }

    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    pub fn with_timeouts(mut self, timeouts: OperationTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub fn with_pre_proposal_deadline(mut self, deadline: Duration) -> Self {
        self.pre_proposal_deadline = deadline;
        self
    }

    pub fn with_cold_proposer_fetch_deadline(mut self, deadline: Duration) -> Self {
        self.cold_proposer_fetch_deadline = deadline;
        self
    }

    pub fn with_attestation_due_bps(mut self, bps: u64) -> Self {
        self.deadline_schedule.pre_gloas.attestation = bps;
        self
    }

    pub fn with_aggregate_due_bps(mut self, bps: u64) -> Self {
        self.deadline_schedule.pre_gloas.aggregate = bps;
        self
    }

    pub fn with_deadline_schedule(mut self, schedule: DeadlineSchedule) -> Self {
        self.deadline_schedule = schedule;
        self
    }

    /// Replace the attestation, sync-message, and aggregate sign/publish concurrency.
    ///
    /// Callers pass [`DispatchLimits::validated`]. A zero is rejected there
    /// because `ready_chunks(0)` panics.
    pub fn with_dispatch_limits(mut self, limits: DispatchLimits) -> Self {
        self.dispatch_limits = limits;
        self
    }

    /// Attestation deadline offset (ms from slot start) for `slot`.
    ///
    /// Same path the coordinator slot loop uses: `ForkName::from_epoch` then
    /// [`DeadlineSchedule::for_fork`] (`>= Gloas` inherits the Gloas set) then
    /// [`due_ms`] — the `phase_deadline` offset. Callers pass the already-resolved
    /// `slot_duration_ms` (P1 1.2/1.3 / BN spec). Issue 6.14's bench and D9 test
    /// share this helper so a TOML-only Gloas bps change moves the reported
    /// deadline with no rebuild.
    pub fn attestation_deadline_ms(&self, slot: Slot, slot_duration_ms: u64) -> u64 {
        let epoch = slot / SLOTS_PER_EPOCH;
        let fork = ForkName::from_epoch(epoch, &self.fork_schedule);
        due_ms(self.deadline_schedule.for_fork(fork).attestation, slot_duration_ms)
    }
}

/// Handle for controlling the orchestrator.
pub struct OrchestratorHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl OrchestratorHandle {
    /// Signals the orchestrator to shut down gracefully.
    ///
    /// The orchestrator will complete processing of the current slot (if any)
    /// before stopping. The signal is delivered via a watch channel, ensuring
    /// the orchestrator receives it even if waiting for the next slot.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Result of processing a single attestation duty.
///
/// [`AttestationOutcome`] is the only status. A published attestation cannot
/// also carry a failure message: the old `success` / `error` pair is gone.
#[derive(Debug)]
pub struct AttestationResult {
    /// Validator index from the attester duty.
    pub validator_index: String,
    /// Slot the duty was processed for.
    pub slot: Slot,
    /// How the duty finished.
    pub outcome: AttestationOutcome,
}

/// How one attestation duty finished.
#[derive(Debug)]
pub enum AttestationOutcome {
    /// The signed attestation was accepted by the beacon node.
    Published,
    /// The duty failed before a beacon-node rejection report.
    ///
    /// The string is the operator-visible reason (sign, fetch, timeout, or
    /// propagate).
    Failed(String),
    /// A beacon node rejected this index in a submit response.
    ///
    /// `bn` is the reporting endpoint from `PropagationOutcome::reported_by`.
    /// It is `None` when that outcome names no endpoint. An empty string is
    /// not stored.
    RejectedByBeaconNode {
        /// Reporting beacon-node endpoint, when the propagator named one.
        bn: Option<String>,
        /// Rejection message from that beacon node.
        message: String,
    },
}

impl AttestationOutcome {
    /// Whether this duty was published.
    ///
    /// [`Self::Failed`] and [`Self::RejectedByBeaconNode`] are not published.
    pub fn is_published(&self) -> bool {
        match self {
            Self::Published => true,
            Self::Failed(_message) => false,
            Self::RejectedByBeaconNode { bn: _bn, message: _message } => false,
        }
    }
}

/// Timeout for builder registration API calls.
const BUILDER_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of a timed wait that can be interrupted by shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitOutcome {
    /// The wait completed (or was zero-length); continue the slot loop.
    Continue,
    /// Shutdown was requested; the caller must exit `run()`.
    Shutdown,
}

/// Phase deadline relative to a slot: offset from slot start, remaining wait,
/// and how far past the deadline we already are.
#[derive(Debug, Clone, Copy)]
struct PhaseDeadline {
    /// Duration from slot start to this phase (bps → ms of slot duration).
    offset: Duration,
    /// Time remaining until the deadline (`ZERO` if already at/past it).
    remaining: Duration,
    /// How far past the deadline we are in ms (`0` if not past).
    overrun_ms: u64,
}

/// Dependencies required to construct a [`DutyOrchestrator`].
///
/// Bundling construction args into a single struct makes omissions (notably
/// `key_gen_rx` and `attesting_enabled`) a compile error rather than a silent
/// runtime defect. There is exactly one constructor: [`DutyOrchestrator::new`].
pub struct OrchestratorDeps<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    pub clock: Arc<C>,
    pub duty_tracker: Arc<DutyTracker>,
    pub signer: Arc<SignerService>,
    pub propagator: Arc<Propagator<S>>,
    pub beacon: Arc<dyn BeaconNodeClient>,
    pub block_beacon: Arc<B>,
    pub builder_service: Option<Arc<BuilderService>>,
    pub validator_store: Arc<validator_store::ValidatorStore>,
    pub config: OrchestratorConfig,
    pub pubkey_map: PubkeyMap,
    /// Shared pubkey → validator-index registry (O(1) prepare_proposers lookups).
    pub pubkey_index: SharedPubkeyIndexRegistry,
    /// Receiver half of the key-generation watch channel shared with keymanager
    /// adapters. When the generation increments, the duty cache is cleared so
    /// newly imported keys participate in duty matching without a restart.
    /// Always supplied by the caller — never fabricated inside the constructor.
    pub key_gen_rx: watch::Receiver<u64>,
    pub circuit_breaker: Arc<CircuitBreakerState>,
    /// Global attesting gate. When false, attestation duties are skipped.
    /// Independent of sync-committee processing (`sync_enabled`, H-7).
    pub attesting_enabled: Arc<AtomicBool>,
    /// Phase-2 wait seam (ARCH-3l timer-only; ARCH-3m races the head event).
    pub head_gate: HeadEventGate,
}

impl<C, S, B> OrchestratorDeps<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    /// Test helper with defaults for fields that most unit tests do not vary.
    ///
    /// Defaults:
    /// - `key_gen_rx`: a discarded channel (not paired with any adapter)
    /// - `circuit_breaker`: `CircuitBreakerState::new(0, 0)`
    /// - `attesting_enabled`: `true`
    ///
    /// Override via struct-update syntax when a test needs a real
    /// `key_gen_rx`, a shared circuit breaker, or a custom attesting flag.
    /// Production code must construct [`OrchestratorDeps`] explicitly with the
    /// real receiver from the channel shared with keymanager adapters.
    #[allow(clippy::too_many_arguments)]
    pub fn for_test(
        clock: Arc<C>,
        duty_tracker: Arc<DutyTracker>,
        signer: Arc<SignerService>,
        propagator: Arc<Propagator<S>>,
        beacon: Arc<dyn BeaconNodeClient>,
        block_beacon: Arc<B>,
        builder_service: Option<Arc<BuilderService>>,
        validator_store: Arc<validator_store::ValidatorStore>,
        config: OrchestratorConfig,
        pubkey_map: PubkeyMap,
    ) -> Self {
        let (_key_gen_tx, key_gen_rx) = watch::channel(0u64);
        let (_bridge, head_gate) = HeadEventGate::pair();
        Self {
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            block_beacon,
            builder_service,
            validator_store,
            config,
            pubkey_map,
            pubkey_index: crate::pubkey_index::PubkeyIndexRegistry::shared(),
            key_gen_rx,
            circuit_breaker: Arc::new(CircuitBreakerState::new(0, 0)),
            attesting_enabled: Arc::new(AtomicBool::new(true)),
            head_gate,
        }
    }
}

/// Main orchestrator for coordinating validator duties.
///
/// Fields used by sibling `impl` blocks (e.g. [`crate::orchestrator::block_proposal`])
/// are `pub(crate)` so methods can live outside this module without a service seam.
pub struct DutyOrchestrator<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    pub(crate) clock: Arc<C>,
    pub(crate) beacon: Arc<dyn BeaconNodeClient>,
    pub(crate) duty_tracker: Arc<DutyTracker>,
    pub(crate) block_service: BlockService<SignerService, B>,
    pub(crate) builder_service: Option<Arc<BuilderService>>,
    pub(crate) circuit_breaker: Arc<CircuitBreakerState>,
    pub(crate) config: OrchestratorConfig,
    pub(crate) pubkey_map: PubkeyMap,
    /// Shared with duty management / bootstrap (held for future sibling readers).
    #[allow(dead_code)]
    pub(crate) pubkey_index: SharedPubkeyIndexRegistry,
    pub(crate) attestation_service: AttestationService<C, S>,
    pub(crate) aggregation_service: AggregationService,
    pub(crate) sync_committee_service: SyncCommitteeService,
    pub(crate) payload_attestation_service: PayloadAttestationService,
    pub(crate) duty_management: DutyManagementService,
    pub(crate) key_gen_rx: watch::Receiver<u64>,
    pub(crate) shutdown_rx: watch::Receiver<bool>,
    pub(crate) attesting_enabled: Arc<AtomicBool>,
    /// Controls whether sync-committee duties are processed independently of
    /// `attesting_enabled`. Defaults to `true`; can be toggled at runtime via
    /// [`set_sync_enabled`]. Internal-only — not wired to any Keymanager API (H-7).
    pub(crate) sync_enabled: Arc<AtomicBool>,
    /// D-3: per-validator doppelganger gate for block proposals.
    /// Shared reference to the ValidatorStore for `is_signing_enabled` checks.
    pub(crate) validator_store: Arc<validator_store::ValidatorStore>,
    /// Next slot's phase-0 offset is labelled `cache=cold` when true (post-boot
    /// or post-key_gen invalidation). Cleared after the offset is recorded.
    phase_block_cache_cold: bool,
    /// Phase-2 wait: timer-only until ARCH-3m races the SSE head event.
    head_gate: HeadEventGate,
    /// Last fork recorded for the slot loop; a boundary log fires on change.
    last_resolved_fork: Option<ForkName>,
    /// `fork` label currently attached to `rvc_fork_next_activation_epoch`.
    next_activation_fork: Option<ForkName>,
}

impl<C, S, B> DutyOrchestrator<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    /// Creates a new DutyOrchestrator from the given dependencies.
    ///
    /// The sole constructor. Callers must supply a real `key_gen_rx` (production)
    /// or use [`OrchestratorDeps::for_test`] (unit tests that do not exercise
    /// key-import notifications).
    pub fn new(deps: OrchestratorDeps<C, S, B>) -> (Self, OrchestratorHandle) {
        let OrchestratorDeps {
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            block_beacon,
            builder_service,
            validator_store,
            config,
            pubkey_map,
            pubkey_index,
            key_gen_rx,
            circuit_breaker,
            attesting_enabled,
            head_gate,
        } = deps;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let mut block_service = BlockService::with_circuit_breaker(
            signer.clone(),
            block_beacon,
            validator_store.clone(),
            config.fork_schedule.clone(),
            config.genesis_validators_root,
            circuit_breaker.clone(),
        )
        .with_deadline_schedule(config.deadline_schedule);
        if let Some(ref builder) = builder_service {
            block_service = block_service
                .with_builder_config_provider(Arc::new(BuilderConfigAdapter(builder.clone())));
        }

        let aggregation_signer: Arc<dyn ValidatorSigner> = signer.clone();
        let aggregation_service = AggregationService::new(
            aggregation_signer,
            beacon.clone(),
            duty_tracker.clone(),
            pubkey_map.clone(),
            config.clone(),
            validator_store.clone(),
        );

        let sync_committee_service = SyncCommitteeService::new(
            signer.clone(),
            beacon.clone(),
            duty_tracker.clone(),
            pubkey_map.clone(),
            config.clone(),
            validator_store.clone(),
        );

        let payload_attestation_service = PayloadAttestationService::new(
            signer.clone(),
            beacon.clone(),
            duty_tracker.clone(),
            pubkey_map.clone(),
            config.clone(),
            validator_store.clone(),
        );

        let attestation_service = AttestationService::new(
            clock.clone(),
            signer.clone(),
            propagator.clone(),
            beacon.clone(),
            duty_tracker.clone(),
            pubkey_map.clone(),
            config.clone(),
            validator_store.clone(),
        );

        let duty_management = DutyManagementService::new(
            signer,
            beacon.clone(),
            duty_tracker.clone(),
            validator_store.clone(),
            pubkey_map.clone(),
            pubkey_index.clone(),
            config.clone(),
        );

        let sync_enabled = Arc::new(AtomicBool::new(true));

        let orchestrator = Self {
            clock,
            beacon,
            duty_tracker,
            block_service,
            builder_service,
            circuit_breaker,
            config,
            pubkey_map,
            pubkey_index,
            attestation_service,
            aggregation_service,
            sync_committee_service,
            payload_attestation_service,
            duty_management,
            key_gen_rx,
            shutdown_rx,
            attesting_enabled,
            sync_enabled,
            validator_store,
            phase_block_cache_cold: true,
            head_gate,
            last_resolved_fork: None,
            next_activation_fork: None,
        };

        let handle = OrchestratorHandle { shutdown_tx };

        (orchestrator, handle)
    }

    /// Runs the orchestrator main loop with four-phase slot processing:
    /// - t=0: bounded parent capture + block proposal
    /// - attestation due: attestations and sync messages concurrently
    ///   (HeadEventGate wait; sync has its own span)
    /// - aggregate due: sync committee contributions + aggregations
    /// - payload attestation due (Gloas+): payload attestations
    /// - post-duty: epoch duty fetches, epoch-boundary prep, builder registration
    pub async fn run(&mut self) -> Result<(), OrchestratorError> {
        info!("Starting duty orchestrator");

        // Defence-in-depth behind the wall-based inter-slot wait. A backward
        // clock step must not re-run a slot whose phases already finished.
        let mut last_processed_slot: Option<Slot> = None;

        loop {
            if *self.shutdown_rx.borrow() {
                info!("Shutdown signal received, stopping orchestrator");
                return Ok(());
            }

            let current_slot = match self.clock.current_slot() {
                Ok(slot) => slot,
                Err(e) => {
                    warn!(error = %e, "Failed to get current slot, waiting...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if let Some(last) = last_processed_slot {
                if current_slot <= last {
                    warn!(
                        current_slot,
                        last_processed_slot = last,
                        "skipping slot replay; clock is at or behind the last processed slot"
                    );
                    RVC_SLOT_REPLAY_SKIPPED_TOTAL.inc();
                    // Re-enter the wall-based wait. A bare `continue` spins
                    // while the clock stays behind.
                    let next_slot = last + 1;
                    let time_until_next_slot = self.clock.time_until_slot(next_slot)?;
                    if matches!(
                        self.run_post_duty_window(
                            time_until_next_slot,
                            std::future::pending::<()>(),
                        )
                        .await,
                        WaitOutcome::Shutdown
                    ) {
                        return Ok(());
                    }
                    continue;
                }
            }

            let current_epoch = current_slot / SLOTS_PER_EPOCH;
            // One resolved fork per slot; wait sites consume `deadlines`, not
            // `from_epoch` or a BN response shape.
            let fork = ForkName::from_epoch(current_epoch, &self.config.fork_schedule);
            self.record_fork_resolution(current_epoch, fork);
            let deadlines = self.config.deadline_schedule.for_fork(fork);

            let slot_span = info_span!("slot.process", slot = current_slot, epoch = current_epoch,);
            // One wall-clock read per slot, taken before the pre-proposal timeout.
            // Phase deadlines and offset stamps are absolute from this anchor.
            let anchor = SlotAnchor::capture(&*self.clock, current_slot);

            // Check if keys changed (dynamic key import/delete via keymanager API).
            // has_changed() does NOT mark the value as seen — mark_unchanged() so
            // subsequent slots do not clear forever after a single notify (S1).
            self.apply_key_gen_cache_invalidation().await;

            // === Phase 1: t=0 — Block proposal ===
            // Parent from slot-1 at t=0, bounded by the aggregate pre-proposal
            // deadline (covers the 3d walk-back and the 3j cold-cache fetch).
            // Head is captured at phase 2 and reused at phase 3 (H-5).
            let ctx = match tokio::time::timeout(self.config.pre_proposal_deadline, async {
                self.maybe_cold_fetch_proposer_duties(current_slot, current_epoch).await;
                SlotContext::capture_parent(&*self.beacon, current_slot, current_epoch).await
            })
            .await
            {
                Ok(ctx) => ctx,
                Err(_) => {
                    warn!(
                        slot = current_slot,
                        deadline_ms = self.config.pre_proposal_deadline.as_millis() as u64,
                        "Pre-proposal parent capture timed out"
                    );
                    SlotContext {
                        slot: current_slot,
                        epoch: current_epoch,
                        parent_root: None,
                        head_root: None,
                    }
                }
            };
            {
                // M2: offset from slot start to entry of maybe_propose_block.
                self.record_phase_block_start_offset(&anchor);
                let phase_span = info_span!(
                    parent: &slot_span,
                    "slot.phase.block",
                    time_into_slot = field::Empty,
                );
                // Block fires at t=0: no bps wait, stamp at entry.
                Self::record_time_into_slot(&phase_span, &anchor);
                Self::record_phase_offset(slot_phase_offset::BLOCK, &anchor);
                self.maybe_propose_block(ctx.slot, ctx.epoch, &ctx).instrument(phase_span).await;
            }

            if self.check_shutdown() {
                return Ok(());
            }

            // Duty waits are absolute offsets from slot start, so they run
            // concurrently after proposal. Sequencing stacked full waits on a
            // frozen MockSlotClock would fire aggregates at att+agg instead of
            // agg, and wall-clock production already uses remaining time.
            let ctx = tokio::sync::Mutex::new(ctx);
            let att_phase_span = info_span!(
                parent: &slot_span,
                "slot.phase.attestation",
                time_into_slot = field::Empty,
            );
            let sync_phase_span = info_span!(
                parent: &slot_span,
                "slot.phase.sync_message",
                time_into_slot = field::Empty,
            );
            let agg_phase_span = info_span!(
                parent: &slot_span,
                "slot.phase.aggregation",
                time_into_slot = field::Empty,
            );
            let ptc_phase_span = info_span!(
                parent: &slot_span,
                "slot.phase.payload_attestation",
                time_into_slot = field::Empty,
            );
            let (att_outcome, agg_outcome, ptc_outcome) = tokio::join!(
                self.run_attestation_and_sync_phases(
                    current_slot,
                    current_epoch,
                    &ctx,
                    deadlines,
                    att_phase_span,
                    sync_phase_span,
                    &anchor,
                ),
                self.run_aggregation_and_contribution_phases(
                    current_slot,
                    current_epoch,
                    &ctx,
                    deadlines,
                    agg_phase_span,
                    &anchor,
                ),
                self.run_payload_attestation_phase(
                    current_slot,
                    current_epoch,
                    fork,
                    deadlines,
                    ptc_phase_span,
                    &anchor,
                ),
            );
            if matches!(att_outcome, WaitOutcome::Shutdown)
                || matches!(agg_outcome, WaitOutcome::Shutdown)
                || matches!(ptc_outcome, WaitOutcome::Shutdown)
            {
                return Ok(());
            }

            last_processed_slot = Some(current_slot);

            // === Post-duty: host work in the next-slot wait ===
            // Occupants race the wait via `run_post_duty_window`. Incomplete
            // work is abandoned when the next slot arrives. The future stays
            // pending after occupants so a warm-cache fetch cannot skip the
            // remainder of the slot.
            let next_slot = current_slot + 1;
            // Inter-slot wait stays wall-based. Architecture §10.11: a backward slew
            // on a monotonic next-slot wait would re-process slot S.
            let time_until_next_slot = self.clock.time_until_slot(next_slot)?;
            let should_register = current_slot % SLOTS_PER_EPOCH == 0;
            let post_duty_work = async {
                self.duty_management
                    .fetch_epoch_duties(current_epoch)
                    .instrument(slot_span.clone())
                    .await;
                self.duty_management
                    .fetch_epoch_duties(current_epoch + 1)
                    .instrument(slot_span.clone())
                    .await;

                if should_register {
                    self.circuit_breaker.reset_epoch(current_epoch);
                    self.update_circuit_breaker_metrics();
                    info!(epoch = current_epoch, "Circuit breaker reset at epoch boundary");

                    let epoch_span =
                        info_span!(parent: &slot_span, "epoch.boundary", epoch = current_epoch);
                    let proposer_root_changed = self
                        .duty_management
                        .on_epoch_boundary(current_epoch, current_slot)
                        .instrument(epoch_span)
                        .await;
                    if proposer_root_changed {
                        self.on_proposer_dependent_root_changed(current_epoch).await;
                    }

                    if self.builder_service.is_some() {
                        let jitter = Duration::from_secs(BuilderService::jitter_seconds());
                        debug!(
                            jitter_secs = jitter.as_secs(),
                            "Delaying builder epoch-boundary work with jitter"
                        );
                        tokio::time::sleep(jitter).await;
                        match tokio::time::timeout(
                            BUILDER_REGISTRATION_TIMEOUT,
                            self.run_builder_epoch_boundary(current_epoch),
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(_) => warn!(
                                "Builder epoch-boundary work timed out after {}s (non-fatal)",
                                BUILDER_REGISTRATION_TIMEOUT.as_secs()
                            ),
                        }
                    }
                }

                // Why: fetches return immediately on a warm cache. Completing
                // this future would take the ready work arm and busy-spin.
                std::future::pending::<()>().await;
            };

            if matches!(
                self.run_post_duty_window(time_until_next_slot, post_duty_work).await,
                WaitOutcome::Shutdown
            ) {
                return Ok(());
            }
        }
    }

    /// Legacy register (pre-Gloas) and preferences for Gloas+ proposal slots.
    ///
    /// Both may run at Gloas-1: register is still live, and next-epoch Gloas
    /// slots are advertised one epoch early.
    pub(crate) async fn run_builder_epoch_boundary(&self, current_epoch: u64) {
        let Some(bs) = &self.builder_service else {
            return;
        };
        let current_fork = ForkName::from_epoch(current_epoch, &self.config.fork_schedule);
        if !legacy_proposer_ops_retired(current_fork) {
            match bs.register_validators(current_epoch).await {
                Ok(_) => info!("Builder registration completed"),
                Err(e) => warn!(error = %e, "Builder registration failed (non-fatal)"),
            }
        }
        self.broadcast_preferences(current_epoch).await;
    }

    /// Re-broadcast preferences after a proposer `dependent_root` change.
    ///
    /// Call when [`DutyTracker::cache_proposer_duties`] returns `true`.
    pub(crate) async fn on_proposer_dependent_root_changed(&self, current_epoch: u64) {
        self.broadcast_preferences(current_epoch).await;
    }

    async fn broadcast_preferences(&self, current_epoch: u64) {
        let Some(bs) = &self.builder_service else {
            return;
        };
        let proposals = self.upcoming_proposals(current_epoch).await;
        match bs
            .broadcast_proposer_preferences(
                current_epoch,
                &proposals,
                &self.config.genesis_validators_root,
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

    /// Bounded proposer-only fetch when the current epoch cache is empty.
    ///
    /// Coldness is `!is_proposer_epoch_cached` — not a boot flag — so a
    /// `key_gen` invalidation takes the same path. Timeout proceeds to the
    /// proposal decision with whatever was learned.
    async fn maybe_cold_fetch_proposer_duties(&self, slot: Slot, epoch: u64) {
        if self.duty_tracker.is_proposer_epoch_cached(epoch).await {
            return;
        }
        let deadline =
            self.config.cold_proposer_fetch_deadline.min(self.config.pre_proposal_deadline);
        let started = std::time::Instant::now();
        let outcome = self.duty_management.fetch_proposer_duties_only(epoch, deadline).await;
        let elapsed_secs = started.elapsed().as_secs_f64();
        let label = match &outcome {
            TimedOutcome::Timeout => pre_proposal_cold_fetch::TIMEOUT,
            TimedOutcome::Err(_) => pre_proposal_cold_fetch::MISS,
            TimedOutcome::Ok(_) => {
                if self.duty_tracker.get_proposer_duty(slot).await.is_some() {
                    pre_proposal_cold_fetch::HIT
                } else {
                    pre_proposal_cold_fetch::MISS
                }
            }
        };
        RVC_PRE_PROPOSAL_COLD_FETCH_TOTAL.with_label_values(&[label]).inc();
        RVC_PRE_PROPOSAL_COLD_FETCH_DURATION_SECONDS
            .with_label_values(&[label])
            .observe(elapsed_secs);
        match outcome {
            TimedOutcome::Timeout => {
                warn!(
                    slot,
                    epoch,
                    deadline_ms = deadline.as_millis() as u64,
                    "Pre-proposal cold-cache proposer fetch timed out"
                );
            }
            TimedOutcome::Err(e) => {
                warn!(slot, epoch, error = %e, "Pre-proposal cold-cache proposer fetch failed");
            }
            TimedOutcome::Ok(_) => {
                info!(slot, epoch, outcome = label, "Pre-proposal cold-cache proposer fetch");
            }
        }
    }

    /// Clears attester/proposer duty caches when keymanager has notified a key
    /// set change. Marks the watch generation as seen so a single notification
    /// produces exactly one clear; further slots do not re-clear until another
    /// `key_gen_tx` send.
    ///
    /// Note: `watch::Receiver::has_changed` does **not** mark the value as seen
    /// (tokio 1.x). Without `mark_unchanged` / `borrow_and_update`, the first
    /// import/delete would thrash duty caches every subsequent slot.
    async fn apply_key_gen_cache_invalidation(&mut self) {
        if self.key_gen_rx.has_changed().unwrap_or(false) {
            self.key_gen_rx.mark_unchanged();
            info!("Key set changed, clearing duty cache to trigger refetch");
            self.duty_tracker.clear_cache().await;
            // Cold-cache phase-0 offset on the slot that sees the invalidation.
            self.phase_block_cache_cold = true;
        }
    }

    /// Records `rvc_slot_phase_block_start_offset_ms` immediately before
    /// `maybe_propose_block` (M2 instrument). The sample is
    /// [`SlotAnchor::elapsed_ms`], the true offset into the slot. Labels
    /// `cache=cold` for post-boot and post-key_gen slots, then clears the
    /// cold flag for subsequent slots.
    fn record_phase_block_start_offset(&mut self, anchor: &SlotAnchor) {
        let offset_ms = anchor.elapsed_ms() as f64;
        let cache = if self.phase_block_cache_cold {
            slot_phase_cache::COLD
        } else {
            slot_phase_cache::WARM
        };
        RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).observe(offset_ms);
        self.phase_block_cache_cold = false;
    }

    fn check_shutdown(&self) -> bool {
        if *self.shutdown_rx.borrow() {
            info!("Shutdown signal received, stopping orchestrator");
            true
        } else {
            false
        }
    }

    /// Phase-2 wait: [`HeadEventGate::wait_for_head_or_deadline`] raced with shutdown.
    async fn wait_for_attestation_or_head(
        &self,
        slot: Slot,
        deadline: tokio::time::Instant,
    ) -> WaitOutcome {
        if tokio::time::Instant::now() >= deadline {
            return if self.check_shutdown() {
                WaitOutcome::Shutdown
            } else {
                WaitOutcome::Continue
            };
        }
        let mut rx = self.shutdown_rx.clone();
        tokio::select! {
            _ = self.head_gate.wait_for_head_or_deadline(slot, deadline) => {}
            _ = rx.changed() => {}
        }
        if self.check_shutdown() {
            WaitOutcome::Shutdown
        } else {
            WaitOutcome::Continue
        }
    }

    /// `&self` wait: clone the shutdown receiver so the slot-loop wait can
    /// race owned fields (e.g. `duty_management`) without a double borrow.
    async fn wait_for_shared(&self, duration: Duration) -> WaitOutcome {
        if !duration.is_zero() {
            let mut rx = self.shutdown_rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(duration) => {}
                _ = rx.changed() => {}
            }
        }
        if self.check_shutdown() {
            WaitOutcome::Shutdown
        } else {
            WaitOutcome::Continue
        }
    }

    /// Absolute-deadline form of [`Self::wait_for_shared`]. `sleep_until` is
    /// raced with shutdown the same way the duration wait is.
    async fn wait_until_deadline(&self, deadline: tokio::time::Instant) -> WaitOutcome {
        let mut rx = self.shutdown_rx.clone();
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {}
            _ = rx.changed() => {}
        }
        if self.check_shutdown() {
            WaitOutcome::Shutdown
        } else {
            WaitOutcome::Continue
        }
    }

    /// Race `work` against the next-slot wait. Work that is still pending when
    /// the slot arrives is abandoned; a ready occupant (or zero duration)
    /// returns without sleeping, matching the previous builder-registration
    /// `select!` / skip-wait branches.
    async fn run_post_duty_window(
        &self,
        duration: Duration,
        work: impl Future<Output = ()>,
    ) -> WaitOutcome {
        if duration.is_zero() {
            return WaitOutcome::Continue;
        }
        tokio::select! {
            outcome = self.wait_for_shared(duration) => outcome,
            _ = work => WaitOutcome::Continue,
        }
    }

    /// Phase deadline at `bps` basis points into the anchored slot.
    ///
    /// Offset, remaining, and overrun come from `anchor` (zero slot-clock reads).
    /// Mainnet examples: 1/3 → 3999 ms, 2/3 → 8000 ms.
    fn phase_deadline(anchor: &SlotAnchor, bps: u64) -> PhaseDeadline {
        let offset_ms = due_ms(bps, anchor.slot_duration_ms());
        let deadline = anchor.deadline(bps);
        let now = tokio::time::Instant::now();
        if now < deadline {
            PhaseDeadline {
                offset: Duration::from_millis(offset_ms),
                remaining: deadline.saturating_duration_since(now),
                overrun_ms: 0,
            }
        } else {
            PhaseDeadline {
                offset: Duration::from_millis(offset_ms),
                remaining: Duration::ZERO,
                overrun_ms: u64::try_from(now.saturating_duration_since(deadline).as_millis())
                    .unwrap_or(u64::MAX),
            }
        }
    }

    /// Wait until `bps` into the anchored slot. Attestation waits use the head-event
    /// gate; other duties use `sleep_until`. A deadline that has already passed
    /// fires immediately.
    async fn wait_until_bps(
        &self,
        anchor: &SlotAnchor,
        bps: u64,
        phase: &'static str,
        use_head_gate: bool,
        span: &tracing::Span,
        wait_msg: &'static str,
    ) -> WaitOutcome {
        let phase_deadline = Self::phase_deadline(anchor, bps);
        if phase_deadline.remaining.is_zero() {
            warn!(
                phase,
                overrun_ms = phase_deadline.overrun_ms,
                slot = anchor.slot(),
                "slot phase deadline already passed; firing immediately"
            );
            RVC_SLOT_PHASE_LATE_TOTAL.with_label_values(&[phase]).inc();
            return if self.check_shutdown() {
                WaitOutcome::Shutdown
            } else {
                WaitOutcome::Continue
            };
        }
        {
            let _guard = span.enter();
            debug!(
                slot = anchor.slot(),
                wait_ms = phase_deadline.remaining.as_millis(),
                "{}",
                wait_msg
            );
        }
        let deadline = anchor.deadline(bps);
        if use_head_gate {
            self.wait_for_attestation_or_head(anchor.slot(), deadline)
                .instrument(span.clone())
                .await
        } else {
            self.wait_until_deadline(deadline).instrument(span.clone()).await
        }
    }

    fn warn_if_attestation_overrun(&self, anchor: &SlotAnchor, attestation_due_bps: u64) {
        let deadline = Self::phase_deadline(anchor, attestation_due_bps);
        let att_window_ms = deadline.offset.as_millis() as u64;
        if deadline.overrun_ms > att_window_ms {
            warn!(
                slot = anchor.slot(),
                delay_ms = deadline.overrun_ms,
                "Missed attestation deadline"
            );
        }
    }

    async fn capture_head_if_needed(&self, ctx: &tokio::sync::Mutex<SlotContext>) {
        let mut ctx = ctx.lock().await;
        if ctx.head_root.is_none() {
            ctx.capture_head(&*self.beacon).await;
        }
    }

    async fn snapshot_ctx(&self, ctx: &tokio::sync::Mutex<SlotContext>) -> SlotContext {
        ctx.lock().await.clone()
    }

    /// Stamps `time_into_slot` when a phase fires.
    ///
    /// The value is [`SlotAnchor::elapsed_ms`]: milliseconds since the true
    /// slot start, so a late wake is included. The slot clock is whole
    /// seconds and cannot represent a sub-second bps offset such as 3999 ms.
    fn record_time_into_slot(span: &tracing::Span, anchor: &SlotAnchor) {
        span.record(observability::logging::fields::TIME_INTO_SLOT, anchor.elapsed_ms());
    }

    /// Records `rvc_slot_phase_offset_ms{phase}` at the moment a phase fires.
    fn record_phase_offset(phase: &'static str, anchor: &SlotAnchor) {
        RVC_SLOT_PHASE_OFFSET_MS.with_label_values(&[phase]).observe(anchor.elapsed_ms() as f64);
    }

    async fn run_attestation_phase(
        &self,
        current_slot: Slot,
        att_phase_span: &tracing::Span,
        slot_end: tokio::time::Instant,
    ) {
        if self.attesting_enabled.load(Ordering::Relaxed) {
            if let Err(e) = self
                .process_slot_until(current_slot, slot_end)
                .instrument(att_phase_span.clone())
                .await
            {
                let _guard = att_phase_span.enter();
                match &e {
                    OrchestratorError::SlotMissed { slot, current_slot } => {
                        warn!(slot = slot, current_slot = current_slot, "Missed slot");
                        RVC_ATTESTATIONS_TOTAL
                            .with_label_values(&[attestation_status::SKIPPED])
                            .inc();
                    }
                    OrchestratorError::NoDutiesForSlot { slot } => {
                        debug!(slot = slot, "No duties for slot");
                    }
                    _ => {
                        error!(slot = current_slot, error = %e, "Error processing slot");
                    }
                }
            }
        } else {
            debug!(slot = current_slot, "Attestation duties skipped (disabled)");
        }
    }

    /// Aggregate duties for `slot` until `slot_end`.
    ///
    /// Intake stops at `slot_end`. A publish still running stops at `slot_end`
    /// plus [`super::dispatch::SLOT_END_PUBLISH_OVERHANG`].
    async fn run_aggregation_phase(
        &self,
        current_slot: Slot,
        current_epoch: u64,
        agg_phase_span: tracing::Span,
        slot_end: tokio::time::Instant,
    ) {
        if self.attesting_enabled.load(Ordering::Relaxed) {
            self.aggregation_service
                .maybe_produce_aggregations(current_slot, current_epoch, slot_end)
                .instrument(agg_phase_span)
                .await;
        } else {
            debug!(slot = current_slot, "Aggregation duties skipped (attesting disabled)");
        }
    }

    /// Attestations and sync messages share a wait while their bps match,
    /// then run concurrently. Otherwise each duty waits from slot start to
    /// its own offset.
    ///
    /// `sync_phase_span` is created beside the other phase spans in [`Self::run`].
    /// `slot.process` is not in scope here.
    #[allow(clippy::too_many_arguments)]
    async fn run_attestation_and_sync_phases(
        &self,
        current_slot: Slot,
        current_epoch: u64,
        ctx: &tokio::sync::Mutex<SlotContext>,
        deadlines: DeadlineBps,
        att_phase_span: tracing::Span,
        sync_phase_span: tracing::Span,
        anchor: &SlotAnchor,
    ) -> WaitOutcome {
        if deadlines.attestation == deadlines.sync_message {
            if matches!(
                self.wait_until_bps(
                    anchor,
                    deadlines.attestation,
                    slot_phase_late::ATTESTATION,
                    true,
                    &att_phase_span,
                    "Waiting for attestation time",
                )
                .await,
                WaitOutcome::Shutdown
            ) {
                return WaitOutcome::Shutdown;
            }
            if self.check_shutdown() {
                return WaitOutcome::Shutdown;
            }
            Self::record_time_into_slot(&att_phase_span, anchor);
            Self::record_phase_offset(slot_phase_offset::ATTESTATION, anchor);
            Self::record_time_into_slot(&sync_phase_span, anchor);
            Self::record_phase_offset(slot_phase_offset::SYNC_MESSAGE, anchor);
            self.capture_head_if_needed(ctx).await;
            self.warn_if_attestation_overrun(anchor, deadlines.attestation);
            // Snapshot before the join. Inside it, sync would block on the
            // ctx mutex while attestation holds it across capture_head.
            let snapshot = self.snapshot_ctx(ctx).await;
            let slot_end = anchor.slot_end();
            tokio::join!(
                self.run_attestation_phase(current_slot, &att_phase_span, slot_end),
                self.run_sync_messages_phase(current_slot, current_epoch, &snapshot, slot_end)
                    .instrument(sync_phase_span),
            );
            return WaitOutcome::Continue;
        }

        let (att_outcome, sync_outcome) = tokio::join!(
            async {
                if matches!(
                    self.wait_until_bps(
                        anchor,
                        deadlines.attestation,
                        slot_phase_late::ATTESTATION,
                        true,
                        &att_phase_span,
                        "Waiting for attestation time",
                    )
                    .await,
                    WaitOutcome::Shutdown
                ) {
                    return WaitOutcome::Shutdown;
                }
                Self::record_time_into_slot(&att_phase_span, anchor);
                Self::record_phase_offset(slot_phase_offset::ATTESTATION, anchor);
                self.capture_head_if_needed(ctx).await;
                self.warn_if_attestation_overrun(anchor, deadlines.attestation);
                self.run_attestation_phase(current_slot, &att_phase_span, anchor.slot_end()).await;
                WaitOutcome::Continue
            },
            async {
                if matches!(
                    self.wait_until_bps(
                        anchor,
                        deadlines.sync_message,
                        slot_phase_late::SYNC_MESSAGE,
                        false,
                        &sync_phase_span,
                        "Waiting for sync message time",
                    )
                    .await,
                    WaitOutcome::Shutdown
                ) {
                    return WaitOutcome::Shutdown;
                }
                Self::record_time_into_slot(&sync_phase_span, anchor);
                Self::record_phase_offset(slot_phase_offset::SYNC_MESSAGE, anchor);
                self.capture_head_if_needed(ctx).await;
                let snapshot = self.snapshot_ctx(ctx).await;
                self.run_sync_messages_phase(
                    current_slot,
                    current_epoch,
                    &snapshot,
                    anchor.slot_end(),
                )
                .instrument(sync_phase_span.clone())
                .await;
                WaitOutcome::Continue
            },
        );
        if matches!(att_outcome, WaitOutcome::Shutdown)
            || matches!(sync_outcome, WaitOutcome::Shutdown)
        {
            WaitOutcome::Shutdown
        } else {
            WaitOutcome::Continue
        }
    }

    /// Contributions share the aggregate wait while their bps match; otherwise
    /// each duty waits from slot start to its own offset.
    async fn run_aggregation_and_contribution_phases(
        &self,
        current_slot: Slot,
        current_epoch: u64,
        ctx: &tokio::sync::Mutex<SlotContext>,
        deadlines: DeadlineBps,
        agg_phase_span: tracing::Span,
        anchor: &SlotAnchor,
    ) -> WaitOutcome {
        if deadlines.contribution == deadlines.aggregate {
            if matches!(
                self.wait_until_bps(
                    anchor,
                    deadlines.aggregate,
                    slot_phase_late::AGGREGATE,
                    false,
                    &agg_phase_span,
                    "Waiting for 2/3 slot time",
                )
                .await,
                WaitOutcome::Shutdown
            ) {
                return WaitOutcome::Shutdown;
            }
            if self.check_shutdown() {
                return WaitOutcome::Shutdown;
            }
            Self::record_time_into_slot(&agg_phase_span, anchor);
            Self::record_phase_offset(slot_phase_offset::CONTRIBUTION, anchor);
            let snapshot = self.snapshot_ctx(ctx).await;
            self.run_sync_contributions_phase(current_slot, current_epoch, &snapshot)
                .instrument(agg_phase_span.clone())
                .await;
            Self::record_phase_offset(slot_phase_offset::AGGREGATE, anchor);
            self.run_aggregation_phase(
                current_slot,
                current_epoch,
                agg_phase_span,
                anchor.slot_end(),
            )
            .await;
            return WaitOutcome::Continue;
        }

        let (contrib_outcome, agg_outcome) = tokio::join!(
            async {
                if matches!(
                    self.wait_until_bps(
                        anchor,
                        deadlines.contribution,
                        slot_phase_late::CONTRIBUTION,
                        false,
                        &agg_phase_span,
                        "Waiting for contribution time",
                    )
                    .await,
                    WaitOutcome::Shutdown
                ) {
                    return WaitOutcome::Shutdown;
                }
                Self::record_phase_offset(slot_phase_offset::CONTRIBUTION, anchor);
                self.capture_head_if_needed(ctx).await;
                let snapshot = self.snapshot_ctx(ctx).await;
                self.run_sync_contributions_phase(current_slot, current_epoch, &snapshot)
                    .instrument(agg_phase_span.clone())
                    .await;
                WaitOutcome::Continue
            },
            async {
                if matches!(
                    self.wait_until_bps(
                        anchor,
                        deadlines.aggregate,
                        slot_phase_late::AGGREGATE,
                        false,
                        &agg_phase_span,
                        "Waiting for aggregate time",
                    )
                    .await,
                    WaitOutcome::Shutdown
                ) {
                    return WaitOutcome::Shutdown;
                }
                Self::record_time_into_slot(&agg_phase_span, anchor);
                Self::record_phase_offset(slot_phase_offset::AGGREGATE, anchor);
                self.run_aggregation_phase(
                    current_slot,
                    current_epoch,
                    agg_phase_span.clone(),
                    anchor.slot_end(),
                )
                .await;
                WaitOutcome::Continue
            },
        );
        if matches!(contrib_outcome, WaitOutcome::Shutdown)
            || matches!(agg_outcome, WaitOutcome::Shutdown)
        {
            WaitOutcome::Shutdown
        } else {
            WaitOutcome::Continue
        }
    }

    pub async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        self.attestation_service.process_slot(slot).await
    }

    /// Attestation duties for `slot` until `slot_end` (coordinator slot anchor).
    pub(crate) async fn process_slot_until(
        &self,
        slot: Slot,
        slot_end: tokio::time::Instant,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        self.attestation_service.process_slot_until(slot, slot_end).await
    }

    /// Sets the sync-committee duty participation flag.
    ///
    /// When `false`, sync-committee messages and contributions are silently
    /// skipped for all subsequent slots until re-enabled. This flag is
    /// independent of `attesting_enabled`, closing H-7: disabling attestations
    /// no longer silently disables sync-committee duties.
    ///
    /// Internal-only — NOT wired to any Keymanager API endpoint (per OQ-A3
    /// decision deferred to Tier-1 follow-up).
    pub fn set_sync_enabled(&self, enabled: bool) {
        self.sync_enabled.store(enabled, Ordering::Release);
    }

    /// Runs the sync-committee messages phase, gated by `sync_enabled`.
    ///
    /// Extracted so both the run loop and tests can invoke the guarded phase
    /// in isolation. `slot_end` bounds intake the same way as attestation
    /// dispatch: duties not yet pulled are dropped, and a publish still
    /// running stops at `slot_end` plus [`super::dispatch::SLOT_END_PUBLISH_OVERHANG`].
    async fn run_sync_messages_phase(
        &self,
        slot: Slot,
        epoch: u64,
        ctx: &SlotContext,
        slot_end: tokio::time::Instant,
    ) {
        if self.sync_enabled.load(Ordering::Acquire) {
            self.sync_committee_service
                .maybe_produce_sync_messages(slot, epoch, ctx, slot_end)
                .await;
        }
    }

    /// Runs the sync-committee contributions phase, gated by `sync_enabled`.
    async fn run_sync_contributions_phase(&self, slot: Slot, epoch: u64, ctx: &SlotContext) {
        if self.sync_enabled.load(Ordering::Acquire) {
            self.sync_committee_service.maybe_produce_sync_contributions(slot, epoch, ctx).await;
        }
    }

    /// Gloas+ payload-attestation phase. Waits to the 4.19-resolved
    /// `deadlines.payload_attestation` offset, then signs and submits.
    async fn run_payload_attestation_phase(
        &self,
        current_slot: Slot,
        current_epoch: u64,
        fork: ForkName,
        deadlines: DeadlineBps,
        ptc_phase_span: tracing::Span,
        anchor: &SlotAnchor,
    ) -> WaitOutcome {
        if fork >= ForkName::Gloas {
            if matches!(
                self.wait_until_bps(
                    anchor,
                    deadlines.payload_attestation,
                    slot_phase_late::PAYLOAD_ATTESTATION,
                    false,
                    &ptc_phase_span,
                    "Waiting for payload attestation time",
                )
                .await,
                WaitOutcome::Shutdown
            ) {
                return WaitOutcome::Shutdown;
            }
            if self.check_shutdown() {
                return WaitOutcome::Shutdown;
            }
            Self::record_time_into_slot(&ptc_phase_span, anchor);
            Self::record_phase_offset(slot_phase_offset::PAYLOAD_ATTESTATION, anchor);
            self.payload_attestation_service
                .maybe_produce_payload_attestations(current_slot, current_epoch)
                .instrument(ptc_phase_span)
                .await;
        }
        WaitOutcome::Continue
    }

    /// Committee subscriptions for one epoch.
    ///
    /// A validator with `ValidatorStore::is_signing_enabled == false` is skipped
    /// before any selection proof (same store gate as aggregate production).
    pub async fn submit_committee_subscriptions(&self, epoch: u64) {
        self.duty_management.submit_committee_subscriptions(epoch).await;
    }

    /// Updates fork-resolution gauges and logs one info line per fork change.
    fn record_fork_resolution(&mut self, epoch: u64, fork: ForkName) {
        RVC_FORK_CURRENT_ID.set(i64::from(fork.id()));

        match self.config.fork_schedule.next_activation(epoch) {
            Some((name, activation)) => {
                if let Some(prev) = self.next_activation_fork {
                    if prev != name {
                        let _ =
                            RVC_FORK_NEXT_ACTIVATION_EPOCH.remove_label_values(&[prev.as_ref()]);
                    }
                }
                RVC_FORK_NEXT_ACTIVATION_EPOCH.with_label_values(&[name.as_ref()]).set(
                    i64::try_from(activation).expect("non-sentinel activation epoch fits i64"),
                );
                self.next_activation_fork = Some(name);
            }
            None => {
                if let Some(prev) = self.next_activation_fork.take() {
                    let _ = RVC_FORK_NEXT_ACTIVATION_EPOCH.remove_label_values(&[prev.as_ref()]);
                }
            }
        }

        if self.last_resolved_fork != Some(fork) {
            info!(
                epoch,
                fork = fork.as_ref(),
                previous = self.last_resolved_fork.as_ref().map(|f| f.as_ref()),
                "Fork boundary"
            );
            self.last_resolved_fork = Some(fork);
        }
    }
}

/// Forwards 6.17 cached signed auth into V4 produce without a block-service→builder edge.
struct BuilderConfigAdapter(Arc<BuilderService>);

#[async_trait]
impl BuilderConfigProvider for BuilderConfigAdapter {
    async fn builder_config_for(&self, pubkey: &[u8; 48], slot: Slot) -> BuilderConfig {
        self.0.builder_config_for(pubkey, slot).await
    }
}

#[cfg(test)]
pub(crate) mod tests;

/// Watch sender with no live slot loop.
///
/// Shutdown-drain tests call [`OrchestratorHandle::shutdown`] without a beacon
/// node, slashing database, or keys. This impl sits after the fork-hazard sites
/// so those line pins do not move.
#[cfg(test)]
impl OrchestratorHandle {
    pub(crate) fn for_drain_test() -> Self {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        Self { shutdown_tx }
    }
}
