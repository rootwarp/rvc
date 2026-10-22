use std::str::FromStr;
use std::sync::Arc;
#[cfg(any(test, feature = "test-utils"))]
use std::sync::Mutex;
use std::time::Instant;

use tracing::{debug, error, info, warn, Instrument};

use beacon::{block_value, GloasBlockContents, ProduceBlockV4Body, RankedBlock, WireBody};
use crypto::PublicKey;
use eth_types::{ForkName, ForkSchedule, Root, Slot, SLOTS_PER_EPOCH, SLOT_DURATION_MS};
use observability::logging::{TruncatedPubkey, TruncatedRoot};
use signer::{
    BeaconAdmission, BeaconBlockHeaderFields, CircuitBreakerState, SigningDuty, ValidatorSigner,
};
use timing::{due_ms, DeadlineBps, DeadlineSchedule};
use validator_store::ValidatorStore;

use crate::metrics::{
    proposal_outcome, RVC_BLOCK_SHAPE_REJECTIONS_TOTAL, RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL,
    RVC_PROPOSALS_TOTAL,
};
use crate::traits::{
    BeaconBlockClient, BuilderConfig, BuilderConfigProvider, ProduceBlockResponse, ProduceDuty,
};
use crate::types::{BlockSelectionMode, CandidateShape};
use crate::validation::{check_mode_shape, BlockResponseValidator, ExpectedParents};
use crate::BlockServiceError;

/// Result of a successful block proposal.
#[derive(Debug, Clone)]
pub struct BlockProposalResult {
    pub slot: Slot,
    pub block_root: Root,
    pub is_blinded: bool,
    pub consensus_version: String,
    pub value_wei: Option<String>,
}

/// Orchestrates the block proposal lifecycle: RANDAO, produce, sign, submit.
pub struct BlockService<S: ValidatorSigner, B: BeaconBlockClient> {
    signer: Arc<S>,
    beacon: Arc<B>,
    validator_store: Arc<ValidatorStore>,
    fork_schedule: Arc<ForkSchedule>,
    genesis_validators_root: Root,
    circuit_breaker: Arc<CircuitBreakerState>,
    builder_config_provider: Option<Arc<dyn BuilderConfigProvider>>,
    deadline_schedule: DeadlineSchedule,
    /// Beacon-node slot length in milliseconds for the Gloas payload deadline.
    ///
    /// [`Self::new`] keeps 12 s. Production passes the resolved duration.
    slot_duration_ms: u64,
    #[cfg(test)]
    envelope_deadline_note: Mutex<Option<EnvelopeDeadlineNote>>,
    /// Runs after produce returns and before the fence is checked again.
    /// Integration tests revoke a pool here. Not compiled into production.
    #[cfg(any(test, feature = "test-utils"))]
    after_produce: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Runs at the start of each `discard_revoked_fences` call.
    ///
    /// A test bumps one generation on a chosen call so a later discard can be
    /// removed without the earlier discard hiding that. Not compiled into
    /// production.
    #[cfg(any(test, feature = "test-utils"))]
    before_discard: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct EnvelopeDeadlineNote {
    pub elapsed_ms: u64,
    pub deadline_ms: u64,
    pub overrun_stage: Option<&'static str>,
}

pub(crate) struct PayloadDeadline {
    start: Instant,
    deadline_ms: u64,
    first_overrun_stage: Option<&'static str>,
}

impl PayloadDeadline {
    fn new(
        fork: ForkName,
        schedule: &DeadlineSchedule,
        start: Instant,
        slot_duration_ms: u64,
    ) -> Self {
        Self {
            start,
            deadline_ms: due_ms(schedule.for_fork(fork).payload, slot_duration_ms),
            first_overrun_stage: None,
        }
    }

    fn mark(&mut self, stage: &'static str) {
        self.mark_at(stage, self.start.elapsed().as_millis() as u64);
    }

    pub(crate) fn mark_at(&mut self, stage: &'static str, elapsed_ms: u64) {
        if self.first_overrun_stage.is_none() && elapsed_ms > self.deadline_ms {
            self.first_overrun_stage = Some(stage);
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    #[cfg(test)]
    pub(crate) fn for_test(deadline_ms: u64) -> Self {
        Self { start: Instant::now(), deadline_ms, first_overrun_stage: None }
    }

    #[cfg(test)]
    pub(crate) fn first_overrun_stage(&self) -> Option<&'static str> {
        self.first_overrun_stage
    }
}

impl<S: ValidatorSigner, B: BeaconBlockClient> BlockService<S, B> {
    pub fn new(
        signer: Arc<S>,
        beacon: Arc<B>,
        validator_store: Arc<ValidatorStore>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self::with_circuit_breaker(
            signer,
            beacon,
            validator_store,
            fork_schedule,
            genesis_validators_root,
            Arc::new(CircuitBreakerState::new(0, 0)),
        )
    }

    pub fn with_circuit_breaker(
        signer: Arc<S>,
        beacon: Arc<B>,
        validator_store: Arc<ValidatorStore>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
        circuit_breaker: Arc<CircuitBreakerState>,
    ) -> Self {
        Self {
            signer,
            beacon,
            validator_store,
            fork_schedule,
            genesis_validators_root,
            circuit_breaker,
            builder_config_provider: None,
            deadline_schedule: DeadlineSchedule::uniform(DeadlineBps::default()),
            slot_duration_ms: SLOT_DURATION_MS,
            #[cfg(test)]
            envelope_deadline_note: Mutex::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            after_produce: Mutex::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            before_discard: Mutex::new(None),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_after_produce(&self, hook: impl Fn() + Send + Sync + 'static) {
        if let Ok(mut slot) = self.after_produce.lock() {
            *slot = Some(Arc::new(hook));
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_before_discard(&self, hook: impl Fn() + Send + Sync + 'static) {
        if let Ok(mut slot) = self.before_discard.lock() {
            *slot = Some(Arc::new(hook));
        }
    }

    fn admission_blocks(duty: SigningDuty, fence: &beacon::DutyFence) -> bool {
        signer::duty_requires_beacon_admission(duty) && !fence.holds()
    }

    async fn under_admission<T>(
        fence: &beacon::DutyFence,
        fut: impl std::future::Future<Output = T>,
    ) -> T {
        let mut generations = fence.generations();
        let Some((seen, current)) = generations.next() else {
            return fut.await;
        };
        let mut admission = BeaconAdmission::new(seen, current);
        for (seen, current) in generations {
            admission = admission.and_generation(seen, current);
        }
        signer::with_beacon_admission(admission, fut).await
    }

    fn discard_revoked_fences(
        &self,
        fences: &[&beacon::DutyFence],
    ) -> Result<(), BlockServiceError> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(hook) = self.before_discard.lock().ok().and_then(|guard| guard.clone()) {
            hook();
        }
        if fences.iter().any(|fence| Self::admission_blocks(SigningDuty::Block, fence)) {
            warn!("beacon node admission revoked; block candidate discarded");
            Err(BlockServiceError::Beacon(
                "beacon node response dropped: admission revoked in flight".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// 6.17 cached signed builder auth. `None` keeps `builders: []` (no dummy unsigned auth).
    pub fn with_builder_config_provider(
        mut self,
        provider: Arc<dyn BuilderConfigProvider>,
    ) -> Self {
        self.builder_config_provider = Some(provider);
        self
    }

    /// Injected deadline schedule. Default is uniform [`DeadlineBps::default`].
    pub fn with_deadline_schedule(mut self, schedule: DeadlineSchedule) -> Self {
        self.deadline_schedule = schedule;
        self
    }

    /// Slot length used by the Gloas payload deadline.
    ///
    /// Production passes the duration resolved from the beacon node.
    pub fn with_slot_duration_ms(mut self, slot_duration_ms: u64) -> Self {
        self.slot_duration_ms = slot_duration_ms;
        self
    }

    /// Slot length in milliseconds stored for [`PayloadDeadline`].
    pub fn slot_duration_ms(&self) -> u64 {
        self.slot_duration_ms
    }

    fn payload_deadline(&self, fork: ForkName, start: Instant) -> PayloadDeadline {
        PayloadDeadline::new(fork, &self.deadline_schedule, start, self.slot_duration_ms)
    }

    #[cfg(test)]
    pub(crate) fn last_envelope_deadline_note(&self) -> Option<EnvelopeDeadlineNote> {
        self.envelope_deadline_note.lock().ok().and_then(|g| *g)
    }

    /// V4 produce body for this slot.
    ///
    /// A boost of 0 clears `builders`. A provider entry must not keep a
    /// non-zero boost after execution-only or a tripped breaker. Any other
    /// boost writes that boost and the store `min_bid` onto every entry.
    async fn v4_builder_config(&self, pubkey: &[u8; 48], slot: Slot, boost: u64) -> BuilderConfig {
        let mut config = match &self.builder_config_provider {
            Some(provider) => provider.builder_config_for(pubkey, slot).await,
            None => BuilderConfig {
                min_bid: self.validator_store.min_bid(pubkey),
                builder_boost_factor: boost,
                builders: Vec::new(),
            },
        };
        let min_bid = self.validator_store.min_bid(pubkey);
        config.builder_boost_factor = boost;
        config.min_bid = min_bid;
        if boost == 0 {
            config.builders.clear();
        } else {
            for entry in &mut config.builders {
                entry.builder_boost_factor = boost;
                entry.min_bid = min_bid;
            }
        }
        config
    }

    /// Propose a block for the given duty slot and validator key.
    ///
    /// Validates `proposer_index` against `expected_proposer_index` and, when
    /// `expected_parents` is `Some`, validates `parent_root` against that set
    /// before calling the signer. On validation failure the duty is dropped
    /// with a `warn!` and no signer call is made (H-4).
    pub async fn propose_block(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        expected_proposer_index: u64,
        expected_parents: Option<ExpectedParents>,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        self.propose_block_until(
            slot,
            pubkey,
            expected_proposer_index,
            expected_parents,
            None,
            &beacon::DutyFence::open(),
        )
        .await
    }

    /// [`Self::propose_block`] with a per-call block-production deadline.
    ///
    /// `deadline` caps only the proposer-pool produce call. Publication keeps
    /// its own budget. `None` uses the configured block-production timeout.
    #[tracing::instrument(
        name = "block.propose",
        level = "debug",
        skip_all,
        fields(
            slot = slot,
            block.blinded = tracing::field::Empty,
            block.consensus_version = tracing::field::Empty,
            block.value_wei = tracing::field::Empty,
        )
    )]
    pub async fn propose_block_until(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        expected_proposer_index: u64,
        expected_parents: Option<ExpectedParents>,
        deadline: Option<tokio::time::Instant>,
        capture_fence: &beacon::DutyFence,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        let mode = self.validator_store.effective_block_selection_mode(&pubkey.to_bytes());
        let validator = BlockResponseValidator { expected_proposer_index, expected_parents };
        self.propose_block_impl(slot, pubkey, mode, Some(&validator), deadline, capture_fence).await
    }

    /// Mode-override entry point for tests. Not part of the public API —
    /// callers must use [`Self::propose_block`], which applies response
    /// validation. Visibility is `pub(crate)` so external crates cannot
    /// bypass validation (F101).
    #[allow(dead_code)] // exercised only from `#[cfg(test)]` modules in this crate
    pub(crate) async fn propose_block_with_mode(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        mode: BlockSelectionMode,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        self.propose_block_impl(slot, pubkey, mode, None, None, &beacon::DutyFence::open()).await
    }

    async fn propose_block_impl(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        mode: BlockSelectionMode,
        validator: Option<&BlockResponseValidator>,
        deadline: Option<tokio::time::Instant>,
        capture_fence: &beacon::DutyFence,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let proposal_start = Instant::now();

        info!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), %mode, "Block proposal started");

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork = ForkName::from_epoch(epoch, &self.fork_schedule);
        let mut payload_deadline = self.payload_deadline(fork, proposal_start);

        let fence = self.beacon.duty_fence()?;
        if Self::admission_blocks(SigningDuty::RandaoReveal, &fence) {
            warn!(slot, "no admitted beacon node; duties halted");
            return Err(BlockServiceError::Beacon("no admitted beacon node; duties halted".into()));
        }
        if Self::admission_blocks(SigningDuty::RandaoReveal, capture_fence) {
            warn!(slot, "beacon node admission revoked; block candidate discarded");
            return Err(BlockServiceError::Beacon(
                "beacon node response dropped: admission revoked in flight".into(),
            ));
        }

        // 1. Sign RANDAO reveal
        let randao_start = std::time::Instant::now();
        let randao_sig = Self::under_admission(
                &fence,
                self.signer.sign_randao_reveal(
                    epoch,
                    pubkey,
                    &self.fork_schedule,
                    &self.genesis_validators_root,
                ),
            )
            .instrument(tracing::info_span!("sign.randao"))
            .await
            .map_err(|e| {
                let err = BlockServiceError::Signer(e.to_string());
                error!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), error = %err, "RANDAO signing failed");
                err
            })?;
        debug!(
            slot = slot,
            duration_ms = randao_start.elapsed().as_millis() as u64,
            "RANDAO reveal signed"
        );
        // Wire boundary: beacon produce_block_v3 takes hex-encoded RANDAO.
        let randao_hex = format!("0x{}", hex::encode(randao_sig.to_bytes()));

        // 2. Get validator preferences, applying block selection mode
        let pubkey_bytes = pubkey.to_bytes();
        let graffiti = self.validator_store.effective_graffiti(&pubkey_bytes);
        let graffiti_hex = graffiti.map(|g| format!("0x{}", hex::encode(g)));

        // Check circuit breaker for builder modes first
        let circuit_breaker_tripped = self.circuit_breaker.is_tripped();

        let boost = match mode {
            BlockSelectionMode::ExecutionOnly => {
                debug!(slot = slot, "ExecutionOnly: builder_boost_factor=0");
                0
            }
            BlockSelectionMode::MaxProfit => {
                if circuit_breaker_tripped {
                    warn!(slot = slot, "Builder circuit breaker tripped, using local block only");
                    0
                } else {
                    self.validator_store.builder_boost_factor(&pubkey_bytes)
                }
            }
            BlockSelectionMode::BuilderAlways => {
                if circuit_breaker_tripped {
                    warn!(
                        slot = slot,
                        "BuilderAlways: circuit breaker tripped, falling back to local"
                    );
                    0
                } else {
                    debug!(slot = slot, "BuilderAlways: builder_boost_factor=u64::MAX");
                    u64::MAX
                }
            }
            BlockSelectionMode::BuilderOnly => {
                if circuit_breaker_tripped {
                    error!(
                        slot = slot,
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        "BuilderOnly mode: circuit breaker tripped, proposal will be missed"
                    );
                    return Err(BlockServiceError::BuilderOnly(
                        "circuit breaker tripped — proposal missed".to_string(),
                    ));
                }
                debug!(slot = slot, "BuilderOnly: builder_boost_factor=u64::MAX");
                u64::MAX
            }
        };

        // 3. Request block from beacon node. Dispatch on the slot fork, never
        // on response headers: Gloas is V4, pre-Gloas stays V3 verbatim.
        let produce_result = if fork >= ForkName::Gloas {
            let builder_config = self.v4_builder_config(&pubkey_bytes, slot, boost).await;
            self.beacon
                .produce_block_v4_by(
                    slot,
                    &randao_hex,
                    graffiti_hex.as_deref(),
                    &builder_config,
                    deadline,
                )
                .instrument(tracing::info_span!("beacon.produce_block_v4"))
                .await
                .map(Produced::V4)
        } else {
            let duty = validator.map(|checks| {
                let fee_recipient = self.validator_store.effective_fee_recipient(&pubkey_bytes);
                duty_from_validator(checks, fee_recipient, fork)
            });
            self.beacon
                .produce_block_v3_ranked_by(
                    slot,
                    &randao_hex,
                    graffiti_hex.as_deref(),
                    Some(boost),
                    duty,
                    deadline,
                )
                .instrument(tracing::info_span!("beacon.produce_block_v3"))
                .await
                .map(Produced::V3)
        };

        // Handle block-production failure, tagging the error so the coordinator
        // can apply H-3 circuit-breaker scoping.
        let produced = match produce_result {
            Ok(produced) => produced,
            Err(e) => {
                if mode == BlockSelectionMode::BuilderOnly {
                    // BuilderOnly: never fall back; always fail the proposal.
                    error!(
                        slot = slot,
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        error = %e,
                        "BuilderOnly mode: builder failed, proposal will be missed"
                    );
                    return Err(BlockServiceError::BuilderOnly(format!(
                        "builder block production failed: {e}"
                    )));
                }
                if boost > 0 {
                    // The BN was asked to contact the builder relay (boost > 0).
                    // Tag the error as BuilderFailure so the coordinator records
                    // a miss on the circuit breaker (H-3).
                    error!(
                        slot = slot,
                        boost,
                        error = %e,
                        "Builder block production failed"
                    );
                    return Err(BlockServiceError::BuilderFailure(e.to_string()));
                }
                // boost == 0: pure local-execution path; BN failure is not a
                // builder-relay issue and must not trip the circuit breaker.
                error!(slot = slot, error = %e, "Block production failed");
                return Err(e);
            }
        };

        payload_deadline.mark("produce");
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(hook) = self.after_produce.lock().ok().and_then(|guard| guard.clone()) {
            hook();
        }
        self.discard_revoked_fences(&[&fence, capture_fence])?;

        // Sign and publish. The slot fork picks V4 or the ranked V3 list.
        // V4 rejects a blinded flag before signing; the shape is the bid
        // builder_index. Pre-Gloas signs the first candidate that passes
        // slot, proposer, and expected parents. Once a signature exists
        // that candidate is committed — no second sign and no re-produce.
        let signed = if fork >= ForkName::Gloas {
            let Produced::V4(response) = produced else {
                return Err(BlockServiceError::Parse(
                    "Gloas slot produced a pre-Gloas candidate list".to_string(),
                ));
            };
            record_produced_response(slot, &response, fork);
            self.sign_and_publish_v4(
                &response,
                slot,
                pubkey,
                validator,
                fork,
                mode,
                &mut payload_deadline,
                &fence,
                capture_fence,
            )
            .await
            .map(|(block_root, is_blinded)| SignedProposal {
                block_root,
                is_blinded,
                consensus_version: response.consensus_version,
                value_wei: response.execution_payload_value,
            })
        } else {
            let Produced::V3(candidates) = produced else {
                return Err(BlockServiceError::Parse(
                    "pre-Gloas slot produced a V4 block".to_string(),
                ));
            };
            self.sign_first_v3_candidate(
                candidates,
                slot,
                pubkey,
                validator,
                fork,
                mode,
                &fence,
                capture_fence,
            )
                .await
        }
        .map_err(|e| {
            if matches!(e, BlockServiceError::EnvelopeAfterPublish(_)) {
                error!(
                    slot = slot,
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    error = %e,
                    "Self-build envelope failed after block publish"
                );
            } else if rejected_before_publish(&e) {
                warn!(
                    slot = slot,
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    error = %e,
                    "Block response rejected before publication"
                );
            } else {
                error!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), error = %e, "Block publication failed");
            }
            e
        })?;

        info!(
            slot = slot,
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            block_root = %TruncatedRoot::new(&signed.block_root),
            is_blinded = signed.is_blinded,
            duration_ms = proposal_start.elapsed().as_millis() as u64,
            "Block publication success"
        );

        Ok(BlockProposalResult {
            slot,
            block_root: signed.block_root,
            is_blinded: signed.is_blinded,
            consensus_version: signed.consensus_version,
            value_wei: signed.value_wei,
        })
    }

    /// Gloas V4 sign+publish. Self-build vs external bid is the bid `builder_index`.
    ///
    /// The mode check, the envelope/bid pairing, and the bid and envelope
    /// bindings all run before `sign_block_header`. A blinded flag is rejected
    /// here, same as pre-Gloas.
    #[allow(clippy::too_many_arguments)]
    async fn sign_and_publish_v4(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
        fork: ForkName,
        mode: BlockSelectionMode,
        payload_deadline: &mut PayloadDeadline,
        fence: &beacon::DutyFence,
        capture_fence: &beacon::DutyFence,
    ) -> Result<(Root, bool), BlockServiceError> {
        cross_check_consensus_version(&response.consensus_version, fork)?;
        reject_blinded_at_gloas(
            response.is_blinded,
            &response.consensus_version,
            slot,
            &self.fork_schedule,
        )?;
        let body = response.decode_v4_body()?;
        let body_ssz = match &body {
            ProduceBlockV4Body::BeaconBlock { block, .. } => block.body.clone(),
            ProduceBlockV4Body::BlockContents(contents) => contents.block.body.clone(),
        };
        let bid = rvc_gloas::gloas_bid_binding(&body_ssz)?;
        let shape = if bid.builder_index == rvc_gloas::BUILDER_INDEX_SELF_BUILD {
            CandidateShape::SelfBuild
        } else {
            CandidateShape::BuilderWin
        };
        enforce_mode_shape(mode, shape).map_err(|err| {
            warn!(slot, error = %err, "BN block response rejected");
            err
        })?;
        let (block, block_ssz, envelope) = match body {
            ProduceBlockV4Body::BeaconBlock { block, block_ssz } => (block, block_ssz, None),
            ProduceBlockV4Body::BlockContents(GloasBlockContents {
                block,
                block_ssz,
                execution_payload_envelope,
                kzg_proofs,
                blobs,
            }) => (block, block_ssz, Some((execution_payload_envelope, blobs, kzg_proofs))),
        };
        if envelope.is_some() && response.builder_url.is_some() {
            return Err(BlockServiceError::Parse(
                "BlockContents must not include Eth-Builder-Url".to_string(),
            ));
        }
        let self_build = bid.builder_index == rvc_gloas::BUILDER_INDEX_SELF_BUILD;
        if envelope.is_some() != self_build {
            return Err(BlockServiceError::Parse(if self_build {
                "self-build bid requires an execution payload envelope".to_string()
            } else {
                "execution payload envelope requires a self-build bid".to_string()
            }));
        }
        check_response_block(validator, slot, block.slot, block.proposer_index, block.parent_root)?;
        let (header, block_root) = gloas_header_and_root(&block)?;
        if bid.slot != block.slot {
            return Err(BlockServiceError::Parse(format!(
                "bid slot {} does not match block slot {}",
                bid.slot, block.slot
            )));
        }
        if bid.parent_block_root != block.parent_root {
            return Err(BlockServiceError::Parse(format!(
                "bid parent_block_root 0x{} does not match block parent root 0x{}",
                hex::encode(bid.parent_block_root),
                hex::encode(block.parent_root)
            )));
        }
        let envelope_root = if let Some((ref envelope_body, _, _)) = envelope {
            let envelope_ssz = envelope_ssz_for_island(envelope_body)?;
            let binding = rvc_gloas::gloas_envelope_binding(&envelope_ssz)?;
            if binding.builder_index != bid.builder_index {
                return Err(BlockServiceError::Parse(format!(
                    "self-build envelope builder_index {} does not match bid builder_index {}",
                    binding.builder_index, bid.builder_index
                )));
            }
            if binding.beacon_block_root != block_root {
                return Err(BlockServiceError::Parse(format!(
                    "self-build envelope beacon_block_root 0x{} does not match block root 0x{}",
                    hex::encode(binding.beacon_block_root),
                    hex::encode(block_root)
                )));
            }
            if binding.parent_beacon_block_root != block.parent_root {
                return Err(BlockServiceError::Parse(format!(
                    "self-build envelope parent_beacon_block_root 0x{} does not match block parent root 0x{}",
                    hex::encode(binding.parent_beacon_block_root),
                    hex::encode(block.parent_root)
                )));
            }
            Some(rvc_gloas::gloas_execution_payload_envelope_root(&envelope_ssz)?)
        } else {
            None
        };
        self.discard_revoked_fences(&[fence, capture_fence])?;
        let sig = Self::under_admission(
            fence,
            self.signer.sign_block_header(
                &header,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            ),
        )
        .instrument(tracing::info_span!("sign.block"))
        .await
        .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        payload_deadline.mark("sign_block");
        let published = async {
            let builder_url =
                if envelope.is_some() { None } else { response.builder_url.as_deref() };
            if let Some(ref block_ssz) = block_ssz {
                let signed_ssz = beacon::ssz_deser::serialize_signed_beacon_block_ssz(
                    block_ssz,
                    &sig.to_bytes(),
                )
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                self.beacon
                    .publish_block_ssz(&signed_ssz, fork.as_ref(), false, builder_url)
                    .instrument(tracing::info_span!("beacon.publish_block"))
                    .await?;
            } else {
                let signed = eth_types::SignedBeaconBlock {
                    message: block,
                    signature: sig.to_bytes().to_vec(),
                };
                self.beacon
                    .publish_block(&signed, fork.as_ref(), builder_url)
                    .instrument(tracing::info_span!("beacon.publish_block"))
                    .await?;
            }
            payload_deadline.mark("publish_block");
            if let (Some((envelope_body, blobs, proofs)), Some(object_root)) =
                (envelope, envelope_root)
            {
                if let Err(e) = self
                    .sign_and_publish_envelope(
                        response,
                        &envelope_body,
                        &blobs,
                        &proofs,
                        object_root,
                        slot,
                        pubkey,
                        fork,
                        payload_deadline,
                        fence,
                        capture_fence,
                    )
                    .await
                {
                    return Err(BlockServiceError::EnvelopeAfterPublish(e.to_string()));
                }
            }
            Ok((block_root, false))
        }
        .await;
        published.map_err(demote_post_sign)
    }

    /// Self-build envelope: never before the block publish; same produce body.
    #[allow(clippy::too_many_arguments)]
    async fn sign_and_publish_envelope(
        &self,
        response: &ProduceBlockResponse,
        envelope_body: &WireBody,
        blobs: &WireBody,
        kzg_proofs: &WireBody,
        object_root: Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork: ForkName,
        payload_deadline: &mut PayloadDeadline,
        fence: &beacon::DutyFence,
        capture_fence: &beacon::DutyFence,
    ) -> Result<(), BlockServiceError> {
        if !response.payload_included {
            return Err(BlockServiceError::Parse(
                "envelope publish requires payload_included on the signed produce response"
                    .to_string(),
            ));
        }
        // The header scope ended when that future completed. Re-enter it, and
        // re-check the capture fence taken before produce.
        self.discard_revoked_fences(&[fence, capture_fence])?;
        let sig = Self::under_admission(
            fence,
            self.signer.sign_execution_payload_envelope_root(
                &object_root,
                slot,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            ),
        )
        .instrument(tracing::info_span!("sign.envelope"))
        .await
        .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        payload_deadline.mark("sign_envelope");
        let signed = signed_envelope_wire(envelope_body, &sig.to_bytes())?;
        let publish = self
            .beacon
            .publish_execution_payload_envelope(&signed, blobs, kzg_proofs, fork.as_ref(), None)
            .instrument(tracing::info_span!("beacon.publish_execution_payload_envelope"))
            .await;
        payload_deadline.mark("publish_envelope");
        self.note_envelope_deadline(payload_deadline);
        publish
    }

    fn note_envelope_deadline(&self, payload_deadline: &PayloadDeadline) {
        let elapsed_ms = payload_deadline.elapsed_ms();
        let deadline_ms = payload_deadline.deadline_ms;
        let overrun_stage = payload_deadline.first_overrun_stage;
        if let Some(stage) = overrun_stage {
            warn!(
                elapsed_ms,
                deadline_ms, stage, "self-build envelope published after payload due"
            );
            RVC_PROPOSALS_TOTAL.with_label_values(&[proposal_outcome::ENVELOPE_LATE]).inc();
        }
        #[cfg(test)]
        if let Ok(mut slot) = self.envelope_deadline_note.lock() {
            *slot = Some(EnvelopeDeadlineNote { elapsed_ms, deadline_ms, overrun_stage });
        }
    }

    /// Walk pre-Gloas candidates. A prepare failure is logged once and skipped.
    /// The first candidate that prepares is signed and published. A signer or
    /// publish error returns immediately and does not try the next candidate.
    #[allow(clippy::too_many_arguments)]
    async fn sign_first_v3_candidate(
        &self,
        candidates: Vec<RankedBlock>,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
        fork: ForkName,
        mode: BlockSelectionMode,
        fence: &beacon::DutyFence,
        capture_fence: &beacon::DutyFence,
    ) -> Result<SignedProposal, BlockServiceError> {
        if candidates.is_empty() {
            return Err(BlockServiceError::Beacon(
                "produce_block_v3 returned no candidate".to_string(),
            ));
        }
        let mut last_error = None;
        let mut builder_only_error = None;
        for candidate in candidates {
            let response = &candidate.response;
            match self.prepare_v3(response, slot, validator, fork, mode) {
                Ok(prepared) => {
                    record_produced_response(slot, response, fork);
                    let expected_fee =
                        self.validator_store.effective_fee_recipient(&pubkey.to_bytes());
                    note_signed_fee_penalty(candidate.bn_index, response, expected_fee, slot);
                    debug!(
                        slot = slot,
                        bn_index = candidate.bn_index,
                        is_blinded = response.is_blinded,
                        "Blinded/unblinded path chosen"
                    );
                    return self
                        .sign_and_publish_prepared(prepared, slot, pubkey, fence, capture_fence)
                        .await;
                }
                Err(err) => {
                    warn!(
                        slot,
                        bn_index = candidate.bn_index,
                        execution_payload_value =
                            response.execution_payload_value.as_deref().unwrap_or(""),
                        consensus_block_value =
                            response.consensus_block_value.as_deref().unwrap_or(""),
                        value_wei = block_value(response),
                        error = %err,
                        "BN block response rejected"
                    );
                    if matches!(err, BlockServiceError::BuilderOnly(_)) {
                        builder_only_error.get_or_insert(err);
                    } else {
                        last_error = Some(err);
                    }
                }
            }
        }
        if let Some(err) = builder_only_error {
            return Err(err);
        }
        match last_error {
            Some(err) => Err(err),
            None => {
                Err(BlockServiceError::Beacon("produce_block_v3 returned no candidate".to_string()))
            }
        }
    }
}

/// A signature already exists. Unsigned-rejection variants are relabeled so
/// the log does not say the block was rejected before publication.
fn demote_post_sign(err: BlockServiceError) -> BlockServiceError {
    if matches!(err, BlockServiceError::EnvelopeAfterPublish(_)) {
        return err;
    }
    if rejected_before_publish(&err) {
        BlockServiceError::Beacon(err.to_string())
    } else {
        err
    }
}

/// True when the duty was dropped before a block publish was attempted.
fn rejected_before_publish(err: &BlockServiceError) -> bool {
    matches!(
        err,
        BlockServiceError::ModeShapeMismatch { .. }
            | BlockServiceError::BuilderOnly(_)
            | BlockServiceError::SlotMismatch { .. }
            | BlockServiceError::Parse(_)
            | BlockServiceError::ProposerIndexMismatch { .. }
            | BlockServiceError::ParentRootMismatch { .. }
            | BlockServiceError::BlindedNotSupportedAtGloas { .. }
            | BlockServiceError::ConsensusVersionMismatch { .. }
            | BlockServiceError::UnknownSszConsensusVersion(_)
            | BlockServiceError::Gloas(_)
            | BlockServiceError::Unsupported(_)
    )
}

/// Warn and count a readable fee mismatch on the candidate that is signed.
///
/// A blinded block is skipped. An unreadable fee does not warn. A fee that
/// matches `expected` does not warn. The head of the ranked list is not
/// counted when a later candidate is the one that prepares.
fn note_signed_fee_penalty(
    bn_index: usize,
    response: &ProduceBlockResponse,
    expected: [u8; 20],
    slot: Slot,
) {
    if response.is_blinded {
        return;
    }
    let Some(got) = execution_fee_address(response) else {
        return;
    };
    if got == expected {
        return;
    }
    warn!(
        slot,
        bn_index,
        fee_expected = %hex_fee(&expected),
        fee_got = %hex_fee(&got),
        "signing block with fee-recipient mismatch"
    );
    inc_signed_fee_penalty();
}

fn inc_signed_fee_penalty() {
    #[cfg(test)]
    {
        with_signed_fee_penalty_lock(|| RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL.inc());
    }
    #[cfg(not(test))]
    {
        RVC_PRODUCE_FEE_RECIPIENT_PENALTY_TOTAL.inc();
    }
}

/// Execution-payload fee recipient, when the signed block carries one.
///
/// JSON may put the address on `execution_payload.fee_recipient` or encode
/// the body as hex SSZ. SSZ responses decode the body the same way. A blinded
/// block, a Gloas body, and a body that does not decode are `None`.
fn execution_fee_address(response: &ProduceBlockResponse) -> Option<[u8; 20]> {
    if response.is_ssz {
        let bytes = response.ssz_bytes.as_deref()?;
        let format = ssz_block_format(false, &response.consensus_version).ok()?;
        let (block, _) =
            beacon::ssz_deser::deserialize_beacon_block_from_ssz(bytes, format).ok()?;
        return fee_from_body_ssz(&response.consensus_version, &block.body);
    }
    let block = eth_types::block_object(&response.data).ok()?;
    let body = block.get("body")?;
    if let Some(hex_body) = body.as_str() {
        let raw = decode_0x(hex_body)?;
        return fee_from_body_ssz(&response.consensus_version, &raw);
    }
    let text = body.get("execution_payload")?.get("fee_recipient")?.as_str()?;
    decode_fee(text)
}

fn fee_from_body_ssz(consensus_version: &str, body: &[u8]) -> Option<[u8; 20]> {
    let fork = ForkName::from_str(consensus_version).ok()?;
    match fork.body_layout()? {
        eth_types::BodyForkLayout::Deneb => eth_types::decode_beacon_block_body_deneb(body)
            .ok()
            .map(|decoded| decoded.execution_payload.fee_recipient),
        eth_types::BodyForkLayout::Electra => eth_types::decode_beacon_block_body_electra(body)
            .ok()
            .map(|decoded| decoded.execution_payload.fee_recipient),
        eth_types::BodyForkLayout::Gloas => None,
    }
}

fn decode_0x(text: &str) -> Option<Vec<u8>> {
    let hex_str = text.strip_prefix("0x").unwrap_or(text);
    hex::decode(hex_str).ok()
}

fn decode_fee(text: &str) -> Option<[u8; 20]> {
    let bytes = decode_0x(text)?;
    let address: [u8; 20] = bytes.try_into().ok()?;
    Some(address)
}

fn hex_fee(bytes: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
thread_local! {
    static SIGNED_FEE_PENALTY_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
static SIGNED_FEE_PENALTY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
thread_local! {
    static SHAPE_REJECTION_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
static SHAPE_REJECTION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serialize shape-rejection increments so a unit test can read an exact delta.
#[cfg(test)]
pub(crate) fn with_shape_rejection_lock<R>(body: impl FnOnce() -> R) -> R {
    if SHAPE_REJECTION_HELD.with(std::cell::Cell::get) {
        return body();
    }
    let _guard = SHAPE_REJECTION_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    SHAPE_REJECTION_HELD.with(|held| held.set(true));
    struct ClearHold;
    impl Drop for ClearHold {
        fn drop(&mut self) {
            SHAPE_REJECTION_HELD.with(|held| held.set(false));
        }
    }
    let _clear = ClearHold;
    body()
}

/// Serialize fee-penalty increments so a unit test can read an exact delta.
#[cfg(test)]
fn with_signed_fee_penalty_lock<R>(body: impl FnOnce() -> R) -> R {
    if SIGNED_FEE_PENALTY_HELD.with(std::cell::Cell::get) {
        return body();
    }
    let _guard = SIGNED_FEE_PENALTY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    SIGNED_FEE_PENALTY_HELD.with(|held| held.set(true));
    struct ClearHold;
    impl Drop for ClearHold {
        fn drop(&mut self) {
            SIGNED_FEE_PENALTY_HELD.with(|held| held.set(false));
        }
    }
    let _clear = ClearHold;
    body()
}

impl<S: ValidatorSigner, B: BeaconBlockClient> BlockService<S, B> {
    /// Decode and check one pre-Gloas candidate. Does not sign.
    fn prepare_v3(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        validator: Option<&BlockResponseValidator>,
        fork: ForkName,
        mode: BlockSelectionMode,
    ) -> Result<PreparedProposal, BlockServiceError> {
        reject_blinded_at_gloas(
            response.is_blinded,
            &response.consensus_version,
            slot,
            &self.fork_schedule,
        )?;
        reject_gloas_version_pre_gloas(&response.consensus_version, fork)?;
        // Every fork, not only Gloas: the header must name the slot fork
        // before the body is decoded or signed.
        cross_check_consensus_version(&response.consensus_version, fork)?;
        let shape =
            if response.is_blinded { CandidateShape::Blinded } else { CandidateShape::Unblinded };
        enforce_mode_shape(mode, shape)?;
        let (header, block_root, payload) = if response.is_ssz {
            prepare_ssz(response, slot, validator)?
        } else if response.is_blinded {
            prepare_blinded(response, slot, validator)?
        } else {
            prepare_full(response, slot, validator)?
        };
        Ok(PreparedProposal {
            header,
            block_root,
            is_blinded: response.is_blinded,
            consensus_version: response.consensus_version.clone(),
            builder_url: response.builder_url.clone(),
            execution_payload_value: response.execution_payload_value.clone(),
            payload,
        })
    }

    /// Sign one prepared candidate and publish it. Any error is final.
    async fn sign_and_publish_prepared(
        &self,
        prepared: PreparedProposal,
        slot: Slot,
        pubkey: &PublicKey,
        fence: &beacon::DutyFence,
        capture_fence: &beacon::DutyFence,
    ) -> Result<SignedProposal, BlockServiceError> {
        let sign_start = std::time::Instant::now();
        self.discard_revoked_fences(&[fence, capture_fence])?;
        let sig = Self::under_admission(
            fence,
            self.signer.sign_block_header(
                &prepared.header,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            ),
        )
        .instrument(tracing::info_span!("sign.block"))
        .await
        .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        debug!(
            slot = slot,
            duration_ms = sign_start.elapsed().as_millis() as u64,
            "Block signing duration"
        );
        let signature = sig.to_bytes();
        let published = async {
            match prepared.payload {
                PreparedPayload::SszWhole(bytes) => {
                    let signed_ssz =
                        beacon::ssz_deser::serialize_signed_beacon_block_ssz(&bytes, &signature)
                            .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                    self.beacon
                        .publish_block_ssz(
                            &signed_ssz,
                            &prepared.consensus_version,
                            prepared.is_blinded,
                            prepared.builder_url.as_deref(),
                        )
                        .instrument(tracing::info_span!("beacon.publish_block"))
                        .await?;
                }
                PreparedPayload::SszContents { block_ssz, kzg_proofs, blobs } => {
                    let signed_block = beacon::ssz_deser::serialize_signed_beacon_block_ssz(
                        &block_ssz, &signature,
                    )
                    .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                    let signed_ssz = beacon::ssz_deser::serialize_signed_block_contents_ssz(
                        &signed_block,
                        &kzg_proofs,
                        &blobs,
                    );
                    self.beacon
                        .publish_block_ssz(
                            &signed_ssz,
                            &prepared.consensus_version,
                            false,
                            prepared.builder_url.as_deref(),
                        )
                        .instrument(tracing::info_span!("beacon.publish_block"))
                        .await?;
                    crate::metrics::RVC_BLOB_SIDECARS_PUBLISHED_TOTAL
                        .with_label_values(&[prepared.consensus_version.as_str()])
                        .inc();
                }
                PreparedPayload::Json(eth_types::BlockContents::BlockAndBlobs {
                    block,
                    kzg_proofs,
                    blobs,
                }) => {
                    let layout = eth_types::body_fork_layout(&prepared.consensus_version)
                        .ok_or_else(|| {
                            BlockServiceError::Parse(format!(
                                "no JSON body layout for consensus version {}",
                                prepared.consensus_version
                            ))
                        })?;
                    let contents = signed_block_contents_json(
                        block,
                        signature.to_vec(),
                        kzg_proofs,
                        blobs,
                        layout,
                    )?;
                    self.beacon
                        .publish_block_contents(
                            &contents,
                            &prepared.consensus_version,
                            prepared.builder_url.as_deref(),
                        )
                        .instrument(tracing::info_span!("beacon.publish_block_contents"))
                        .await?;
                    crate::metrics::RVC_BLOB_SIDECARS_PUBLISHED_TOTAL
                        .with_label_values(&[prepared.consensus_version.as_str()])
                        .inc();
                }
                PreparedPayload::Json(eth_types::BlockContents::Block(block)) => {
                    let signed = eth_types::SignedBeaconBlock {
                        message: block,
                        signature: signature.to_vec(),
                    };
                    self.beacon
                        .publish_block(
                            &signed,
                            &prepared.consensus_version,
                            prepared.builder_url.as_deref(),
                        )
                        .instrument(tracing::info_span!("beacon.publish_block"))
                        .await?;
                }
                PreparedPayload::Blinded(block) => {
                    let signed = eth_types::SignedBlindedBeaconBlock {
                        message: block,
                        signature: signature.to_vec(),
                    };
                    self.beacon
                        .publish_blinded_block(&signed, &prepared.consensus_version)
                        .instrument(tracing::info_span!("beacon.publish_block"))
                        .await?;
                }
            }
            Ok(SignedProposal {
                block_root: prepared.block_root,
                is_blinded: prepared.is_blinded,
                consensus_version: prepared.consensus_version,
                value_wei: prepared.execution_payload_value,
            })
        }
        .await;
        published.map_err(demote_post_sign)
    }
}

/// One pre-Gloas candidate after decode and duty checks, before the signer.
struct PreparedProposal {
    header: BeaconBlockHeaderFields,
    block_root: Root,
    is_blinded: bool,
    consensus_version: String,
    builder_url: Option<String>,
    execution_payload_value: Option<String>,
    payload: PreparedPayload,
}

enum PreparedPayload {
    /// Blinded SSZ: the whole unsigned block buffer.
    ///
    /// A pre-Deneb full SSZ body is not published through this variant.
    /// `ssz_block_format` selects `BeaconBlock`, then `full_body_layout`
    /// rejects that fork before a header is signed.
    SszWhole(Vec<u8>),
    /// Deneb+ `BlockContents` regions, copied out before the signature.
    SszContents {
        block_ssz: Vec<u8>,
        kzg_proofs: Vec<u8>,
        blobs: Vec<u8>,
    },
    Json(eth_types::BlockContents),
    Blinded(eth_types::BlindedBeaconBlock),
}

/// Gloas returns one block. Pre-Gloas returns the ranked candidate list.
enum Produced {
    V4(ProduceBlockResponse),
    V3(Vec<RankedBlock>),
}

struct SignedProposal {
    block_root: Root,
    is_blinded: bool,
    consensus_version: String,
    value_wei: Option<String>,
}

fn duty_from_validator(
    checks: &BlockResponseValidator,
    fee_recipient: [u8; 20],
    fork: ForkName,
) -> ProduceDuty {
    ProduceDuty {
        expected_proposer_index: checks.expected_proposer_index,
        expected_parent_root: checks
            .expected_parents
            .filter(|parents| !parents.closed)
            .map(|parents| parents.root),
        alternate_parent_root: checks
            .expected_parents
            .filter(|parents| !parents.closed)
            .and_then(|parents| parents.parent),
        parent_closed: checks.expected_parents.is_some_and(|parents| parents.closed),
        expected_fee_recipient: Some(fee_recipient),
        expected_consensus_version: fork,
    }
}

fn record_produced_response(slot: Slot, response: &ProduceBlockResponse, slot_fork: ForkName) {
    let span = tracing::Span::current();
    span.record("block.consensus_version", response.consensus_version.as_str());
    if let Some(value) = response.execution_payload_value.as_deref() {
        span.record("block.value_wei", value);
    }
    if slot_fork >= ForkName::Gloas {
        info!(
            slot = slot,
            fork = slot_fork.as_ref(),
            execution_payload_value = response.execution_payload_value.as_deref().unwrap_or("none"),
            "Block production response received"
        );
    } else {
        info!(
            slot = slot,
            is_blinded = response.is_blinded,
            execution_payload_value = response.execution_payload_value.as_deref().unwrap_or("none"),
            "Block production response received"
        );
        span.record("block.blinded", response.is_blinded);
    }
}

fn prepare_ssz(
    response: &ProduceBlockResponse,
    slot: Slot,
    validator: Option<&BlockResponseValidator>,
) -> Result<(BeaconBlockHeaderFields, Root, PreparedPayload), BlockServiceError> {
    let ssz_bytes = response
        .ssz_bytes
        .as_ref()
        .ok_or_else(|| BlockServiceError::Parse("SSZ response missing ssz_bytes".to_string()))?;
    let format = ssz_block_format(response.is_blinded, &response.consensus_version)?;
    // Blobs-offset failures must happen before the header is signed.
    let contents = if format == beacon::ssz_deser::SszBlockFormat::BlockContents {
        Some(
            beacon::ssz_deser::deserialize_block_contents_ssz(ssz_bytes, format)
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?,
        )
    } else {
        None
    };
    if response.is_blinded {
        let layout = blinded_body_layout(&response.consensus_version)?;
        let (block, _) =
            beacon::ssz_deser::deserialize_blinded_beacon_block_from_ssz(ssz_bytes, format)
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
        validate_response_block(
            validator,
            slot,
            block.slot,
            block.proposer_index,
            block.parent_root,
        )?;
        let block_root = compute_blinded_block_root_for_layout(&block, layout)?;
        let header = header_from_blinded(&block, layout)?;
        require_block_root_matches_header(&header, block_root)?;
        return Ok((header, block_root, PreparedPayload::SszWhole(ssz_bytes.clone())));
    }
    if let Some(contents) = contents.as_ref() {
        let block = &contents.block;
        validate_response_block(
            validator,
            slot,
            block.slot,
            block.proposer_index,
            block.parent_root,
        )?;
        // The header's fork, already cross-checked against the slot. A body
        // that only decodes under another fork is Parse before the signer.
        let layout = full_body_layout(&response.consensus_version)?;
        let block_root = compute_block_root_for_layout(block, layout)?;
        let header = header_from_full(block, layout)?;
        require_block_root_matches_header(&header, block_root)?;
        // ISSUE-4.3 (L-3) defense-in-depth: log internal KZG commitment binding.
        // For Deneb+ BlockContents payloads the body includes blob_kzg_commitments;
        // this fingerprint is an rvc-internal binding (NOT spec-aligned —
        // see kzg_commitment_list_root doc) separate from the signing scope.
        // Fail closed: malformed body must not fingerprint as empty list.
        let kzg_count =
            block.blob_kzg_count(layout).map_err(|e| BlockServiceError::Parse(e.to_string()))?;
        let commitment_root = block
            .kzg_commitment_root(layout)
            .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
        debug!(
            slot = slot,
            kzg_count = kzg_count,
            commitment_root = %TruncatedRoot::new(&commitment_root),
            "SSZ BlockContents: internal KZG commitment binding (ISSUE-4.3)"
        );
        return Ok((
            header,
            block_root,
            PreparedPayload::SszContents {
                block_ssz: contents.block_ssz.to_vec(),
                kzg_proofs: contents.kzg_proofs.to_vec(),
                blobs: contents.blobs.to_vec(),
            },
        ));
    }
    // Pre-Deneb full SSZ lands here and fails in `full_body_layout`.
    // Blinded SSZ already returned. This arm does not publish a pre-Deneb block.
    let (block, _) = beacon::ssz_deser::deserialize_beacon_block_from_ssz(ssz_bytes, format)
        .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
    validate_response_block(validator, slot, block.slot, block.proposer_index, block.parent_root)?;
    let layout = full_body_layout(&response.consensus_version)?;
    let block_root = compute_block_root_for_layout(&block, layout)?;
    let header = header_from_full(&block, layout)?;
    require_block_root_matches_header(&header, block_root)?;
    Ok((header, block_root, PreparedPayload::SszWhole(ssz_bytes.clone())))
}

fn prepare_full(
    response: &ProduceBlockResponse,
    slot: Slot,
    validator: Option<&BlockResponseValidator>,
) -> Result<(BeaconBlockHeaderFields, Root, PreparedPayload), BlockServiceError> {
    let block_contents = response.parse_full_block()?;
    let block = block_contents.block().clone();
    validate_response_block(validator, slot, block.slot, block.proposer_index, block.parent_root)?;

    // ISSUE-4.3 (L-3) defense-in-depth: bind blob KZG commitments canonically.
    //
    // The signing scope is the spec block root (`hash_tree_root` over the
    // typed Electra body — SEC-6c). Here we additionally parse the
    // commitments, compute an internal list fingerprint, and verify that the
    // commitment count in the body matches the number of blobs.
    // This does NOT change the BN-facing signing scope; it is a rvc-internal
    // consistency check performed before the signature is created.
    //
    // Proof cardinality is separate and fail-closed, before the signer is
    // called. It uses the fork name: `body_fork_layout` maps Fulu to Electra,
    // which would apply the one-proof rule to cell proofs. The commitment-count
    // check below stays warn-only.
    if let eth_types::BlockContents::BlockAndBlobs { ref kzg_proofs, ref blobs, .. } =
        block_contents
    {
        let proof_count = kzg_proofs.len();
        let blob_count = blobs.len();
        let consensus_version = &response.consensus_version;
        let fork = ForkName::from_str(consensus_version).map_err(|_| {
            BlockServiceError::Parse(format!(
                "kzg proof cardinality: unknown fork {consensus_version} ({proof_count} proofs, {blob_count} blobs)"
            ))
        })?;
        let expected = eth_types::expected_kzg_proof_count(fork, blob_count).map_err(|e| {
            BlockServiceError::Parse(format!(
                "kzg proof cardinality is not defined for fork {consensus_version} ({proof_count} proofs, {blob_count} blobs): {e}"
            ))
        })?;
        if proof_count != expected {
            return Err(BlockServiceError::Parse(format!(
                "kzg proof cardinality mismatch for fork {consensus_version}: expected {expected} proofs, got {proof_count} proofs for {blob_count} blobs"
            )));
        }
        let layout = eth_types::body_fork_layout(consensus_version).ok_or_else(|| {
            BlockServiceError::Parse(format!(
                "no JSON body layout for consensus version {consensus_version}"
            ))
        })?;
        // Fail closed: malformed body must not fingerprint as empty list.
        let kzg_commitments = block_contents
            .blob_kzg_commitments(layout)
            .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
        let commitment_root = eth_types::kzg_commitment_list_root(&kzg_commitments);
        debug!(
            slot = slot,
            blobs = blob_count,
            kzg_in_body = kzg_commitments.len(),
            commitment_root = %TruncatedRoot::new(&commitment_root),
            "BlockAndBlobs: internal KZG commitment binding (ISSUE-4.3)"
        );
        // Intentionally warn-only: the signing scope covers the typed body
        // (self-consistent). Sidecar propagation is the BN's responsibility.
        // Aborting here would drop proposals on legitimate BN inconsistencies
        // during fork transitions.
        if kzg_commitments.len() != blob_count {
            warn!(
                slot = slot,
                kzg_in_body = kzg_commitments.len(),
                blobs = blob_count,
                "blob KZG commitment count mismatch — body inconsistent with blobs"
            );
        }
    }

    let layout = full_body_layout(&response.consensus_version)?;
    let block_root = compute_block_root_for_layout(&block, layout)?;
    let header = header_from_full(&block, layout)?;
    require_block_root_matches_header(&header, block_root)?;
    Ok((header, block_root, PreparedPayload::Json(block_contents)))
}

fn prepare_blinded(
    response: &ProduceBlockResponse,
    slot: Slot,
    validator: Option<&BlockResponseValidator>,
) -> Result<(BeaconBlockHeaderFields, Root, PreparedPayload), BlockServiceError> {
    let block = response.parse_blinded_block()?;
    validate_response_block(validator, slot, block.slot, block.proposer_index, block.parent_root)?;
    let layout = blinded_body_layout(&response.consensus_version)?;
    let block_root = compute_blinded_block_root_for_layout(&block, layout)?;
    let header = header_from_blinded(&block, layout)?;
    require_block_root_matches_header(&header, block_root)?;
    Ok((header, block_root, PreparedPayload::Blinded(block)))
}

/// Slot, proposer, and parent checks without a log. The caller logs once.
fn validate_response_block(
    validator: Option<&BlockResponseValidator>,
    slot: Slot,
    got_slot: Slot,
    proposer_index: u64,
    parent_root: Root,
) -> Result<(), BlockServiceError> {
    if got_slot != slot {
        return Err(BlockServiceError::SlotMismatch { requested: slot, got: got_slot });
    }
    if let Some(validator) = validator {
        validator.validate(proposer_index, parent_root)?;
    }
    Ok(())
}

/// [`check_mode_shape`], with builder-only rewritten to [`BlockServiceError::BuilderOnly`].
///
/// The coordinator records a builder miss only for `BuilderOnly` and
/// `BuilderFailure`. A shape rejection under builder-only stays on that path
/// and names the shape. Execution-only keeps [`BlockServiceError::ModeShapeMismatch`]
/// so a blinded response does not trip the breaker.
fn enforce_mode_shape(
    mode: BlockSelectionMode,
    shape: CandidateShape,
) -> Result<(), BlockServiceError> {
    match check_mode_shape(mode, shape) {
        Ok(()) => Ok(()),
        Err(_) => {
            note_shape_rejection(mode, shape);
            if mode == BlockSelectionMode::BuilderOnly {
                Err(BlockServiceError::BuilderOnly(format!(
                    "response shape {shape} contradicts builder-only"
                )))
            } else {
                Err(BlockServiceError::ModeShapeMismatch { mode, shape })
            }
        }
    }
}

fn note_shape_rejection(mode: BlockSelectionMode, shape: CandidateShape) {
    let inc = || {
        RVC_BLOCK_SHAPE_REJECTIONS_TOTAL
            .with_label_values(&[&mode.to_string(), &shape.to_string()])
            .inc();
    };
    #[cfg(test)]
    {
        with_shape_rejection_lock(inc);
    }
    #[cfg(not(test))]
    {
        inc();
    }
}

/// One pre-sign check for every produce arm that logs on its own.
///
/// Slot is compared to the duty first. Proposer index and parent root run only
/// when a validator is present (`propose_block_with_mode` passes `None`). A
/// rejection is logged at WARN and returned; the signer is not called.
/// The pre-Gloas candidate walk uses [`validate_response_block`] and logs once
/// itself, so this function is the V4 path.
fn check_response_block(
    validator: Option<&BlockResponseValidator>,
    slot: Slot,
    got_slot: Slot,
    proposer_index: u64,
    parent_root: Root,
) -> Result<(), BlockServiceError> {
    validate_response_block(validator, slot, got_slot, proposer_index, parent_root).map_err(|err| {
        warn!(slot, error = %err, "BN block response rejected");
        err
    })
}

/// Encode a signed block plus the produce-time arrays. The signed block is not published.
fn signed_block_contents_json(
    block: eth_types::BeaconBlock,
    signature: Vec<u8>,
    kzg_proofs: Vec<Vec<u8>>,
    blobs: Vec<Vec<u8>>,
    layout: eth_types::BodyForkLayout,
) -> Result<eth_types::SignedBlockContentsJson, BlockServiceError> {
    let signed = eth_types::SignedBeaconBlock { message: block, signature };
    eth_types::SignedBlockContentsJson::from_signed_block(&signed, kzg_proofs, blobs, layout)
        .map_err(|err| BlockServiceError::Parse(err.to_string()))
}

/// Island envelope root needs SSZ. JSON is accepted only as hex-encoded SSZ.
fn envelope_ssz_for_island(body: &WireBody) -> Result<Vec<u8>, BlockServiceError> {
    match body {
        WireBody::Ssz(bytes) => Ok(bytes.clone()),
        WireBody::Json(serde_json::Value::String(s)) => {
            let hex_str = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(hex_str).map_err(|e| {
                BlockServiceError::Parse(format!(
                    "JSON execution payload envelope is not island SSZ: {e}"
                ))
            })
        }
        WireBody::Json(_) => Err(BlockServiceError::Parse(
            "JSON execution payload envelope is not island SSZ".to_string(),
        )),
    }
}

fn signed_envelope_wire(
    unsigned: &WireBody,
    signature: &[u8],
) -> Result<WireBody, BlockServiceError> {
    match unsigned {
        WireBody::Ssz(ssz) => {
            let framed = beacon::ssz_deser::serialize_signed_beacon_block_ssz(ssz, signature)
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
            Ok(WireBody::Ssz(framed))
        }
        WireBody::Json(message) => Ok(WireBody::Json(serde_json::json!({
            "message": message,
            "signature": format!("0x{}", hex::encode(signature)),
        }))),
    }
}

/// Gloas header leaves + proposal root from the island, never Electra/Deneb HTR.
fn gloas_header_and_root(
    block: &eth_types::BeaconBlock,
) -> Result<(BeaconBlockHeaderFields, Root), BlockServiceError> {
    let body_root = rvc_gloas::gloas_body_root(&block.body)?;
    let header = BeaconBlockHeaderFields {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root,
        body_ssz: block.body.clone(),
        is_blinded: false,
    };
    let block_root = rvc_gloas::gloas_block_root(
        &rvc_gloas::HeaderFields {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
        },
        &block.body,
    )?;
    // libssz vs tree_hash 0.9 must not sign one root and return the other.
    if header.object_root() != block_root {
        return Err(BlockServiceError::Parse(
            "Gloas island block root diverged from header object_root".to_string(),
        ));
    }
    Ok((header, block_root))
}

fn header_from_full(
    block: &eth_types::BeaconBlock,
    layout: eth_types::BodyForkLayout,
) -> Result<BeaconBlockHeaderFields, BlockServiceError> {
    let body_root = eth_types::body_tree_hash_root_for_layout(&block.body, layout)
        .map(|h| h.0)
        .map_err(|e| BlockServiceError::Parse(format!("invalid block body for body leaf: {e}")))?;
    Ok(BeaconBlockHeaderFields {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root,
        body_ssz: block.body.clone(),
        is_blinded: false,
    })
}

/// Layout named by the header. Pre-Deneb has none; trial decoding is not used.
fn full_body_layout(
    consensus_version: &str,
) -> Result<eth_types::BodyForkLayout, BlockServiceError> {
    eth_types::body_fork_layout(consensus_version).ok_or_else(|| {
        BlockServiceError::Parse(format!(
            "full block body is unsupported for consensus version {consensus_version}"
        ))
    })
}

fn blinded_body_layout(
    consensus_version: &str,
) -> Result<eth_types::BodyForkLayout, BlockServiceError> {
    eth_types::body_fork_layout(consensus_version).ok_or_else(|| {
        BlockServiceError::Parse(format!(
            "JSON blinded block is unsupported for consensus version {consensus_version}"
        ))
    })
}

/// `tree_hash` 0.9 of the header must be the block root that was hashed.
fn require_block_root_matches_header(
    header: &BeaconBlockHeaderFields,
    block_root: Root,
) -> Result<(), BlockServiceError> {
    if header.object_root() != block_root {
        return Err(BlockServiceError::Parse(
            "block root diverged from header object_root".to_string(),
        ));
    }
    Ok(())
}

fn header_from_blinded(
    block: &eth_types::BlindedBeaconBlock,
    layout: eth_types::BodyForkLayout,
) -> Result<BeaconBlockHeaderFields, BlockServiceError> {
    let body_root = eth_types::blinded_body_tree_hash_root_for_layout(&block.body, layout)
        .map(|h| h.0)
        .map_err(|e| {
            BlockServiceError::Parse(format!("invalid blinded block body for body leaf: {e}"))
        })?;
    Ok(BeaconBlockHeaderFields {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root,
        body_ssz: block.body.clone(),
        is_blinded: true,
    })
}

/// Spec `hash_tree_root(BeaconBlock)` with the header's [`eth_types::BodyForkLayout`].
///
/// Production proposal path. Auto-detect would sign a Deneb body under an
/// Electra or Fulu header. Malformed body SSZ is [`BlockServiceError::Parse`].
fn compute_block_root_for_layout(
    block: &eth_types::BeaconBlock,
    layout: eth_types::BodyForkLayout,
) -> Result<Root, BlockServiceError> {
    block.try_tree_hash_root_for_layout(layout).map(|h| h.0).map_err(|e| {
        BlockServiceError::Parse(format!("invalid block body for tree_hash_root: {e}"))
    })
}

/// Auto-detect body fork. Tests only; production uses [`compute_block_root_for_layout`].
#[cfg(test)]
fn compute_block_root(block: &eth_types::BeaconBlock) -> Result<Root, BlockServiceError> {
    block.try_tree_hash_root().map(|h| h.0).map_err(|e| {
        BlockServiceError::Parse(format!("invalid block body for tree_hash_root: {e}"))
    })
}

/// Spec `hash_tree_root(BlindedBeaconBlock)` via typed Electra/Deneb body leaf (SEC-6c/6d).
///
/// **Production root path** for blinded proposal signing (prefer this over
/// `TreeHash::tree_hash_root`). Malformed body → [`BlockServiceError::Parse`].
#[cfg(test)]
fn compute_blinded_block_root(
    block: &eth_types::BlindedBeaconBlock,
) -> Result<Root, BlockServiceError> {
    block.try_tree_hash_root().map(|h| h.0).map_err(|e| {
        BlockServiceError::Parse(format!("invalid blinded block body for tree_hash_root: {e}"))
    })
}

/// Block root for the layout `consensus_version` names.
///
/// Auto-detect would sign a Deneb body under an Electra header and only fail
/// when the publish encoder demands the header's layout.
fn compute_blinded_block_root_for_layout(
    block: &eth_types::BlindedBeaconBlock,
    layout: eth_types::BodyForkLayout,
) -> Result<Root, BlockServiceError> {
    block.try_tree_hash_root_for_layout(layout).map(|h| h.0).map_err(|e| {
        BlockServiceError::Parse(format!("invalid blinded block body for tree_hash_root: {e}"))
    })
}

/// Determines the SSZ wire format based on block type and consensus version.
///
/// - Blinded blocks are always raw `BeaconBlock` SSZ (all known forks).
/// - Unblinded Deneb/Electra/Fulu use `BlockContents` (block + kzg_proofs + blobs).
/// - Unblinded Gloas uses a named `BeaconBlock` arm (bare `SignedBeaconBlock`).
/// - Unknown versions fail closed — they must not inherit a layout.
fn ssz_block_format(
    is_blinded: bool,
    consensus_version: &str,
) -> Result<beacon::ssz_deser::SszBlockFormat, BlockServiceError> {
    use beacon::ssz_deser::SszBlockFormat;
    let fork = ForkName::from_str(consensus_version).map_err(|_| {
        BlockServiceError::UnknownSszConsensusVersion(consensus_version.to_string())
    })?;
    if is_blinded {
        return Ok(SszBlockFormat::BeaconBlock);
    }
    // Named Gloas arm is intentionally separate from pre-Deneb: a new fork
    // must not inherit BeaconBlock via a shared catch-all (issue 6.4).
    #[allow(clippy::match_same_arms)]
    let format = match fork {
        ForkName::Deneb | ForkName::Electra | ForkName::Fulu => SszBlockFormat::BlockContents,
        ForkName::Gloas => SszBlockFormat::BeaconBlock,
        ForkName::Phase0 | ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
            SszBlockFormat::BeaconBlock
        }
    };
    Ok(format)
}

/// Blinded production is pre-Gloas only. Slot fork or `Eth-Consensus-Version`
/// of Gloas both fail closed so a mis-advertised header cannot sign blinded.
fn reject_blinded_at_gloas(
    is_blinded: bool,
    consensus_version: &str,
    slot: Slot,
    fork_schedule: &ForkSchedule,
) -> Result<(), BlockServiceError> {
    if !is_blinded {
        return Ok(());
    }
    let slot_fork = ForkName::from_epoch(slot / SLOTS_PER_EPOCH, fork_schedule);
    if slot_fork >= ForkName::Gloas || consensus_version == "gloas" {
        error!(slot = slot, consensus_version, "Blinded block at Gloas — dropping duty");
        return Err(BlockServiceError::BlindedNotSupportedAtGloas { slot });
    }
    Ok(())
}

/// Pre-Gloas slots must not Electra/Deneb-hash a Gloas-versioned body.
fn reject_gloas_version_pre_gloas(
    consensus_version: &str,
    slot_fork: ForkName,
) -> Result<(), BlockServiceError> {
    if slot_fork >= ForkName::Gloas {
        return Ok(());
    }
    if let Ok(got) = ForkName::from_str(consensus_version) {
        if got >= ForkName::Gloas {
            return Err(BlockServiceError::ConsensusVersionMismatch {
                expected: slot_fork.as_ref().to_string(),
                got: got.as_ref().to_string(),
            });
        }
    }
    Ok(())
}

/// Header-derived fork is a cross-check only: mismatch drops the duty unsigned.
fn cross_check_consensus_version(got: &str, expected: ForkName) -> Result<(), BlockServiceError> {
    match ForkName::from_str(got) {
        Ok(parsed) if parsed == expected => Ok(()),
        _ => Err(BlockServiceError::ConsensusVersionMismatch {
            expected: expected.as_ref().to_string(),
            got: got.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests;
