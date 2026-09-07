use std::str::FromStr;
use std::sync::Arc;

use tracing::{debug, error, info, warn, Instrument};

use crypto::PublicKey;
use eth_types::{
    blinded_body_tree_hash_root, body_tree_hash_root, ForkName, ForkSchedule, Root, Slot,
    SLOTS_PER_EPOCH,
};
use observability::logging::{TruncatedPubkey, TruncatedRoot};
use signer::{BeaconBlockHeaderFields, CircuitBreakerState, ValidatorSigner};
use validator_store::ValidatorStore;

use crate::traits::{
    BeaconBlockClient, BuilderConfig, BuilderConfigProvider, ProduceBlockResponse,
};
use crate::types::BlockSelectionMode;
use crate::validation::BlockResponseValidator;
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

    async fn v4_builder_config(&self, pubkey: &[u8; 48], slot: Slot, boost: u64) -> BuilderConfig {
        let mut config = match &self.builder_config_provider {
            Some(provider) => provider.builder_config_for(pubkey, slot).await,
            None => BuilderConfig {
                min_bid: self.validator_store.min_bid(pubkey),
                builder_boost_factor: boost,
                builders: Vec::new(),
            },
        };
        config.builder_boost_factor = boost;
        config.min_bid = self.validator_store.min_bid(pubkey);
        config
    }

    /// Propose a block for the given duty slot and validator key.
    ///
    /// Validates `proposer_index` against `expected_proposer_index` and, when
    /// `expected_parent_root` is `Some`, validates `parent_root` against the
    /// previous-slot parent before calling the signer. On validation failure the
    /// duty is dropped with an `error!` log and no signer call is made (H-4).
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
    pub async fn propose_block(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        expected_proposer_index: u64,
        expected_parent_root: Option<Root>,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        let mode = self.validator_store.effective_block_selection_mode(&pubkey.to_bytes());
        let validator = BlockResponseValidator {
            expected_proposer_index,
            expected_parent_root,
            expected_slot: slot,
        };
        self.propose_block_impl(slot, pubkey, mode, Some(&validator)).await
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
        self.propose_block_impl(slot, pubkey, mode, None).await
    }

    async fn propose_block_impl(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        mode: BlockSelectionMode,
        validator: Option<&BlockResponseValidator>,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let proposal_start = std::time::Instant::now();

        info!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), %mode, "Block proposal started");

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork = ForkName::from_epoch(epoch, &self.fork_schedule);

        // 1. Sign RANDAO reveal
        let randao_start = std::time::Instant::now();
        let randao_sig = self
            .signer
            .sign_randao_reveal(epoch, pubkey, &self.fork_schedule, &self.genesis_validators_root)
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
                .produce_block_v4(slot, &randao_hex, graffiti_hex.as_deref(), &builder_config)
                .instrument(tracing::info_span!("beacon.produce_block_v4"))
                .await
        } else {
            self.beacon
                .produce_block_v3(slot, &randao_hex, graffiti_hex.as_deref(), Some(boost))
                .instrument(tracing::info_span!("beacon.produce_block_v3"))
                .await
        };

        // Handle block-production failure, tagging the error so the coordinator
        // can apply H-3 circuit-breaker scoping.
        let response = match produce_result {
            Ok(resp) => resp,
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

        // Record dynamic attributes after block production
        let span = tracing::Span::current();
        span.record("block.consensus_version", &response.consensus_version);
        if let Some(ref value) = response.execution_payload_value {
            span.record("block.value_wei", value.as_str());
        }

        if fork >= ForkName::Gloas {
            info!(
                slot = slot,
                fork = fork.as_ref(),
                execution_payload_value =
                    response.execution_payload_value.as_deref().unwrap_or("none"),
                "Block production response received"
            );
        } else {
            info!(
                slot = slot,
                is_blinded = response.is_blinded,
                execution_payload_value =
                    response.execution_payload_value.as_deref().unwrap_or("none"),
                "Block production response received"
            );
            span.record("block.blinded", response.is_blinded);
        }

        // 4. Sign and publish. Fork is resolved from the slot; V4 never
        // dispatches on `Eth-Consensus-Version` or `is_blinded`.
        // D29: this `response` is committed once a signature exists — no
        // re-production and no second sign for the slot. Publish keeps the
        // existing broadcast/submit policy; envelope publish (6.20) must use
        // the same bytes.
        let (block_root, is_blinded) = if fork >= ForkName::Gloas {
            self.sign_and_publish_v4(&response, slot, pubkey, validator, fork).await
        } else {
            reject_blinded_at_gloas(
                response.is_blinded,
                &response.consensus_version,
                slot,
                &self.fork_schedule,
            )?;
            reject_gloas_version_pre_gloas(&response.consensus_version, fork)?;
            // Pre-Gloas keeps response.consensus_version for format/publish (V3 verbatim).
            debug!(slot = slot, is_blinded = response.is_blinded, "Blinded/unblinded path chosen");
            if response.is_ssz {
                self.sign_and_publish_ssz(
                    &response,
                    slot,
                    pubkey,
                    validator,
                    response.is_blinded,
                    &response.consensus_version,
                )
                .await
            } else if response.is_blinded {
                self.sign_and_publish_blinded(&response, slot, pubkey, validator).await
            } else {
                self.sign_and_publish_full(
                    &response,
                    slot,
                    pubkey,
                    validator,
                    &response.consensus_version,
                )
                .await
            }
        }
        .map_err(|e| {
            error!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), error = %e, "Block publication failed");
            e
        })?;

        info!(
            slot = slot,
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            block_root = %TruncatedRoot::new(&block_root),
            is_blinded = is_blinded,
            duration_ms = proposal_start.elapsed().as_millis() as u64,
            "Block publication success"
        );

        Ok(BlockProposalResult {
            slot,
            block_root,
            is_blinded,
            consensus_version: response.consensus_version,
            value_wei: response.execution_payload_value,
        })
    }

    /// Gloas V4 sign+publish: slot-resolved `fork` only. Self-build vs builder-win is 6.20.
    async fn sign_and_publish_v4(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
        fork: ForkName,
    ) -> Result<(Root, bool), BlockServiceError> {
        cross_check_consensus_version(&response.consensus_version, fork)?;
        // Envelope BlockContents parse is 6.18; fail closed rather than Electra-hash.
        if response.payload_included {
            return Err(BlockServiceError::Parse(
                "Gloas payload_included body requires BlockContents parse (6.18)".to_string(),
            ));
        }
        if response.is_ssz {
            self.sign_and_publish_ssz_gloas(response, slot, pubkey, validator, fork).await
        } else {
            self.sign_and_publish_json_gloas(response, slot, pubkey, validator, fork).await
        }
    }

    async fn sign_and_publish_json_gloas(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
        fork: ForkName,
    ) -> Result<(Root, bool), BlockServiceError> {
        let block_contents = response.parse_full_block()?;
        let block = block_contents.block().clone();
        if block.slot != slot {
            return Err(BlockServiceError::SlotMismatch { requested: slot, got: block.slot });
        }
        if let Some(v) = validator {
            v.validate_full(&block).map_err(|e| {
                error!(slot = slot, error = %e, "BN block response validation failed — dropping duty");
                e
            })?;
        }
        let (header, block_root) = gloas_header_and_root(&block)?;
        let sig = self
            .signer
            .sign_block_header(&header, pubkey, &self.fork_schedule, &self.genesis_validators_root)
            .instrument(tracing::info_span!("sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        let signed =
            eth_types::SignedBeaconBlock { message: block, signature: sig.to_bytes().to_vec() };
        self.beacon
            .publish_block(&signed, fork.as_ref(), response.builder_url.as_deref())
            .instrument(tracing::info_span!("beacon.publish_block"))
            .await?;
        Ok((block_root, false))
    }

    async fn sign_and_publish_ssz_gloas(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
        fork: ForkName,
    ) -> Result<(Root, bool), BlockServiceError> {
        let ssz_bytes = response.ssz_bytes.as_ref().ok_or_else(|| {
            BlockServiceError::Parse("SSZ response missing ssz_bytes".to_string())
        })?;
        let format = beacon::ssz_deser::SszBlockFormat::BeaconBlock;
        let (block, block_data_offset) =
            beacon::ssz_deser::deserialize_beacon_block_from_ssz(ssz_bytes, format)
                .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
        if block.slot != slot {
            return Err(BlockServiceError::Parse(format!(
                "SSZ block slot mismatch: header has {}, expected {}",
                block.slot, slot,
            )));
        }
        if let Some(v) = validator {
            v.validate_full(&block).map_err(|e| {
                error!(slot = slot, error = %e, "BN SSZ block validation failed — dropping duty");
                e
            })?;
        }
        let (header, block_root) = gloas_header_and_root(&block)?;
        let sig = self
            .signer
            .sign_block_header(&header, pubkey, &self.fork_schedule, &self.genesis_validators_root)
            .instrument(tracing::info_span!("sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        let block_ssz = &ssz_bytes[block_data_offset..];
        let message_offset: u32 = 100;
        let mut signed_ssz = Vec::with_capacity(100 + block_ssz.len());
        signed_ssz.extend_from_slice(&message_offset.to_le_bytes());
        signed_ssz.extend_from_slice(&sig.to_bytes());
        signed_ssz.extend_from_slice(block_ssz);
        self.beacon
            .publish_block_ssz(&signed_ssz, fork.as_ref(), false, response.builder_url.as_deref())
            .instrument(tracing::info_span!("beacon.publish_block"))
            .await?;
        Ok((block_root, false))
    }

    async fn sign_and_publish_ssz(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
        is_blinded: bool,
        consensus_version: &str,
    ) -> Result<(Root, bool), BlockServiceError> {
        let ssz_bytes = response.ssz_bytes.as_ref().ok_or_else(|| {
            BlockServiceError::Parse("SSZ response missing ssz_bytes".to_string())
        })?;

        let format = ssz_block_format(is_blinded, consensus_version)?;
        let (block_root, block_data_offset, header): (Root, usize, BeaconBlockHeaderFields) =
            if is_blinded {
                let (block, offset) =
                    beacon::ssz_deser::deserialize_blinded_beacon_block_from_ssz(ssz_bytes, format)
                        .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                if block.slot != slot {
                    return Err(BlockServiceError::Parse(format!(
                        "SSZ block slot mismatch: header has {}, expected {}",
                        block.slot, slot,
                    )));
                }
                if let Some(v) = validator {
                    v.validate_blinded(&block).map_err(|e| {
                    error!(slot = slot, error = %e, "BN SSZ blinded block validation failed — dropping duty");
                    e
                })?;
                }
                (compute_blinded_block_root(&block)?, offset, header_from_blinded(&block)?)
            } else {
                let (block, offset) =
                    beacon::ssz_deser::deserialize_beacon_block_from_ssz(ssz_bytes, format)
                        .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                if block.slot != slot {
                    return Err(BlockServiceError::Parse(format!(
                        "SSZ block slot mismatch: header has {}, expected {}",
                        block.slot, slot,
                    )));
                }
                if let Some(v) = validator {
                    v.validate_full(&block).map_err(|e| {
                    error!(slot = slot, error = %e, "BN SSZ block validation failed — dropping duty");
                    e
                })?;
                }
                // ISSUE-4.3 (L-3) defense-in-depth: log internal KZG commitment binding.
                // For Deneb+ BlockContents payloads the body includes blob_kzg_commitments;
                // this fingerprint is an rvc-internal binding (NOT spec-aligned —
                // see kzg_commitment_list_root doc) separate from the signing scope.
                if format == beacon::ssz_deser::SszBlockFormat::BlockContents {
                    if let Some(layout) = eth_types::body_fork_layout(consensus_version) {
                        // Fail closed: malformed body must not fingerprint as empty list.
                        let kzg_count = block
                            .blob_kzg_count(layout)
                            .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                        let commitment_root = block
                            .kzg_commitment_root(layout)
                            .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                        debug!(
                            slot = slot,
                            kzg_count = kzg_count,
                            commitment_root = %TruncatedRoot::new(&commitment_root),
                            "SSZ BlockContents: internal KZG commitment binding (ISSUE-4.3)"
                        );
                    }
                }
                (compute_block_root(&block)?, offset, header_from_full(&block)?)
            };

        let sign_start = std::time::Instant::now();
        let sig = self
            .signer
            .sign_block_header(&header, pubkey, &self.fork_schedule, &self.genesis_validators_root)
            .instrument(tracing::info_span!("sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        debug!(
            slot = slot,
            duration_ms = sign_start.elapsed().as_millis() as u64,
            "Block signing duration"
        );

        // Construct SignedBeaconBlock SSZ:
        // [message_offset: 4 bytes LE] [signature: 96 bytes] [BeaconBlock SSZ bytes]
        let block_ssz = &ssz_bytes[block_data_offset..];
        let message_offset: u32 = 100; // 4 (offset) + 96 (signature)
        let mut signed_ssz = Vec::with_capacity(100 + block_ssz.len());
        signed_ssz.extend_from_slice(&message_offset.to_le_bytes());
        // Wire boundary: SSZ SignedBeaconBlock encodes raw 96-byte BLS signature.
        signed_ssz.extend_from_slice(&sig.to_bytes());
        signed_ssz.extend_from_slice(block_ssz);

        self.beacon
            .publish_block_ssz(
                &signed_ssz,
                consensus_version,
                is_blinded,
                response.builder_url.as_deref(),
            )
            .instrument(tracing::info_span!("beacon.publish_block"))
            .await?;

        Ok((block_root, is_blinded))
    }

    async fn sign_and_publish_full(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
        consensus_version: &str,
    ) -> Result<(Root, bool), BlockServiceError> {
        let block_contents = response.parse_full_block()?;
        let block = block_contents.block().clone();

        if block.slot != slot {
            return Err(BlockServiceError::SlotMismatch { requested: slot, got: block.slot });
        }

        // H-4: validate proposer_index and parent_root before signing.
        if let Some(v) = validator {
            v.validate_full(&block).map_err(|e| {
                error!(slot = slot, error = %e, "BN block response validation failed — dropping duty");
                e
            })?;
        }

        // ISSUE-4.3 (L-3) defense-in-depth: bind blob KZG commitments canonically.
        //
        // The signing scope is the spec block root (`hash_tree_root` over the
        // typed Electra body — SEC-6c). Here we additionally parse the
        // commitments, compute an internal list fingerprint, and verify that the
        // commitment count in the body matches the number of blob sidecars.
        // This does NOT change the BN-facing signing scope; it is a rvc-internal
        // consistency check performed before the signature is created.
        if let eth_types::BlockContents::BlockAndBlobs { ref blob_sidecars, .. } = block_contents {
            if let Some(layout) = eth_types::body_fork_layout(consensus_version) {
                // Fail closed: malformed body must not fingerprint as empty list.
                let kzg_commitments = block_contents
                    .blob_kzg_commitments(layout)
                    .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
                let commitment_root = eth_types::kzg_commitment_list_root(&kzg_commitments);
                debug!(
                    slot = slot,
                    blob_sidecars = blob_sidecars.len(),
                    kzg_in_body = kzg_commitments.len(),
                    commitment_root = %TruncatedRoot::new(&commitment_root),
                    "BlockAndBlobs: internal KZG commitment binding (ISSUE-4.3)"
                );
                // Intentionally warn-only: the signing scope covers the typed body
                // (self-consistent). Sidecar propagation is the BN's responsibility.
                // Aborting here would drop proposals on legitimate BN inconsistencies
                // during fork transitions.
                if kzg_commitments.len() != blob_sidecars.len() {
                    warn!(
                        slot = slot,
                        kzg_in_body = kzg_commitments.len(),
                        sidecars = blob_sidecars.len(),
                        "blob KZG commitment count mismatch — body inconsistent with sidecars"
                    );
                }
            }
        }

        let block_root = compute_block_root(&block)?;
        let header = header_from_full(&block)?;

        let sign_start = std::time::Instant::now();
        let sig = self
            .signer
            .sign_block_header(&header, pubkey, &self.fork_schedule, &self.genesis_validators_root)
            .instrument(tracing::info_span!("sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        debug!(
            slot = slot,
            duration_ms = sign_start.elapsed().as_millis() as u64,
            "Block signing duration"
        );

        // Wire boundary: eth_types::Signature is Vec<u8> for JSON/SSZ serde.
        let signed =
            eth_types::SignedBeaconBlock { message: block, signature: sig.to_bytes().to_vec() };
        self.beacon
            .publish_block(&signed, consensus_version, response.builder_url.as_deref())
            .instrument(tracing::info_span!("beacon.publish_block"))
            .await?;

        Ok((block_root, false))
    }

    async fn sign_and_publish_blinded(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
        validator: Option<&BlockResponseValidator>,
    ) -> Result<(Root, bool), BlockServiceError> {
        reject_blinded_at_gloas(true, &response.consensus_version, slot, &self.fork_schedule)?;
        let block = response.parse_blinded_block()?;

        if block.slot != slot {
            return Err(BlockServiceError::SlotMismatch { requested: slot, got: block.slot });
        }

        // H-4: validate proposer_index and parent_root before signing.
        if let Some(v) = validator {
            v.validate_blinded(&block).map_err(|e| {
                error!(slot = slot, error = %e, "BN blinded block response validation failed — dropping duty");
                e
            })?;
        }

        let block_root = compute_blinded_block_root(&block)?;
        let header = header_from_blinded(&block)?;

        let sign_start = std::time::Instant::now();
        let sig = self
            .signer
            .sign_block_header(&header, pubkey, &self.fork_schedule, &self.genesis_validators_root)
            .instrument(tracing::info_span!("sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        debug!(
            slot = slot,
            duration_ms = sign_start.elapsed().as_millis() as u64,
            "Block signing duration"
        );

        // Wire boundary: eth_types::Signature is Vec<u8> for JSON/SSZ serde.
        let signed = eth_types::SignedBlindedBeaconBlock {
            message: block,
            signature: sig.to_bytes().to_vec(),
        };
        self.beacon
            .publish_blinded_block(&signed, &response.consensus_version)
            .instrument(tracing::info_span!("beacon.publish_block"))
            .await?;

        Ok((block_root, true))
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
) -> Result<BeaconBlockHeaderFields, BlockServiceError> {
    let body_root = body_tree_hash_root(&block.body)
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

fn header_from_blinded(
    block: &eth_types::BlindedBeaconBlock,
) -> Result<BeaconBlockHeaderFields, BlockServiceError> {
    let body_root = blinded_body_tree_hash_root(&block.body).map(|h| h.0).map_err(|e| {
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

/// Spec `hash_tree_root(BeaconBlock)` via typed Electra/Deneb body leaf (SEC-6c/6d).
///
/// **Production root path** for proposal signing (prefer this over
/// `TreeHash::tree_hash_root`, which panics on malformed body SSZ).
/// Malformed body SSZ returns [`BlockServiceError::Parse`] rather than panicking.
fn compute_block_root(block: &eth_types::BeaconBlock) -> Result<Root, BlockServiceError> {
    block.try_tree_hash_root().map(|h| h.0).map_err(|e| {
        BlockServiceError::Parse(format!("invalid block body for tree_hash_root: {e}"))
    })
}

/// Spec `hash_tree_root(BlindedBeaconBlock)` via typed Electra/Deneb body leaf (SEC-6c/6d).
///
/// **Production root path** for blinded proposal signing (prefer this over
/// `TreeHash::tree_hash_root`). Malformed body → [`BlockServiceError::Parse`].
fn compute_blinded_block_root(
    block: &eth_types::BlindedBeaconBlock,
) -> Result<Root, BlockServiceError> {
    block.try_tree_hash_root().map(|h| h.0).map_err(|e| {
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
