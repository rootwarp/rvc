use std::sync::Arc;

use tracing::{debug, info, info_span, warn, Instrument, Span};

use crate::metrics::{attestation_status, RVC_AGGREGATIONS_TOTAL};
use beacon::{AttesterDuty, VersionedAggregateAttestation, VersionedSignedAggregateAndProof};
use bn_manager::BeaconNodeClient;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{
    AggregateAndProof, ElectraAggregateAndProof, ForkName, SignedAggregateAndProof,
    SignedElectraAggregateAndProof, Slot,
};
use observability::logging::TruncatedPubkey;
use signer::{is_aggregator, SignerService, ValidatorSigner};
use tree_hash::TreeHash;
use validator_store::ValidatorStore;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::utils::{self, TimedOutcome};

pub(crate) struct AggregationService {
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    /// D-3: per-validator doppelganger gate.  Mirrors the M-12 check already
    /// present in attestation.rs so that aggregation and selection proofs
    /// are also suppressed during the post-import doppelganger window.
    validator_store: Arc<ValidatorStore>,
}

/// Signed aggregate produced for one aggregator duty (fork-discriminated).
enum ProducedAggregate {
    PreElectra(SignedAggregateAndProof),
    Electra(SignedElectraAggregateAndProof),
}

/// Selects the pre-refactor log message set for aggregate submission.
enum AggregateSubmitLabel {
    PreElectra,
    Electra,
}

/// Result of attempting aggregation for a single attester duty.
///
/// `None` means the duty was skipped before selection (parse / disabled / not
/// selected). `Some` means the validator was selected as aggregator; `proof`
/// is `None` when a later step failed after selection (source_validators still
/// records the validator_index — matches pre-refactor behaviour).
struct AggregateDutyOutcome {
    validator_index: String,
    proof: Option<ProducedAggregate>,
}

impl AggregationService {
    pub(crate) fn new(
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
        validator_store: Arc<ValidatorStore>,
    ) -> Self {
        Self { signer, beacon, duty_tracker, pubkey_map, config, validator_store }
    }

    #[tracing::instrument(name = "orchestrator.produce_aggregations", level = "debug", skip_all, fields(slot = slot, epoch = epoch))]
    pub(crate) async fn maybe_produce_aggregations(&self, slot: Slot, epoch: u64) {
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

        let mut pre_electra_aggregates: Vec<SignedAggregateAndProof> = Vec::new();
        let mut electra_aggregates: Vec<SignedElectraAggregateAndProof> = Vec::new();
        let mut source_validators: Vec<String> = Vec::new();

        let fork_label = if fork_name >= ForkName::Fulu {
            "fulu"
        } else if uses_electra_wire {
            "electra"
        } else {
            "pre_electra"
        };

        for duty in &duties {
            let agg_span = info_span!(
                "aggregation.produce",
                slot = slot,
                validator_index = %duty.validator_index,
                pubkey = %TruncatedPubkey::new(&duty.pubkey),
                aggregation.fork = fork_label,
            );

            let Some(outcome) = self.produce_one_aggregate(duty, slot, fork_name, agg_span).await
            else {
                continue;
            };

            source_validators.push(outcome.validator_index);
            match outcome.proof {
                Some(ProducedAggregate::PreElectra(p)) => pre_electra_aggregates.push(p),
                Some(ProducedAggregate::Electra(p)) => electra_aggregates.push(p),
                None => {}
            }
        }

        if !pre_electra_aggregates.is_empty() {
            let versioned = VersionedSignedAggregateAndProof::PreElectra(pre_electra_aggregates);
            self.submit_versioned(
                slot,
                versioned,
                &source_validators,
                AggregateSubmitLabel::PreElectra,
            )
            .await;
        }

        if !electra_aggregates.is_empty() {
            let versioned = if fork_name >= ForkName::Fulu {
                VersionedSignedAggregateAndProof::Fulu(electra_aggregates)
            } else {
                VersionedSignedAggregateAndProof::Electra(electra_aggregates)
            };
            self.submit_versioned(
                slot,
                versioned,
                &source_validators,
                AggregateSubmitLabel::Electra,
            )
            .await;
        }
    }

    /// Select-as-aggregator path for a single duty: selection proof through
    /// signed aggregate-and-proof. Returns `None` when the duty is skipped
    /// before selection; `Some` once selected (proof may still be `None`).
    async fn produce_one_aggregate(
        &self,
        duty: &AttesterDuty,
        slot: Slot,
        fork_name: ForkName,
        agg_span: Span,
    ) -> Option<AggregateDutyOutcome> {
        let committee_length: u64 = duty.committee_length.parse().ok()?;

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

        let selection_proof = match self
            .signer
            .sign_selection_proof(
                slot,
                &pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            )
            .instrument(agg_span.clone())
            .await
        {
            Ok(sig) => sig,
            Err(e) => {
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

        let validator_index = duty.validator_index.clone();
        let proof = self
            .fetch_sign_aggregate(
                duty,
                slot,
                fork_name,
                &pubkey,
                selection_proof.to_bytes().to_vec(),
                agg_span,
            )
            .await;

        Some(AggregateDutyOutcome { validator_index, proof })
    }

    /// Fetch attestation data + aggregate, then sign_and_wrap for the fork.
    async fn fetch_sign_aggregate(
        &self,
        duty: &AttesterDuty,
        slot: Slot,
        fork_name: ForkName,
        pubkey: &PublicKey,
        selection_proof: Vec<u8>,
        agg_span: Span,
    ) -> Option<ProducedAggregate> {
        let uses_electra_wire = utils::uses_electra_attestation_wire(fork_name);
        let committee_index: u64 = duty.committee_index.parse().ok()?;

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

        let aggregator_index: u64 = duty.validator_index.parse().ok()?;

        if uses_electra_wire {
            let electra_agg = match aggregate {
                VersionedAggregateAttestation::Electra(a)
                | VersionedAggregateAttestation::Fulu(a) => a,
                _ => {
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
            let signed = self
                .sign_and_wrap_electra(slot, &duty.validator_index, pubkey, message, agg_span)
                .await?;
            Some(ProducedAggregate::Electra(signed))
        } else {
            let pre_electra_agg = match aggregate {
                VersionedAggregateAttestation::PreElectra(a) => a,
                _ => {
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
                .sign_and_wrap_pre_electra(slot, &duty.validator_index, pubkey, message, agg_span)
                .await?;
            Some(ProducedAggregate::PreElectra(signed))
        }
    }

    /// Tree-hash guard + sign + wrap for pre-Electra aggregate-and-proof.
    ///
    /// Explicit (non-generic) twin of [`Self::sign_and_wrap_electra`]: the two
    /// signer methods and log strings differ; a generic over proof type would
    /// contort more than it saves.
    async fn sign_and_wrap_pre_electra(
        &self,
        slot: Slot,
        validator_index: &str,
        pubkey: &PublicKey,
        message: AggregateAndProof,
        agg_span: Span,
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
        let signature = match self
            .signer
            .sign_aggregate_and_proof(
                &message,
                pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            )
            .instrument(agg_span)
            .await
        {
            Ok(sig) => sig,
            Err(e) => {
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
    async fn sign_and_wrap_electra(
        &self,
        slot: Slot,
        validator_index: &str,
        pubkey: &PublicKey,
        message: ElectraAggregateAndProof,
        agg_span: Span,
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
        let signature = match self
            .signer
            .sign_electra_aggregate_and_proof(
                &message,
                pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            )
            .instrument(agg_span)
            .await
        {
            Ok(sig) => sig,
            Err(e) => {
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

    /// Submit a versioned batch of signed aggregates; shared by pre-Electra and
    /// Electra/Fulu. Log messages stay as static literals (byte-identical to
    /// the pre-refactor paths) via [`AggregateSubmitLabel`].
    async fn submit_versioned(
        &self,
        slot: Slot,
        versioned: VersionedSignedAggregateAndProof,
        source_validators: &[String],
        label: AggregateSubmitLabel,
    ) {
        let count = match &versioned {
            VersionedSignedAggregateAndProof::PreElectra(v) => v.len(),
            VersionedSignedAggregateAndProof::Electra(v)
            | VersionedSignedAggregateAndProof::Fulu(v) => v.len(),
        };
        let source_validators_str = source_validators.join(",");

        let submit_span = info_span!(
            "aggregation.submit",
            slot = slot,
            aggregation.count = count,
            aggregation.source_validators = %source_validators_str,
        );

        match utils::timed(
            "aggregate_submit",
            self.config.timeouts.aggregate_submit,
            self.beacon.submit_aggregate_and_proofs(&versioned),
        )
        .instrument(submit_span)
        .await
        {
            TimedOutcome::Ok(()) => {
                match label {
                    AggregateSubmitLabel::PreElectra => {
                        info!(slot, count, "Submitted aggregate and proofs");
                    }
                    AggregateSubmitLabel::Electra => {
                        info!(slot, count, "Submitted Electra aggregate and proofs");
                    }
                }
                RVC_AGGREGATIONS_TOTAL
                    .with_label_values(&[attestation_status::SUCCESS])
                    .inc_by(count as u64);
            }
            TimedOutcome::Err(e) => {
                match label {
                    AggregateSubmitLabel::PreElectra => {
                        warn!(slot, error = %e, "Failed to submit aggregate and proofs");
                    }
                    AggregateSubmitLabel::Electra => {
                        warn!(slot, error = %e, "Failed to submit Electra aggregate and proofs");
                    }
                }
                RVC_AGGREGATIONS_TOTAL
                    .with_label_values(&[attestation_status::FAILED])
                    .inc_by(count as u64);
            }
            TimedOutcome::Timeout => {
                match label {
                    AggregateSubmitLabel::PreElectra => {
                        warn!(
                            slot,
                            "Aggregate and proofs submit timed out after {}s",
                            self.config.timeouts.aggregate_submit.as_secs()
                        );
                    }
                    AggregateSubmitLabel::Electra => {
                        warn!(
                            slot,
                            "Electra aggregate and proofs submit timed out after {}s",
                            self.config.timeouts.aggregate_submit.as_secs()
                        );
                    }
                }
                RVC_AGGREGATIONS_TOTAL
                    .with_label_values(&[attestation_status::FAILED])
                    .inc_by(count as u64);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use beacon::{DataResponse, DependentRootResponse, VersionedAggregateAttestation};
    use bn_manager::MockBeaconNodeClient;
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use duty_tracker::DutyTracker;
    use eth_types::{
        Attestation as EthAttestation, AttestationData, Checkpoint, ForkName, ForkSchedule,
    };
    use signer::{always_enabled, SignerService};
    use slashing::SlashingDb;
    use tree_hash::TreeHash;
    use validator_store::{ValidatorConfig, ValidatorStore};

    use super::utils;
    use super::{AggregationService, OrchestratorConfig};

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

    /// Shared mock that records submit_aggregate_and_proofs calls (RF4-24).
    fn tracking_beacon(
        duty_pubkey: String,
        submit_agg_calls: Arc<AtomicUsize>,
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
                        slot: "0".to_string(),
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
            .with_get_aggregate_attestation(|slot, _root, _idx| {
                Ok(VersionedAggregateAttestation::PreElectra(EthAttestation {
                    aggregation_bits: vec![0xff, 0x01],
                    data: AttestationData {
                        slot,
                        index: 0,
                        beacon_block_root: [0x11; 32],
                        source: eth_types::Checkpoint { epoch: 0, root: [0u8; 32] },
                        target: eth_types::Checkpoint { epoch: 0, root: [0u8; 32] },
                    },
                    signature: vec![0xab; 96],
                }))
            })
            .with_submit_aggregate_and_proofs(move |_proofs| {
                submit_agg_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
    }

    async fn setup_agg_service(
        duty_pubkey: String,
        pk: crypto::PublicKey,
        sk: SecretKey,
        validator_store: Arc<ValidatorStore>,
        submit_agg_calls: Arc<AtomicUsize>,
    ) -> AggregationService {
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        let beacon = Arc::new(tracking_beacon(duty_pubkey.clone(), submit_agg_calls));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_duties_for_epoch(0).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        AggregationService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            validator_store,
        )
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

        let service = setup_agg_service(pk_hex, pk, sk, store, submit_calls.clone()).await;

        // Epoch 0 / slot 0 — the duty tracker has the duty for slot 0.
        service.maybe_produce_aggregations(0, 0).await;

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
}
