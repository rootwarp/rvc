use std::collections::BTreeSet;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::metrics::{
    sync_committee_skip_phase, sync_committee_skip_reason, RVC_SYNC_COMMITTEE_SKIPPED_TOTAL,
};
use bn_manager::BeaconNodeClient;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{
    is_sync_committee_aggregator, subcommittee_index, ContributionAndProof,
    SignedContributionAndProof, Slot, SyncCommitteeDuty,
};
use observability::logging::TruncatedRoot;
use signer::{SignerService, ValidatorSigner};
use validator_store::ValidatorStore;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::slot_context::SlotContext;
use super::utils;

pub(crate) struct SyncCommitteeService {
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    /// D-3: per-validator doppelganger gate.  Mirrors the M-12 check already
    /// present in attestation.rs so that sync messages and contributions
    /// are also suppressed during the post-import doppelganger window.
    validator_store: Arc<ValidatorStore>,
}

impl SyncCommitteeService {
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

    #[tracing::instrument(name = "orchestrator.produce_sync_messages", level = "debug", skip_all, fields(slot = slot))]
    pub(crate) async fn maybe_produce_sync_messages(
        &self,
        slot: Slot,
        _epoch: u64,
        ctx: &SlotContext,
    ) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
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

        let mut messages = Vec::new();

        for (duty, pubkey) in matching_duties.iter().zip(matching_pubkeys.iter()) {
            match self
                .signer
                .sign_sync_committee_message(
                    &head_root,
                    slot,
                    pubkey,
                    &self.config.fork_schedule,
                    &self.config.genesis_validators_root,
                )
                .await
            {
                Ok(sig) => {
                    messages.push(beacon::SyncCommitteeMessage {
                        slot,
                        beacon_block_root: head_root,
                        validator_index: duty.validator_index,
                        signature: sig.to_bytes().to_vec(),
                    });
                }
                Err(e) => {
                    warn!(
                        slot,
                        validator_index = duty.validator_index,
                        error = %e,
                        "Failed to sign sync committee message"
                    );
                }
            }
        }

        if !messages.is_empty() {
            let count = messages.len();
            match tokio::time::timeout(
                self.config.timeouts.sync_message,
                self.beacon.submit_sync_committee_messages(&messages),
            )
            .await
            {
                Ok(Ok(_)) => info!(slot, count, "Submitted sync committee messages"),
                Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit sync committee messages"),
                Err(_) => warn!(
                    slot,
                    "Sync committee message submit timed out after {}s",
                    self.config.timeouts.sync_message.as_secs()
                ),
            }
        }
    }

    #[tracing::instrument(name = "orchestrator.produce_sync_contributions", level = "debug", skip_all, fields(slot = slot))]
    pub(crate) async fn maybe_produce_sync_contributions(
        &self,
        slot: Slot,
        _epoch: u64,
        ctx: &SlotContext,
    ) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
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

        let head_root_hex = format!("0x{}", hex::encode(head_root));
        let mut signed_proofs = Vec::new();

        for (duty, pubkey) in matching_duties.iter().zip(matching_pubkeys.iter()) {
            let subcommittee_indices: BTreeSet<u64> = duty
                .validator_sync_committee_indices
                .iter()
                .map(|&pos| subcommittee_index(pos))
                .collect();

            for subcommittee_index in &subcommittee_indices {
                let selection_proof = match self
                    .signer
                    .sign_sync_committee_selection_proof(
                        slot,
                        *subcommittee_index,
                        pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            slot,
                            subcommittee_index,
                            validator_index = duty.validator_index,
                            error = %e,
                            "Failed to sign sync committee selection proof"
                        );
                        continue;
                    }
                };

                if !is_sync_committee_aggregator(&selection_proof.to_bytes()) {
                    debug!(
                        slot,
                        subcommittee_index,
                        validator_index = duty.validator_index,
                        "Not selected as sync committee aggregator"
                    );
                    continue;
                }

                debug!(
                    slot,
                    subcommittee_index,
                    validator_index = duty.validator_index,
                    "Selected as sync committee aggregator"
                );

                let contribution = match tokio::time::timeout(
                    self.config.timeouts.sync_contribution,
                    self.beacon.get_sync_committee_contribution(
                        slot,
                        *subcommittee_index,
                        &head_root_hex,
                    ),
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
                        continue;
                    }
                    Err(_) => {
                        warn!(
                            slot,
                            subcommittee_index,
                            "Sync committee contribution fetch timed out after {}s",
                            self.config.timeouts.sync_contribution.as_secs()
                        );
                        continue;
                    }
                };

                let proof = ContributionAndProof {
                    aggregator_index: duty.validator_index,
                    contribution,
                    selection_proof: selection_proof.to_bytes().to_vec(),
                };

                let sig = match self
                    .signer
                    .sign_contribution_and_proof(
                        &proof,
                        pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            slot,
                            subcommittee_index,
                            validator_index = duty.validator_index,
                            error = %e,
                            "Failed to sign contribution and proof"
                        );
                        continue;
                    }
                };

                signed_proofs.push(SignedContributionAndProof {
                    message: proof,
                    signature: sig.to_bytes().to_vec(),
                });
            }
        }

        if !signed_proofs.is_empty() {
            let count = signed_proofs.len();
            match tokio::time::timeout(
                self.config.timeouts.sync_contribution,
                self.beacon.submit_contribution_and_proofs(&signed_proofs),
            )
            .await
            {
                Ok(Ok(_)) => info!(slot, count, "Submitted sync committee contribution and proofs"),
                Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit contribution and proofs"),
                Err(_) => warn!(
                    slot,
                    "Contribution and proofs submit timed out after {}s",
                    self.config.timeouts.sync_contribution.as_secs()
                ),
            }
        }
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
    use beacon::{DataResponse, ExecutionOptimisticResponse};
    use bn_manager::{BeaconNodeClient, MockBeaconNodeClient};
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
            .with_submit_contribution_and_proofs(|_proofs| Ok(()))
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
                        aggregation_bits: vec![0xFF, 0x01],
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
                        aggregation_bits: vec![0xFF, 0x01],
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
        let sk = SecretKey::generate();
        let pk = sk.public_key();
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
        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some(r_captured) };

        // Run both sync-committee phases with the same context.
        service.maybe_produce_sync_messages(0, 0, &ctx).await;
        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

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
            !roots.is_empty(),
            "Expected sync committee messages to be submitted; \
             check that the test key is in the KeyManager and pubkey_map"
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
        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: None };

        let before_messages = skip_count(sync_committee_skip_phase::MESSAGES);
        let before_contributions = skip_count(sync_committee_skip_phase::CONTRIBUTIONS);

        service.maybe_produce_sync_messages(0, 0, &ctx).await;
        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

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
        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: None };

        service.maybe_produce_sync_messages(0, 0, &ctx).await;

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
        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: None };

        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

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

        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some([0xAA; 32]) };
        service.maybe_produce_sync_messages(0, 0, &ctx).await;

        // No messages must be submitted for a disabled validator.
        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "D-3: sync committee message must not be produced when is_signing_enabled=false"
        );
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

        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some([0xAA; 32]) };
        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

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

        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some([0xAA; 32]) };
        // Must complete without panic / hang — isolation property.
        service.maybe_produce_sync_messages(0, 0, &ctx).await;

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

        let ctx = SlotContext { slot: 0, epoch: 0, parent_root: None, head_root: Some([0xAA; 32]) };
        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

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

        ctx.capture_head(beacon.as_ref()).await;
        assert!(
            ctx.head_root.is_some(),
            "phase-2 capture_head must supply a head even when the current slot 404s"
        );

        service.maybe_produce_sync_messages(slot, epoch, &ctx).await;
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
}
