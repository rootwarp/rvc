use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::metrics::{payload_attestation_skip_reason, RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL};
use bn_manager::{BeaconNodeClient, PtcDuty};
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{PayloadAttestationMessage, Slot};
use observability::logging::TruncatedPubkey;
use signer::{SignerService, ValidatorSigner};
use validator_store::ValidatorStore;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::utils;

pub(crate) struct PayloadAttestationService {
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    validator_store: Arc<ValidatorStore>,
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
        Self { signer, beacon, duty_tracker, pubkey_map, config, validator_store }
    }

    /// Fetch payload attestation data once per slot and sign/submit for every
    /// local PTC duty. HTTP 204 (`Ok(None)`) skips with no signatures.
    #[tracing::instrument(
        name = "orchestrator.produce_payload_attestations",
        level = "debug",
        skip_all,
        fields(slot = slot)
    )]
    pub(crate) async fn maybe_produce_payload_attestations(&self, slot: Slot, _epoch: u64) {
        let duties = self.duty_tracker.get_ptc_duties_for_slot(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_ptc_duties(&duties);
        if matching_duties.is_empty() {
            return;
        }

        // VC is the single observer: one fetch, identical bytes to every signer.
        let data = match tokio::time::timeout(
            self.config.timeouts.attestation_fetch,
            self.beacon.get_payload_attestation_data(slot),
        )
        .await
        {
            Ok(Ok(Some(resp))) => resp.data,
            Ok(Ok(None)) => {
                debug!(slot, "Skipping payload attestations: no data (HTTP 204)");
                RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL
                    .with_label_values(&[payload_attestation_skip_reason::NO_DATA])
                    .inc();
                return;
            }
            Ok(Err(e)) => {
                warn!(slot, error = %e, "Failed to get payload attestation data");
                return;
            }
            Err(_) => {
                warn!(
                    slot,
                    "Payload attestation data fetch timed out after {}s",
                    self.config.timeouts.attestation_fetch.as_secs()
                );
                return;
            }
        };

        let mut messages = Vec::new();
        for (duty, pubkey) in matching_duties.iter().zip(matching_pubkeys.iter()) {
            let validator_index = match duty.validator_index.parse::<u64>() {
                Ok(i) => i,
                Err(e) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        error = %e,
                        "Failed to parse PTC validator_index"
                    );
                    continue;
                }
            };
            match self
                .signer
                .sign_payload_attestation(
                    &data,
                    pubkey,
                    &self.config.fork_schedule,
                    &self.config.genesis_validators_root,
                )
                .await
            {
                Ok(sig) => {
                    messages.push(PayloadAttestationMessage {
                        validator_index,
                        data: data.clone(),
                        signature: sig.to_bytes().to_vec(),
                    });
                }
                Err(e) => {
                    // H6: one signer failure must not abort the remaining validators.
                    warn!(
                        slot,
                        validator_index,
                        error = %e,
                        "Failed to sign payload attestation"
                    );
                }
            }
        }

        if !messages.is_empty() {
            let count = messages.len();
            match tokio::time::timeout(
                self.config.timeouts.attestation_submit,
                self.beacon.submit_payload_attestations(&messages),
            )
            .await
            {
                Ok(Ok(_)) => info!(slot, count, "Submitted payload attestations"),
                Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit payload attestations"),
                Err(_) => warn!(
                    slot,
                    "Payload attestation submit timed out after {}s",
                    self.config.timeouts.attestation_submit.as_secs()
                ),
            }
        }
    }

    fn filter_ptc_duties(&self, duties: &[PtcDuty]) -> (Vec<PtcDuty>, Vec<PublicKey>) {
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

    use crate::metrics::{payload_attestation_skip_reason, RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL};
    use beacon::PayloadAttestationDataResponse;
    use bn_manager::{BeaconNodeClient, MockBeaconNodeClient, PtcDutiesResponse, PtcDuty};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use duty_tracker::DutyTracker;
    use eth_types::{ForkSchedule, PayloadAttestationData, PayloadAttestationMessage};
    use signer::{always_enabled, SignerService};
    use slashing::SlashingDb;
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
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut key_manager = KeyManager::new();
        let mut map = HashMap::new();
        let mut indices = Vec::new();
        for k in keys {
            store.add_validator(ValidatorConfig::new(k.pk.to_bytes()));
            if !omit_secret_for.contains(&k.index) {
                key_manager.insert(k.sk);
            }
            map.insert(k.pk.to_bytes(), k.pk);
            indices.push(k.index.to_string());
        }
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), indices.clone()));
        duty_tracker.fetch_ptc_duties(0, &indices).await.unwrap();

        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));
        PayloadAttestationService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            store,
        )
    }

    fn skip_count() -> u64 {
        RVC_PAYLOAD_ATTESTATION_SKIPPED_TOTAL
            .with_label_values(&[payload_attestation_skip_reason::NO_DATA])
            .get()
    }

    #[tokio::test]
    async fn test_payload_attestation_204_skips_without_signature_or_submission() {
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
        service.maybe_produce_payload_attestations(0, 0).await;

        assert_eq!(fetch_count.load(Ordering::SeqCst), 1, "204 path must still fetch once");
        assert!(submitted.lock().unwrap().is_empty(), "204 must not submit payload attestations");
        assert_eq!(
            skip_count(),
            before + 1,
            "204 must increment rvc_payload_attestation_skipped_total{{reason=no_data}}"
        );
        assert!(
            mock.submit_payload_attestations_calls().is_empty(),
            "204 must not call submit_payload_attestations"
        );
    }

    #[tokio::test]
    async fn test_one_signer_failure_does_not_abort_remaining_ptc_validators() {
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

        service.maybe_produce_payload_attestations(0, 0).await;

        let mut indices = submitted_indices.lock().unwrap().clone();
        indices.sort_unstable();
        assert_eq!(
            indices,
            vec![10, 12],
            "H6: A and C must submit; B (KeyNotFound) must be skipped"
        );
    }

    #[tokio::test]
    async fn test_payload_attestation_data_fetched_once_identical_bytes_to_every_signer() {
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
                        assert_eq!(n, 0, "payload attestation data must be fetched once per slot");
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

        service.maybe_produce_payload_attestations(0, 0).await;

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
    }
}
