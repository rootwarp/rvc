//! Phase-2 signer calls from aggregation and sync contributions share one cap.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use beacon::{DataResponse, DependentRootResponse, ExecutionOptimisticResponse};
use bn_manager::MockBeaconNodeClient;
use crypto::{PublicKey, Signature};
use eth_types::{
    Epoch, ForkSchedule, Root, Slot, SyncCommitteeDuty, ValidatorRegistrationV1, VoluntaryExit,
};
use signer::{mock_sig, SignerError, StubValidatorSigner, ValidatorSigner};
use tokio::sync::watch;
use validator_store::ValidatorConfig;

use super::*;
use crate::orchestrator::aggregation::AggregationService;
use crate::orchestrator::dispatch::DispatchLimits;
use crate::orchestrator::slot_anchor::SlotAnchor;
use crate::orchestrator::slot_context::SlotContext;
use crate::orchestrator::sync_committee::SyncCommitteeService;

struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct PeakSigner {
    inner: StubValidatorSigner,
    in_flight: Arc<AtomicUsize>,
    peak: AtomicUsize,
    agg_selection: AtomicUsize,
    sync_selection: AtomicUsize,
    agg_proof: AtomicUsize,
    legacy_proof: AtomicUsize,
    electra_proof: AtomicUsize,
    gloas_proof: AtomicUsize,
    sync_proof: AtomicUsize,
    seq: AtomicU64,
    arrived: watch::Sender<u64>,
    release: watch::Receiver<u8>,
    sync_aggregator: Signature,
}

impl PeakSigner {
    fn new(release: watch::Receiver<u8>, arrived: watch::Sender<u64>) -> Self {
        Self {
            inner: StubValidatorSigner::new(),
            in_flight: Arc::new(AtomicUsize::new(0)),
            peak: AtomicUsize::new(0),
            agg_selection: AtomicUsize::new(0),
            sync_selection: AtomicUsize::new(0),
            agg_proof: AtomicUsize::new(0),
            legacy_proof: AtomicUsize::new(0),
            electra_proof: AtomicUsize::new(0),
            gloas_proof: AtomicUsize::new(0),
            sync_proof: AtomicUsize::new(0),
            seq: AtomicU64::new(0),
            arrived,
            release,
            sync_aggregator: sync_aggregator_signature(),
        }
    }

    async fn enter(&self, kind: Phase2Kind) {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        let _guard = InFlightGuard(Arc::clone(&self.in_flight));
        self.peak.fetch_max(now, Ordering::SeqCst);
        match kind {
            Phase2Kind::AggSelection => {
                self.agg_selection.fetch_add(1, Ordering::SeqCst);
            }
            Phase2Kind::SyncSelection => {
                self.sync_selection.fetch_add(1, Ordering::SeqCst);
            }
            Phase2Kind::AggProof => {
                self.agg_proof.fetch_add(1, Ordering::SeqCst);
                self.legacy_proof.fetch_add(1, Ordering::SeqCst);
            }
            Phase2Kind::AggProofElectra => {
                self.agg_proof.fetch_add(1, Ordering::SeqCst);
                self.electra_proof.fetch_add(1, Ordering::SeqCst);
            }
            Phase2Kind::AggProofGloas => {
                self.agg_proof.fetch_add(1, Ordering::SeqCst);
                self.gloas_proof.fetch_add(1, Ordering::SeqCst);
            }
            Phase2Kind::SyncProof => {
                self.sync_proof.fetch_add(1, Ordering::SeqCst);
            }
            Phase2Kind::Other => {}
        }
        let n = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.arrived.send(n);
        let target: u8 = match kind {
            Phase2Kind::AggSelection | Phase2Kind::SyncSelection => 1,
            _ => 2,
        };
        let mut release = self.release.clone();
        loop {
            if *release.borrow_and_update() >= target {
                break;
            }
            if release.changed().await.is_err() {
                break;
            }
        }
    }
}

fn sync_aggregator_signature() -> Signature {
    loop {
        let signature = mock_sig(b"sync-selection");
        if eth_types::is_sync_committee_aggregator(&signature.to_bytes()) {
            return signature;
        }
    }
}

macro_rules! peak_fwd {
    ($($name:ident($($arg:ident: $ty:ty),*) => $kind:ident);* $(;)?) => {
        #[async_trait]
        impl ValidatorSigner for PeakSigner {
            $(
                async fn $name(&self, $($arg: $ty),*) -> Result<Signature, SignerError> {
                    peak_fwd!(@body $kind, $name, self, $($arg),*)
                }
            )*
        }
    };
    (@body sync_sel, $name:ident, $self:ident, $($arg:ident),*) => {{
        let _ = ($($arg),*);
        $self.enter(Phase2Kind::SyncSelection).await;
        Ok($self.sync_aggregator.clone())
    }};
    (@body $kind:ident, $name:ident, $self:ident, $($arg:ident),*) => {{
        peak_fwd!(@enter $kind, $self);
        $self.inner.$name($($arg),*).await
    }};
    (@enter agg, $self:ident) => { $self.enter(Phase2Kind::AggSelection).await };
    (@enter sync, $self:ident) => { $self.enter(Phase2Kind::SyncSelection).await };
    (@enter agg_proof, $self:ident) => { $self.enter(Phase2Kind::AggProof).await };
    (@enter agg_proof_electra, $self:ident) => { $self.enter(Phase2Kind::AggProofElectra).await };
    (@enter agg_proof_gloas, $self:ident) => { $self.enter(Phase2Kind::AggProofGloas).await };
    (@enter sync_proof, $self:ident) => { $self.enter(Phase2Kind::SyncProof).await };
    (@enter other, $self:ident) => { $self.enter(Phase2Kind::Other).await };
}

enum Phase2Kind {
    AggSelection,
    SyncSelection,
    AggProof,
    AggProofElectra,
    AggProofGloas,
    SyncProof,
    Other,
}

peak_fwd! {
    sign_attestation(data: &eth_types::AttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_block(block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_block_header(header: &signer::BeaconBlockHeaderFields, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_randao_reveal(epoch: Epoch, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_sync_committee_message(beacon_block_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_selection_proof(slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => agg;
    sign_aggregate_and_proof(aggregate_and_proof: &eth_types::AggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => agg_proof;
    sign_electra_aggregate_and_proof(aggregate_and_proof: &eth_types::ElectraAggregateAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => agg_proof_electra;
    sign_voluntary_exit(voluntary_exit: &VoluntaryExit, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_builder_registration(registration: &ValidatorRegistrationV1, pubkey: &PublicKey, fork_version: [u8; 4]) => other;
    sign_sync_committee_selection_proof(slot: Slot, subcommittee_index: u64, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => sync_sel;
    sign_contribution_and_proof(contribution_and_proof: &eth_types::ContributionAndProof, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => sync_proof;
    sign_payload_attestation(data: &eth_types::PayloadAttestationData, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_execution_payload_envelope_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => other;
    sign_aggregate_and_proof_root(object_root: &Root, slot: Slot, pubkey: &PublicKey, fork_schedule: &ForkSchedule, genesis_validators_root: &Root) => agg_proof_gloas;
}

#[derive(Clone, Copy)]
enum AggregateShape {
    PreElectra,
    Electra,
    Gloas,
}

fn electra_body(data: eth_types::AttestationData) -> eth_types::ElectraAttestation {
    eth_types::ElectraAttestation {
        aggregation_bits: vec![0xff, 0x01],
        data,
        signature: vec![0xab; 96],
        committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn phase2_signer_concurrency_is_capped_across_aggregation_and_contributions() {
    run_capped_phase(0, 0, AggregateShape::PreElectra).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn electra_aggregate_and_proof_signs_under_the_phase2_cap() {
    let epoch = 50u64;
    run_capped_phase(epoch * eth_types::SLOTS_PER_EPOCH, epoch, AggregateShape::Electra).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gloas_aggregate_and_proof_root_signs_under_the_phase2_cap() {
    let epoch = 70u64;
    run_capped_phase(epoch * eth_types::SLOTS_PER_EPOCH, epoch, AggregateShape::Gloas).await;
}

async fn run_capped_phase(slot: Slot, epoch: u64, shape: AggregateShape) {
    let _metrics = m2_metric_lock().await;
    // Each pipeline has fewer duties than the cap, so one branch cannot hold
    // every permit. Together they fill it, and both final signs are in
    // flight at once. Dropping the permit on either and-proof lets the
    // other three duties in and the in-flight count goes past the cap.
    const AGG: u64 = 3;
    const SYNC: u64 = 3;
    const CAP: u32 = 4;

    let mut attester_duties = Vec::new();
    let mut sync_duties = Vec::new();
    let mut pubkey_map_inner = HashMap::new();
    let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
    for index in 0..AGG {
        let secret = SecretKey::generate();
        let pubkey = secret.public_key();
        let bytes = pubkey.to_bytes();
        store.add_validator(ValidatorConfig::new(bytes)).unwrap();
        pubkey_map_inner.insert(bytes, pubkey.clone());
        attester_duties.push(AttesterDuty {
            pubkey: format!("0x{}", hex::encode(bytes)),
            validator_index: index.to_string(),
            committee_index: "0".to_string(),
            committee_length: "8".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "0".to_string(),
            slot: slot.to_string(),
        });
        if index < SYNC {
            sync_duties.push(SyncCommitteeDuty {
                pubkey: bytes,
                validator_index: index,
                validator_sync_committee_indices: vec![index],
            });
        }
    }

    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_attester_duties(move |_epoch, _indices| {
                Ok(DependentRootResponse {
                    dependent_root: "0xaabb".to_string(),
                    execution_optimistic: false,
                    data: attester_duties.clone(),
                })
            })
            .with_post_sync_committee_duties(move |_epoch, _indices| {
                Ok(ExecutionOptimisticResponse {
                    execution_optimistic: false,
                    data: sync_duties.clone(),
                })
            })
            .with_get_attestation_data(|queried, _committee| {
                Ok(DataResponse {
                    data: beacon::AttestationData {
                        slot: queried.to_string(),
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
            .with_get_aggregate_attestation(move |queried, _root, _idx, _fork| {
                let data = eth_types::AttestationData {
                    slot: queried,
                    index: 0,
                    beacon_block_root: [0x11; 32],
                    source: eth_types::Checkpoint { epoch: 0, root: [0u8; 32] },
                    target: eth_types::Checkpoint { epoch: 0, root: [0u8; 32] },
                };
                Ok(match shape {
                    AggregateShape::PreElectra => {
                        beacon::VersionedAggregateAttestation::PreElectra(eth_types::Attestation {
                            aggregation_bits: vec![0xff, 0x01],
                            data,
                            signature: vec![0xab; 96],
                        })
                    }
                    AggregateShape::Electra => {
                        beacon::VersionedAggregateAttestation::Electra(electra_body(data))
                    }
                    AggregateShape::Gloas => {
                        beacon::VersionedAggregateAttestation::Gloas(electra_body(data))
                    }
                })
            })
            .with_submit_aggregate_and_proofs(|_proofs| Ok(()))
            .with_get_sync_committee_contribution(|queried, subcommittee, root| {
                Ok(DataResponse {
                    data: eth_types::SyncCommitteeContribution {
                        slot: queried,
                        beacon_block_root: decode_root(&root),
                        subcommittee_index: subcommittee,
                        aggregation_bits: vec![0xff; 16],
                        signature: vec![0xcd; 96],
                    },
                })
            })
            .with_submit_contribution_and_proofs(|_proofs| Ok(())),
    );
    let indices: Vec<String> = (0..AGG).map(|index| index.to_string()).collect();
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), indices));
    duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
    duty_tracker.fetch_sync_committee_duties(epoch).await.unwrap();

    let key_manager = KeyManager::new();
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(60), 32));
    clock.set_slot_with_offset_ms(slot, 50_000);
    let config = create_test_config().with_dispatch_limits(
        DispatchLimits::validated(CAP, DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY)
            .expect("cap is non-zero"),
    );
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));
    let (mut orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock.clone(),
        duty_tracker.clone(),
        signer,
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        beacon.clone(),
        create_mock_block_beacon(),
        None,
        store.clone(),
        config.clone(),
        pubkey_map.clone(),
    ));

    let (release_tx, release_rx) = watch::channel(0u8);
    let (arrived_tx, mut arrived) = watch::channel(0u64);
    let peak = Arc::new(PeakSigner::new(release_rx, arrived_tx));
    let phase_signer: Arc<dyn ValidatorSigner> = peak.clone();
    orchestrator.aggregation_service = AggregationService::new(
        phase_signer.clone(),
        beacon.clone(),
        duty_tracker.clone(),
        pubkey_map.clone(),
        config.clone(),
        store.clone(),
    );
    orchestrator.sync_committee_service =
        SyncCommitteeService::new(phase_signer, beacon, duty_tracker, pubkey_map, config, store);

    let mut ctx = SlotContext::bare(slot, epoch);
    ctx.set_head([0x11; 32]);
    let ctx = tokio::sync::Mutex::new(ctx);
    let anchor = SlotAnchor::capture(clock.as_ref(), slot);
    let gate = Phase2Head::new();
    let deadlines = timing::DeadlineBps::default();
    let phase = orchestrator.run_aggregation_and_contribution_phases(
        slot,
        epoch,
        &ctx,
        deadlines,
        tracing::info_span!("slot.phase.aggregation"),
        &anchor,
        &gate,
    );
    tokio::pin!(phase);
    wait_for_rendezvous(&mut phase, &mut arrived, || {
        let in_flight = peak.in_flight.load(Ordering::SeqCst);
        assert!(in_flight <= CAP as usize, "selection proofs in flight {in_flight}, cap is {CAP}");
        let agg_selections = peak.agg_selection.load(Ordering::SeqCst);
        let sync_selections = peak.sync_selection.load(Ordering::SeqCst);
        in_flight == CAP as usize && agg_selections > 0 && sync_selections > 0
    })
    .await;
    let selection_peak = peak.peak.load(Ordering::SeqCst);
    assert!(
        selection_peak <= CAP as usize,
        "selection proofs peaked at {selection_peak}, cap is {CAP}"
    );

    release_tx.send(1).expect("release selection proofs");
    wait_for_rendezvous(&mut phase, &mut arrived, || {
        let in_flight = peak.in_flight.load(Ordering::SeqCst);
        assert!(in_flight <= CAP as usize, "and-proof signs in flight {in_flight}, cap is {CAP}");
        let agg_proofs = peak.agg_proof.load(Ordering::SeqCst);
        let sync_proofs = peak.sync_proof.load(Ordering::SeqCst);
        in_flight == CAP as usize && agg_proofs > 0 && sync_proofs > 0
    })
    .await;
    let proof_in_flight = peak.in_flight.load(Ordering::SeqCst);
    let proof_peak = peak.peak.load(Ordering::SeqCst);
    assert!(
        proof_in_flight <= CAP as usize,
        "aggregate-and-proof and contribution-and-proof in flight {proof_in_flight}, cap is {CAP}"
    );
    assert!(proof_peak <= CAP as usize, "and-proof signs peaked at {proof_peak}, cap is {CAP}");

    release_tx.send(2).expect("release and-proof signs");
    phase.await;
    assert!(
        peak.agg_selection.load(Ordering::SeqCst) > 0,
        "aggregation selection proofs did not sign"
    );
    assert!(peak.sync_selection.load(Ordering::SeqCst) > 0, "sync selection proofs did not sign");
    assert!(peak.agg_proof.load(Ordering::SeqCst) > 0, "aggregate-and-proof was not signed");
    match shape {
        AggregateShape::PreElectra => {
            assert!(
                peak.legacy_proof.load(Ordering::SeqCst) > 0,
                "pre-Electra and-proof did not sign"
            );
            assert_eq!(peak.electra_proof.load(Ordering::SeqCst), 0);
            assert_eq!(peak.gloas_proof.load(Ordering::SeqCst), 0);
        }
        AggregateShape::Electra => {
            assert!(
                peak.electra_proof.load(Ordering::SeqCst) > 0,
                "sign_electra_aggregate_and_proof did not run"
            );
            assert_eq!(peak.legacy_proof.load(Ordering::SeqCst), 0);
            assert_eq!(peak.gloas_proof.load(Ordering::SeqCst), 0);
        }
        AggregateShape::Gloas => {
            assert!(
                peak.gloas_proof.load(Ordering::SeqCst) > 0,
                "sign_aggregate_and_proof_root did not run"
            );
            assert_eq!(peak.legacy_proof.load(Ordering::SeqCst), 0);
            assert_eq!(peak.electra_proof.load(Ordering::SeqCst), 0);
        }
    }
    assert!(peak.sync_proof.load(Ordering::SeqCst) > 0, "contribution-and-proof was not signed");
    assert!(
        peak.peak.load(Ordering::SeqCst) <= CAP as usize,
        "phase-2 sign calls peaked at {}, cap is {CAP}",
        peak.peak.load(Ordering::SeqCst)
    );
}

async fn wait_for_rendezvous(
    phase: &mut std::pin::Pin<&mut impl std::future::Future>,
    arrived: &mut watch::Receiver<u64>,
    ready: impl Fn() -> bool,
) {
    loop {
        arrived.borrow_and_update();
        if ready() {
            // One more poll. A sign that skipped the shared permit can still
            // enter; the cap predicate then fails. A full cap stays pending.
            tokio::select! {
                biased;
                _ = &mut *phase => panic!("phase finished before the signer rendezvous"),
                _ = tokio::task::yield_now() => {}
            }
            if ready() {
                return;
            }
            continue;
        }
        tokio::select! {
            biased;
            _ = &mut *phase => panic!("phase finished before the signer rendezvous"),
            result = arrived.changed() => {
                result.expect("arrival watch");
            }
        }
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn in_flight_returns_to_zero_when_a_blocked_sign_is_dropped() {
    let (release_tx, release_rx) = watch::channel(0u8);
    let (arrived_tx, mut arrived) = watch::channel(0u64);
    let signer = Arc::new(PeakSigner::new(release_rx, arrived_tx));
    let running = Arc::clone(&signer);
    let task = tokio::spawn(async move {
        running.enter(Phase2Kind::AggSelection).await;
    });
    while signer.in_flight.load(Ordering::SeqCst) == 0 {
        arrived.changed().await.expect("arrival");
    }
    task.abort();
    let _ = task.await;
    assert_eq!(
        signer.in_flight.load(Ordering::SeqCst),
        0,
        "dropping a blocked sign must release the in-flight count"
    );
    drop(release_tx);
}

fn decode_root(hex_str: &str) -> [u8; 32] {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).expect("root hex");
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    root
}
