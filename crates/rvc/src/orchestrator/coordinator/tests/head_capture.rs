//! Head capture is deadline-bounded and does not hold the slot-context lock.
//! Equal contribution and aggregate deadlines start together.

use super::*;
use beacon::{
    AttestationData, AttesterDuty, Checkpoint, DataResponse, DependentRootResponse,
    ExecutionOptimisticResponse,
};
use bn_manager::{MockBeaconNodeClient, MockMethod};
use eth_types::{
    is_sync_committee_aggregator, ForkName, SyncAggregatorSelectionData, SyncCommitteeDuty,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
};
use std::sync::Mutex as StdMutex;
use timing::{DeadlineBps, DeadlineSchedule, SlotClock, TimingError};
use validator_store::ValidatorConfig;

const HEAD_HANG: Duration = Duration::from_secs(30);
const SLOT_MS: u64 = 12_000;
const ATTESTATION_DUE_MS: u64 = 3_999;
const AGGREGATE_DUE_MS: u64 = 8_000;

/// Slot clock whose `now` is `start_slot` plus paused tokio time since `origin`.
struct AlignedClock {
    origin: tokio::time::Instant,
    start_slot: u64,
}

impl SlotClock for AlignedClock {
    fn genesis_time(&self) -> u64 {
        0
    }

    fn slot_duration(&self) -> Duration {
        Duration::from_millis(SLOT_MS)
    }

    fn slots_per_epoch(&self) -> u64 {
        32
    }

    fn now_since_epoch(&self) -> Duration {
        let elapsed = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(self.start_slot.saturating_mul(SLOT_MS).saturating_add(elapsed))
    }

    fn current_slot(&self) -> Result<Slot, TimingError> {
        let ms = u64::try_from(self.now_since_epoch().as_millis()).unwrap_or(0);
        Ok(ms / SLOT_MS)
    }
}

struct SlotSubmitter {
    submits: StdMutex<Vec<(String, tokio::time::Instant, usize)>>,
}

impl SlotSubmitter {
    fn new() -> Self {
        Self { submits: StdMutex::new(Vec::new()) }
    }
}

impl AttestationSubmitter for SlotSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a VersionedAttestation,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<beacon::SubmitAttestationResult, beacon::BeaconError>>
                + Send
                + 'a,
        >,
    > {
        let (slot, sig_len) = match attestations {
            VersionedAttestation::PreElectra(items) => items
                .first()
                .map(|item| (item.data.slot.clone(), item.signature.len()))
                .unwrap_or_else(|| (String::new(), 0)),
            VersionedAttestation::Electra(items)
            | VersionedAttestation::Fulu(items)
            | VersionedAttestation::Gloas(items) => items
                .first()
                .map(|item| (item.data.slot.clone(), item.signature.len()))
                .unwrap_or_else(|| (String::new(), 0)),
        };
        self.submits.lock().expect("submit log").push((slot, tokio::time::Instant::now(), sig_len));
        Box::pin(async { Ok(beacon::SubmitAttestationResult::Success) })
    }
}

fn hex_root(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

fn attester_duty(pubkey_hex: &str, slot: Slot) -> AttesterDuty {
    AttesterDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: "1".to_string(),
        committee_index: "0".to_string(),
        committee_length: "1".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: slot.to_string(),
    }
}

fn attestation_data(slot: u64) -> AttestationData {
    let epoch = slot / 32;
    AttestationData {
        slot: slot.to_string(),
        index: "0".to_string(),
        beacon_block_root: hex_root(0x11),
        source: Checkpoint { epoch: epoch.saturating_sub(1).to_string(), root: hex_root(0x22) },
        target: Checkpoint { epoch: epoch.to_string(), root: hex_root(0x33) },
    }
}

fn find_aggregator(
    slot: Slot,
    subcommittees: &[u64],
    schedule: &ForkSchedule,
    genesis: Root,
) -> (SecretKey, PublicKey) {
    let fork = ForkName::from_epoch(slot / 32, schedule);
    let domain = crypto::compute_domain(
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        fork.fork_version(schedule),
        genesis,
    );
    loop {
        let sk = SecretKey::generate();
        let selected = subcommittees.iter().all(|subcommittee| {
            let data = SyncAggregatorSelectionData { slot, subcommittee_index: *subcommittee };
            let signing_root = crypto::compute_signing_root(&data, domain);
            is_sync_committee_aggregator(&sk.sign(&signing_root).to_bytes())
        });
        if selected {
            let pk = sk.public_key();
            return (sk, pk);
        }
    }
}

fn within(at: tokio::time::Instant, origin: tokio::time::Instant, target_ms: u64) {
    let elapsed = at.saturating_duration_since(origin);
    let target = Duration::from_millis(target_ms);
    assert!(
        elapsed + Duration::from_millis(100) >= target
            && elapsed <= target + Duration::from_millis(100),
        "elapsed {elapsed:?} is not within 100 ms of {target:?}"
    );
}

/// `get_block_root` for slot N never answers. Slot N's attestation is submitted
/// before slot end, and slot N+1's attestation phase fires within 100 ms of
/// its deadline. Slots 63 and 64 are different target epochs.
async fn hung_head_submits_before_slot_end(equal_sync: bool) {
    let origin = tokio::time::Instant::now();
    let clock = Arc::new(AlignedClock { origin, start_slot: 63 });
    let secret = SecretKey::generate();
    let pubkey = secret.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_method_delay(MockMethod::GetBlockRoot, HEAD_HANG)
            .with_slot_aware_block_root(65, &[], |_| hex_root(0xab))
            .with_get_attester_duties({
                let pubkey_hex = pubkey_hex.clone();
                move |epoch, _| {
                    let slot = match epoch {
                        1 => 63,
                        2 => 64,
                        _ => {
                            return Ok(DependentRootResponse {
                                dependent_root: hex_root(0),
                                execution_optimistic: false,
                                data: Vec::new(),
                            })
                        }
                    };
                    Ok(DependentRootResponse {
                        dependent_root: hex_root(0),
                        execution_optimistic: false,
                        data: vec![attester_duty(&pubkey_hex, slot)],
                    })
                }
            })
            .with_get_attestation_data(|slot, _| Ok(DataResponse { data: attestation_data(slot) })),
    );
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    duty_tracker.fetch_duties_for_epoch(1).await.expect("epoch 1 duties");

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret);
    let signer = Arc::new(
        SignerService::new(
            Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
            Arc::new(SlashingDb::open_in_memory().expect("memory slashing db")),
        )
        .with_enablement(always_enabled()),
    );
    let store = Arc::new(ValidatorStore::new([0xaa; 20], 30_000_000));
    store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).expect("add validator");
    let mut map = HashMap::new();
    map.insert(pubkey.to_bytes(), pubkey);
    let submitter = Arc::new(SlotSubmitter::new());
    let mut config = create_test_config().with_timeouts(OperationTimeouts {
        attestation_fetch: Duration::from_secs(4),
        ..OperationTimeouts::default()
    });
    if !equal_sync {
        config.deadline_schedule.pre_gloas.sync_message = 5_000;
    }

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(submitter.clone())),
        beacon.clone(),
        create_mock_block_beacon(),
        None,
        store,
        config,
        Arc::new(parking_lot::RwLock::new(map)),
    ));
    orchestrator.set_sync_enabled(false);

    let run = tokio::spawn(async move { orchestrator.run().await });
    tokio::time::sleep_until(origin + Duration::from_millis(SLOT_MS + ATTESTATION_DUE_MS + 100))
        .await;

    let submits = submitter.submits.lock().expect("submit log").clone();
    assert_eq!(submits.len(), 2, "both slots are signed and published, got {submits:?}");
    assert_eq!(submits[0].0, "63");
    assert!(submits[0].2 > 0, "slot 63 signature is empty");
    assert!(
        submits[0].1 < origin + Duration::from_millis(SLOT_MS),
        "slot 63 attestation published at {:?}, after slot end",
        submits[0].1.saturating_duration_since(origin)
    );
    assert_eq!(submits[1].0, "64");
    assert!(submits[1].2 > 0, "slot 64 signature is empty");
    within(submits[1].1, origin, SLOT_MS + ATTESTATION_DUE_MS);
    assert!(
        beacon.call_stamps().iter().any(|stamp| stamp.method == MockMethod::GetBlockRoot),
        "the hung head fetch must be attempted"
    );

    handle.shutdown();
    tokio::time::timeout(Duration::from_secs(40), run)
        .await
        .expect("orchestrator did not stop")
        .expect("run task")
        .expect("run");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn hung_head_does_not_delay_attestations_or_the_next_slot() {
    hung_head_submits_before_slot_end(true).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn unequal_attestation_arm_does_not_await_head_capture() {
    hung_head_submits_before_slot_end(false).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn head_fetch_deadline_duration_max_is_already_due() {
    let now = tokio::time::Instant::now();
    let deadline =
        DutyOrchestrator::<MockSlotClock, MockSubmitter, MockBlockBeacon>::head_fetch_deadline(
            now + Duration::from_secs(12),
            Duration::MAX,
        );
    assert_eq!(deadline, now);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn snapshot_ctx_returns_while_the_head_fetch_is_pending() {
    let parent = [0x11; 32];
    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_method_delay(MockMethod::GetBlockRoot, Duration::from_secs(60))
            .with_slot_aware_block_root(34, &[], |_| hex_root(0xab)),
    );
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()])),
        Arc::new(SignerService::new(
            Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new()))),
            Arc::new(SlashingDb::open_in_memory().expect("memory slashing db")),
        )),
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config(),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));
    let ctx = tokio::sync::Mutex::new(SlotContext {
        slot: 33,
        epoch: 1,
        parent_root: Some(parent),
        expected_parents: None,
        head_root: None,
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let gate = Phase2Head::new();
    let capture = orchestrator.capture_head_if_needed(&ctx, deadline, &gate);
    tokio::pin!(capture);
    tokio::select! {
        biased;
        _ = &mut capture => panic!("head fetch returned before its deadline"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
    }
    let before = tokio::time::Instant::now();
    let snap = tokio::time::timeout(Duration::from_millis(50), orchestrator.snapshot_ctx(&ctx))
        .await
        .expect("the snapshot blocked on the head-fetch lock");
    assert!(
        tokio::time::Instant::now().saturating_duration_since(before) < Duration::from_millis(50)
    );
    assert!(snap.head_root.is_none(), "a pending fetch has not published a head");

    tokio::time::sleep(Duration::from_secs(30)).await;
    (&mut capture).await;
    let snap = orchestrator.snapshot_ctx(&ctx).await;
    assert_eq!(snap.head_root, Some(parent));
}

/// Equal aggregate and contribution deadlines. Three subcommittee GETs of 2 s
/// start with aggregation, and the contribution phase is done by slot end
/// plus the 500 ms overhang.
async fn equal_deadlines_run_contributions_with_aggregation(sync_enabled: bool) {
    let origin = tokio::time::Instant::now();
    let slot: Slot = 33;
    let config = create_test_config().with_timeouts(OperationTimeouts {
        sync_contribution: Duration::from_secs(3),
        attestation_fetch: Duration::from_secs(4),
        ..OperationTimeouts::default()
    });
    let (secret, pubkey) =
        find_aggregator(slot, &[0, 1, 2], &config.fork_schedule, config.genesis_validators_root);
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let head = [0xab; 32];
    let published = Arc::new(StdMutex::new(Vec::new()));

    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_method_delay(MockMethod::GetSyncCommitteeContribution, Duration::from_secs(2))
            .with_slot_aware_block_root(slot + 1, &[], move |queried| match queried {
                Some(queried_slot) if queried_slot == slot => hex_root(0xab),
                _ => hex_root(0x11),
            })
            .with_get_attester_duties({
                let pubkey_hex = pubkey_hex.clone();
                move |epoch, _| {
                    let data = if epoch == 1 {
                        vec![attester_duty(&pubkey_hex, slot)]
                    } else {
                        Vec::new()
                    };
                    Ok(DependentRootResponse {
                        dependent_root: hex_root(0),
                        execution_optimistic: false,
                        data,
                    })
                }
            })
            .with_get_attestation_data(move |requested, _| {
                Ok(DataResponse { data: attestation_data(requested) })
            })
            .with_post_sync_committee_duties({
                let duty_pk = pubkey.to_bytes();
                move |_epoch, _| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0, 128, 256],
                        }],
                    })
                }
            })
            .with_get_sync_committee_contribution(move |requested_slot, subcommittee, _root| {
                Ok(DataResponse {
                    data: eth_types::SyncCommitteeContribution {
                        slot: requested_slot,
                        beacon_block_root: head,
                        subcommittee_index: subcommittee,
                        aggregation_bits: vec![0xff; 16],
                        signature: vec![1u8; 96],
                    },
                })
            })
            .with_submit_contribution_and_proofs({
                let published = Arc::clone(&published);
                move |proofs| {
                    published.lock().expect("proofs").extend(proofs.iter().cloned());
                    Ok(())
                }
            }),
    );
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    duty_tracker.fetch_duties_for_epoch(1).await.expect("attester duties");
    duty_tracker.fetch_sync_committee_duties(1).await.expect("sync duties");

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret);
    let signer = Arc::new(
        SignerService::new(
            Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
            Arc::new(SlashingDb::open_in_memory().expect("memory slashing db")),
        )
        .with_enablement(always_enabled()),
    );
    let store = Arc::new(ValidatorStore::new([0xaa; 20], 30_000_000));
    store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).expect("add validator");
    let mut map = HashMap::new();
    map.insert(pubkey.to_bytes(), pubkey);
    let clock = Arc::new(MockSlotClock::new(0, Duration::from_millis(SLOT_MS), 32));
    clock.set_slot(slot);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        beacon.clone(),
        create_mock_block_beacon(),
        None,
        store,
        config,
        Arc::new(parking_lot::RwLock::new(map)),
    ));
    orchestrator.set_sync_enabled(sync_enabled);

    tokio::spawn(async move {
        tokio::time::sleep_until(origin + Duration::from_millis(12_500)).await;
        handle.shutdown();
    });
    orchestrator.run().await.expect("run");
    let returned = tokio::time::Instant::now().saturating_duration_since(origin);
    assert!(
        returned <= Duration::from_millis(12_600),
        "run returned after {returned:?}, past slot end plus the 500 ms overhang"
    );

    let aggregate_at = beacon
        .call_stamps()
        .into_iter()
        .find(|stamp| stamp.method == MockMethod::GetAggregateAttestation)
        .expect("aggregation must call get_aggregate_attestation");
    within(aggregate_at.at, origin, AGGREGATE_DUE_MS);

    let contribution_gets: Vec<_> = beacon
        .call_stamps()
        .into_iter()
        .filter(|stamp| stamp.method == MockMethod::GetSyncCommitteeContribution)
        .collect();
    if sync_enabled {
        assert_eq!(contribution_gets.len(), 3, "three subcommittee fetches");
        for stamp in &contribution_gets {
            within(stamp.at, origin, AGGREGATE_DUE_MS);
        }
        let proofs = published.lock().expect("proofs").clone();
        assert_eq!(proofs.len(), 3);
        let mut seen = Vec::new();
        for proof in &proofs {
            assert_eq!(proof.message.contribution.slot, slot);
            assert_eq!(proof.message.contribution.beacon_block_root, head);
            assert_eq!(proof.signature.len(), 96);
            assert!(proof.signature.iter().any(|byte| *byte != 0), "signature is zero");
            seen.push(proof.message.contribution.subcommittee_index);
        }
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2]);
    } else {
        assert!(contribution_gets.is_empty(), "sync disabled must not fetch contributions");
        assert!(published.lock().expect("proofs").is_empty());
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn equal_contribution_and_aggregate_deadlines_start_together() {
    equal_deadlines_run_contributions_with_aggregation(true).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn sync_disabled_does_not_fetch_contributions_or_delay_aggregation() {
    equal_deadlines_run_contributions_with_aggregation(false).await;
}

fn gloas_like_deadlines() -> DeadlineBps {
    DeadlineBps {
        attestation: 2_500,
        sync_message: 2_500,
        aggregate: 5_000,
        contribution: 5_000,
        payload: 5_000,
        payload_attestation: 7_500,
    }
}

fn decode_root(hex_root: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_root.strip_prefix("0x").unwrap_or(hex_root)).expect("root hex");
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    root
}

/// Gloas-like offsets: attestation at 3 s, aggregate and contributions at 6 s.
/// A 4 s head budget. `head_delay` of 2.5 s and 3.5 s publish the current-slot
/// root; 5 s exceeds the budget and publishes the t=0 parent. Aggregation
/// still starts at 6 s.
async fn head_delay_publishes(head_delay: Duration, expect: [u8; 32], submit_ms: u64) {
    let origin = tokio::time::Instant::now();
    let slot: Slot = 33;
    let deadlines = gloas_like_deadlines();
    let config = create_test_config()
        .with_timeouts(OperationTimeouts {
            attestation_fetch: Duration::from_secs(4),
            sync_contribution: Duration::from_secs(4),
            ..OperationTimeouts::default()
        })
        .with_deadline_schedule(DeadlineSchedule { pre_gloas: deadlines, gloas: deadlines });
    let (secret, pubkey) =
        find_aggregator(slot, &[0], &config.fork_schedule, config.genesis_validators_root);
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let published = Arc::new(StdMutex::new(Vec::new()));

    let beacon = Arc::new(
        MockBeaconNodeClient::new()
            .with_method_delay(MockMethod::GetBlockRoot, head_delay)
            .with_slot_aware_block_root(slot + 1, &[], move |queried| match queried {
                Some(queried_slot) if queried_slot == slot => hex_root(0xab),
                _ => hex_root(0x11),
            })
            .with_get_attester_duties({
                let pubkey_hex = pubkey_hex.clone();
                move |epoch, _| {
                    let data = if epoch == 1 {
                        vec![attester_duty(&pubkey_hex, slot)]
                    } else {
                        Vec::new()
                    };
                    Ok(DependentRootResponse {
                        dependent_root: hex_root(0),
                        execution_optimistic: false,
                        data,
                    })
                }
            })
            .with_get_attestation_data(|requested, _| {
                Ok(DataResponse { data: attestation_data(requested) })
            })
            .with_post_sync_committee_duties({
                let duty_pk = pubkey.to_bytes();
                move |_epoch, _| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                }
            })
            .with_get_sync_committee_contribution(move |requested, subcommittee, root| {
                Ok(DataResponse {
                    data: eth_types::SyncCommitteeContribution {
                        slot: requested,
                        beacon_block_root: decode_root(&root),
                        subcommittee_index: subcommittee,
                        aggregation_bits: vec![0xff; 16],
                        signature: vec![1u8; 96],
                    },
                })
            })
            .with_submit_contribution_and_proofs({
                let published = Arc::clone(&published);
                move |proofs| {
                    let at = tokio::time::Instant::now();
                    published.lock().expect("proofs").extend(proofs.iter().map(|proof| {
                        (proof.message.contribution.beacon_block_root, at, proof.signature.clone())
                    }));
                    Ok(())
                }
            }),
    );
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    duty_tracker.fetch_duties_for_epoch(1).await.expect("attester duties");
    duty_tracker.fetch_sync_committee_duties(1).await.expect("sync duties");

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret);
    let signer = Arc::new(
        SignerService::new(
            Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
            Arc::new(SlashingDb::open_in_memory().expect("memory slashing db")),
        )
        .with_enablement(always_enabled()),
    );
    let store = Arc::new(ValidatorStore::new([0xaa; 20], 30_000_000));
    store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).expect("add validator");
    let mut map = HashMap::new();
    map.insert(pubkey.to_bytes(), pubkey);
    let clock = Arc::new(MockSlotClock::new(0, Duration::from_millis(SLOT_MS), 32));
    clock.set_slot(slot);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::new(MockSubmitter::new()))),
        beacon.clone(),
        create_mock_block_beacon(),
        None,
        store,
        config,
        Arc::new(parking_lot::RwLock::new(map)),
    ));

    tokio::spawn(async move {
        tokio::time::sleep_until(origin + Duration::from_millis(12_500)).await;
        handle.shutdown();
    });
    orchestrator.run().await.expect("run");
    let returned = tokio::time::Instant::now().saturating_duration_since(origin);
    assert!(returned <= Duration::from_millis(12_600), "run returned after {returned:?}");

    let roots = beacon
        .call_stamps()
        .into_iter()
        .filter(|stamp| stamp.method == MockMethod::GetBlockRoot)
        .count();
    assert_eq!(roots, 1, "one phase-2 fetch for a {head_delay:?} head");
    let aggregate_at = beacon
        .call_stamps()
        .into_iter()
        .find(|stamp| stamp.method == MockMethod::GetAggregateAttestation)
        .expect("aggregation starts at 6 s");
    within(aggregate_at.at, origin, 6_000);

    let proofs = published.lock().expect("proofs").clone();
    assert_eq!(proofs.len(), 1, "a {head_delay:?} head must publish one contribution");
    assert_eq!(proofs[0].0, expect);
    assert_eq!(proofs[0].2.len(), 96);
    assert!(proofs[0].2.iter().any(|byte| *byte != 0));
    within(proofs[0].1, origin, submit_ms);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gloas_timings_publish_a_head_that_returns_inside_the_fetch_budget() {
    head_delay_publishes(Duration::from_millis(2_500), [0xab; 32], 6_000).await;
    head_delay_publishes(Duration::from_millis(3_500), [0xab; 32], 6_500).await;
    head_delay_publishes(Duration::from_secs(5), [0x11; 32], 7_000).await;
}
