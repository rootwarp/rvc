//! RR2-06: one slot shares attestation data.
//!
//! Post-Electra the beacon API is slot-scoped (`committee_index` 0), so N
//! duties cost one `get_attestation_data`. Pre-Electra is one fetch per
//! distinct committee index. A failed key fails only the duties that share
//! it, and a duty signs only the data fetched for its own committee.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bn_manager::{
    AttestationData, AttestationDataResponse, AttesterDutiesResponse, AttesterDuty, BeaconError,
    BeaconNodeClient, Checkpoint, LegacyAttestation, MockBeaconNodeClient, MockMethod,
    OperationTimeouts, Propagator, SingleAttestation, SubmitAttestationResult,
    VersionedAttestation,
};
use common::pipeline_fixture::NoopBlockBeacon;
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
use duty_tracker::DutyTracker;
use eth_types::ForkSchedule;
use rvc::orchestrator::{
    AttestationResult, DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, PubkeyMap,
};
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use validator_store::{ValidatorConfig, ValidatorStore};

const GENESIS: u64 = 1_606_824_023;
const SLOTS_PER_EPOCH: u64 = 32;
/// Epoch 3 is Phase0 on the fixture schedule.
const PRE_ELECTRA_SLOT: u64 = 100;
/// First slot of Electra (epoch 50).
const POST_ELECTRA_SLOT: u64 = 1_600;
const COMMITTEE_LENGTH: u64 = 64;

struct Val {
    index: String,
    committee: u64,
}

struct Spec {
    slot: u64,
    committees: Vec<u64>,
    /// When set, every response uses this `data.index` instead of the committee.
    bn_index: Option<u64>,
    /// When set, `target.epoch` is this value instead of the duty slot's epoch.
    target_epoch: Option<u64>,
    /// Committees whose fetch always fails.
    fail_committees: Vec<u64>,
    /// Fail this many attestation-data calls, then succeed.
    fail_first: usize,
    fetch_delay: Duration,
    attestation_fetch: Option<Duration>,
    /// Pre-Electra aggregation-bit position equals the committee index.
    position_is_committee: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            slot: PRE_ELECTRA_SLOT,
            committees: vec![0],
            bn_index: None,
            target_epoch: None,
            fail_committees: Vec::new(),
            fail_first: 0,
            fetch_delay: Duration::ZERO,
            attestation_fetch: None,
            position_is_committee: false,
        }
    }
}

struct Harness {
    orchestrator: DutyOrchestrator<MockSlotClock, MockBeaconNodeClient, NoopBlockBeacon>,
    mock: Arc<MockBeaconNodeClient>,
    validators: Vec<Val>,
    slot: u64,
    _db_dir: tempfile::TempDir,
}

impl Harness {
    async fn run(&self) -> Vec<AttestationResult> {
        self.orchestrator.process_slot(self.slot).await.expect("process_slot")
    }
}

fn fork_schedule() -> Arc<ForkSchedule> {
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
        gloas_fork_epoch: 70,
        gloas_fork_version: [0, 0, 0, 8],
    })
}

fn root_hex(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

fn attestation_data(slot: u64, index: u64, root_byte: u8, target_epoch: u64) -> AttestationData {
    AttestationData {
        slot: slot.to_string(),
        index: index.to_string(),
        beacon_block_root: root_hex(root_byte),
        source: Checkpoint {
            epoch: target_epoch.saturating_sub(1).to_string(),
            root: root_hex(0x22),
        },
        target: Checkpoint { epoch: target_epoch.to_string(), root: root_hex(0x33) },
    }
}

fn wire(spec: Spec) -> Harness {
    let slot = spec.slot;
    let target_epoch = spec.target_epoch.unwrap_or(slot / SLOTS_PER_EPOCH);
    let mut manager = KeyManager::new();
    let mut map = HashMap::new();
    let store = Arc::new(ValidatorStore::new([0xaa; 20], 30_000_000));
    let mut validators = Vec::with_capacity(spec.committees.len());
    let mut duties = Vec::with_capacity(spec.committees.len());

    for (offset, committee) in spec.committees.iter().copied().enumerate() {
        let secret = SecretKey::generate();
        let pubkey = secret.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
        let index = offset.to_string();
        let position = if spec.position_is_committee { committee } else { 0 };
        let length = if spec.position_is_committee { COMMITTEE_LENGTH } else { 1 };
        duties.push(AttesterDuty {
            pubkey: pubkey_hex,
            validator_index: index.clone(),
            committee_index: committee.to_string(),
            committee_length: length.to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: position.to_string(),
            slot: slot.to_string(),
        });
        let bytes = pubkey.to_bytes();
        map.insert(bytes, pubkey.clone());
        store.add_validator(ValidatorConfig::new(bytes)).expect("register validator");
        manager.insert(secret);
        validators.push(Val { index, committee });
    }

    let duties_for_fetch = duties.clone();
    let bn_index = spec.bn_index;
    let fail_committees = spec.fail_committees.clone();
    let fail_remaining = Arc::new(AtomicUsize::new(spec.fail_first));
    let mut mock = MockBeaconNodeClient::new()
        .with_get_attester_duties(move |epoch, _indices| {
            let data =
                if epoch == slot / SLOTS_PER_EPOCH { duties_for_fetch.clone() } else { Vec::new() };
            Ok(AttesterDutiesResponse {
                dependent_root: root_hex(0xdd),
                execution_optimistic: false,
                data,
            })
        })
        .with_get_attestation_data(move |_slot, committee| {
            let index = bn_index.unwrap_or(committee);
            let root_byte = u8::try_from(committee).unwrap_or(0);
            Ok(AttestationDataResponse {
                data: attestation_data(slot, index, root_byte, target_epoch),
            })
        })
        .with_get_attestation_data_error(move |_slot, committee| {
            if fail_committees.contains(&committee) {
                return Some(BeaconError::HttpError(format!("committee {committee}")));
            }
            if fail_remaining.load(Ordering::SeqCst) > 0 {
                fail_remaining.fetch_sub(1, Ordering::SeqCst);
                return Some(BeaconError::HttpError("transient".to_string()));
            }
            None
        })
        .with_submit_attestation(|_| Ok(SubmitAttestationResult::Success));
    if !spec.fetch_delay.is_zero() {
        mock = mock.with_method_delay(MockMethod::GetAttestationData, spec.fetch_delay);
    }
    let mock = Arc::new(mock);

    let db_dir = tempfile::tempdir().expect("slashing db dir");
    let slashing_db = Arc::new(
        SlashingDb::open(db_dir.path().join("slashing.sqlite")).expect("open slashing db"),
    );
    let signer = Arc::new(
        SignerService::new(Arc::new(CompositeSigner::new(LocalSigner::new(manager))), slashing_db)
            .with_enablement(always_enabled()),
    );
    let indices: Vec<String> = validators.iter().map(|val| val.index.clone()).collect();
    let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
    let duty_tracker = Arc::new(DutyTracker::new(Arc::clone(&beacon), indices));
    let clock = Arc::new(MockSlotClock::new(GENESIS, Duration::from_secs(12), SLOTS_PER_EPOCH));
    clock.set_slot(slot);
    let mut config = OrchestratorConfig::new([0xaa; 32], fork_schedule());
    if let Some(attestation_fetch) = spec.attestation_fetch {
        config = config
            .with_timeouts(OperationTimeouts { attestation_fetch, ..OperationTimeouts::default() });
    }
    let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(map));
    let deps = OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        Arc::new(Propagator::new(Arc::clone(&mock))),
        beacon,
        Arc::new(NoopBlockBeacon),
        None,
        store,
        config,
        pubkey_map,
    );
    let (orchestrator, _handle) = DutyOrchestrator::new(deps);
    Harness { orchestrator, mock, validators, slot, _db_dir: db_dir }
}

fn pre_electra_items(calls: &[VersionedAttestation]) -> Vec<LegacyAttestation> {
    let mut items = Vec::new();
    for batch in calls {
        let VersionedAttestation::PreElectra(batch) = batch else {
            panic!("pre-Electra slot published {batch:?}");
        };
        items.extend(batch.iter().cloned());
    }
    items
}

fn electra_items(calls: &[VersionedAttestation]) -> Vec<SingleAttestation> {
    let mut items = Vec::new();
    for batch in calls {
        let VersionedAttestation::Electra(batch) = batch else {
            panic!("Electra slot published {batch:?}");
        };
        items.extend(batch.iter().cloned());
    }
    items
}

fn participation_bits(aggregation_bits: &str, committee_length: usize) -> Vec<usize> {
    let raw = aggregation_bits.strip_prefix("0x").unwrap_or(aggregation_bits);
    let bytes = hex::decode(raw).expect("aggregation bits");
    let mut set = Vec::new();
    for (byte_index, byte) in bytes.iter().enumerate() {
        for bit in 0..8 {
            let position = byte_index * 8 + bit;
            if position < committee_length && byte & (1 << bit) != 0 {
                set.push(position);
            }
        }
    }
    set
}

fn root_is_repeated(root: &str, byte: u8) -> bool {
    let raw = root.strip_prefix("0x").unwrap_or(root);
    let bytes = hex::decode(raw).expect("root");
    bytes.len() == 32 && bytes.iter().all(|value| *value == byte)
}

/// N = 200, several committees, paused clock. Post-Electra is one fetch.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn post_electra_fetches_attestation_data_once_per_slot() {
    const N: usize = 200;
    // No duty sits in committee 0, so a fetch of committee 0 is the shared key
    // and not "the first duty's committee".
    let committees: Vec<u64> = (0..N as u64).map(|index| (index % 16) + 1).collect();
    let harness = wire(Spec {
        slot: POST_ELECTRA_SLOT,
        committees: committees.clone(),
        bn_index: Some(9),
        ..Spec::default()
    });
    let results = harness.run().await;
    assert_eq!(results.len(), N);
    assert!(results.iter().all(|result| result.outcome.is_published()), "{results:?}");
    assert_eq!(
        harness.mock.get_attestation_data_calls(),
        vec![(POST_ELECTRA_SLOT, 0)],
        "one post-Electra get_attestation_data for the slot"
    );

    let by_index: HashMap<u64, u64> = harness
        .validators
        .iter()
        .map(|val| (val.index.parse::<u64>().expect("index"), val.committee))
        .collect();
    let items = electra_items(&harness.mock.submit_attestation_calls());
    assert_eq!(items.len(), N);
    for item in &items {
        assert_eq!(item.data.index, "0", "EIP-7549 zeros data.index before publish");
        assert_eq!(item.committee_index, by_index[&item.attester_index]);
    }
}

/// Duplicate committees still cost one fetch each, not one per duty.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pre_electra_fetches_once_per_distinct_committee_index() {
    let harness = wire(Spec {
        slot: PRE_ELECTRA_SLOT,
        committees: vec![2, 2, 5, 5, 5, 8],
        ..Spec::default()
    });
    let results = harness.run().await;
    assert_eq!(results.len(), 6);
    assert!(results.iter().all(|result| result.outcome.is_published()), "{results:?}");
    let mut calls = harness.mock.get_attestation_data_calls();
    calls.sort();
    assert_eq!(calls, vec![(PRE_ELECTRA_SLOT, 2), (PRE_ELECTRA_SLOT, 5), (PRE_ELECTRA_SLOT, 8)]);
}

/// Committee 3's shared fetch fails. The other committees still publish.
///
/// Two duties share committee 3. Today that is two per-duty failures; after the
/// memo it is one key plus its single retry. Either way the call count is 2
/// and only those two duties fail.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn failing_fetch_for_committee_3_fails_only_committee_3() {
    let harness = wire(Spec {
        slot: PRE_ELECTRA_SLOT,
        committees: vec![0, 1, 3, 3, 5],
        fail_committees: vec![3],
        ..Spec::default()
    });
    let results = harness.run().await;
    assert_eq!(results.len(), 5);

    let mut failed: Vec<String> = results
        .iter()
        .filter(|result| !result.outcome.is_published())
        .map(|result| result.validator_index.clone())
        .collect();
    failed.sort();
    assert_eq!(failed, vec!["2".to_string(), "3".to_string()]);
    for result in results.iter().filter(|result| !result.outcome.is_published()) {
        let error = common::failed_attestation_message(result);
        assert!(
            error.contains("committee 3"),
            "committee 3 failure must name that fetch, got {error}"
        );
    }
    let succeeded: Vec<_> = results.iter().filter(|result| result.outcome.is_published()).collect();
    assert_eq!(succeeded.len(), 3);

    let mut calls = harness.mock.get_attestation_data_calls();
    let committee_3 = calls.iter().filter(|(_, committee)| *committee == 3).count();
    calls.retain(|(_, committee)| *committee != 3);
    calls.sort();
    assert_eq!(committee_3, 2, "one attempt plus one retry for the failed key");
    assert_eq!(calls, vec![(PRE_ELECTRA_SLOT, 0), (PRE_ELECTRA_SLOT, 1), (PRE_ELECTRA_SLOT, 5)]);

    let mut indexes: Vec<String> = pre_electra_items(&harness.mock.submit_attestation_calls())
        .into_iter()
        .map(|item| item.data.index)
        .collect();
    indexes.sort();
    assert_eq!(indexes, vec!["0".to_string(), "1".to_string(), "5".to_string()]);
}

/// Each pre-Electra duty signs the data fetched for its committee.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pre_electra_duty_uses_its_own_committee_data() {
    let committees = vec![0, 1, 4, 7];
    let harness = wire(Spec {
        slot: PRE_ELECTRA_SLOT,
        committees: committees.clone(),
        position_is_committee: true,
        ..Spec::default()
    });
    let results = harness.run().await;
    assert!(results.iter().all(|result| result.outcome.is_published()), "{results:?}");
    let mut calls = harness.mock.get_attestation_data_calls();
    calls.sort();
    assert_eq!(
        calls,
        vec![
            (PRE_ELECTRA_SLOT, 0),
            (PRE_ELECTRA_SLOT, 1),
            (PRE_ELECTRA_SLOT, 4),
            (PRE_ELECTRA_SLOT, 7),
        ]
    );

    let items = pre_electra_items(&harness.mock.submit_attestation_calls());
    assert_eq!(items.len(), committees.len());
    let mut seen = Vec::new();
    for item in &items {
        let index: u64 = item.data.index.parse().expect("data.index");
        let bits = participation_bits(&item.aggregation_bits, COMMITTEE_LENGTH as usize);
        assert_eq!(bits, vec![index as usize], "aggregation bit must be this duty's committee");
        assert!(
            root_is_repeated(&item.data.beacon_block_root, u8::try_from(index).expect("index")),
            "head root must be the committee byte, got {}",
            item.data.beacon_block_root
        );
        seen.push(index);
    }
    seen.sort();
    assert_eq!(seen, committees);
}

/// A fast failure is retried once. The second attempt still sits inside
/// `attestation_fetch`; it does not start a new timeout.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn attestation_data_fetch_retries_once_inside_the_fetch_budget() {
    let harness = wire(Spec {
        slot: PRE_ELECTRA_SLOT,
        committees: vec![4],
        fail_first: 1,
        ..Spec::default()
    });
    let started = tokio::time::Instant::now();
    let results = harness.run().await;
    let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
    assert_eq!(results.len(), 1);
    assert!(results[0].outcome.is_published(), "{results:?}");
    assert_eq!(
        harness.mock.get_attestation_data_calls(),
        vec![(PRE_ELECTRA_SLOT, 4), (PRE_ELECTRA_SLOT, 4)]
    );
    assert_eq!(elapsed, Duration::ZERO, "a fast retry must not spend a second budget");
}

/// A call that burns the whole `attestation_fetch` budget is not retried.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn attestation_data_fetch_does_not_retry_when_the_budget_is_spent() {
    let budget = Duration::from_millis(50);
    let harness = wire(Spec {
        slot: PRE_ELECTRA_SLOT,
        committees: vec![4],
        fetch_delay: Duration::from_millis(500),
        attestation_fetch: Some(budget),
        ..Spec::default()
    });
    let started = tokio::time::Instant::now();
    let results = harness.run().await;
    let elapsed = tokio::time::Instant::now().saturating_duration_since(started);
    assert_eq!(results.len(), 1);
    assert!(!results[0].outcome.is_published(), "{results:?}");
    let error = common::failed_attestation_message(&results[0]);
    assert!(
        error.contains("Timeout getting attestation data"),
        "budget exhaustion must surface as the fetch timeout, got {error}"
    );
    let attempts = harness
        .mock
        .call_stamps()
        .into_iter()
        .filter(|stamp| stamp.method == MockMethod::GetAttestationData)
        .count();
    assert_eq!(attempts, 1, "no second attempt after the budget is spent");
    assert!(
        harness.mock.get_attestation_data_calls().is_empty(),
        "the in-flight attempt is cancelled before the mock records a result"
    );
    assert_eq!(elapsed, budget, "elapsed {elapsed:?} must be the one fetch budget, not a second");
}

/// Duty-slot fork is Electra, but the response target epoch is still Deneb.
/// The shared entry must not be reused; each committee is fetched on its own.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn boundary_slot_fork_disagreement_fetches_per_committee() {
    let harness = wire(Spec {
        slot: POST_ELECTRA_SLOT,
        committees: vec![1, 3],
        // Epoch 49 is Deneb on the fixture schedule (Electra starts at 50).
        target_epoch: Some(49),
        ..Spec::default()
    });
    let results = harness.run().await;
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|result| !result.outcome.is_published()), "{results:?}");
    for result in &results {
        let error = common::failed_attestation_message(result);
        assert!(
            error.contains("target epoch"),
            "mismatched target epoch must fail the duty, got {error}"
        );
    }
    assert!(harness.mock.submit_attestation_calls().is_empty(), "nothing is published");

    let calls = harness.mock.get_attestation_data_calls();
    assert_eq!(
        calls.first().copied(),
        Some((POST_ELECTRA_SLOT, 0)),
        "shared fetch first: {calls:?}"
    );
    let mut rest = calls[1..].to_vec();
    rest.sort();
    assert_eq!(
        rest,
        vec![(POST_ELECTRA_SLOT, 1), (POST_ELECTRA_SLOT, 3)],
        "disagreement refetches each committee: {calls:?}"
    );
}
