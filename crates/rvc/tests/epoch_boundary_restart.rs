//! Restart regression through the public bootstrap (W4-E4d, #652).
//!
//! `boot_at_slot` starts `rvc::bootstrap::run_with_slot_clock` with a
//! wiremock beacon node and a slot clock that paused tokio time moves.
//!
//! A client-operation completion ledger controls the virtual time:
//!
//! - `ClientLedger` records each `beacon.http` and
//!   `beacon.get_aggregate_attestation` span of the beacon client. The span
//!   opens before the request. It closes after the client reads and decodes
//!   the answer, or when the call is dropped.
//! - `spawn_advance_gate` stops tokio auto-advance while one or more of
//!   these spans are open.
//! - `Boot::step_to` sleeps until a slot offset. Then it waits until no
//!   client operation is open, and compares the ledger with the server.
//!
//! Virtual time does not move during a beacon-node call. The SSE stream is
//! not in the ledger. A std-thread watchdog stops a test that hangs. The
//! watchdog is not an assertion.
//!
//! `orchestrator_at_slot` is the second harness (W4-E6b3). It starts
//! `DutyOrchestrator::run` and its epoch boundary runner. The harness uses a
//! mock beacon node in the test process. The tests update the live
//! `ValidatorStore` and count calls to the registration signer. The public
//! bootstrap function gives callers no access to the store or the signer.
//! A tracing layer records the end of each registration step of the runner.
//! The tests wait for this event before they check the POSTs and the calls.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use beacon::{BeaconClient, BeaconClientConfig, DependentRootResponse};
use bn_manager::{
    BeaconNodeClient, MockBeaconNodeClient, MockMethod, OperationTimeouts, Propagator,
    SignedValidatorRegistration,
};
use builder::{BuilderService, RegistrationSigner};
use common::pipeline_fixture::NoopBlockBeacon;
use crypto::{
    CompositeSigner, EncryptionKdf, KeyManager, Keystore, LocalSigner, PublicKey, SecretKey,
    Signature,
};
use duty_tracker::DutyTracker;
use eth_types::{
    BuilderRequestAuth, ForkSchedule, ProposerPreferences, Root, ValidatorRegistrationV1,
};
use keymanager_api::traits::ValidatorManager;
use rvc::background_tasks::config_url::{
    ProposerConfigApplier, ValidatorConfigUpdate as UrlUpdate,
};
use rvc::bootstrap::{run_with_slot_clock, BootstrapError, RunOptions, TaskExecutor};
use rvc::config::{Config, Network};
use rvc::keymanager_adapters::ValidatorManagerAdapter;
use rvc::orchestrator::{
    DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorError, OrchestratorHandle,
};
use serde_json::{json, Value};
use signer::{always_enabled, SignerError, SignerService, ValidatorSigner};
use slashing::SlashingDb;
use tempfile::TempDir;
use timing::{DeadlineBps, DeadlineSchedule, SlotClock, TimingError};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::subscriber::DefaultGuard;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use validator_store::{ValidatorConfig, ValidatorStore};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SLOT_MS: u64 = 12_000;
const SLOTS_PER_EPOCH: u64 = 32;
const GENESIS_TIME: u64 = 1_606_824_023;
/// The fixture chain does not reach this fork epoch.
const FAR_FUTURE_EPOCH: &str = "18446744073709551615";
const INDEX: &str = "7";
const PASSWORD: &str = "w4e4d-restart";
const FEE_RECIPIENT: &str = "0x1111111111111111111111111111111111111111";
/// The key has its attester duty at this slot of each epoch.
const DUTY_OFFSET: u64 = 20;
const TRACKED_SPANS: [&str; 2] = ["beacon.http", "beacon.get_aggregate_attestation"];
const EVENTS: &str = "/eth/v1/events";
const PREPARE: &str = "/eth/v1/validator/prepare_beacon_proposer";
const SUBSCRIPTIONS: &str = "/eth/v1/validator/beacon_committee_subscriptions";
const REGISTRATION: &str = "/eth/v1/validator/register_validator";
const RUNNER_TASK: &str = "epoch.boundary.runner";
const ORCHESTRATOR_TASK: &str = "duty_orchestrator";
/// Each drain aborts this Telemetry task, because it has no cooperative stop.
const METRICS_TASK: &str = "metrics_server";
/// The watchdog gives hang protection only. A test that passes takes a few
/// seconds.
const WATCHDOG: Duration = Duration::from_secs(120);
const RECORDING: &str = "The wiremock server must record the requests.";
const SLOT: Duration = Duration::from_millis(SLOT_MS);
/// The tests start in the first slot of epoch E.
const EPOCH_E: u64 = 3;
/// The runner logs this event at the end of the registration step of an epoch.
const REGISTRATION_DONE: &str = "Epoch builder registration completed";
/// These constants contain the bytes of the secret keys for validators A and B.
const KEY_A: [u8; 32] = [0x2b; 32];
const KEY_B: [u8; 32] = [0x2c; 32];

/// #652: a restart at slot 10 sends the prepare and the committee
/// subscriptions of epochs 0 and 1 to the beacon node before slot 32.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_restart_at_slot_10_prepares_and_subscribes_in_that_epoch() {
    let boot = boot_at_slot(10, BootOpts::default()).await;
    let ledger = boot.recorders.ledger.clone();
    watched(&ledger, async move {
        boot.step_to(31, 11_900).await;
        assert_prepared(&boot).await;
        assert_subscribed(&boot).await;
        boot.shut_down().await;
    })
    .await;
}

/// A cancel of the executor token joins the runner and the slot loop, and
/// `run_with_slot_clock` returns `Ok`. The drain aborts only the metrics
/// server. It is a Telemetry task with no cooperative stop.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_restart_shutdown_joins_the_runner_and_returns() {
    let boot = boot_at_slot(10, BootOpts::default()).await;
    let ledger = boot.recorders.ledger.clone();
    watched(&ledger, async move {
        boot.step_to(31, 11_900).await;
        assert_prepared(&boot).await;
        let drain = boot.shut_down().await;
        for task in [RUNNER_TASK, ORCHESTRATOR_TASK] {
            assert!(
                drain.joined.contains(&format!("{task:?}")),
                "The drain must join the {task} task. Joined: {}",
                drain.joined
            );
        }
        assert_eq!(
            drain.aborted,
            format!("[{METRICS_TASK:?}]"),
            "The drain must abort no task other than {METRICS_TASK}."
        );
    })
    .await;
}

/// The runner's boot-epoch step registers the key when the builder is on.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_restart_at_slot_10_registers_in_that_epoch_when_the_builder_is_on() {
    let boot = boot_at_slot(10, BootOpts { builder: true, ..BootOpts::default() }).await;
    let ledger = boot.recorders.ledger.clone();
    watched(&ledger, async move {
        boot.step_to(31, 11_900).await;
        let registered = boot.posted(REGISTRATION).await;
        assert!(
            registered.iter().any(|item| item["message"]["pubkey"] == boot.pubkey.as_str()),
            "The beacon node must receive a register_validator entry for the key in epoch 0. \
             Entries: {registered:?}"
        );
        boot.shut_down().await;
    })
    .await;
}

/// W4-E6a (654-AC1). The client starts at slot 10 with the builder enabled.
/// These conditions must hold:
///
/// - The beacon node receives a register_validator POST in epoch 0.
/// - The beacon node receives a register_validator POST in epoch 1.
/// - The two POSTs contain the same keys and the same signature bytes.
///
/// The byte check does not count the signer calls. The runner tests and the
/// coordinator tests count them.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_registration_reaches_bn_in_restart_epoch_and_every_epoch_after() {
    let boot = boot_at_slot(10, BootOpts { builder: true, ..BootOpts::default() }).await;
    let ledger = boot.recorders.ledger.clone();
    watched(&ledger, async move {
        boot.step_to(31, 11_900).await;
        let epoch_0 = boot.posted(REGISTRATION).await;
        boot.step_to(32, 11_900).await;
        let epoch_1 = boot.posted(REGISTRATION).await.split_off(epoch_0.len());
        assert!(
            !epoch_0.is_empty(),
            "The beacon node must receive a register_validator POST in epoch 0."
        );
        assert!(
            !epoch_1.is_empty(),
            "The beacon node must receive a register_validator POST in epoch 1. Epoch-0 \
             entries: {epoch_0:?}"
        );
        assert_eq!(
            signatures_by_key(&epoch_1),
            signatures_by_key(&epoch_0),
            "The epoch-1 POST must carry the same keys, each with its epoch-0 signature."
        );
        assert!(
            signatures_by_key(&epoch_0).contains_key(boot.pubkey.as_str()),
            "The registration must carry the key. Entries: {epoch_0:?}"
        );
        boot.shut_down().await;
    })
    .await;
}

/// Maps each registration entry's `message.pubkey` to its `signature`.
fn signatures_by_key(entries: &[Value]) -> BTreeMap<String, Value> {
    entries
        .iter()
        .map(|entry| {
            let pubkey =
                entry["message"]["pubkey"].as_str().expect("Each entry must have a pubkey.");
            (pubkey.to_owned(), entry["signature"].clone())
        })
        .collect()
}

/// W4-E6b3 (654-AC10, 696-5). No keymanager route sets `builder_proposals`.
/// The test uses `ValidatorManagerAdapter::remove_validator` to remove key A
/// from the store. The keymanager DELETE uses this adapter. These conditions
/// must hold:
///
/// - The epoch E POST must contain keys A and B.
/// - After the adapter removes key A, the epoch E+1 POST must contain only
///   the epoch E registration for key B.
/// - The service must make no calls to sign a registration in epoch E+1.
///
/// `registration_epoch` also requires one POST in each epoch, in the first
/// slot of that epoch.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_builder_flag_off_via_keymanager_evicts_registration() {
    let opts = OrchestratorOpts { builder_keys: vec![KEY_A, KEY_B] };
    let mut orch = orchestrator_at_slot(EPOCH_E * SLOTS_PER_EPOCH, opts).await;
    let (a, b) = (orch.pubkeys[0], orch.pubkeys[1]);
    let epoch_e = orch.registration_epoch(EPOCH_E).await;
    assert_epoch_e(&epoch_e, a, b);

    let removed = ValidatorManagerAdapter::new(Arc::clone(&orch.store)).remove_validator(&a);
    assert_eq!(removed, Ok(true), "The validator manager must remove key A from the store.");
    orch.advance_to_epoch(EPOCH_E + 1).await;
    let epoch_e1 = orch.registration_epoch(EPOCH_E + 1).await;

    assert!(
        !keys_of(&epoch_e1.post).contains(&a),
        "After the keymanager DELETE, the epoch E+1 POST must not contain key A."
    );
    assert_epoch_e1(&epoch_e1, &epoch_e, &b);
    orch.shut_down().await;
}

/// W4-E6b3 (654-AC11, 696-5). The test uses `ProposerConfigApplier::apply` to
/// set `builder_enabled` to `false` for key A. Then the test sets
/// `builder_enabled` to `true` for key A. These conditions must hold:
///
/// - The epoch E POST must contain keys A and B.
/// - While `builder_enabled` is `false`, the epoch E+1 POST must contain only
///   the epoch E registration for key B.
/// - The service must make no calls to sign a registration in epoch E+1.
/// - After the test sets `builder_enabled` to `true`, the epoch E+2 POST must
///   contain key A.
/// - In epoch E+2, the service must make one call to sign a registration for
///   key A.
/// - The epoch E+2 POST must contain only the new registration for key A and
///   the epoch E registration for key B.
///
/// `registration_epoch` also requires one POST in each epoch, in the first
/// slot of that epoch.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn test_builder_flag_off_via_proposer_config_url_evicts_registration() {
    let opts = OrchestratorOpts { builder_keys: vec![KEY_A, KEY_B] };
    let mut orch = orchestrator_at_slot(EPOCH_E * SLOTS_PER_EPOCH, opts).await;
    let (a, b) = (orch.pubkeys[0], orch.pubkeys[1]);
    let mut applier = ProposerConfigApplier::new();
    let epoch_e = orch.registration_epoch(EPOCH_E).await;
    assert_epoch_e(&epoch_e, a, b);

    applier.apply(&orch.store, Some(vec![builder_flag(&a, false)]), None);
    orch.advance_to_epoch(EPOCH_E + 1).await;
    let epoch_e1 = orch.registration_epoch(EPOCH_E + 1).await;

    assert!(
        !keys_of(&epoch_e1.post).contains(&a),
        "While `builder_enabled` is `false`, the epoch E+1 POST must not contain key A."
    );
    assert_epoch_e1(&epoch_e1, &epoch_e, &b);

    applier.apply(&orch.store, Some(vec![builder_flag(&a, true)]), None);
    orch.advance_to_epoch(EPOCH_E + 2).await;
    let epoch_e2 = orch.registration_epoch(EPOCH_E + 2).await;

    assert!(
        keys_of(&epoch_e2.post).contains(&a),
        "After the test sets `builder_enabled` to `true`, the epoch E+2 POST must contain key A."
    );
    assert_eq!(
        keys_of(&epoch_e2.signed),
        vec![a],
        "In epoch E+2, the service must make one call to sign a registration for key A."
    );
    assert_eq!(
        by_key(&epoch_e2.post),
        by_key(&[epoch_e2.signed.clone(), entries_of(&epoch_e.post, &b)].concat()),
        "The epoch E+2 POST must contain only the new registration for key A and the epoch E \
         registration for key B."
    );
    orch.shut_down().await;
}

/// Checks the epoch E record of the two builder-flag tests.
fn assert_epoch_e(epoch_e: &EpochRegistration, a: [u8; 48], b: [u8; 48]) {
    let mut both = vec![a, b];
    both.sort_unstable();
    assert_eq!(keys_of(&epoch_e.post), both, "The epoch E POST must contain keys A and B.");
    assert_eq!(
        keys_of(&epoch_e.signed),
        both,
        "In epoch E, the service must make one call to sign a registration for each of keys A \
         and B."
    );
    assert_eq!(
        by_key(&epoch_e.post),
        by_key(&epoch_e.signed),
        "The epoch E POST must contain the registrations that the signer signs in epoch E."
    );
}

/// Checks the epoch E+1 record of the two builder-flag tests. Key A is not
/// in the builder set in epoch E+1.
fn assert_epoch_e1(epoch_e1: &EpochRegistration, epoch_e: &EpochRegistration, b: &[u8; 48]) {
    assert_eq!(
        keys_of(&epoch_e1.signed),
        Vec::<[u8; 48]>::new(),
        "The service must make no calls to sign a registration in epoch E+1."
    );
    assert_eq!(
        epoch_e1.post,
        entries_of(&epoch_e.post, b),
        "The epoch E+1 POST must contain only the epoch E registration for key B."
    );
}

/// Gets the `message.pubkey` values of the registrations, in sorted order.
fn keys_of(posted: &[SignedValidatorRegistration]) -> Vec<[u8; 48]> {
    by_key(posted).iter().map(|entry| entry.message.pubkey).collect()
}

/// Gets a copy of the registrations, in the order of `message.pubkey`.
fn by_key(posted: &[SignedValidatorRegistration]) -> Vec<SignedValidatorRegistration> {
    let mut sorted = posted.to_vec();
    sorted.sort_by_key(|entry| entry.message.pubkey);
    sorted
}

/// Gets the registrations for `pubkey` from `posted`.
fn entries_of(
    posted: &[SignedValidatorRegistration],
    pubkey: &[u8; 48],
) -> Vec<SignedValidatorRegistration> {
    posted.iter().filter(|entry| entry.message.pubkey == *pubkey).cloned().collect()
}

/// Makes a proposer configuration update that sets only `builder_enabled` for
/// `pubkey`.
fn builder_flag(pubkey: &[u8; 48], enabled: bool) -> UrlUpdate {
    UrlUpdate {
        pubkey: format!("0x{}", hex::encode(pubkey)),
        fee_recipient: None,
        builder_enabled: Some(enabled),
        gas_limit: None,
    }
}

/// This is the harness self-test. The server holds the answer, so the call stays
/// open. The 1 s client timeout must not fire, because virtual time does not
/// move while the call is open.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn ledger_freezes_virtual_time_until_the_client_has_the_answer() {
    let recorders = install_recorders();
    let server = MockServer::start().await;
    let (arrival, arrived) = tokio::sync::oneshot::channel::<()>();
    // Declared after the server, so a panic drops it first and frees the
    // server thread.
    let (release, hold) = std::sync::mpsc::channel::<()>();
    let arrival = Mutex::new(Some(arrival));
    let hold = Mutex::new(hold);
    Mock::given(method("GET"))
        .and(path("/eth/v2/node/version"))
        .respond_with(move |_: &Request| {
            if let Some(arrival) =
                arrival.lock().expect("The arrival lock must not be poisoned.").take()
            {
                let _ = arrival.send(());
            }
            // This blocks the wiremock thread. The test runtime continues.
            let _ = hold.lock().expect("The hold lock must not be poisoned.").recv();
            ResponseTemplate::new(200).set_body_json(node_version())
        })
        .mount(&server)
        .await;
    let client = BeaconClient::new(
        BeaconClientConfig::new(server.uri())
            .with_timeout(Duration::from_secs(1))
            .with_max_retries(0),
    )
    .expect("The test must build the beacon client.");
    let ledger = &recorders.ledger;
    watched(ledger, async {
        let t0 = Instant::now();
        let mut call = tokio::spawn(async move { client.get_node_version().await });
        tokio::select! {
            biased;
            arrived = arrived => arrived.expect("The responder must signal the arrival."),
            ended = &mut call => {
                panic!("The call must not end before the server answers. It returned {ended:?}.")
            }
        }
        assert_eq!(Instant::now(), t0, "Virtual time must not move while the request is open.");
        assert_eq!(ledger.outstanding(), 1, "The ledger must hold the open call.");
        release.send(()).expect("The responder must wait for the release.");
        let answer = call.await.expect("The call task must not panic.");
        assert!(answer.is_ok(), "The call must return the answer, not a timeout: {answer:?}");
        assert_eq!(
            Instant::now(),
            t0,
            "Virtual time must not move before the client has the answer."
        );
        ledger.settled(&server).await;
    })
    .await;
}

/// Asserts that the beacon node received a prepare for the key's index.
async fn assert_prepared(boot: &Boot) {
    let prepared = boot.posted(PREPARE).await;
    assert!(
        prepared.iter().any(|item| item["validator_index"] == INDEX),
        "The beacon node must receive prepare_beacon_proposer for index {INDEX} before slot 32. \
         Entries: {prepared:?}"
    );
}

/// Asserts that the beacon node received the committee subscription of the
/// key's duty slot in epoch 0 and in epoch 1.
async fn assert_subscribed(boot: &Boot) {
    let slots: BTreeSet<String> = boot
        .posted(SUBSCRIPTIONS)
        .await
        .iter()
        .filter(|item| item["validator_index"] == INDEX)
        .filter_map(|item| item["slot"].as_str().map(str::to_owned))
        .collect();
    for epoch in [0, 1] {
        let slot = duty_slot(epoch).to_string();
        assert!(
            slots.contains(&slot),
            "The beacon node must receive the committee subscription for the epoch-{epoch} duty \
             slot {slot} before slot 32. Subscribed slots: {slots:?}"
        );
    }
}

/// W4-D2c fix1: the Keymanager step fails after boot spawns the index
/// resolver. Boot must cancel the process token and join the resolver before
/// it returns the error. Nextest runs each test in its own process, so the
/// running-task gauge counts only the tasks of this boot.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn boot_error_after_the_first_spawn_stops_the_index_resolver() {
    let boot =
        boot_at_slot(10, BootOpts { missing_keymanager_token: true, ..BootOpts::default() }).await;
    let Boot { run, token, recorders, .. } = boot;
    watched(&recorders.ledger, async {
        let running =
            |task: &str| metrics::definitions::RVC_TASKS_RUNNING.with_label_values(&[task]).get();
        let result = run.await.expect("The boot task must not panic.");
        let (resolvers, loops) = (running("index.resolve"), running("liveness_loop"));
        let cancelled = token.is_cancelled();
        token.cancel();
        assert!(
            matches!(
                result,
                Err(BootstrapError::Keymanager(
                    rvc::keymanager_adapters::SpawnKeymanagerApiError::Token(_)
                ))
            ),
            "Boot must return the Keymanager token error. The result is {result:?}."
        );
        assert_eq!(loops, 0, "Boot must not start the liveness loop before the token error.");
        assert_eq!(resolvers, 0, "Boot must stop the index resolver before it returns an error.");
        assert!(cancelled, "Boot must cancel the process token before it returns an error.");
    })
    .await;
}

/// `boot_at_slot` reads these options.
#[derive(Clone, Copy, Default)]
struct BootOpts {
    /// This is the `builder_proposals` value of the key in the validators file.
    builder: bool,
    /// Detection and the Keymanager API are on, and the Keymanager token file
    /// is in a directory that does not exist. Boot then fails at the
    /// Keymanager step, after it spawns the index resolver.
    missing_keymanager_token: bool,
}

/// This is one `run_with_slot_clock` process with a wiremock beacon node.
struct Boot {
    server: MockServer,
    token: CancellationToken,
    run: JoinHandle<Result<(), BootstrapError>>,
    recorders: Recorders,
    /// This is the start of the boot slot, in paused tokio time.
    origin: Instant,
    start_slot: u64,
    pubkey: String,
    _dir: TempDir,
}

/// Boots `run_with_slot_clock` at the start of `start_slot`.
///
/// The ledger and the drain capture are the thread default before the
/// `run_with_slot_clock` task starts.
async fn boot_at_slot(start_slot: u64, opts: BootOpts) -> Boot {
    let recorders = install_recorders();
    let dir = TempDir::new().expect("The test must create the temporary directory.");
    let secret = SecretKey::from_bytes(&[0x2a; 32]).expect("The fixed secret key must be valid.");
    let pubkey = format!("0x{}", hex::encode(secret.public_key().to_bytes()));
    let (keystore_path, password_file) = write_keys(dir.path(), &secret);
    let validators_config = dir.path().join("validators.toml");
    std::fs::write(
        &validators_config,
        format!(
            "[defaults]\nfee_recipient = \"{FEE_RECIPIENT}\"\n\n[[validators]]\npubkey = \
             \"{pubkey}\"\nbuilder_proposals = {}\n",
            opts.builder
        ),
    )
    .expect("The test must write the validators file.");

    let server = MockServer::start().await;
    mount_beacon_node(&server, &pubkey).await;
    let mut config = Config {
        beacon_url: server.uri(),
        beacon_nodes: vec![server.uri()],
        network: Network::Custom,
        genesis_time: Some(GENESIS_TIME),
        genesis_validators_root: Some(root("11")),
        keystore_path,
        password_file: Some(password_file),
        slashing_db_path: dir.path().join("slashing.sqlite"),
        allow_fresh_db: true,
        disable_keystore_locking: true,
        doppelganger_detection: false,
        metrics_port: 0,
        validators_config: Some(validators_config),
        ..Default::default()
    };
    if opts.missing_keymanager_token {
        config.doppelganger_detection = true;
        config.keymanager.enabled = true;
        config.keymanager.address = Some("127.0.0.1:0".into());
        config.keymanager.token_file = Some(dir.path().join("absent").join("token"));
    }
    let options = RunOptions {
        strict_permissions: false,
        strict_slashing_semantics: false,
        timeouts: OperationTimeouts::default(),
    };
    let token = CancellationToken::new();
    let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
    let origin = Instant::now();
    let clock = Arc::new(PausedSlotClock { origin, start_slot });
    let run = tokio::spawn(run_with_slot_clock(config, options, executor, shutdown_rx, clock));
    Boot { server, token, run, recorders, origin, start_slot, pubkey, _dir: dir }
}

impl Boot {
    /// Sleeps until `offset_ms` into `slot`, timer by timer. Then waits until
    /// no client operation is open.
    async fn step_to(&self, slot: u64, offset_ms: u64) {
        let slots = slot
            .checked_sub(self.start_slot)
            .expect("The step slot must not be before the boot slot.");
        let target = self.origin + Duration::from_millis(slots * SLOT_MS + offset_ms);
        tokio::time::sleep_until(target).await;
        self.recorders.ledger.settled(&self.server).await;
    }

    /// Returns the entries of each JSON-array body that the server received
    /// as a POST to `route`.
    async fn posted(&self, route: &str) -> Vec<Value> {
        let requests = self.server.received_requests().await.expect(RECORDING);
        requests
            .iter()
            .filter(|request| request.method.as_str() == "POST" && request.url.path() == route)
            .flat_map(|request| {
                serde_json::from_slice::<Vec<Value>>(&request.body)
                    .expect("Each POST body must be a JSON array.")
            })
            .collect()
    }

    /// Cancels the executor token, the public cancel path. Asserts that
    /// `run_with_slot_clock` returns `Ok`, and returns the drain record.
    async fn shut_down(self) -> DrainRecord {
        self.token.cancel();
        let result = self.run.await.expect("The run task must not panic.");
        assert!(
            result.is_ok(),
            "run_with_slot_clock must return Ok after the token cancel: {result:?}"
        );
        self.recorders.drain.take().expect("run_with_slot_clock must log the drain record.")
    }
}

/// Runs `test`. A std thread fails the test when it does not finish in
/// `WATCHDOG`, and the message names the open client operations. This is
/// hang protection only.
async fn watched(ledger: &ClientLedger, test: impl Future<Output = ()>) {
    let (expired, expiry) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(WATCHDOG);
        let _ = expired.send(());
    });
    tokio::select! {
        () = test => {}
        _ = expiry => panic!(
            "The test did not finish in {WATCHDOG:?}. Open client operations: {:?}",
            ledger.open_operations()
        ),
    }
}

/// This slot clock reads the genesis, plus `start_slot` slots, plus the
/// paused tokio time since `origin` (the `AlignedClock` pattern).
struct PausedSlotClock {
    origin: Instant,
    start_slot: u64,
}

impl PausedSlotClock {
    fn since_genesis(&self) -> Duration {
        Duration::from_millis(self.start_slot * SLOT_MS) + self.origin.elapsed()
    }

    /// Gets the slot number at the virtual time `at`.
    fn slot_at(&self, at: Instant) -> u64 {
        let slots = at.duration_since(self.origin).as_millis() / u128::from(SLOT_MS);
        self.start_slot + u64::try_from(slots).expect("The slot must fit in u64.")
    }
}

impl SlotClock for PausedSlotClock {
    fn genesis_time(&self) -> u64 {
        GENESIS_TIME
    }

    fn slot_duration(&self) -> Duration {
        Duration::from_millis(SLOT_MS)
    }

    fn slots_per_epoch(&self) -> u64 {
        SLOTS_PER_EPOCH
    }

    fn now_since_epoch(&self) -> Duration {
        Duration::from_secs(GENESIS_TIME) + self.since_genesis()
    }

    fn current_slot(&self) -> Result<u64, TimingError> {
        let slot = self.since_genesis().as_millis() / u128::from(SLOT_MS);
        Ok(u64::try_from(slot).expect("The slot must fit in u64."))
    }
}

/// These are the layers of the thread-default subscriber of one test.
struct Recorders {
    ledger: ClientLedger,
    drain: DrainCapture,
    _default: DefaultGuard,
}

/// Installs the ledger and the drain capture as the thread default, and
/// starts the advance gate. The test runtime has one thread, so the default
/// applies to each task.
fn install_recorders() -> Recorders {
    let ledger = ClientLedger::default();
    let drain = DrainCapture::default();
    let default = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(ledger.clone()).with(drain.clone()),
    );
    spawn_advance_gate(ledger.clone());
    Recorders { ledger, drain, _default: default }
}

/// The ledger records client operations from the beacon client's own spans.
#[derive(Clone, Default)]
struct ClientLedger(Arc<LedgerShared>);

#[derive(Default)]
struct LedgerShared {
    state: Mutex<LedgerState>,
    /// Wakes the advance gate when an operation opens or closes.
    gate: Notify,
    /// Wakes `settled` when an operation closes.
    closed: Notify,
}

#[derive(Default)]
struct LedgerState {
    /// This maps each open span id to the span name and fields.
    open: HashMap<u64, String>,
    opened: usize,
    closed: usize,
}

impl ClientLedger {
    fn state(&self) -> MutexGuard<'_, LedgerState> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn outstanding(&self) -> usize {
        self.state().open.len()
    }

    fn open_operations(&self) -> Vec<String> {
        self.state().open.values().cloned().collect()
    }

    /// Waits until no client operation is open. Then asserts that the ledger
    /// closed at least as many operations as the server received requests,
    /// `/eth/v1/events` not included.
    async fn settled(&self, server: &MockServer) {
        loop {
            while self.outstanding() > 0 {
                self.0.closed.notified().await;
            }
            let received = received_excluding_events(server).await;
            let (open, opened, closed) = {
                let state = self.state();
                (state.open.len(), state.opened, state.closed)
            };
            if open > 0 {
                continue;
            }
            assert!(
                closed >= received,
                "Each beacon-node request must be a client operation in the ledger. The ledger \
                 opened {opened} and closed {closed} operations. The server received {received} \
                 requests."
            );
            return;
        }
    }
}

impl<S: Subscriber> Layer<S> for ClientLedger {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        let name = attrs.metadata().name();
        if !TRACKED_SPANS.contains(&name) {
            return;
        }
        let mut label = name.to_owned();
        attrs.record(&mut FieldText(&mut label));
        {
            let mut state = self.state();
            state.open.insert(id.into_u64(), label);
            state.opened += 1;
        }
        self.0.gate.notify_one();
    }

    fn on_close(&self, id: Id, _ctx: Context<'_, S>) {
        {
            let mut state = self.state();
            if state.open.remove(&id.into_u64()).is_none() {
                return;
            }
            state.closed += 1;
        }
        self.0.gate.notify_one();
        self.0.closed.notify_one();
    }
}

/// Adds ` name=value` for each field.
struct FieldText<'a>(&'a mut String);

impl Visit for FieldText<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

/// This blocking task holds tokio auto-advance off until this value drops.
///
/// On a current-thread runtime, tokio stops auto-advance when a blocking task
/// starts, and lets it continue when the task returns. The drop of the
/// sender returns the task.
struct Inhibitor {
    _release: std::sync::mpsc::Sender<()>,
}

impl Inhibitor {
    fn start() -> Self {
        let (release, hold) = std::sync::mpsc::channel::<()>();
        drop(tokio::task::spawn_blocking(move || {
            let _ = hold.recv();
        }));
        Self { _release: release }
    }
}

/// Holds an `Inhibitor` while the ledger has an open operation.
///
/// The ledger wakes this task when an operation opens. The woken task keeps
/// the runtime busy, so time cannot move before the task runs. Runtime
/// teardown drops the task and its `Inhibitor`, also after a panic.
fn spawn_advance_gate(ledger: ClientLedger) {
    drop(tokio::spawn(async move {
        let mut inhibitor = None;
        loop {
            if ledger.outstanding() > 0 {
                inhibitor.get_or_insert_with(Inhibitor::start);
            } else {
                drop(inhibitor.take());
            }
            ledger.0.gate.notified().await;
        }
    }));
}

async fn received_excluding_events(server: &MockServer) -> usize {
    let requests = server.received_requests().await.expect(RECORDING);
    requests.iter().filter(|request| request.url.path() != EVENTS).count()
}

/// This holds the `joined` and `aborted` fields of the "TaskExecutor drain
/// complete" event, as `Debug` text.
#[derive(Debug, Default)]
struct DrainRecord {
    joined: String,
    aborted: String,
}

#[derive(Clone, Default)]
struct DrainCapture(Arc<Mutex<Option<DrainRecord>>>);

impl DrainCapture {
    fn take(&self) -> Option<DrainRecord> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

impl<S: Subscriber> Layer<S> for DrainCapture {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = DrainFields::default();
        event.record(&mut fields);
        if fields.message == "TaskExecutor drain complete" {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(fields.record);
        }
    }
}

#[derive(Default)]
struct DrainFields {
    message: String,
    record: DrainRecord,
}

impl Visit for DrainFields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let text = format!("{value:?}");
        match field.name() {
            "message" => self.message = text,
            "joined" => self.record.joined = text,
            "aborted" => self.record.aborted = text,
            _ => {}
        }
    }
}

/// Writes one keystore and a `*=<password>` password file. Returns the
/// keystore directory and the password file.
fn write_keys(dir: &Path, secret: &SecretKey) -> (PathBuf, PathBuf) {
    let keys = dir.join("keys");
    std::fs::create_dir(&keys).expect("The test must create the keystore directory.");
    let keystore = Keystore::encrypt(
        secret,
        PASSWORD.as_bytes(),
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("The test must encrypt the keystore.");
    let json = serde_json::to_string(&keystore).expect("The keystore must serialize to JSON.");
    let name = format!("keystore-0x{}.json", hex::encode(secret.public_key().to_bytes()));
    std::fs::write(keys.join(name), json).expect("The test must write the keystore.");
    let password_file = dir.join("password.txt");
    std::fs::write(&password_file, format!("*={PASSWORD}\n"))
        .expect("The test must write the password file.");
    (keys, password_file)
}

fn root(byte: &str) -> String {
    format!("0x{}", byte.repeat(32))
}

fn duty_slot(epoch: u64) -> u64 {
    epoch * SLOTS_PER_EPOCH + DUTY_OFFSET
}

fn node_version() -> Value {
    json!({
        "data": {
            "beacon_node": { "code": "MK", "name": "mock-bn", "version": "w4e4d", "commit": "00" }
        }
    })
}

/// Mounts the beacon-node routes of the boot fixture, from
/// `duty_coverage.rs::mount_bn`. Each fork through Electra is at epoch 0, so
/// slot 10 is an Electra slot.
async fn mount_beacon_node(server: &MockServer, pubkey: &str) {
    let spec = json!({
        "GENESIS_FORK_VERSION": "0x00000000",
        "ALTAIR_FORK_EPOCH": "0",
        "ALTAIR_FORK_VERSION": "0x01000000",
        "BELLATRIX_FORK_EPOCH": "0",
        "BELLATRIX_FORK_VERSION": "0x02000000",
        "CAPELLA_FORK_EPOCH": "0",
        "CAPELLA_FORK_VERSION": "0x03000000",
        "DENEB_FORK_EPOCH": "0",
        "DENEB_FORK_VERSION": "0x04000000",
        "ELECTRA_FORK_EPOCH": "0",
        "ELECTRA_FORK_VERSION": "0x05000000",
        "FULU_FORK_EPOCH": FAR_FUTURE_EPOCH,
        "FULU_FORK_VERSION": "0x06000000",
        "GLOAS_FORK_EPOCH": FAR_FUTURE_EPOCH,
        "GLOAS_FORK_VERSION": "0x07000000",
        "SECONDS_PER_SLOT": "12",
        "SLOTS_PER_EPOCH": "32"
    });
    let gets = [
        ("/eth/v1/config/spec", json!({ "data": spec })),
        (
            "/eth/v1/beacon/genesis",
            json!({ "data": {
                "genesis_time": GENESIS_TIME.to_string(),
                "genesis_validators_root": root("11"),
                "genesis_fork_version": "0x00000000"
            } }),
        ),
        (
            "/eth/v1/beacon/states/head/fork",
            json!({ "execution_optimistic": false, "finalized": false, "data": {
                "previous_version": "0x04000000",
                "current_version": "0x05000000",
                "epoch": "0"
            } }),
        ),
        (
            "/eth/v1/node/syncing",
            json!({ "data": {
                "head_slot": "10",
                "sync_distance": "0",
                "is_syncing": false,
                "is_optimistic": false,
                "el_offline": false
            } }),
        ),
        ("/eth/v2/node/version", node_version()),
        (
            "/eth/v1/beacon/states/head/validators",
            json!({ "data": [{
                "index": INDEX,
                "status": "active_ongoing",
                "validator": { "pubkey": pubkey }
            }] }),
        ),
    ];
    for (route, body) in gets {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path_regex(r"^/eth/v1/validator/duties/proposer/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "dependent_root": root("22"),
            "execution_optimistic": false,
            "data": []
        })))
        .mount(server)
        .await;
    let duty_pubkey = pubkey.to_owned();
    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/attester/\d+$"))
        .respond_with(move |request: &Request| {
            let epoch: u64 = request
                .url
                .path()
                .rsplit('/')
                .next()
                .and_then(|epoch| epoch.parse().ok())
                .expect("The attester duty path must end with an epoch.");
            ResponseTemplate::new(200).set_body_json(json!({
                "dependent_root": root("22"),
                "execution_optimistic": false,
                "data": [{
                    "pubkey": duty_pubkey,
                    "validator_index": INDEX,
                    "committee_index": "0",
                    "committee_length": "128",
                    "committees_at_slot": "1",
                    "validator_committee_index": "3",
                    "slot": duty_slot(epoch).to_string()
                }]
            }))
        })
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/sync/\d+$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "execution_optimistic": false, "data": [] })),
        )
        .mount(server)
        .await;
    for route in [PREPARE, SUBSCRIPTIONS, REGISTRATION] {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(EVENTS))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/event-stream"))
        .mount(server)
        .await;
}

/// `orchestrator_at_slot` reads these options.
struct OrchestratorOpts {
    /// Each secret key gives one validator with the builder enabled.
    builder_keys: Vec<[u8; 32]>,
}

/// This harness keeps `DutyOrchestrator::run`, its epoch boundary runner, and
/// the mock beacon node of the test process.
struct Orchestrated {
    store: Arc<ValidatorStore>,
    mock: Arc<MockBeaconNodeClient>,
    signer: Arc<CountingSigner>,
    clock: Arc<PausedSlotClock>,
    handle: OrchestratorHandle,
    /// The public keys, in the order of `OrchestratorOpts::builder_keys`.
    pubkeys: Vec<[u8; 48]>,
    /// The epochs of the `REGISTRATION_DONE` events, in event order.
    done: watch::Receiver<Vec<u64>>,
    /// The number of registration POSTs that `registration_epoch` checked.
    checked_posts: usize,
    /// The number of signer calls that `registration_epoch` checked.
    checked_calls: usize,
    /// The slot number at the current virtual time.
    slot: u64,
    run: JoinHandle<Result<(), OrchestratorError>>,
    runner: JoinHandle<()>,
    _events: DefaultGuard,
}

/// The registration POST and the signer calls of one epoch.
struct EpochRegistration {
    /// The body of the one registration POST.
    post: Vec<SignedValidatorRegistration>,
    /// The registration and the signature of each signer call.
    signed: Vec<SignedValidatorRegistration>,
}

/// Starts `DutyOrchestrator::run` and the epoch boundary runner at the start
/// of `slot`. The fork schedule has no Gloas activation epoch. The
/// registration step sends a POST in each epoch. The duty phase offsets are
/// zero. The mock gives no duties.
async fn orchestrator_at_slot(slot: u64, opts: OrchestratorOpts) -> Orchestrated {
    let (steps, done) = watch::channel(Vec::new());
    let events = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(RegistrationSteps(steps)),
    );
    let mock = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_attester_duties(|_, _| Ok(no_duties()))
            .with_get_proposer_duties(|_| Ok(no_duties()))
            .with_prepare_beacon_proposer(|_| Ok(()))
            .with_submit_beacon_committee_subscriptions(|_| Ok(()))
            .with_register_validators(|_| Ok(())),
    );
    let beacon: Arc<dyn BeaconNodeClient> = mock.clone();
    let store = Arc::new(ValidatorStore::new([0x11; 20], 30_000_000));
    let mut key_manager = KeyManager::new();
    let mut pubkey_map = HashMap::new();
    let mut pubkeys = Vec::new();
    for bytes in opts.builder_keys {
        let secret = SecretKey::from_bytes(&bytes).expect("Each secret key must be valid.");
        let pubkey = secret.public_key();
        let mut config = ValidatorConfig::new(pubkey.to_bytes());
        config.builder_proposals = true;
        store.add_validator(config).expect("The store must add each key.");
        pubkeys.push(pubkey.to_bytes());
        pubkey_map.insert(pubkey.to_bytes(), pubkey);
        key_manager.insert(secret);
    }
    let slashing =
        SlashingDb::open_in_memory().expect("The test must open the slashing database in memory.");
    let service = SignerService::new(
        Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
        Arc::new(slashing),
    );
    let service = Arc::new(service.with_enablement(always_enabled()));
    let signer = Arc::new(CountingSigner { inner: Arc::clone(&service), calls: Mutex::default() });
    let schedule = Arc::new(ForkSchedule::unscheduled_gloas());
    let builder = BuilderService::new(
        signer.clone(),
        Arc::new(beacon.clone()),
        Arc::clone(&store),
        schedule.genesis_fork_version,
        Arc::clone(&schedule),
    );
    let at_slot_start = DeadlineBps {
        attestation: 0,
        aggregate: 0,
        sync_message: 0,
        contribution: 0,
        payload: 0,
        payload_attestation: 0,
    };
    let config = OrchestratorConfig::new([0x11; 32], schedule)
        .with_deadline_schedule(DeadlineSchedule::uniform(at_slot_start));
    let indices: Vec<String> = (0..pubkeys.len()).map(|index| index.to_string()).collect();
    let clock = Arc::new(PausedSlotClock { origin: Instant::now(), start_slot: slot });
    let deps = OrchestratorDeps::for_test(
        Arc::clone(&clock),
        Arc::new(DutyTracker::new(mock.clone(), indices.clone())),
        service,
        Arc::new(Propagator::new(Arc::clone(&mock))),
        beacon,
        Arc::new(NoopBlockBeacon),
        Some(Arc::new(builder)),
        Arc::clone(&store),
        config,
        Arc::new(parking_lot::RwLock::new(pubkey_map)),
    );
    for (pubkey, index) in pubkeys.iter().zip(indices) {
        deps.pubkey_index.write().insert(*pubkey, index);
    }
    let (mut orchestrator, handle) = DutyOrchestrator::new(deps);
    let runner = orchestrator.take_epoch_boundary_runner().expect("The runner must be present.");
    let runner = tokio::spawn(runner.run());
    let run = tokio::spawn(async move { orchestrator.run().await });
    Orchestrated {
        store,
        mock,
        signer,
        clock,
        handle,
        pubkeys,
        done,
        checked_posts: 0,
        checked_calls: 0,
        slot,
        run,
        runner,
        _events: events,
    }
}

impl Orchestrated {
    /// Advances virtual time to the start of `epoch`. Each call to
    /// `tokio::time::advance` moves time forward by one slot.
    async fn advance_to_epoch(&mut self, epoch: u64) {
        while self.slot < epoch * SLOTS_PER_EPOCH {
            tokio::time::advance(SLOT).await;
            self.slot += 1;
        }
    }

    /// Waits for the `REGISTRATION_DONE` event of `epoch`. The wait has a time
    /// limit of half a slot. Then gets each registration POST and each signer
    /// call that the last call of this function did not get. These conditions
    /// must hold:
    ///
    /// - Each of these POSTs must arrive in the first slot of `epoch`.
    /// - The epoch must have one POST.
    async fn registration_epoch(&mut self, epoch: u64) -> EpochRegistration {
        let done = self.done.wait_for(|epochs| epochs.contains(&epoch));
        let done = tokio::time::timeout(SLOT / 2, done).await.map(|seen| seen.map(|_| ()));
        assert!(
            matches!(done, Ok(Ok(()))),
            "The runner must end the registration step of epoch {epoch} before the time limit."
        );
        let posts = self.mock.register_validators_calls().split_off(self.checked_posts);
        let stamps = self.mock.call_stamps().into_iter();
        let stamps = stamps.filter(|stamp| stamp.method == MockMethod::RegisterValidators);
        let expected_slot = epoch * SLOTS_PER_EPOCH;
        for (count, stamp) in (self.checked_posts + 1..).zip(stamps.skip(self.checked_posts)) {
            let actual_slot = self.clock.slot_at(stamp.at);
            assert_eq!(
                actual_slot, expected_slot,
                "Registration POST {count} must arrive in slot {expected_slot}. The recorded slot \
                 is {actual_slot}."
            );
        }
        assert_eq!(
            posts.len(),
            1,
            "In epoch {epoch}, the service must send one registration POST. The POSTs are \
             {posts:?}."
        );
        let signed = self.signer.calls()[self.checked_calls..].to_vec();
        self.checked_posts += posts.len();
        self.checked_calls += signed.len();
        EpochRegistration { post: posts.concat(), signed }
    }

    /// Stops the orchestrator and its epoch boundary runner. The test checks
    /// that both tasks stop and that `DutyOrchestrator::run` returns `Ok`.
    async fn shut_down(self) {
        self.handle.shutdown();
        let result = self.run.await.expect("The orchestrator task must not panic.");
        assert!(
            result.is_ok(),
            "`DutyOrchestrator::run` must return `Ok` on shutdown. The result is `{result:?}`."
        );
        self.runner.await.expect("The epoch boundary runner task must not panic.");
    }
}

/// Records the epoch of each `REGISTRATION_DONE` event.
struct RegistrationSteps(watch::Sender<Vec<u64>>);

impl<S: Subscriber> Layer<S> for RegistrationSteps {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = StepFields::default();
        event.record(&mut fields);
        if let (REGISTRATION_DONE, Some(epoch)) = (fields.message.as_str(), fields.epoch) {
            self.0.send_modify(|epochs| epochs.push(epoch));
        }
    }
}

#[derive(Default)]
struct StepFields {
    message: String,
    epoch: Option<u64>,
}

impl Visit for StepFields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "epoch" {
            self.epoch = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

/// Gives a duty response with no duties.
fn no_duties<T>() -> DependentRootResponse<Vec<T>> {
    DependentRootResponse {
        dependent_root: root("00"),
        execution_optimistic: false,
        data: Vec::new(),
    }
}

/// This `RegistrationSigner` records each call to sign a registration. The
/// wrapper records the registration before each call. `SignerService` handles
/// the call. Then the wrapper adds the signature to the record.
struct CountingSigner {
    inner: Arc<SignerService>,
    calls: Mutex<Vec<SignedValidatorRegistration>>,
}

impl CountingSigner {
    fn calls(&self) -> MutexGuard<'_, Vec<SignedValidatorRegistration>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl RegistrationSigner for CountingSigner {
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Signature, SignerError> {
        let call = {
            let mut calls = self.calls();
            let message = registration.clone();
            calls.push(SignedValidatorRegistration { message, signature: Vec::new() });
            calls.len() - 1
        };
        let inner = &*self.inner;
        let signature =
            ValidatorSigner::sign_builder_registration(inner, registration, pubkey, fork_version)
                .await?;
        self.calls()[call].signature = signature.to_bytes().to_vec();
        Ok(signature)
    }

    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let inner = &*self.inner;
        ValidatorSigner::sign_proposer_preferences(
            inner,
            prefs,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )
        .await
    }

    async fn sign_builder_request_auth(
        &self,
        auth: &BuilderRequestAuth,
        pubkey: &PublicKey,
        genesis_fork_version: [u8; 4],
    ) -> Result<Signature, SignerError> {
        ValidatorSigner::sign_builder_request_auth(&*self.inner, auth, pubkey, genesis_fork_version)
            .await
    }
}
