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

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use beacon::{BeaconClient, BeaconClientConfig};
use bn_manager::OperationTimeouts;
use crypto::{EncryptionKdf, Keystore, SecretKey};
use rvc::bootstrap::{run_with_slot_clock, BootstrapError, RunOptions, TaskExecutor};
use rvc::config::{Config, Network};
use serde_json::{json, Value};
use tempfile::TempDir;
use timing::{SlotClock, TimingError};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::subscriber::DefaultGuard;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
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
    let boot = boot_at_slot(10, BootOpts { builder: true }).await;
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

/// `boot_at_slot` reads these options.
#[derive(Clone, Copy, Default)]
struct BootOpts {
    /// This is the `builder_proposals` value of the key in the validators file.
    builder: bool,
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
    let config = Config {
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
