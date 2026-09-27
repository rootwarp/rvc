//! Live duty index set: `registry ∩ PubkeyMap` (ADR-R06).
//!
//! [`Harness`] is parameterised on `doppelganger_enabled`. [`AdmissionKind`] is
//! the extension point RR-2.4 uses for secret-provider and gRPC-remote keys.
//! The duty tracker is the one [`rvc::bootstrap::build_services`] returns, so a
//! frozen boot snapshot fails these tests.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crypto::{
    CompositeSigner, EncryptionKdf, KeyManager, Keystore, LocalSigner, PublicKey, SecretKey,
};
use doppelganger::{
    DoppelgangerDisabledByOperator, ForwardWindowMachine, MonotonicEpochClock, SigningEnablement,
    ValidatorLivenessData, DEFAULT_MONITORING_EPOCHS,
};
use eth_types::{AttestationData, Checkpoint, Root, SLOTS_PER_EPOCH};
use keymanager_api::traits::{DoppelgangerMonitor, KeystoreManager, ValidatorManager};
use keymanager_api::{DoppelgangerLifecycle, ImportKind};
use rvc::bootstrap::{build_services, BeaconHandles, EnablementHandles, LoadedKeys};
use rvc::config::{Config, ServiceBuilder};
use rvc::deletion_denylist::DeletionDenylist;
use rvc::index_resolver::{IndexResolver, IndexResolverDeps};
use rvc::key_admission::KeyAdmissionService;
use rvc::keymanager_adapters::{
    DoppelgangerDisabledMonitor, ForwardWindowMonitor, KeystoreManagerAdapter,
    ValidatorManagerAdapter,
};
use rvc::orchestrator::{OrchestratorDeps, OrchestratorError, PubkeyMap};
use rvc::pubkey_index::PubkeyIndexRegistry;
use signer::{SignerError, ValidatorSigner};
use slashing::SlashingDb;
use tempfile::TempDir;
use timing::SlotClock;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const GVR: Root = [0x11; 32];
const INDEX: &str = "42";
const PASSWORD: &str = "rr-2-3-duty-coverage";
const FEE_RECIPIENT: &str = "0x1111111111111111111111111111111111111111";
const DEPENDENT_ROOT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const DUTY_EPOCH: u64 = 3;

/// How a key is admitted. RR-2.4 adds secret-provider and gRPC-remote arms.
#[derive(Clone, Copy)]
enum AdmissionKind {
    Keymanager,
}

struct AdmittedKey {
    pubkey: PublicKey,
    bytes: [u8; 48],
    index: String,
}

struct BnState {
    pubkey_0x: Mutex<Option<String>>,
    /// Slot written into attester-duty responses so `process_slot` can see it.
    duty_slot: Mutex<u64>,
}

struct Harness {
    doppelganger_enabled: bool,
    _dir: TempDir,
    server: MockServer,
    bn_state: Arc<BnState>,
    pubkey_map: PubkeyMap,
    registry: rvc::pubkey_index::SharedPubkeyIndexRegistry,
    enablement: Arc<dyn SigningEnablement>,
    machine: Option<Arc<ForwardWindowMachine>>,
    epoch_clock: Arc<MonotonicEpochClock>,
    handles: rvc::bootstrap::ServiceHandles,
    resolver: IndexResolver,
    keystores: KeystoreManagerAdapter,
    lifecycle: Arc<DoppelgangerLifecycle>,
}

impl Harness {
    async fn boot(doppelganger_enabled: bool) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let validators = dir.path().join("validators.toml");
        std::fs::write(&validators, format!("[defaults]\nfee_recipient = \"{FEE_RECIPIENT}\"\n"))
            .expect("validators config");

        let server = MockServer::start().await;
        let bn_state = Arc::new(BnState { pubkey_0x: Mutex::new(None), duty_slot: Mutex::new(0) });
        mount_bn(&server, Arc::clone(&bn_state)).await;

        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let registry = PubkeyIndexRegistry::shared();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
        // Epoch 1 at boot. `register_for_import` stays Pending at epoch 0 too;
        // a non-zero epoch keeps the clear-window loop off the pre-genesis path.
        let epoch_clock = Arc::new(MonotonicEpochClock::with_start_time(
            0,
            std::time::Instant::now(),
            SLOTS_PER_EPOCH * 12,
        ));

        let (enablement, machine) = if doppelganger_enabled {
            let reader: Arc<dyn slashing::SlashingDbReader> =
                Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
            let machine =
                Arc::new(ForwardWindowMachine::new(reader, DEFAULT_MONITORING_EPOCHS, GVR));
            (Arc::clone(&machine) as Arc<dyn SigningEnablement>, Some(machine))
        } else {
            (Arc::new(DoppelgangerDisabledByOperator) as Arc<dyn SigningEnablement>, None)
        };

        let keys = LoadedKeys {
            composite_signer: Arc::clone(&composite),
            validator_count: 0,
            local_pubkeys: HashSet::new(),
            pubkey_map: Arc::clone(&pubkey_map),
            secret_providers: vec![],
            grpc_signer: None,
        };
        let enablement_handles = EnablementHandles {
            signing_enablement: Arc::clone(&enablement),
            forward_window_machine: machine.clone(),
            epoch_clock: Arc::clone(&epoch_clock),
            pubkey_map: Arc::clone(&pubkey_map),
            liveness_task: None,
            pubkey_index: Arc::clone(&registry),
        };

        let config = Config {
            beacon_url: server.uri(),
            beacon_nodes: vec![server.uri()],
            validators_config: Some(validators),
            disable_keystore_locking: true,
            allow_fresh_db: true,
            doppelganger_detection: doppelganger_enabled,
            genesis_time: Some(1_606_824_023),
            ..Default::default()
        };
        let beacon = beacon_handles(&config).await;
        let handles = build_services(
            &config,
            &keys,
            &enablement_handles,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().expect("signer slashing db")),
            bn_manager::OperationTimeouts::default(),
        )
        .await
        .expect("build_services");

        let denylist = Arc::new(DeletionDenylist::load(dir.path()).expect("denylist"));
        let admissions = Arc::new(KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx.clone(),
            Arc::clone(&composite),
            Arc::clone(&handles.validator_store),
            Arc::clone(&denylist),
            machine.clone(),
            Arc::clone(&epoch_clock),
        ));
        let keystores = KeystoreManagerAdapter::new(
            dir.path().to_path_buf(),
            composite,
            Arc::clone(&pubkey_map),
            key_gen_tx.clone(),
        )
        .with_denylist(Arc::clone(&denylist))
        .with_admission_service(admissions);

        let monitor: Arc<dyn DoppelgangerMonitor> = if let Some(ref machine) = machine {
            let clock = Arc::clone(&epoch_clock);
            Arc::new(ForwardWindowMonitor::new(
                Arc::clone(machine),
                Arc::new(move || clock.current_epoch()),
            ))
        } else {
            Arc::new(DoppelgangerDisabledMonitor::new())
        };
        // Doppelganger off uses a zero window (production). On uses a long
        // window so the M-12 enable task cannot open the store during the test.
        let window = if doppelganger_enabled { Duration::from_secs(3600) } else { Duration::ZERO };
        let validator_manager: Arc<dyn ValidatorManager> =
            Arc::new(ValidatorManagerAdapter::new(Arc::clone(&handles.validator_store)));
        let lifecycle = Arc::new(DoppelgangerLifecycle::new(window, monitor, validator_manager));

        let resolver = IndexResolver::new(
            IndexResolverDeps {
                registry: Arc::clone(&registry),
                pubkey_map: Arc::clone(&pubkey_map),
                beacon: Arc::clone(&handles.beacon),
                key_gen_tx,
                key_gen_rx,
                epoch_clock: Arc::clone(&epoch_clock),
            },
            CancellationToken::new(),
        );

        Self {
            doppelganger_enabled,
            _dir: dir,
            server,
            bn_state,
            pubkey_map,
            registry,
            enablement,
            machine,
            epoch_clock,
            handles,
            resolver,
            keystores,
            lifecycle,
        }
    }

    /// Keymanager import: `import_keystore` then `DoppelgangerLifecycle::on_import`.
    fn admit(&mut self, kind: AdmissionKind) -> AdmittedKey {
        match kind {
            AdmissionKind::Keymanager => self.admit_keymanager(),
        }
    }

    fn admit_keymanager(&mut self) -> AdmittedKey {
        let secret = SecretKey::generate();
        let pubkey = secret.public_key();
        let bytes = pubkey.to_bytes();
        let keystore = Keystore::encrypt(
            &secret,
            PASSWORD.as_bytes(),
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let json = serde_json::to_string(&keystore).expect("keystore json");
        self.keystores.import_keystore(&json, PASSWORD).expect("import keystore");
        self.lifecycle.on_import(bytes, ImportKind::Local);
        *self.bn_state.pubkey_0x.lock().expect("pubkey") =
            Some(format!("0x{}", hex::encode(bytes)));
        AdmittedKey { pubkey, bytes, index: INDEX.to_string() }
    }

    async fn resolve(&mut self) {
        let epoch = self.epoch_clock.current_epoch();
        let pass = self.resolver.drive_once_for_test(epoch).await;
        assert!(
            pass.len_after_write > pass.len_before,
            "resolver must insert the new index before the next duty request; \
             doppelganger={} pass={pass:?}",
            self.doppelganger_enabled
        );
        assert_eq!(
            self.registry.read().index_of(&self.bn_pubkey_bytes()),
            Some(INDEX),
            "registry holds {INDEX}"
        );
    }

    fn bn_pubkey_bytes(&self) -> [u8; 48] {
        let hex_key = self.bn_state.pubkey_0x.lock().expect("pubkey").clone().expect("pubkey set");
        rvc::pubkey_index::parse_pubkey_bytes(&hex_key).expect("pubkey bytes")
    }

    async fn mark(&self) -> usize {
        self.server.received_requests().await.expect("requests").len()
    }

    async fn since(&self, mark: usize) -> Vec<Request> {
        self.server.received_requests().await.expect("requests").into_iter().skip(mark).collect()
    }

    /// Next attester, sync-committee, and PTC posts. Mirrors one fetch cycle.
    async fn assert_index_in_next_requests(&self, index: &str) {
        let mark = self.mark().await;
        self.handles.duty_tracker.fetch_duties_for_epoch(DUTY_EPOCH).await.expect("attester");
        self.handles.duty_tracker.fetch_sync_committee_duties(DUTY_EPOCH).await.expect("sync");
        self.handles.duty_tracker.fetch_ptc_duties_for_epoch(DUTY_EPOCH).await.expect("ptc");
        let reqs = self.since(mark).await;
        for (kind, prefix) in [
            ("attester", "/eth/v1/validator/duties/attester/"),
            ("sync", "/eth/v1/validator/duties/sync/"),
            ("ptc", "/eth/v1/validator/duties/ptc/"),
        ] {
            let bodies = posted_indices(&reqs, prefix);
            let last = bodies.last().unwrap_or_else(|| {
                panic!("{kind} duty request missing (doppelganger={})", self.doppelganger_enabled)
            });
            assert!(
                last.iter().any(|i| i == index),
                "{kind} request {last:?} does not carry index {index} \
                 (doppelganger={})",
                self.doppelganger_enabled
            );
        }
    }

    async fn assert_index_absent_from_next_requests(&self, index: &str) {
        let mark = self.mark().await;
        self.handles.duty_tracker.fetch_duties_for_epoch(DUTY_EPOCH).await.expect("attester");
        self.handles.duty_tracker.fetch_sync_committee_duties(DUTY_EPOCH).await.expect("sync");
        self.handles.duty_tracker.fetch_ptc_duties_for_epoch(DUTY_EPOCH).await.expect("ptc");
        let reqs = self.since(mark).await;
        for (kind, prefix) in [
            ("attester", "/eth/v1/validator/duties/attester/"),
            ("sync", "/eth/v1/validator/duties/sync/"),
            ("ptc", "/eth/v1/validator/duties/ptc/"),
        ] {
            let bodies = posted_indices(&reqs, prefix);
            let last = bodies.last().expect(kind);
            assert!(
                last.iter().all(|i| i != index),
                "{kind} still carries deleted index {index}: {last:?}"
            );
        }
    }

    /// Same gate as `DutyManagementService::fetch_epoch_duties`: skip the BN
    /// when the cached snapshot still equals the current index set.
    async fn refetch_attester_if_snapshot_changed(&self) -> bool {
        if self.handles.duty_tracker.is_epoch_cached(DUTY_EPOCH).await {
            return false;
        }
        self.handles.duty_tracker.fetch_duties_for_epoch(DUTY_EPOCH).await.expect("refetch");
        true
    }

    async fn sign(&self, pubkey: &PublicKey) -> Result<crypto::Signature, SignerError> {
        let data = AttestationData {
            slot: 64,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 1, root: [0x22; 32] },
            target: Checkpoint { epoch: 2, root: [0x33; 32] },
        };
        let schedule = &self.handles.orchestrator_config.fork_schedule;
        self.handles
            .signer
            .sign_attestation(
                &data,
                pubkey,
                schedule.as_ref(),
                &self.handles.orchestrator_config.genesis_validators_root,
            )
            .await
    }

    fn open_forward_window(&self, pubkey: &PublicKey) {
        let machine = self.machine.as_ref().expect("forward-window machine");
        let start = self.epoch_clock.current_epoch();
        let end = start + DEFAULT_MONITORING_EPOCHS;
        let bare = hex::encode(pubkey.to_bytes());
        for epoch in start..=end {
            machine
                .observe_liveness(
                    epoch,
                    &[ValidatorLivenessData { index: bare.clone(), is_live: false }],
                )
                .expect("observe liveness");
        }
        machine.tick(end + 1, 0);
        assert!(
            machine.is_signing_enabled(pubkey),
            "forward-window gate must be open after a clean not-live window"
        );
    }

    /// `process_slot` while the store gate is closed: the cached duty is
    /// dropped and nothing is signed.
    async fn assert_store_gate_yields_no_signature(&self, key: &AdmittedKey) {
        let slot = self.handles.slot_clock.current_slot().expect("current slot");
        *self.bn_state.duty_slot.lock().expect("slot") = slot;
        let epoch = slot / SLOTS_PER_EPOCH;
        self.handles.duty_tracker.fetch_duties_for_epoch(epoch).await.expect("cache duty");
        let cached = self.handles.duty_tracker.get_duties_for_slot(slot).await;
        assert!(
            cached.iter().any(|d| d.validator_index == key.index),
            "precondition: attester duty for {INDEX} is cached, got {cached:?}"
        );
        assert!(
            !self.handles.validator_store.is_signing_enabled(&key.bytes),
            "ValidatorStore::is_signing_enabled must be closed before process_slot"
        );

        let mut deps = OrchestratorDeps::for_test(
            Arc::clone(&self.handles.slot_clock),
            Arc::clone(&self.handles.duty_tracker),
            Arc::clone(&self.handles.signer),
            Arc::clone(&self.handles.propagator),
            Arc::clone(&self.handles.beacon),
            Arc::clone(&self.handles.block_beacon),
            self.handles.builder_service.clone(),
            Arc::clone(&self.handles.validator_store),
            self.handles.orchestrator_config.clone(),
            Arc::clone(&self.pubkey_map),
        );
        deps.pubkey_index = Arc::clone(&self.registry);
        let (orchestrator, _handle) = rvc::orchestrator::DutyOrchestrator::new(deps);
        let outcome = orchestrator.process_slot(slot).await;
        assert!(
            matches!(outcome, Err(OrchestratorError::NoDutiesForSlot { .. })),
            "ValidatorStore gate must yield no signature; got {outcome:?}"
        );
    }

    /// Selection proof is non-slashable and, with doppelganger off, the signer
    /// allows every pubkey. A successful proof is posted as a committee
    /// subscription, so no such POST means the store gate skipped the sign.
    async fn assert_no_selection_proof_while_store_closed(&self, key: &AdmittedKey) {
        let slot = self.handles.slot_clock.current_slot().expect("current slot");
        *self.bn_state.duty_slot.lock().expect("slot") = slot;
        let epoch = slot / SLOTS_PER_EPOCH;
        self.handles.duty_tracker.fetch_duties_for_epoch(epoch).await.expect("cache duty");
        let cached = self.handles.duty_tracker.get_duties_for_slot(slot).await;
        assert!(
            cached.iter().any(|d| d.validator_index == key.index),
            "precondition: subscription loop must see the cached duty"
        );
        assert!(!self.handles.validator_store.is_signing_enabled(&key.bytes));

        let mut deps = OrchestratorDeps::for_test(
            Arc::clone(&self.handles.slot_clock),
            Arc::clone(&self.handles.duty_tracker),
            Arc::clone(&self.handles.signer),
            Arc::clone(&self.handles.propagator),
            Arc::clone(&self.handles.beacon),
            Arc::clone(&self.handles.block_beacon),
            self.handles.builder_service.clone(),
            Arc::clone(&self.handles.validator_store),
            self.handles.orchestrator_config.clone(),
            Arc::clone(&self.pubkey_map),
        );
        deps.pubkey_index = Arc::clone(&self.registry);
        let (orchestrator, _handle) = rvc::orchestrator::DutyOrchestrator::new(deps);
        let mark = self.mark().await;
        orchestrator.submit_committee_subscriptions(epoch).await;
        let signed = self.since(mark).await.into_iter().any(|r| {
            r.method.as_str() == "POST"
                && r.url.path() == "/eth/v1/validator/beacon_committee_subscriptions"
        });
        assert!(
            !signed,
            "submit_committee_subscriptions signed a selection proof while the store gate was closed"
        );
    }
}

fn posted_indices(requests: &[Request], prefix: &str) -> Vec<Vec<String>> {
    requests
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path().starts_with(prefix))
        .map(|r| serde_json::from_slice::<Vec<String>>(&r.body).unwrap_or_default())
        .collect()
}

async fn mount_bn(server: &MockServer, state: Arc<BnState>) {
    let mut data = serde_json::json!({
        "GENESIS_FORK_VERSION": "0x00000000",
        "ALTAIR_FORK_EPOCH": "74240",
        "ALTAIR_FORK_VERSION": "0x01000000",
        "BELLATRIX_FORK_EPOCH": "144896",
        "BELLATRIX_FORK_VERSION": "0x02000000",
        "CAPELLA_FORK_EPOCH": "194048",
        "CAPELLA_FORK_VERSION": "0x03000000",
        "DENEB_FORK_EPOCH": "269568",
        "DENEB_FORK_VERSION": "0x04000000",
        "ELECTRA_FORK_EPOCH": "364544",
        "ELECTRA_FORK_VERSION": "0x05000000",
        "FULU_FORK_EPOCH": "18446744073709551615",
        "FULU_FORK_VERSION": "0x06000000",
        "GLOAS_FORK_EPOCH": "18446744073709551615",
        "GLOAS_FORK_VERSION": "0x07000000",
        "SECONDS_PER_SLOT": "12",
        "SLOTS_PER_EPOCH": "32"
    });
    let _ = &mut data;

    Mock::given(method("GET"))
        .and(path("/eth/v1/config/spec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": data })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/fork"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "execution_optimistic": false,
            "finalized": false,
            "data": {
                "previous_version": "0x04000000",
                "current_version": "0x05000000",
                "epoch": "364544"
            }
        })))
        .mount(server)
        .await;

    let state_v = Arc::clone(&state);
    Mock::given(method("GET"))
        .and(path("/eth/v1/beacon/states/head/validators"))
        .respond_with(move |_req: &Request| {
            let pubkey = state_v.pubkey_0x.lock().expect("pubkey").clone();
            let data = pubkey
                .map(|pk| {
                    serde_json::json!([{
                        "index": INDEX,
                        "status": "active_ongoing",
                        "validator": { "pubkey": pk }
                    }])
                })
                .unwrap_or_else(|| serde_json::json!([]));
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": data }))
        })
        .mount(server)
        .await;

    let state_a = Arc::clone(&state);
    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/attester/\d+$"))
        .respond_with(move |_req: &Request| {
            let pubkey = state_a.pubkey_0x.lock().expect("pubkey").clone();
            let slot = *state_a.duty_slot.lock().expect("slot");
            let data = match pubkey {
                Some(pk) => serde_json::json!([{
                    "pubkey": pk,
                    "validator_index": INDEX,
                    "committee_index": "0",
                    "committee_length": "4",
                    "committees_at_slot": "1",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]),
                None => serde_json::json!([]),
            };
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": DEPENDENT_ROOT,
                "execution_optimistic": false,
                "data": data
            }))
        })
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/sync/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "execution_optimistic": false,
            "data": []
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/ptc/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": DEPENDENT_ROOT,
            "execution_optimistic": false,
            "data": []
        })))
        .mount(server)
        .await;
}

async fn beacon_handles(config: &Config) -> BeaconHandles {
    let sb = ServiceBuilder::new(config.clone());
    let beacon_client = sb.build_beacon().expect("beacon client");
    let bn_manager =
        sb.build_bn_manager_with_timeouts(bn_manager::OperationTimeouts::default()).expect("bn");
    BeaconHandles {
        beacon_client,
        bn_manager,
        genesis_validators_root: GVR,
        genesis_validators_root_hex: format!("0x{}", hex::encode(GVR)),
        genesis_time: config.genesis_time.unwrap_or(1_606_824_023),
    }
}

async fn g6_once(doppelganger_enabled: bool) {
    let mut harness = Harness::boot(doppelganger_enabled).await;
    let key = harness.admit(AdmissionKind::Keymanager);
    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;
}

#[tokio::test]
async fn g6_keymanager_key_earns_duties_in_the_next_request() {
    g6_once(true).await;
    g6_once(false).await;
}

#[tokio::test]
async fn request_after_insert_is_not_served_from_the_pre_insert_cache() {
    let mut harness = Harness::boot(false).await;
    let tracker = Arc::clone(&harness.handles.duty_tracker);
    tracker.fetch_duties_for_epoch(DUTY_EPOCH).await.expect("pre-insert attester");
    tracker.fetch_sync_committee_duties(DUTY_EPOCH).await.expect("pre-insert sync");
    tracker.fetch_ptc_duties_for_epoch(DUTY_EPOCH).await.expect("pre-insert ptc");
    assert!(tracker.is_epoch_cached(DUTY_EPOCH).await, "pre-insert attester cache");
    assert!(tracker.is_sync_period_cached(DUTY_EPOCH).await, "pre-insert sync cache");
    assert!(tracker.is_ptc_epoch_cached(DUTY_EPOCH).await, "pre-insert ptc cache");

    let key = harness.admit(AdmissionKind::Keymanager);
    harness.resolve().await;
    assert!(!tracker.is_epoch_cached(DUTY_EPOCH).await, "attester cache must miss after insert");
    assert!(!tracker.is_sync_period_cached(DUTY_EPOCH).await, "sync cache must miss after insert");
    assert!(!tracker.is_ptc_epoch_cached(DUTY_EPOCH).await, "ptc cache must miss after insert");

    let mark = harness.mark().await;
    let refetched = harness.refetch_attester_if_snapshot_changed().await;
    assert!(refetched, "request after insert was served from the pre-insert cache");
    tracker.fetch_sync_committee_duties(DUTY_EPOCH).await.expect("post-insert sync");
    tracker.fetch_ptc_duties_for_epoch(DUTY_EPOCH).await.expect("post-insert ptc");
    let reqs = harness.since(mark).await;
    for (kind, prefix) in [
        ("attester", "/eth/v1/validator/duties/attester/"),
        ("sync", "/eth/v1/validator/duties/sync/"),
        ("ptc", "/eth/v1/validator/duties/ptc/"),
    ] {
        let bodies = posted_indices(&reqs, prefix);
        let last = bodies.last().unwrap_or_else(|| panic!("post-insert {kind} request missing"));
        assert!(
            last.iter().any(|i| i == &key.index),
            "post-insert {kind} call {last:?} does not carry {INDEX}"
        );
    }
}

#[tokio::test]
async fn c1_admitted_key_produces_no_signature_until_both_gates_open() {
    let mut harness = Harness::boot(true).await;
    let key = harness.admit(AdmissionKind::Keymanager);
    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;

    assert!(
        !harness.handles.validator_store.is_signing_enabled(&key.bytes),
        "ValidatorStore::is_signing_enabled must block a newly admitted key"
    );
    let machine = harness.machine.as_ref().expect("forward-window gate");
    assert!(
        !machine.is_signing_enabled(&key.pubkey),
        "forward-window gate must block: register_for_import is Pending"
    );
    harness.assert_store_gate_yields_no_signature(&key).await;
    let blocked = harness.sign(&key.pubkey).await;
    assert!(
        matches!(blocked, Err(SignerError::BlockedByDoppelganger)),
        "forward-window gate must produce no signature; got {blocked:?}"
    );

    // Opening only ValidatorStore leaves the forward-window gate closed.
    harness.handles.validator_store.set_enabled(&key.bytes, true);
    assert!(harness.handles.validator_store.is_signing_enabled(&key.bytes));
    assert!(!machine.is_signing_enabled(&key.pubkey), "forward-window gate still Pending");
    let still_blocked = harness.sign(&key.pubkey).await;
    assert!(
        matches!(still_blocked, Err(SignerError::BlockedByDoppelganger)),
        "ValidatorStore alone must not yield a signature; got {still_blocked:?}"
    );
    harness.assert_index_in_next_requests(&key.index).await;

    harness.open_forward_window(&key.pubkey);
    assert!(
        machine.is_signing_enabled(&key.pubkey)
            && harness.handles.validator_store.is_signing_enabled(&key.bytes),
        "both gates open"
    );
    harness.sign(&key.pubkey).await.expect("signature once both gates are open");
    harness.assert_index_in_next_requests(&key.index).await;
}

#[tokio::test]
async fn c1_with_doppelganger_disabled_only_the_validator_store_gate_blocks() {
    let mut harness = Harness::boot(false).await;
    let key = harness.admit(AdmissionKind::Keymanager);
    // Zero window enables the key. Wait until that task has run, then apply
    // the validators-config `enabled` gate — the only one left.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !harness.handles.validator_store.is_signing_enabled(&key.bytes) {
        if tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::task::yield_now().await;
    }
    harness.handles.validator_store.set_enabled(&key.bytes, false);

    assert!(
        harness.enablement.is_signing_enabled(&key.pubkey),
        "DoppelgangerDisabledByOperator::is_signing_enabled returns true; it does not block"
    );
    assert!(
        !harness.handles.validator_store.is_signing_enabled(&key.bytes),
        "ValidatorStore::is_signing_enabled is the only gate on a newly admitted key"
    );

    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;
    harness.assert_store_gate_yields_no_signature(&key).await;
    harness.assert_no_selection_proof_while_store_closed(&key).await;
    harness.assert_index_in_next_requests(&key.index).await;
}

#[tokio::test]
async fn deleted_key_index_leaves_the_effective_set_via_the_intersection() {
    let mut harness = Harness::boot(false).await;
    let key = harness.admit(AdmissionKind::Keymanager);
    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;

    let lifecycle = Arc::clone(&harness.lifecycle);
    let deleted = lifecycle.on_delete(&key.bytes, ImportKind::Local, || {
        match harness.keystores.delete_keystore(&key.bytes) {
            Ok(removed) => (removed, Ok(removed)),
            Err(e) => (false, Err(e)),
        }
    });
    assert!(matches!(deleted, Ok(true)), "keymanager delete must remove the key, got {deleted:?}");

    assert_eq!(
        harness.registry.read().index_of(&key.bytes),
        Some(INDEX),
        "PubkeyIndexRegistry has no remove; the index stays"
    );
    assert!(
        !harness.pubkey_map.read().contains_key(&key.bytes),
        "delete must drop the key from PubkeyMap"
    );
    harness.assert_index_absent_from_next_requests(&key.index).await;
}
