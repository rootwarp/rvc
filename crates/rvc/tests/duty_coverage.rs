//! Live duty index set: `registry ∩ PubkeyMap` (ADR-R06).
//!
//! [`Harness`] is parameterised on `doppelganger_enabled`. Keymanager import is
//! [`AdmissionKind`]. Secret-provider refresh admits through
//! [`KeyAdmissionService`], and gRPC remote keys arrive from
//! [`load_signing_keys`] before boot. The duty tracker is the one
//! [`rvc::bootstrap::build_services`] returns, so a frozen boot snapshot fails
//! these tests.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
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
use rvc::bootstrap::{
    build_services, load_signing_keys, BeaconHandles, EnablementHandles, LoadedKeys,
};
use rvc::config::{Config, GrpcSignerConfig, ServiceBuilder};
use rvc::deletion_denylist::DeletionDenylist;
use rvc::index_resolver::{IndexResolver, IndexResolverDeps};
use rvc::key_admission::{AdmissionOutcome, AdmissionSource, KeyAdmissionService};
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
const REMOTE_INDEX: &str = "43";

/// Post-boot admission. gRPC remote keys are not admitted here; they are loaded
/// by [`load_signing_keys`] before [`Harness::boot_with`].
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
    /// `(0x-pubkey, validator index)` the mock beacon returns.
    validators: Mutex<Vec<(String, String)>>,
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
    admissions: Arc<KeyAdmissionService>,
    denylist: Arc<DeletionDenylist>,
    /// Boot snapshot passed to secret-provider refresh. Remote keys stay out.
    local_pubkeys: HashSet<[u8; 48]>,
    grpc_server: Option<tokio::task::JoinHandle<()>>,
}

impl Harness {
    async fn boot(doppelganger_enabled: bool) -> Self {
        Self::boot_with(doppelganger_enabled, None, Vec::new()).await
    }

    /// `loaded` is `None` for an empty key set. When `Some`, those keys are the
    /// boot set: gRPC remote pubkeys are already in `PubkeyMap` and not in
    /// `local_pubkeys`. `validators` is the beacon's pubkey→index list.
    async fn boot_with(
        doppelganger_enabled: bool,
        loaded: Option<LoadedKeys>,
        validators: Vec<(String, String)>,
    ) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let validators_config = dir.path().join("validators.toml");
        std::fs::write(
            &validators_config,
            format!("[defaults]\nfee_recipient = \"{FEE_RECIPIENT}\"\n"),
        )
        .expect("validators config");

        let server = MockServer::start().await;
        let bn_state =
            Arc::new(BnState { validators: Mutex::new(validators), duty_slot: Mutex::new(0) });
        mount_bn(&server, Arc::clone(&bn_state)).await;

        let loaded = loaded.unwrap_or_else(|| {
            let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
            LoadedKeys {
                composite_signer: composite,
                validator_count: 0,
                local_pubkeys: HashSet::new(),
                pubkey_map: Arc::new(parking_lot::RwLock::new(HashMap::new())),
                secret_providers: vec![],
                grpc_signer: None,
            }
        });
        let pubkey_map = Arc::clone(&loaded.pubkey_map);
        let local_pubkeys = loaded.local_pubkeys.clone();
        let composite = Arc::clone(&loaded.composite_signer);
        let registry = PubkeyIndexRegistry::shared();
        let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
        // Epoch 1 at boot. `register` at epoch 0 would mark keys Safe; a
        // non-zero epoch keeps the forward window Pending.
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
        // Production boot calls `register` for every loaded pubkey. Empty for
        // the keymanager tests; gRPC keys loaded before boot are Pending here.
        if let Some(ref machine) = machine {
            let epoch = epoch_clock.current_epoch();
            for pk in pubkey_map.read().values() {
                machine.register(pk, epoch);
            }
        }

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
            validators_config: Some(validators_config),
            disable_keystore_locking: true,
            allow_fresh_db: true,
            doppelganger_detection: doppelganger_enabled,
            genesis_time: Some(1_606_824_023),
            ..Default::default()
        };
        let beacon = beacon_handles(&config).await;
        let handles = build_services(
            &config,
            &loaded,
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
        .with_admission_service(Arc::clone(&admissions));

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
            admissions,
            denylist,
            local_pubkeys,
            grpc_server: None,
        }
    }

    /// Keymanager import: `import_keystore` then `DoppelgangerLifecycle::on_import`.
    async fn admit(&mut self, kind: AdmissionKind) -> AdmittedKey {
        match kind {
            AdmissionKind::Keymanager => self.admit_keymanager().await,
        }
    }

    async fn admit_keymanager(&mut self) -> AdmittedKey {
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
        self.keystores.import_keystore(&json, PASSWORD).await.expect("import keystore");
        self.lifecycle.on_import(bytes, ImportKind::Local);
        self.bn_state
            .validators
            .lock()
            .expect("validators")
            .push((format!("0x{}", hex::encode(bytes)), INDEX.to_string()));
        AdmittedKey { pubkey, bytes, index: INDEX.to_string() }
    }

    async fn resolve(&mut self) {
        let epoch = self.epoch_clock.current_epoch();
        let expected = self.bn_state.validators.lock().expect("validators").clone();
        assert!(!expected.is_empty(), "BN validators must be set before resolve");
        let pass = self.resolver.drive_once_for_test(epoch).await;
        assert!(
            pass.len_after_write > pass.len_before,
            "resolver must insert the new index before the next duty request; \
             doppelganger={} pass={pass:?}",
            self.doppelganger_enabled
        );
        for (pk, index) in &expected {
            let bytes = rvc::pubkey_index::parse_pubkey_bytes(pk).expect("pubkey bytes");
            assert_eq!(
                self.registry.read().index_of(&bytes),
                Some(index.as_str()),
                "registry holds {index} for {pk}; doppelganger={}",
                self.doppelganger_enabled
            );
        }
    }

    fn pubkey_bytes_for_index(&self, index: &str) -> [u8; 48] {
        let validators = self.bn_state.validators.lock().expect("validators");
        let (hex_pk, _) = validators
            .iter()
            .find(|(_, i)| i == index)
            .unwrap_or_else(|| panic!("no BN validator for index {index}"));
        rvc::pubkey_index::parse_pubkey_bytes(hex_pk).expect("pubkey bytes")
    }

    /// PubkeyMap membership, not only the duty request that follows resolve.
    fn require_mapped_key(&self, index: &str) -> AdmittedKey {
        let bytes = self.pubkey_bytes_for_index(index);
        assert!(
            self.pubkey_map.read().contains_key(&bytes),
            "PubkeyMap must contain index {index} before the duty request \
             (doppelganger={})",
            self.doppelganger_enabled
        );
        let pubkey = self.pubkey_map.read().get(&bytes).cloned().expect("pubkey");
        AdmittedKey { pubkey, bytes, index: index.to_string() }
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
        let data = sample_attestation();
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

    /// The signing root `sign` asks the remote signer to produce.
    fn assert_sample_attestation_signature(&self, pubkey: &PublicKey, sig: &crypto::Signature) {
        let data = sample_attestation();
        let schedule = self.handles.orchestrator_config.fork_schedule.as_ref();
        let version =
            eth_types::ForkName::from_epoch(data.target.epoch, schedule).fork_version(schedule);
        let root = crypto::signing_root_with_fork_version(
            &data,
            eth_types::DOMAIN_BEACON_ATTESTER,
            version,
            self.handles.orchestrator_config.genesis_validators_root,
        );
        sig.verify(pubkey, &root).expect("signature must match the attestation signing root");
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
            cached.iter().any(|d| d.raw.validator_index == key.index),
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
            cached.iter().any(|d| d.raw.validator_index == key.index),
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

    /// Config whose only key source is `grpc_signer.url`.
    async fn boot_grpc_remote(doppelganger_enabled: bool) -> Self {
        let _env = InsecureGrpcEnv::enter();
        let remote = SecretKey::generate();
        let remote_pk = remote.public_key().to_bytes();
        let (addr, handle) = start_plaintext_mock(vec![remote]).await;
        let loaded = load_grpc_only(&format!("http://{addr}")).await;
        let validators = vec![(format!("0x{}", hex::encode(remote_pk)), INDEX.to_string())];
        let mut harness = Self::boot_with(doppelganger_enabled, Some(loaded), validators).await;
        harness.grpc_server = Some(handle);
        harness
    }

    /// One local keystore key and one gRPC remote key.
    async fn boot_local_and_remote(doppelganger_enabled: bool) -> (Self, [u8; 48], [u8; 48]) {
        let _env = InsecureGrpcEnv::enter();
        let remote = SecretKey::generate();
        let remote_pk = remote.public_key().to_bytes();
        let local = SecretKey::generate();
        let (addr, handle) = start_plaintext_mock(vec![remote]).await;
        let dir = TempDir::new().expect("tempdir");
        let ks = dir.path().join("keys");
        std::fs::create_dir_all(&ks).expect("keystore dir");
        let local_pk = write_keystore(&ks, &local);
        let password = write_password_file(dir.path());
        let denylist = DeletionDenylist::load(dir.path()).expect("denylist");
        let loaded = load_with_grpc(&format!("http://{addr}"), &ks, &password, &denylist).await;
        let validators = vec![
            (format!("0x{}", hex::encode(local_pk)), INDEX.to_string()),
            (format!("0x{}", hex::encode(remote_pk)), REMOTE_INDEX.to_string()),
        ];
        let mut harness = Self::boot_with(doppelganger_enabled, Some(loaded), validators).await;
        harness.grpc_server = Some(handle);
        (harness, local_pk, remote_pk)
    }

    /// `RefreshService::refresh` then `KeyAdmissionService::admit(RawSecret)`,
    /// the production secret-provider refresh callback.
    async fn admit_secret_provider_refresh(&mut self) -> AdmittedKey {
        let secret = SecretKey::generate();
        let bytes = secret.public_key().to_bytes();
        let provider = Arc::new(ListedKeyProvider::from_secrets(std::slice::from_ref(&secret)));
        let denylist = Arc::clone(&self.denylist);
        let is_denied: secret_provider::DenylistCheck =
            Arc::new(move |pk: &[u8; 48]| denylist.contains(pk));
        let mut refresh = secret_provider::RefreshService::with_denylist(
            vec![provider],
            self.local_pubkeys.clone(),
            Some(is_denied),
            Duration::from_secs(3600),
            CancellationToken::new(),
        );
        let mut new_keys = refresh.refresh().await;
        assert_eq!(
            new_keys.len(),
            1,
            "secret-provider refresh must surface the new key (doppelganger={})",
            self.doppelganger_enabled
        );
        let admitted = new_keys.pop().expect("one key");
        let outcome = self.admissions.admit(admitted, AdmissionSource::RawSecret).expect("admit");
        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { pubkey, .. } if pubkey == bytes),
            "refresh path must admit into PubkeyMap, got {outcome:?}"
        );
        self.bn_state
            .validators
            .lock()
            .expect("validators")
            .push((format!("0x{}", hex::encode(bytes)), INDEX.to_string()));
        let pubkey = self.pubkey_map.read().get(&bytes).cloned().expect("pubkey map");
        AdmittedKey { pubkey, bytes, index: INDEX.to_string() }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(handle) = self.grpc_server.take() {
            handle.abort();
        }
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
            let validators = state_v.validators.lock().expect("validators").clone();
            let data: Vec<_> = validators
                .iter()
                .map(|(pk, index)| {
                    serde_json::json!({
                        "index": index,
                        "status": "active_ongoing",
                        "validator": { "pubkey": pk }
                    })
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": data }))
        })
        .mount(server)
        .await;

    let state_a = Arc::clone(&state);
    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/attester/\d+$"))
        .respond_with(move |_req: &Request| {
            let validators = state_a.validators.lock().expect("validators").clone();
            let slot = *state_a.duty_slot.lock().expect("slot");
            let data: Vec<_> = validators
                .iter()
                .map(|(pk, index)| {
                    serde_json::json!({
                        "pubkey": pk,
                        "validator_index": index,
                        "committee_index": "0",
                        "committee_length": "4",
                        "committees_at_slot": "1",
                        "validator_committee_index": "0",
                        "slot": slot.to_string()
                    })
                })
                .collect();
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
    let key = harness.admit(AdmissionKind::Keymanager).await;
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

    let key = harness.admit(AdmissionKind::Keymanager).await;
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
    let key = harness.admit(AdmissionKind::Keymanager).await;
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
    let key = harness.admit(AdmissionKind::Keymanager).await;
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
    let key = harness.admit(AdmissionKind::Keymanager).await;
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

async fn g6_grpc_once(doppelganger_enabled: bool) {
    let mut harness = Harness::boot_grpc_remote(doppelganger_enabled).await;
    let key = harness.require_mapped_key(INDEX);
    assert!(
        !harness.local_pubkeys.contains(&key.bytes),
        "remote pubkey must stay out of local_pubkeys (doppelganger={doppelganger_enabled})"
    );
    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;
}

#[tokio::test]
async fn g6_grpc_remote_key_earns_duties_in_the_next_request() {
    g6_grpc_once(true).await;
    g6_grpc_once(false).await;
}

async fn g6_secret_once(doppelganger_enabled: bool) {
    let mut harness = Harness::boot(doppelganger_enabled).await;
    let key = harness.admit_secret_provider_refresh().await;
    assert!(
        harness.pubkey_map.read().contains_key(&key.bytes),
        "secret-provider refresh must insert into PubkeyMap (doppelganger={doppelganger_enabled})"
    );
    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;
}

#[tokio::test]
async fn g6_secret_provider_key_earns_duties_in_the_next_request() {
    g6_secret_once(true).await;
    g6_secret_once(false).await;
}

#[tokio::test]
async fn remote_pubkeys_enter_the_pubkey_map_not_only_the_composite_signer() {
    let _env = InsecureGrpcEnv::enter();
    let remote = SecretKey::generate();
    let remote_pk = remote.public_key().to_bytes();
    let (addr, handle) = start_plaintext_mock(vec![remote]).await;
    let loaded = load_grpc_only(&format!("http://{addr}")).await;
    assert!(
        loaded.composite_signer.has_grpc_remote(&remote_pk),
        "remote pubkey is registered on CompositeSigner"
    );
    assert!(
        loaded.pubkey_map.read().contains_key(&remote_pk),
        "remote pubkey must be inserted into PubkeyMap, not only CompositeSigner"
    );
    assert!(!loaded.local_pubkeys.contains(&remote_pk));
    assert!(!loaded.composite_signer.has_local_key(&remote_pk));
    handle.abort();
}

#[tokio::test]
async fn mixed_local_and_remote_resolves_both_sets() {
    let (mut harness, local_pk, remote_pk) = Harness::boot_local_and_remote(false).await;
    assert!(harness.pubkey_map.read().contains_key(&local_pk), "local key in PubkeyMap");
    assert!(harness.pubkey_map.read().contains_key(&remote_pk), "remote key in PubkeyMap");
    assert!(harness.local_pubkeys.contains(&local_pk));
    assert!(!harness.local_pubkeys.contains(&remote_pk));
    harness.resolve().await;
    harness.assert_index_in_next_requests(INDEX).await;
    harness.assert_index_in_next_requests(REMOTE_INDEX).await;
}

#[tokio::test]
async fn local_keystore_denylist_behaviour_is_unchanged_after_the_reorder() {
    let _env = InsecureGrpcEnv::enter();
    let remote = SecretKey::generate();
    let remote_pk = remote.public_key().to_bytes();
    let kept = SecretKey::generate();
    let denied = SecretKey::generate();
    let remote_entry = ListedKey::from_secret(&remote);
    let kept_entry = ListedKey::from_secret(&kept);
    let denied_entry = ListedKey::from_secret(&denied);
    let (addr, handle) = start_plaintext_mock(vec![remote]).await;

    let dir = TempDir::new().expect("tempdir");
    let ks = dir.path().join("keys");
    std::fs::create_dir_all(&ks).expect("keystore dir");
    let kept_pk = write_keystore(&ks, &kept);
    let denied_pk = write_keystore(&ks, &denied);
    std::fs::write(dir.path().join(".rvc.deleted_keys"), format!("0x{}\n", hex::encode(denied_pk)))
        .expect("denylist file");
    let denylist = DeletionDenylist::load(dir.path()).expect("denylist");
    let password = write_password_file(dir.path());
    let loaded = load_with_grpc(&format!("http://{addr}"), &ks, &password, &denylist).await;

    assert!(loaded.local_pubkeys.contains(&kept_pk));
    assert!(!loaded.local_pubkeys.contains(&denied_pk), "denylisted local key is skipped");
    assert!(!loaded.local_pubkeys.contains(&remote_pk), "remote keys never enter local_pubkeys");
    assert!(loaded.pubkey_map.read().contains_key(&kept_pk));
    assert!(!loaded.pubkey_map.read().contains_key(&denied_pk));
    assert!(loaded.pubkey_map.read().contains_key(&remote_pk));
    assert!(loaded.composite_signer.has_local_key(&kept_pk));
    assert!(!loaded.composite_signer.has_local_key(&denied_pk));
    assert!(loaded.composite_signer.has_grpc_remote(&remote_pk));
    assert!(!loaded.composite_signer.has_local_key(&remote_pk));

    // Refresh known-set is `local_pubkeys`. The denied key is skipped by the
    // denylist; the remote key is not in that set, so refresh still returns it.
    let denylist = Arc::new(denylist);
    let check = Arc::clone(&denylist);
    let is_denied: secret_provider::DenylistCheck = Arc::new(move |pk| check.contains(pk));
    let provider =
        Arc::new(ListedKeyProvider { keys: vec![kept_entry, denied_entry, remote_entry] });
    let mut refresh = secret_provider::RefreshService::with_denylist(
        vec![provider],
        loaded.local_pubkeys.clone(),
        Some(is_denied),
        Duration::from_secs(3600),
        CancellationToken::new(),
    );
    let new_keys = refresh.refresh().await;
    let new_pks: Vec<[u8; 48]> = new_keys.iter().map(|sk| sk.public_key().to_bytes()).collect();
    assert!(!new_pks.contains(&denied_pk), "denylisted local key is still skipped on refresh");
    assert!(!new_pks.contains(&kept_pk), "known local key is not rediscovered");
    assert!(new_pks.contains(&remote_pk), "remote pubkey must not be in the refresh known-set");
    handle.abort();
}

#[tokio::test]
async fn denylisted_grpc_pubkey_is_absent_from_pubkey_map_and_signer() {
    let _env = InsecureGrpcEnv::enter();
    let denied = SecretKey::generate();
    let kept = SecretKey::generate();
    let denied_pk = denied.public_key().to_bytes();
    let kept_pk = kept.public_key().to_bytes();
    let (addr, handle) = start_plaintext_mock(vec![denied, kept]).await;

    let dir = TempDir::new().expect("tempdir");
    let ks = dir.path().join("keys");
    std::fs::create_dir_all(&ks).expect("keystore dir");
    std::fs::write(dir.path().join(".rvc.deleted_keys"), format!("0x{}\n", hex::encode(denied_pk)))
        .expect("denylist file");
    let denylist = DeletionDenylist::load(dir.path()).expect("denylist");
    assert!(denylist.contains(&denied_pk));
    let password = write_password_file(dir.path());
    let loaded = load_with_grpc(&format!("http://{addr}"), &ks, &password, &denylist).await;

    assert!(!loaded.pubkey_map.read().contains_key(&denied_pk));
    assert!(!loaded.local_pubkeys.contains(&denied_pk));
    assert!(!loaded.composite_signer.has_grpc_remote(&denied_pk));
    assert!(loaded.pubkey_map.read().contains_key(&kept_pk), "non-denied remote key stays");
    assert!(loaded.composite_signer.has_grpc_remote(&kept_pk));
    assert!(!loaded.local_pubkeys.contains(&kept_pk));
    handle.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_connect_failure_logs_no_retry_promise() {
    use tracing_subscriber::layer::SubscriberExt;

    let _env = InsecureGrpcEnv::enter();
    let logs = Arc::new(Mutex::new(String::new()));
    let subscriber = tracing_subscriber::registry().with(LogCapture { buf: Arc::clone(&logs) });
    let _guard = tracing::subscriber::set_default(subscriber);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let dir = TempDir::new().expect("tempdir");
    let ks = dir.path().join("keys");
    std::fs::create_dir_all(&ks).expect("keystore dir");
    let password = write_password_file(dir.path());
    let denylist = DeletionDenylist::load(dir.path()).expect("denylist");
    let config = grpc_config(&ks, &password, &format!("http://{addr}"));
    let loaded =
        load_signing_keys(&config, &denylist).await.expect("gRPC connect failure is non-fatal");
    assert!(loaded.grpc_signer.is_none());
    assert!(loaded.pubkey_map.read().is_empty());
    let text = logs.lock().expect("logs").clone();
    assert!(
        text.contains("Failed to connect to gRPC remote signer"),
        "connect failure must be logged; got {text}"
    );
    assert!(!text.contains("retry on demand"), "failure log must not promise a retry; got {text}");
    assert!(!text.contains("will retry"), "failure log must not promise a retry; got {text}");
}

#[tokio::test]
async fn c1_remote_key_produces_no_signature_until_both_gates_open() {
    let mut harness = Harness::boot_grpc_remote(true).await;
    let key = harness.require_mapped_key(INDEX);
    // D-3 registers a loaded key enabled. Hold the store shut so both gates
    // start closed, the same pair the keymanager C-1 test holds closed.
    harness.handles.validator_store.set_enabled(&key.bytes, false);

    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;

    assert!(
        !harness.handles.validator_store.is_signing_enabled(&key.bytes),
        "ValidatorStore::is_signing_enabled must block a newly loaded remote key"
    );
    let machine = harness.machine.as_ref().expect("forward-window gate");
    assert!(
        !machine.is_signing_enabled(&key.pubkey),
        "forward-window gate must block: boot register at epoch 1 is Pending"
    );
    harness.assert_store_gate_yields_no_signature(&key).await;
    let blocked = harness.sign(&key.pubkey).await;
    assert!(
        matches!(blocked, Err(SignerError::BlockedByDoppelganger)),
        "forward-window gate must produce no signature; got {blocked:?}"
    );

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
    let released = harness.sign(&key.pubkey).await.expect("signature once both gates are open");
    harness.assert_sample_attestation_signature(&key.pubkey, &released);
    harness.assert_index_in_next_requests(&key.index).await;
}

#[tokio::test]
async fn c1_remote_key_with_doppelganger_disabled_only_the_validator_store_gate_blocks() {
    let mut harness = Harness::boot_grpc_remote(false).await;
    let key = harness.require_mapped_key(INDEX);
    assert!(
        harness.enablement.is_signing_enabled(&key.pubkey),
        "DoppelgangerDisabledByOperator::is_signing_enabled returns true; it does not block"
    );
    // D-3 enables loaded keys. The store flag is the only remaining gate.
    harness.handles.validator_store.set_enabled(&key.bytes, false);
    assert!(
        !harness.handles.validator_store.is_signing_enabled(&key.bytes),
        "ValidatorStore::is_signing_enabled is the only gate on a remote key"
    );

    harness.resolve().await;
    harness.assert_index_in_next_requests(&key.index).await;
    harness.assert_store_gate_yields_no_signature(&key).await;
    harness.assert_no_selection_proof_while_store_closed(&key).await;
    harness.assert_index_in_next_requests(&key.index).await;

    harness.handles.validator_store.set_enabled(&key.bytes, true);
    assert!(harness.handles.validator_store.is_signing_enabled(&key.bytes));
    let sig =
        harness.sign(&key.pubkey).await.expect("open store gate yields the attestation signature");
    harness.assert_sample_attestation_signature(&key.pubkey, &sig);
}

fn sample_attestation() -> AttestationData {
    AttestationData {
        slot: 64,
        index: 0,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 1, root: [0x22; 32] },
        target: Checkpoint { epoch: 2, root: [0x33; 32] },
    }
}

fn write_password_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("password.txt");
    std::fs::write(&path, format!("*={PASSWORD}\n")).expect("password file");
    path
}

fn write_keystore(dir: &std::path::Path, sk: &SecretKey) -> [u8; 48] {
    let keystore = Keystore::encrypt(
        sk,
        PASSWORD.as_bytes(),
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt keystore");
    let json = serde_json::to_string(&keystore).expect("keystore json");
    let pk = sk.public_key().to_bytes();
    std::fs::write(dir.join(format!("keystore-0x{}.json", hex::encode(pk))), json)
        .expect("write keystore");
    pk
}

fn grpc_config(
    keystore_path: &std::path::Path,
    password_file: &std::path::Path,
    url: &str,
) -> Config {
    Config {
        keystore_path: keystore_path.to_path_buf(),
        password_file: Some(password_file.to_path_buf()),
        disable_keystore_locking: true,
        allow_fresh_db: true,
        grpc_signer: GrpcSignerConfig { url: Some(url.to_string()), ..Default::default() },
        ..Default::default()
    }
}

async fn load_grpc_only(url: &str) -> LoadedKeys {
    let dir = TempDir::new().expect("tempdir");
    let ks = dir.path().join("keys");
    std::fs::create_dir_all(&ks).expect("keystore dir");
    let password = write_password_file(dir.path());
    let denylist = DeletionDenylist::load(dir.path()).expect("denylist");
    load_with_grpc(url, &ks, &password, &denylist).await
}

async fn load_with_grpc(
    url: &str,
    keystore_path: &std::path::Path,
    password_file: &std::path::Path,
    denylist: &DeletionDenylist,
) -> LoadedKeys {
    let config = grpc_config(keystore_path, password_file, url);
    load_signing_keys(&config, denylist).await.expect("load_signing_keys")
}

struct LogCapture {
    buf: Arc<Mutex<String>>,
}

struct LogVisitor<'a>(&'a mut String);

impl tracing::field::Visit for LogVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={}", field.name(), value);
    }
}

impl<S> tracing_subscriber::Layer<S> for LogCapture
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut line = String::new();
        event.record(&mut LogVisitor(&mut line));
        let mut buf = self.buf.lock().expect("logs");
        buf.push_str(&line);
        buf.push('\n');
    }
}

/// Holds the plaintext-gRPC env gate for one connect. Tests in this file share
/// the process, so the lock keeps `set_var` / `remove_var` from overlapping.
struct InsecureGrpcEnv {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[allow(unsafe_code)]
impl InsecureGrpcEnv {
    fn enter() -> Self {
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        let lock = LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // SAFETY: test-only env mutation for the plaintext gRPC gate.
        unsafe {
            std::env::set_var(grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR, "true");
        }
        Self { _lock: lock }
    }
}

#[allow(unsafe_code)]
impl Drop for InsecureGrpcEnv {
    fn drop(&mut self) {
        // SAFETY: test-only env mutation for the plaintext gRPC gate.
        unsafe {
            std::env::remove_var(grpc_signer::REMOTE_SIGNER_INSECURE_ENV_VAR);
        }
    }
}

struct ListedKey {
    id: String,
    pubkey_hex: String,
    keystore_json: String,
}

struct ListedKeyProvider {
    keys: Vec<ListedKey>,
}

impl ListedKey {
    fn from_secret(sk: &SecretKey) -> Self {
        let keystore = Keystore::encrypt(
            sk,
            PASSWORD.as_bytes(),
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let pubkey_hex = format!("0x{}", hex::encode(sk.public_key().to_bytes()));
        Self {
            id: pubkey_hex.clone(),
            pubkey_hex,
            keystore_json: serde_json::to_string(&keystore).expect("keystore json"),
        }
    }
}

impl ListedKeyProvider {
    fn from_secrets(secrets: &[SecretKey]) -> Self {
        Self { keys: secrets.iter().map(ListedKey::from_secret).collect() }
    }
}

#[async_trait::async_trait]
impl secret_provider::SecretProvider for ListedKeyProvider {
    fn name(&self) -> &str {
        "rr-2-4"
    }

    async fn list_keys(
        &self,
    ) -> Result<Vec<secret_provider::SecretKeyEntry>, secret_provider::SecretProviderError> {
        Ok(self
            .keys
            .iter()
            .map(|key| secret_provider::SecretKeyEntry {
                id: key.id.clone(),
                pubkey_hex: Some(key.pubkey_hex.clone()),
            })
            .collect())
    }

    async fn fetch_key(
        &self,
        id: &str,
    ) -> Result<secret_provider::KeyMaterial, secret_provider::SecretProviderError> {
        let key = self
            .keys
            .iter()
            .find(|key| key.id == id)
            .ok_or_else(|| secret_provider::SecretProviderError::NotFound(id.to_string()))?;
        Ok(secret_provider::KeyMaterial::Keystore {
            keystore_json: key.keystore_json.clone(),
            password: zeroize::Zeroizing::new(PASSWORD.to_string()),
        })
    }
}

async fn start_plaintext_mock(
    secrets: Vec<SecretKey>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use grpc_signer::proto::signer_v2::{
        AttestationData as ProtoAttestationData, GetStatusRequest, GetStatusResponse,
        ListPublicKeysRequest, ListPublicKeysResponse, SignAggregateAndProofRequest,
        SignAttestationDataRequest, SignBeaconBlockRequest, SignBlindedBeaconBlockRequest,
        SignBlockHeaderRequest, SignBuilderRegistrationRequest, SignContributionAndProofRequest,
        SignRandaoRevealRequest, SignResponse, SignRootRequest,
        SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
        SignVoluntaryExitRequest,
    };
    use grpc_signer::{SignerServiceServerV2, SignerServiceV2};
    use tonic::{Request, Response, Status};

    struct MockV2 {
        keys: Vec<([u8; 48], SecretKey)>,
    }

    fn bytes32(bytes: &[u8]) -> Result<[u8; 32], &'static str> {
        bytes.try_into().map_err(|_| "expected 32 bytes")
    }

    fn attestation_from_proto(
        data: &ProtoAttestationData,
    ) -> Result<AttestationData, &'static str> {
        let source = data.source.as_ref().ok_or("missing source")?;
        let target = data.target.as_ref().ok_or("missing target")?;
        Ok(AttestationData {
            slot: data.slot,
            index: data.index,
            beacon_block_root: bytes32(&data.beacon_block_root)?,
            source: Checkpoint { epoch: source.epoch, root: bytes32(&source.root)? },
            target: Checkpoint { epoch: target.epoch, root: bytes32(&target.root)? },
        })
    }

    #[tonic::async_trait]
    impl SignerServiceV2 for MockV2 {
        async fn list_public_keys(
            &self,
            _request: Request<ListPublicKeysRequest>,
        ) -> Result<Response<ListPublicKeysResponse>, Status> {
            Ok(Response::new(ListPublicKeysResponse {
                pubkeys: self.keys.iter().map(|(pk, _)| pk.to_vec()).collect(),
            }))
        }

        async fn get_status(
            &self,
            _request: Request<GetStatusRequest>,
        ) -> Result<Response<GetStatusResponse>, Status> {
            Ok(Response::new(GetStatusResponse {
                ready: true,
                backend: "rr-2-4-mock".into(),
                key_count: self.keys.len() as u32,
            }))
        }

        async fn sign_beacon_block(
            &self,
            _: Request<SignBeaconBlockRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_blinded_beacon_block(
            &self,
            _: Request<SignBlindedBeaconBlockRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_attestation_data(
            &self,
            request: Request<SignAttestationDataRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            let req = request.into_inner();
            let pk: [u8; 48] =
                req.pubkey.as_slice().try_into().map_err(|_| Status::invalid_argument("pubkey"))?;
            let sk = self
                .keys
                .iter()
                .find(|(bytes, _)| *bytes == pk)
                .map(|(_, sk)| sk)
                .ok_or_else(|| Status::not_found("pubkey"))?;
            let fork = req.fork_info.ok_or_else(|| Status::invalid_argument("fork_info"))?;
            let proto = req.data.ok_or_else(|| Status::invalid_argument("data"))?;
            let data = attestation_from_proto(&proto).map_err(Status::invalid_argument)?;
            let fork_version: [u8; 4] = fork
                .current_version
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("fork version"))?;
            let gvr: [u8; 32] = fork
                .genesis_validators_root
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("genesis validators root"))?;
            let root = crypto::signing_root_with_fork_version(
                &data,
                eth_types::DOMAIN_BEACON_ATTESTER,
                fork_version,
                gvr,
            );
            let signature = sk.sign(&root).to_bytes().to_vec();
            Ok(Response::new(SignResponse { signature }))
        }
        async fn sign_aggregate_and_proof(
            &self,
            _: Request<SignAggregateAndProofRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_randao_reveal(
            &self,
            _: Request<SignRandaoRevealRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_sync_committee_message(
            &self,
            _: Request<SignSyncCommitteeMessageRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_sync_aggregator_selection_data(
            &self,
            _: Request<SignSyncAggregatorSelectionDataRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_contribution_and_proof(
            &self,
            _: Request<SignContributionAndProofRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_builder_registration(
            &self,
            _: Request<SignBuilderRegistrationRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_voluntary_exit(
            &self,
            _: Request<SignVoluntaryExitRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_block_header(
            &self,
            _: Request<SignBlockHeaderRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
        async fn sign_root(
            &self,
            _: Request<SignRootRequest>,
        ) -> Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("mock"))
        }
    }

    let keys: Vec<([u8; 48], SecretKey)> =
        secrets.into_iter().map(|sk| (sk.public_key().to_bytes(), sk)).collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SignerServiceServerV2::new(MockV2 { keys }))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("mock gRPC server");
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("gRPC mock did not accept connections on {addr}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (addr, handle)
}
