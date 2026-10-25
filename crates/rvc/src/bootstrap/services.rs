//! Bootstrap phase: build remaining services (signer, store, fork gate, adapters).
//!
//! Extracted from `bin/rvc` startup Step 7 / 7b / 7b2: production signer, D-3
//! validator registration, duty/propagator/clock wiring, SEC-9 fork-compat gate,
//! proposer `BnManager` + block beacon adapter, builder service, remote-signer
//! log, and the shared attesting toggle.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use bn_manager::{BeaconNodeClient, BnManager, DutiesProvider, OperationTimeouts, Propagator};
use builder::BuilderService;
use duty_tracker::DutyTracker;
use signer::SignerService;
use slashing::SlashingDb;
use timing::SystemSlotClock;
use tracing::{error, info, warn};
use validator_store::ValidatorStore;

use super::beacon::BeaconHandles;
use super::enablement::EnablementHandles;
use super::keys::LoadedKeys;
use super::BootstrapError;
use crate::beacon_adapter::BeaconBlockAdapter;
use crate::config::{Config, ServiceBuilder};
use crate::orchestrator::OrchestratorConfig;
use crate::quiesce::QuiesceRegistry;
use crate::startup::{self, StartupError};

/// Handles produced by [`build_services`].
///
/// Held as locals by the binary composition root until a future `run()` moves
/// selected fields into [`super::BootstrapCtx`] (at most three named fields per
/// the growth rule).
pub struct ServiceHandles {
    /// Production signer with slashing protection and signing enablement.
    pub signer: Arc<SignerService>,
    /// Quiesce set read by the signer's [`crate::quiesce::QuiescingEnablement`].
    ///
    /// Same `Arc` the decorator holds. This issue exposes no removal; re-admission
    /// is a later change.
    pub quiesce_registry: Arc<QuiesceRegistry>,
    /// Per-validator config store (fee recipient, enabled, gas limit).
    pub validator_store: Arc<ValidatorStore>,
    /// Attestation propagator over the main-pool `BnManager`.
    pub propagator: Arc<Propagator<BnManager>>,
    /// Main-pool beacon trait object (duties, fallback block path, monitors).
    pub beacon: Arc<dyn BeaconNodeClient>,
    /// Duty tracker seeded with resolved validator indices.
    pub duty_tracker: Arc<DutyTracker>,
    /// System slot clock for the duty orchestrator.
    pub slot_clock: Arc<SystemSlotClock>,
    /// Orchestrator config (GVR + fork schedule + timeouts).
    pub orchestrator_config: OrchestratorConfig,
    /// Dedicated proposer-pool manager when `proposer_nodes` is configured.
    pub proposer_bn_manager: Option<Arc<BnManager>>,
    /// Block-production adapter (proposer pool when set, else main pool).
    pub block_beacon: Arc<BeaconBlockAdapter>,
    /// MEV builder registration service (always constructed in production).
    pub builder_service: Option<Arc<BuilderService>>,
    /// Shared attesting on/off toggle (orchestrator + keymanager API).
    pub attesting_enabled: Arc<AtomicBool>,
}

/// Apply a fork-compatibility check result (SEC-9 / M-15).
///
/// Fatal by default so an unknown fork version cannot silently produce invalid
/// signatures. When `allow_unsupported_fork` is set (testnets / experimental
/// forks), the error is logged and startup continues.
fn apply_fork_compatibility_result(
    result: Result<(), StartupError>,
    allow_unsupported_fork: bool,
) -> Result<(), StartupError> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if allow_unsupported_fork => {
            warn!(
                error = %e,
                "Fork compatibility check failed; continuing because allow_unsupported_fork is set"
            );
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "Fork compatibility check failed");
            Err(e)
        }
    }
}

/// Admit proposer nodes against the identity the main pool already agreed.
///
/// Seeded from [`BnManager::agreed_chain_identity`], which
/// [`BnManager::agreed_spec_and_genesis`] stored. This does not call
/// `agreed_spec_and_genesis` or `confirm_genesis_validators_root` on the
/// proposer pool: both fail the process when every node disagrees, and both
/// would seed an identity independent of the main pool. Zero admitted nodes
/// is not a boot error. The caller logs that once.
async fn admit_proposer_pool(main: &BnManager, proposer: &BnManager) -> usize {
    let Some(identity) = main.agreed_chain_identity().await else {
        proposer.revoke_unidentified();
        return 0;
    };
    proposer.admit_against_identity(identity).await
}

/// Build signer, validator store (with D-3 registration), duty path, fork gate,
/// proposer/main block adapters, builder service, and the shared attesting toggle.
///
/// # Behaviour preserved from `run_validator`
///
/// - D-3: every pubkey in `keys.pubkey_map` is registered in the validator store
///   so the fail-closed per-validator gate permits keystore-loaded keys.
/// - SEC-9: fork mismatch is fatal by default; `allow_unsupported_fork` opts out.
/// - Proposer path uses dedicated `BnManager` when configured (E7), never a
///   hand-built single-endpoint client for block production.
/// - Attesting toggle is one `Arc<AtomicBool>` for orchestrator and keymanager.
///
/// Health-status updates remain the caller's responsibility.
pub async fn build_services(
    config: &Config,
    keys: &LoadedKeys,
    enablement: &EnablementHandles,
    beacon: &BeaconHandles,
    slashing_db: Arc<SlashingDb>,
    timeouts: OperationTimeouts,
) -> Result<ServiceHandles, BootstrapError> {
    let builder = ServiceBuilder::new(config.clone());

    let (signer, quiesce_registry) = builder.build_signer(
        Arc::clone(&keys.composite_signer),
        slashing_db,
        Arc::clone(&enablement.signing_enablement),
    );
    let validator_store = builder.build_validator_store(config.validators_config.as_deref())?;

    // D-3 (Issue 2.11): register every keystore-loaded validator so the
    // fail-closed per-validator signing gate permits the keys the VC loaded.
    // Without this, the common no-validators_config deployment would have every
    // loaded validator silently blocked from signing.
    builder.register_loaded_validators(&validator_store, &keys.pubkey_map);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Elapsed doppelganger holds are re-enabled here. A still-open hold stays
    // disabled. When the keymanager is running, the wall-clock enable task is
    // started again for the time left. A restart does not replay doppelganger
    // observations. Boot registration already routed an unfinished import
    // (open hold, any or unreadable sidecar, or staged sidecar)
    // through register_for_import, so the signer gate stays Pending until
    // this process observes the forward window and removes the sidecar.
    let _open = validator_store.reconcile_doppelganger_holds_at_boot(now_unix);

    // Attestation submit path uses the main-pool BnManager (failover-aware).
    // `build_beacon`'s client is still constructed and is not the keymanager
    // exit path. Propagator needs a Sized submitter, so keep the concrete
    // BnManager here rather than `dyn BeaconNodeClient`.
    let propagator = builder.build_propagator(Arc::clone(&beacon.bn_manager));
    // Main-pool trait object for duties and (when no dedicated proposer pool)
    // block production.
    let main_beacon: Arc<dyn BeaconNodeClient> =
        Arc::clone(&beacon.bn_manager) as Arc<dyn BeaconNodeClient>;

    // Same value `connect_beacon` stored. Do not resolve the spec again.
    let slot_duration_ms = beacon.slot_duration_ms;

    let slot_clock = match builder.build_slot_clock(slot_duration_ms) {
        Ok(clock) => clock,
        Err(e) => {
            error!("Failed to create slot clock: {}", e);
            return Err(e.into());
        }
    };

    let fork_schedule = match builder.build_agreed_fork_schedule(&beacon.bn_manager).await {
        Ok(schedule) => schedule,
        Err(e) => {
            error!("Failed to get the agreed fork schedule: {}", e);
            return Err(e.into());
        }
    };

    // D12: local `[fork_schedule]` vs BN `/eth/v1/config/spec`. Not opt-outable.
    if let Err(e) =
        startup::reconcile_gloas_fork_schedule(&config.fork_schedule, fork_schedule.as_ref())
    {
        error!(error = %e, "Gloas fork schedule reconciliation failed");
        return Err(e.into());
    }

    // ADR-R06: registry ∩ PubkeyMap, one snapshot per fetch. The registry has
    // no remove, so a deleted key leaves the effective set through this read.
    let index_source = Arc::new(crate::pubkey_index::PubkeyIndexSource {
        registry: Arc::clone(&enablement.pubkey_index),
        pubkey_map: Arc::clone(&keys.pubkey_map),
    });
    let duty_tracker = Arc::new(
        DutyTracker::new_with_source(
            Arc::clone(&beacon.bn_manager) as Arc<dyn DutiesProvider>,
            index_source,
        )
        .with_fork_schedule(fork_schedule.as_ref().clone()),
    );

    // SEC-9 / M-15: fork mismatch is fatal by default (mirrors the GVR chain-swap
    // gate). Opt out with `allow_unsupported_fork` for testnets / experimental forks.
    // Do not change `startup::check_fork_compatibility` itself.
    apply_fork_compatibility_result(
        startup::check_fork_compatibility(main_beacon.as_ref(), &fork_schedule).await,
        config.allow_unsupported_fork,
    )?;

    let orchestrator_config = builder
        .build_orchestrator_config(beacon.genesis_validators_root, fork_schedule)?
        .with_timeouts(timeouts);

    // Build proposer BnManager if proposer nodes are configured (T3.1)
    let proposer_bn_manager = match builder.build_proposer_bn_manager() {
        Ok(Some(mgr)) => {
            info!(
                proposer_nodes = ?config.proposer_nodes,
                "Proposer nodes configured — block production will use dedicated pool"
            );
            Some(mgr)
        }
        Ok(None) => None,
        Err(e) => {
            error!("Failed to create proposer BnManager: {}", e);
            return Err(e.into());
        }
    };

    let admitted_proposers = match &proposer_bn_manager {
        Some(proposer) => Some(admit_proposer_pool(&beacon.bn_manager, proposer).await),
        None => None,
    };
    match admitted_proposers {
        Some(0) => {
            warn!("no admitted proposer node; block production uses the main pool");
        }
        Some(admitted) => {
            info!(admitted, "proposer pool admitted against the main pool identity");
        }
        None => {}
    }

    // Block production goes through BnManager so multi-node failover applies.
    // The proposer pool is preferred while it has an admitted node. An empty
    // proposer pool stays installed and routes to the main pool.
    let block_beacon = match &proposer_bn_manager {
        Some(proposer_mgr) => Arc::new(BeaconBlockAdapter::with_proposer(
            main_beacon.clone(),
            proposer_mgr.clone() as Arc<dyn BeaconNodeClient>,
        )),
        None => Arc::new(BeaconBlockAdapter::new(main_beacon.clone())),
    };

    let builder_service = Some(builder.build_builder_service(
        signer.clone(),
        main_beacon.clone(),
        validator_store.clone(),
        orchestrator_config.fork_schedule.genesis_fork_version,
        orchestrator_config.fork_schedule.clone(),
    ));

    // Step 7b: Configure remote signer if URL provided
    if let Some(ref url) = config.keymanager.remote_signer_url {
        if !config.keymanager.enabled {
            warn!(
                url = %url,
                "Remote signer URL configured but Keymanager API is disabled; \
                 enable --keymanager-enabled to manage remote keys at runtime"
            );
        }
        info!(url = %url, "Remote signer URL configured");
    }

    // Step 7b2: Create attesting_enabled toggle (shared with orchestrator + API)
    let attesting_enabled = Arc::new(AtomicBool::new(!config.disable_attesting));
    metrics::definitions::RVC_ATTESTING_ENABLED.set(if config.disable_attesting {
        0.0
    } else {
        1.0
    });
    if config.disable_attesting {
        warn!("Attestation duties disabled at startup (--disable-attesting)");
    }

    Ok(ServiceHandles {
        signer,
        quiesce_registry,
        validator_store,
        propagator,
        beacon: main_beacon,
        duty_tracker,
        slot_clock,
        orchestrator_config,
        proposer_bn_manager,
        block_beacon,
        builder_service,
        attesting_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ForkScheduleConfig};
    use crate::orchestrator::PubkeyMap;
    use beacon::BeaconClient;
    use block_service::BeaconBlockClient;
    use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
    use doppelganger::{DoppelgangerDisabledByOperator, MonotonicEpochClock};
    use eth_types::{ForkName, Root};
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::Ordering;
    use tempfile::TempDir;
    use timing::SlotClock;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const GVR: Root = [0x11u8; 32];
    const TEST_FEE_RECIPIENT: &str = "0x1111111111111111111111111111111111111111";

    fn validators_config(dir: &TempDir) -> std::path::PathBuf {
        let path = dir.path().join("validators.toml");
        std::fs::write(&path, format!("[defaults]\nfee_recipient = \"{TEST_FEE_RECIPIENT}\"\n"))
            .expect("write validators config");
        path
    }

    fn pubkey_map_with(keys: &[PublicKey]) -> PubkeyMap {
        let mut map = HashMap::new();
        for pk in keys {
            map.insert(pk.to_bytes(), pk.clone());
        }
        Arc::new(parking_lot::RwLock::new(map))
    }

    fn loaded_keys(pubkey_map: PubkeyMap) -> LoadedKeys {
        let km = KeyManager::new();
        let validator_count = pubkey_map.read().len();
        LoadedKeys {
            composite_signer: Arc::new(CompositeSigner::new(LocalSigner::new(km))),
            validator_count,
            local_pubkeys: HashSet::new(),
            pubkey_map,
            secret_providers: vec![],
            grpc_signer: None,
        }
    }

    fn enablement_handles(pubkey_map: PubkeyMap) -> EnablementHandles {
        EnablementHandles {
            signing_enablement: Arc::new(DoppelgangerDisabledByOperator),
            forward_window_machine: None,
            epoch_clock: Arc::new(MonotonicEpochClock::new(0, 12_000)),
            pubkey_map,
            liveness_task: None,
            pubkey_index: crate::pubkey_index::PubkeyIndexRegistry::shared(),
            tracked_keys: Arc::new(crate::quiesce::TrackedKeys::new()),
        }
    }

    /// Mount fork-schedule (`/eth/v1/config/spec`) + head fork for SEC-9 gate.
    async fn mock_bn_server(head_fork_version: &str) -> MockServer {
        mock_bn_server_gloas(head_fork_version, Some("18446744073709551615"), Some("0x07000000"))
            .await
    }

    async fn mock_bn_server_gloas(
        head_fork_version: &str,
        gloas_epoch: Option<&str>,
        gloas_version: Option<&str>,
    ) -> MockServer {
        let server = MockServer::start().await;

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
            "SECONDS_PER_SLOT": "12",
            "SLOTS_PER_EPOCH": "32"
        });
        let map = data.as_object_mut().expect("spec data object");
        if let Some(epoch) = gloas_epoch {
            map.insert("GLOAS_FORK_EPOCH".into(), serde_json::json!(epoch));
        }
        if let Some(version) = gloas_version {
            map.insert("GLOAS_FORK_VERSION".into(), serde_json::json!(version));
        }

        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": data
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/fork"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "execution_optimistic": false,
                "finalized": false,
                "data": {
                    "previous_version": "0x04000000",
                    "current_version": head_fork_version,
                    "epoch": "364544"
                }
            })))
            .mount(&server)
            .await;

        server
    }

    async fn beacon_handles(uri: &str) -> BeaconHandles {
        let config = Config {
            beacon_url: uri.to_string(),
            beacon_nodes: vec![uri.to_string()],
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        };
        let sb = ServiceBuilder::new(config);
        let beacon_client: Arc<BeaconClient> = sb.build_beacon().expect("beacon client");
        let bn_manager =
            sb.build_bn_manager_with_timeouts(OperationTimeouts::default()).expect("bn manager");
        BeaconHandles {
            beacon_client,
            bn_manager,
            genesis_validators_root: GVR,
            genesis_validators_root_hex: format!("0x{}", hex::encode(GVR)),
            genesis_time: 0,
            slot_duration_ms: 12_000,
            genesis_confirmed: true,
        }
    }

    /// [`beacon_handles`] after the main pool agreed spec and genesis, as
    /// `connect_beacon` does before `build_services`.
    async fn agreed_beacon_handles(server: &MockServer) -> BeaconHandles {
        mount_genesis(server, "0xabc").await;
        let beacon = beacon_handles(&server.uri()).await;
        beacon
            .bn_manager
            .agreed_spec_and_genesis(bn_manager::SpecAgreement::Responding, "0xabc")
            .await
            .expect("main pool agrees");
        beacon
    }

    fn base_config(dir: &TempDir, beacon_uri: &str) -> Config {
        Config {
            beacon_url: beacon_uri.to_string(),
            beacon_nodes: vec![beacon_uri.to_string()],
            validators_config: Some(validators_config(dir)),
            disable_keystore_locking: true,
            allow_fresh_db: true,
            doppelganger_detection: false,
            ..Default::default()
        }
    }

    async fn run_phase(
        config: &Config,
        keys: &LoadedKeys,
        beacon: &BeaconHandles,
    ) -> Result<ServiceHandles, BootstrapError> {
        let enablement = enablement_handles(Arc::clone(&keys.pubkey_map));
        build_services(
            config,
            keys,
            &enablement,
            beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            OperationTimeouts::default(),
        )
        .await
    }

    /// D-3: every loaded pubkey is registered so fail-closed signing permits it.
    #[tokio::test]
    async fn test_build_services_registers_all_loaded_validators() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server("0x05000000").await;
        let config = base_config(&dir, &server.uri());
        let beacon = agreed_beacon_handles(&server).await;

        let sks: Vec<_> = (0..3).map(|_| SecretKey::generate()).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        let keys = loaded_keys(pubkey_map_with(&pks));

        // Before phase: untracked keys are fail-closed.
        {
            let store = ServiceBuilder::new(config.clone())
                .build_validator_store(config.validators_config.as_deref())
                .unwrap();
            for pk in &pks {
                assert!(
                    !store.is_signing_enabled(&pk.to_bytes()),
                    "untracked key must be fail-closed before registration"
                );
            }
        }

        let handles = run_phase(&config, &keys, &beacon).await.expect("phase succeeds");

        for pk in &pks {
            assert!(
                handles.validator_store.is_signing_enabled(&pk.to_bytes()),
                "loaded keystore key must be permitted after D-3 registration"
            );
            assert!(
                handles.validator_store.has_validator(&pk.to_bytes()),
                "loaded key must be tracked in the store"
            );
        }
    }

    /// The slot clock is the duration stored by `connect_beacon`, not a second spec read.
    #[tokio::test]
    async fn test_build_services_uses_stored_slot_duration() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server("0x05000000").await;
        let config = base_config(&dir, &server.uri());
        let mut beacon = agreed_beacon_handles(&server).await;
        beacon.slot_duration_ms = 6_000;
        let keys = loaded_keys(pubkey_map_with(&[]));

        let handles = run_phase(&config, &keys, &beacon).await.expect("phase succeeds");
        assert_eq!(handles.slot_clock.slot_duration(), std::time::Duration::from_secs(6));
    }

    #[tokio::test]
    async fn test_build_services_fork_mismatch_is_fatal_by_default() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server("0xdeadbeef").await;
        let config = base_config(&dir, &server.uri());
        assert!(!config.allow_unsupported_fork);
        let beacon = agreed_beacon_handles(&server).await;
        let keys = loaded_keys(pubkey_map_with(&[]));

        let result = run_phase(&config, &keys, &beacon).await;
        assert!(result.is_err(), "must fail closed on unsupported fork");
        match result.err().unwrap() {
            BootstrapError::Startup(StartupError::UnsupportedForkVersion { version }) => {
                assert!(version.contains("deadbeef") || version.contains("0xdeadbeef"));
            }
            other => panic!("expected UnsupportedForkVersion, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_build_services_fork_mismatch_allowed_with_optout() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server("0xdeadbeef").await;
        let mut config = base_config(&dir, &server.uri());
        config.allow_unsupported_fork = true;
        let beacon = agreed_beacon_handles(&server).await;
        let keys = loaded_keys(pubkey_map_with(&[]));

        let handles = run_phase(&config, &keys, &beacon)
            .await
            .expect("opt-out must continue past unknown fork");
        assert!(handles.builder_service.is_some());
        assert!(handles.attesting_enabled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_build_services_proposer_path_uses_proposer_bn_manager() {
        let dir = TempDir::new().unwrap();
        // Separate mock for proposer pool so the dedicated BnManager is distinct.
        let main_server = mock_bn_server("0x05000000").await;
        let proposer_server = mock_bn_server("0x05000000").await;
        mount_genesis(&main_server, "0xabc").await;
        mount_genesis(&proposer_server, "0xabc").await;

        let mut config = base_config(&dir, &main_server.uri());
        config.proposer_nodes = vec![proposer_server.uri()];
        let beacon = beacon_handles(&main_server.uri()).await;
        beacon
            .bn_manager
            .agreed_spec_and_genesis(bn_manager::SpecAgreement::Responding, "0xabc")
            .await
            .expect("main pool agrees");
        let keys = loaded_keys(pubkey_map_with(&[]));

        let handles = run_phase(&config, &keys, &beacon).await.expect("proposer path builds");

        let proposer =
            handles.proposer_bn_manager.as_ref().expect("proposer_nodes set → dedicated BnManager");
        let proposer_as_client: Arc<dyn BeaconNodeClient> = Arc::clone(proposer) as _;
        let production = handles.block_beacon.production();
        assert!(
            Arc::ptr_eq(&proposer_as_client, &production),
            "block_beacon must wrap the proposer BnManager (E7), not a hand-built client"
        );
        // Main pool must not be the block path when a proposer node is admitted.
        let main_as_client: Arc<dyn BeaconNodeClient> = Arc::clone(&beacon.bn_manager) as _;
        assert!(
            !Arc::ptr_eq(&main_as_client, &production),
            "block_beacon must not use main pool when proposer nodes are set"
        );
    }

    /// One `Arc<AtomicBool>` is returned so orchestrator and keymanager share it.
    #[tokio::test]
    async fn test_attesting_toggle_shared_between_orchestrator_and_keymanager() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server("0x05000000").await;

        // Default: attesting enabled.
        {
            let config = base_config(&dir, &server.uri());
            let beacon = agreed_beacon_handles(&server).await;
            let keys = loaded_keys(pubkey_map_with(&[]));
            let handles = run_phase(&config, &keys, &beacon).await.expect("phase");
            assert!(
                handles.attesting_enabled.load(Ordering::SeqCst),
                "default disable_attesting=false → toggle true"
            );
            // Clone as orchestrator / keymanager would; mutations are shared.
            let orch = Arc::clone(&handles.attesting_enabled);
            let km = Arc::clone(&handles.attesting_enabled);
            assert!(Arc::ptr_eq(&orch, &km));
            km.store(false, Ordering::SeqCst);
            assert!(!orch.load(Ordering::SeqCst));
            assert!(!handles.attesting_enabled.load(Ordering::SeqCst));
        }

        // Opt-out at startup.
        {
            let mut config = base_config(&dir, &server.uri());
            config.disable_attesting = true;
            let beacon = agreed_beacon_handles(&server).await;
            let keys = loaded_keys(pubkey_map_with(&[]));
            let handles = run_phase(&config, &keys, &beacon).await.expect("phase");
            assert!(
                !handles.attesting_enabled.load(Ordering::SeqCst),
                "disable_attesting must seed toggle false"
            );
        }
    }

    #[tokio::test]
    async fn test_build_services_gloas_both_unscheduled_omitted_keys() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server_gloas("0x05000000", None, None).await;
        let config = base_config(&dir, &server.uri());
        let beacon = agreed_beacon_handles(&server).await;
        let keys = loaded_keys(pubkey_map_with(&[]));

        let handles =
            run_phase(&config, &keys, &beacon).await.expect("both sources unscheduled must start");
        assert_eq!(handles.orchestrator_config.fork_schedule.gloas_fork_epoch, u64::MAX);
    }

    #[tokio::test]
    async fn test_build_services_gloas_both_scheduled_equal_resolves_gloas() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server_gloas("0x05000000", Some("600000"), Some("0x07000000")).await;
        let mut config = base_config(&dir, &server.uri());
        config.fork_schedule = ForkScheduleConfig {
            gloas_fork_epoch: Some(600_000),
            gloas_fork_version: Some("0X07000000".into()),
        };
        let beacon = agreed_beacon_handles(&server).await;
        let keys = loaded_keys(pubkey_map_with(&[]));

        let handles =
            run_phase(&config, &keys, &beacon).await.expect("equal scheduled pair must start");
        let schedule = handles.orchestrator_config.fork_schedule.as_ref();
        assert_eq!(schedule.gloas_fork_epoch, 600_000);
        assert_eq!(ForkName::from_epoch(600_000, schedule), ForkName::Gloas);
    }

    #[tokio::test]
    async fn test_build_services_gloas_disagreement_ignores_allow_unsupported_fork() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server_gloas("0x05000000", Some("600000"), Some("0x07000000")).await;
        let mut config = base_config(&dir, &server.uri());
        config.allow_unsupported_fork = true;
        let beacon = agreed_beacon_handles(&server).await;
        let keys = loaded_keys(pubkey_map_with(&[]));

        let result = run_phase(&config, &keys, &beacon).await;
        assert!(result.is_err(), "D12 disagreement is not opt-outable");
        match result.err().unwrap() {
            BootstrapError::Startup(err @ StartupError::ForkScheduleMismatch(_)) => {
                let msg = err.to_string();
                assert!(msg.contains("rvc-config"), "{msg}");
                assert!(msg.contains("/eth/v1/config/spec"), "{msg}");
                assert!(msg.contains("600000"), "{msg}");
                assert!(msg.contains("0x07000000"), "{msg}");
            }
            other => panic!("expected ForkScheduleMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_apply_fork_compatibility_result_fatal_and_optout() {
        let err = StartupError::UnsupportedForkVersion { version: "0xdeadbeef".to_string() };

        let fatal = apply_fork_compatibility_result(Err(err), false);
        assert!(fatal.is_err());
        assert!(matches!(fatal.unwrap_err(), StartupError::UnsupportedForkVersion { .. }));

        let err = StartupError::UnsupportedForkVersion { version: "0xdeadbeef".to_string() };
        assert!(apply_fork_compatibility_result(Err(err), true).is_ok());
        assert!(apply_fork_compatibility_result(Ok(()), false).is_ok());
        assert!(apply_fork_compatibility_result(Ok(()), true).is_ok());
    }

    fn identity_genesis(root: &str) -> String {
        format!(
            r#"{{"data":{{"genesis_time":"1606824023","genesis_validators_root":"{root}","genesis_fork_version":"0x00000000"}}}}"#
        )
    }

    async fn mount_genesis(server: &MockServer, root: &str) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(identity_genesis(root)))
            .mount(server)
            .await;
    }

    async fn produce_hits(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .filter(|request| request.url.path().starts_with("/eth/v3/validator/blocks/"))
            .count()
    }

    /// Two proposer nodes, one with a different genesis validators root.
    /// Production asks only the node that matches the main pool's identity.
    #[tokio::test]
    async fn proposer_pool_wrong_root_node_is_not_admitted() {
        let dir = TempDir::new().unwrap();
        let main = mock_bn_server("0x05000000").await;
        let good = mock_bn_server("0x05000000").await;
        let bad = mock_bn_server("0x05000000").await;
        mount_genesis(&main, "0xabc").await;
        mount_genesis(&good, "0xabc").await;
        mount_genesis(&bad, "0xdef").await;

        let mut config = base_config(&dir, &main.uri());
        config.proposer_nodes = vec![good.uri(), bad.uri()];
        let beacon = beacon_handles(&main.uri()).await;
        beacon
            .bn_manager
            .agreed_spec_and_genesis(bn_manager::SpecAgreement::Responding, "0xabc")
            .await
            .expect("main pool agrees");
        let keys = loaded_keys(pubkey_map_with(&[]));
        let handles = run_phase(&config, &keys, &beacon).await.expect("proposer boot is not fatal");

        let _ = handles.block_beacon.produce_block_v3(42, "0xrandao", None, None).await;
        assert_eq!(
            produce_hits(&bad).await,
            0,
            "a proposer node on the wrong genesis root is not asked for a block"
        );
        assert!(produce_hits(&good).await > 0, "the matching proposer node is asked for a block");
        assert_eq!(
            produce_hits(&main).await,
            0,
            "the main pool is not used while a proposer node is admitted"
        );
    }

    fn proposer_spec(slot_ms: &str, slots: &str) -> String {
        format!(
            r#"{{"data":{{"SLOT_DURATION_MS":"{slot_ms}","SLOTS_PER_EPOCH":"{slots}",{}}}}}"#,
            bn_manager::MAINNET_FORK_SPEC_FIELDS
        )
    }

    async fn mount_identity_body(server: &MockServer, spec: &str, genesis_root: &str) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_string(spec))
            .mount(server)
            .await;
        mount_genesis(server, genesis_root).await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"100","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(server)
            .await;
    }

    async fn path_hits(server: &MockServer, route: &str) -> usize {
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .filter(|request| request.url.path() == route)
            .count()
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn proposer_pool_with_no_admitted_node_falls_back_to_the_main_pool() {
        let dir = TempDir::new().unwrap();
        let main = mock_bn_server("0x05000000").await;
        let bad = mock_bn_server("0x05000000").await;
        mount_genesis(&main, "0xabc").await;
        mount_genesis(&bad, "0xdef").await;
        let mut config = base_config(&dir, &main.uri());
        config.proposer_nodes = vec![bad.uri()];
        let beacon = beacon_handles(&main.uri()).await;
        beacon
            .bn_manager
            .agreed_spec_and_genesis(bn_manager::SpecAgreement::Responding, "0xabc")
            .await
            .expect("main pool agrees");
        let keys = loaded_keys(pubkey_map_with(&[]));
        let handles = run_phase(&config, &keys, &beacon).await.expect("boot is not fatal");
        logs_assert(|lines: &[&str]| {
            let n = lines
                .iter()
                .filter(|line| {
                    line.contains("no admitted proposer node; block production uses the main pool")
                })
                .count();
            if n == 1 {
                Ok(())
            } else {
                Err(format!("fallback warning count {n}"))
            }
        });
        assert!(!logs_contain("no admitted beacon node; duties halted"));
        let _ = handles.block_beacon.produce_block_v3(42, "0xrandao", None, None).await;
        assert_eq!(produce_hits(&bad).await, 0, "the unadmitted proposer is not asked");
        assert!(produce_hits(&main).await > 0, "production uses the main pool");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn proposer_pool_node_revoked_at_runtime_on_an_identity_change_is_never_asked_for_a_block(
    ) {
        let dir = TempDir::new().unwrap();
        let main = mock_bn_server("0x05000000").await;
        let proposer = mock_bn_server("0x05000000").await;
        mount_genesis(&main, "0xabc").await;
        mount_genesis(&proposer, "0xabc").await;
        let mut config = base_config(&dir, &main.uri());
        config.proposer_nodes = vec![proposer.uri()];
        let beacon = beacon_handles(&main.uri()).await;
        beacon
            .bn_manager
            .agreed_spec_and_genesis(bn_manager::SpecAgreement::Responding, "0xabc")
            .await
            .expect("main pool agrees");
        let keys = loaded_keys(pubkey_map_with(&[]));
        let handles = run_phase(&config, &keys, &beacon).await.expect("boot");
        let pool = handles.proposer_bn_manager.as_ref().expect("proposer pool");

        let _ = handles.block_beacon.produce_block_v3(42, "0xrandao", None, None).await;
        assert!(produce_hits(&proposer).await > 0, "the matching proposer is asked");
        assert_eq!(produce_hits(&main).await, 0);

        // reset() drops the request log, so later counts start again at zero.
        proposer.reset().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&proposer)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&proposer)
            .await;
        pool.check_sync_status().await;
        let before_transient = produce_hits(&proposer).await;
        let _ = handles.block_beacon.produce_block_v3(43, "0xrandao", None, None).await;
        let after_transient = produce_hits(&proposer).await;
        assert!(
            after_transient > before_transient,
            "a transient error does not revoke the proposer"
        );
        assert_eq!(produce_hits(&main).await, 0, "the main pool stays unused");

        proposer.reset().await;
        mount_identity_body(&proposer, &proposer_spec("12000", "32"), "0xdef").await;
        pool.check_sync_status().await;
        assert!(logs_contain("no admitted proposer node; block production uses the main pool"));
        assert!(!logs_contain("no admitted beacon node; duties halted"));
        let before_revoke = produce_hits(&proposer).await;
        let _ = handles.block_beacon.produce_block_v3(44, "0xrandao", None, None).await;
        assert_eq!(
            produce_hits(&proposer).await,
            before_revoke,
            "the revoked proposer is not asked for a block"
        );
        assert!(produce_hits(&main).await > 0, "production falls back to the main pool");
    }

    #[tokio::test]
    async fn revoked_proposer_node_still_receives_identity_probes() {
        let dir = TempDir::new().unwrap();
        let main = mock_bn_server("0x05000000").await;
        let proposer = mock_bn_server("0x05000000").await;
        mount_genesis(&main, "0xabc").await;
        mount_genesis(&proposer, "0xabc").await;
        let mut config = base_config(&dir, &main.uri());
        config.proposer_nodes = vec![proposer.uri()];
        let beacon = beacon_handles(&main.uri()).await;
        beacon
            .bn_manager
            .agreed_spec_and_genesis(bn_manager::SpecAgreement::Responding, "0xabc")
            .await
            .expect("main pool agrees");
        let keys = loaded_keys(pubkey_map_with(&[]));
        let handles = run_phase(&config, &keys, &beacon).await.expect("boot");
        let pool = handles.proposer_bn_manager.as_ref().expect("proposer pool");

        proposer.reset().await;
        mount_identity_body(&proposer, &proposer_spec("12000", "32"), "0xdef").await;
        pool.check_sync_status().await;
        let spec_before = path_hits(&proposer, "/eth/v1/config/spec").await;
        let genesis_before = path_hits(&proposer, "/eth/v1/beacon/genesis").await;
        let sync_before = path_hits(&proposer, "/eth/v1/node/syncing").await;
        pool.check_sync_status().await;
        assert!(path_hits(&proposer, "/eth/v1/config/spec").await > spec_before);
        assert!(path_hits(&proposer, "/eth/v1/beacon/genesis").await > genesis_before);
        assert!(path_hits(&proposer, "/eth/v1/node/syncing").await > sync_before);

        proposer.reset().await;
        mount_identity_body(&proposer, &proposer_spec("12000", "32"), "0xabc").await;
        pool.check_sync_status().await;
        let before = produce_hits(&proposer).await;
        let _ = handles.block_beacon.produce_block_v3(42, "0xrandao", None, None).await;
        assert!(produce_hits(&proposer).await > before, "a matching identity re-admits the node");
        assert_eq!(produce_hits(&main).await, 0, "the main pool is not used after re-admission");
    }

    /// No main-pool identity must revoke the proposer pool. Deleting
    /// `revoke_unidentified` leaves the nodes admitted, which is how a
    /// manager starts.
    #[tokio::test]
    async fn admit_proposer_pool_revokes_when_the_main_identity_is_missing() {
        let endpoint = "http://127.0.0.1:9".to_string();
        let main =
            BnManager::new(bn_manager::BnManagerConfig::new(vec![endpoint.clone()])).expect("main");
        let proposer =
            BnManager::new(bn_manager::BnManagerConfig::new(vec![endpoint])).expect("proposer");
        assert!(BeaconNodeClient::duty_fence(&proposer).is_ok(), "a new manager starts admitted");
        let admitted = admit_proposer_pool(&main, &proposer).await;
        assert_eq!(admitted, 0);
        let err = BeaconNodeClient::duty_fence(&proposer)
            .expect_err("missing main identity must revoke the proposer pool");
        assert!(
            matches!(err, bn_manager::BeaconError::NoAdmittedNode),
            "revoke_unidentified must clear admission, got {err:?}"
        );
    }
}
