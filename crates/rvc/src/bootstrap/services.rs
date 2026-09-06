//! Bootstrap phase: build remaining services (signer, store, fork gate, adapters).
//!
//! Extracted from `bin/rvc` startup Step 7 / 7b / 7b2: production signer, D-3
//! validator registration, duty/propagator/clock wiring, SEC-9 fork-compat gate,
//! proposer `BnManager` + block beacon adapter, builder service, remote-signer
//! log, and the shared attesting toggle.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use bn_manager::{BeaconNodeClient, BnManager, OperationTimeouts, Propagator};
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
use crate::startup::{self, StartupError};

/// Handles produced by [`build_services`].
///
/// Held as locals by the binary composition root until a future `run()` moves
/// selected fields into [`super::BootstrapCtx`] (at most three named fields per
/// the growth rule).
pub struct ServiceHandles {
    /// Production signer with slashing protection and signing enablement.
    pub signer: Arc<SignerService>,
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

    let signer = builder.build_signer(
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

    // Attestation submit path uses the main-pool BnManager (failover-aware).
    // `build_beacon` remains only for single-client exit tooling
    // (keymanager voluntary exit). Propagator needs a Sized submitter, so keep
    // the concrete BnManager here rather than `dyn BeaconNodeClient`.
    let propagator = builder.build_propagator(Arc::clone(&beacon.bn_manager));
    // Main-pool trait object for duties and (when no dedicated proposer pool)
    // block production.
    let main_beacon: Arc<dyn BeaconNodeClient> =
        Arc::clone(&beacon.bn_manager) as Arc<dyn BeaconNodeClient>;
    let validator_indices: Vec<String> =
        enablement.pubkey_index.read().indices().cloned().collect();

    let slot_duration_ms = match builder.resolve_slot_duration_ms(main_beacon.as_ref()).await {
        Ok(ms) => ms,
        Err(e) => {
            error!("Failed to resolve slot duration from beacon node: {}", e);
            return Err(e.into());
        }
    };

    let slot_clock = match builder.build_slot_clock(slot_duration_ms) {
        Ok(clock) => clock,
        Err(e) => {
            error!("Failed to create slot clock: {}", e);
            return Err(e.into());
        }
    };

    let fork_schedule = match builder.build_fork_schedule(main_beacon.as_ref()).await {
        Ok(schedule) => schedule,
        Err(e) => {
            error!("Failed to fetch fork schedule from beacon node: {}", e);
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

    let duty_tracker = builder.build_duty_tracker(
        main_beacon.clone(),
        validator_indices,
        fork_schedule.as_ref().clone(),
    );

    // SEC-9 / M-15: fork mismatch is fatal by default (mirrors the GVR chain-swap
    // gate). Opt out with `allow_unsupported_fork` for testnets / experimental forks.
    // Do not change `startup::check_fork_compatibility` itself.
    apply_fork_compatibility_result(
        startup::check_fork_compatibility(main_beacon.as_ref(), &fork_schedule).await,
        config.allow_unsupported_fork,
    )?;

    let orchestrator_config = builder
        .build_orchestrator_config(beacon.genesis_validators_root, fork_schedule)
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

    // Block production goes through BnManager so multi-node failover applies.
    // Prefer the dedicated proposer pool when configured; otherwise the main pool.
    let block_beacon = match &proposer_bn_manager {
        Some(proposer_mgr) => {
            Arc::new(BeaconBlockAdapter(proposer_mgr.clone() as Arc<dyn BeaconNodeClient>))
        }
        None => Arc::new(BeaconBlockAdapter(main_beacon.clone())),
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
    use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
    use doppelganger::{DoppelgangerDisabledByOperator, MonotonicEpochClock};
    use eth_types::{ForkName, Root};
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::Ordering;
    use tempfile::TempDir;
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
            epoch_clock: Arc::new(MonotonicEpochClock::new(0)),
            pubkey_map,
            liveness_task: None,
            pubkey_index: crate::pubkey_index::PubkeyIndexRegistry::shared(),
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
        }
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
        let beacon = beacon_handles(&server.uri()).await;

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

    #[tokio::test]
    async fn test_build_services_fork_mismatch_is_fatal_by_default() {
        let dir = TempDir::new().unwrap();
        let server = mock_bn_server("0xdeadbeef").await;
        let config = base_config(&dir, &server.uri());
        assert!(!config.allow_unsupported_fork);
        let beacon = beacon_handles(&server.uri()).await;
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
        let beacon = beacon_handles(&server.uri()).await;
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

        let mut config = base_config(&dir, &main_server.uri());
        config.proposer_nodes = vec![proposer_server.uri()];
        let beacon = beacon_handles(&main_server.uri()).await;
        let keys = loaded_keys(pubkey_map_with(&[]));

        let handles = run_phase(&config, &keys, &beacon).await.expect("proposer path builds");

        let proposer =
            handles.proposer_bn_manager.as_ref().expect("proposer_nodes set → dedicated BnManager");
        let proposer_as_client: Arc<dyn BeaconNodeClient> = Arc::clone(proposer) as _;
        assert!(
            Arc::ptr_eq(&proposer_as_client, &handles.block_beacon.0),
            "block_beacon must wrap the proposer BnManager (E7), not a hand-built client"
        );
        // Main pool must not be the block path when proposer is configured.
        let main_as_client: Arc<dyn BeaconNodeClient> = Arc::clone(&beacon.bn_manager) as _;
        assert!(
            !Arc::ptr_eq(&main_as_client, &handles.block_beacon.0),
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
            let beacon = beacon_handles(&server.uri()).await;
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
            let beacon = beacon_handles(&server.uri()).await;
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
        let beacon = beacon_handles(&server.uri()).await;
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
        let beacon = beacon_handles(&server.uri()).await;
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
        let beacon = beacon_handles(&server.uri()).await;
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
}
