//! Bootstrap phase: beacon client, BnManager, single GVR parse, genesis gate.
//!
//! Extracted from `bin/rvc` startup Steps 3–5 so the chain-swap gate and GVR
//! parse can be unit-tested without spawning the binary.

use std::sync::Arc;

use beacon::BeaconClient;
use bn_manager::{BnManager, NodeStatusApi, OperationTimeouts};
use eth_types::canonical::gvr_hex::GvrHex;
use eth_types::Root;
use slashing::SlashingDb;
use tracing::{error, info, warn};

use super::BootstrapError;
use crate::config::{Config, ServiceBuilder};
use crate::startup;

/// Handles produced by [`connect_beacon`].
///
/// Moved into [`super::BootstrapCtx`] by a future `run()` (or held as locals
/// by the binary composition root until that lands).
pub struct BeaconHandles {
    /// Single-endpoint beacon client. Keymanager voluntary exit uses [`Self::bn_manager`].
    pub beacon_client: Arc<BeaconClient>,
    /// Multi-node beacon pool for runtime duties and genesis validation.
    pub bn_manager: Arc<BnManager>,
    /// Genesis validators root, parsed once from config/network preset.
    pub genesis_validators_root: Root,
    /// Canonical lowercase `0x`-prefixed encoding of [`Self::genesis_validators_root`].
    pub genesis_validators_root_hex: String,
    /// Genesis Unix time from config/network preset (slot/epoch clock anchor).
    pub genesis_time: u64,
    /// Slot length in milliseconds, resolved once from the beacon node spec.
    ///
    /// Doppelganger, liveness, exit, and payload timing share this value.
    /// A missing, zero, conflicting, out-of-range, or cross-node-disagreement
    /// spec fails [`connect_beacon`] rather than assuming 12 seconds.
    pub slot_duration_ms: u64,
    /// True only on a named network whose responding BNs matched the preset
    /// genesis. Custom stays false: those BNs also supply the slot duration,
    /// and an inflated duration can hold the clock at epoch 0.
    pub genesis_confirmed: bool,
}

/// Create the beacon client and BnManager, parse GVR once, validate against the
/// beacon node (fail-closed chain-swap gate), check reachability, and log version.
///
/// `slashing_db` is required for genesis-root persistence / comparison inside
/// [`startup::validate_genesis_root`]. Health-status updates remain the caller's
/// responsibility (see module docs on [`super`]).
///
/// Log lines and order match the former inline `run_validator` Steps 3–5.
pub async fn connect_beacon(
    config: &Config,
    timeouts: OperationTimeouts,
    slashing_db: &SlashingDb,
) -> Result<BeaconHandles, BootstrapError> {
    let builder = ServiceBuilder::new(config.clone());

    // Step 3: Create beacon client and BnManager
    let beacon_client = match builder.build_beacon() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create beacon client: {}", e);
            return Err(e.into());
        }
    };

    let bn_manager = match builder.build_bn_manager_with_timeouts(timeouts) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to create BnManager: {}", e);
            return Err(e.into());
        }
    };

    // Step 4: Validate genesis root against beacon node (single GVR parse)
    let genesis_validators_root = match builder.parse_genesis_validators_root() {
        Ok(root) => root,
        Err(e) => {
            error!("Failed to parse genesis validators root: {}", e);
            return Err(e.into());
        }
    };
    let genesis_validators_root_hex =
        GvrHex::from_root(genesis_validators_root).as_normalised_hex().to_string();

    if let Err(e) = startup::validate_genesis_root(
        slashing_db,
        bn_manager.as_ref(),
        &genesis_validators_root_hex,
    )
    .await
    {
        error!("Genesis root validation failed: {}", e);
        return Err(e.into());
    }

    let genesis_time = match config.effective_genesis_time() {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to resolve genesis time: {}", e);
            return Err(e.into());
        }
    };

    // One resolution for every later clock. Do not fall back to 12 s.
    // Responding BNs must agree. A named network skips an unreachable BN
    // and must match its preset. Custom requires every configured BN.
    let (slot_duration_ms, genesis_confirmed) =
        match builder.resolve_slot_duration_ms(bn_manager.as_ref()).await {
            Ok(resolved) => resolved,
            Err(e) => {
                error!("Failed to resolve slot duration from beacon node: {}", e);
                return Err(e.into());
            }
        };

    // Step 5: Check beacon reachability
    startup::check_beacon_reachability(bn_manager.as_ref()).await;

    // Log beacon node version (non-fatal)
    match bn_manager.get_node_version().await {
        Ok(version) => info!(bn_version = %version, "connected to beacon node"),
        Err(e) => warn!(error = %e, "failed to fetch beacon node version"),
    }

    Ok(BeaconHandles {
        beacon_client,
        bn_manager,
        genesis_validators_root,
        genesis_validators_root_hex,
        genesis_time,
        slot_duration_ms,
        genesis_confirmed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::startup::{StartupError, EXIT_GENESIS_ROOT_MISMATCH};
    use eth_types::NetworkPreset;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const MAINNET_GVR: &str = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";

    fn mainnet_config(beacon_url: &str, slashing_db: &std::path::Path) -> Config {
        Config {
            beacon_url: beacon_url.to_string(),
            beacon_nodes: vec![beacon_url.to_string()],
            slashing_db_path: slashing_db.to_path_buf(),
            allow_fresh_db: true,
            disable_keystore_locking: true,
            network: crate::config::Network::Mainnet,
            genesis_validators_root: None,
            genesis_time: None,
            ..Default::default()
        }
    }

    async fn mount_genesis(server: &MockServer, gvr: &str) {
        let genesis_time = NetworkPreset::MAINNET.genesis_time.to_string();
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": genesis_time,
                    "genesis_validators_root": gvr,
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(server)
            .await;
    }

    async fn mount_spec(server: &MockServer, data: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": data
            })))
            .mount(server)
            .await;
    }

    fn expect_err(result: Result<BeaconHandles, BootstrapError>, what: &str) -> BootstrapError {
        match result {
            Ok(_) => panic!("{what}"),
            Err(err) => err,
        }
    }

    async fn mount_spec_status(server: &MockServer, status: u16) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(status).set_body_string("unavailable"))
            .mount(server)
            .await;
    }

    async fn mount_version(server: &MockServer, status: u16) {
        let template = if status == 200 {
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "data": { "version": "mock-bn/rf5-04" } }))
        } else {
            ResponseTemplate::new(status).set_body_string("unavailable")
        };
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn test_connect_beacon_parses_gvr_once_into_bytes_and_hex() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(
            &server,
            serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let handles = connect_beacon(&config, OperationTimeouts::default(), &db)
            .await
            .expect("connect against matching mock BN");

        let expected_bytes = eth_types::canonical::gvr_hex::parse_gvr_hex(MAINNET_GVR).unwrap();
        assert_eq!(handles.genesis_validators_root, expected_bytes);
        assert_eq!(
            handles.genesis_validators_root_hex,
            GvrHex::from_root(expected_bytes).as_normalised_hex()
        );
        assert_eq!(
            handles.genesis_validators_root_hex,
            format!("0x{}", hex::encode(handles.genesis_validators_root))
        );
        assert_eq!(handles.genesis_time, NetworkPreset::MAINNET.genesis_time);
        assert_eq!(handles.slot_duration_ms, 12_000);
        // Clients constructed and usable
        let _ = handles.beacon_client;
        let _ = handles.bn_manager;
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_genesis_root_mismatch() {
        let server = MockServer::start().await;
        // Beacon advertises a different GVR than mainnet config.
        let foreign_gvr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        mount_genesis(&server, foreign_gvr).await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        match connect_beacon(&config, OperationTimeouts::default(), &db).await {
            Err(BootstrapError::Startup(StartupError::GenesisRootMismatch { local, beacon })) => {
                assert!(local.contains("4b363db9"), "local={local}");
                assert!(beacon.contains("aaaaaaaa"), "beacon={beacon}");
                assert_eq!(
                    BootstrapError::Startup(StartupError::GenesisRootMismatch {
                        local: local.clone(),
                        beacon: beacon.clone(),
                    })
                    .exit_code(),
                    EXIT_GENESIS_ROOT_MISMATCH
                );
            }
            Ok(_) => panic!("chain-swap mismatch must be fatal"),
            Err(other) => panic!("expected GenesisRootMismatch, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_connect_beacon_reports_unreachable_node() {
        // Bound-but-closed port: connection refused during genesis validation.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{addr}");

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&url, &db_path);

        match connect_beacon(&config, OperationTimeouts::default(), &db).await {
            Err(BootstrapError::Startup(StartupError::Beacon(_))) => {}
            Ok(_) => panic!("unreachable BN must fail genesis validation"),
            Err(other) => panic!("expected Startup::Beacon for unreachable node, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_connect_beacon_version_log_is_non_fatal_on_error() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(
            &server,
            serde_json::json!({ "SECONDS_PER_SLOT": "12", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        // Version endpoint fails; connect_beacon must still succeed.
        mount_version(&server, 500).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let handles = connect_beacon(&config, OperationTimeouts::default(), &db)
            .await
            .expect("version failure must be non-fatal");
        assert_eq!(handles.genesis_validators_root_hex, MAINNET_GVR.to_lowercase());
        assert_eq!(handles.slot_duration_ms, 12_000);
        assert!(handles.genesis_confirmed);
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_six_second_duration_on_named_network() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(
            &server,
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "named network must match the preset duration",
        );
        assert!(err.to_string().contains("preset"), "{err}");
    }

    #[tokio::test]
    async fn test_connect_beacon_custom_network_accepts_six_second_duration() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(
            &server,
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let mut config = mainnet_config(&server.uri(), &db_path);
        config.network = crate::config::Network::Custom;
        config.genesis_validators_root = Some(MAINNET_GVR.to_string());
        config.genesis_time = Some(NetworkPreset::MAINNET.genesis_time);

        let handles = connect_beacon(&config, OperationTimeouts::default(), &db)
            .await
            .expect("custom network accepts a bounded 6 s duration");
        assert_eq!(handles.slot_duration_ms, 6_000);
        assert!(
            !handles.genesis_confirmed,
            "custom duration is not an independent genesis confirmation"
        );
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_huge_slot_duration() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(
            &server,
            serde_json::json!({ "SLOT_DURATION_MS": "86400000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "huge duration must fail closed",
        );
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_disagreeing_slot_duration() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        mount_genesis(&first, MAINNET_GVR).await;
        mount_genesis(&second, MAINNET_GVR).await;
        mount_spec(
            &first,
            serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_spec(
            &second,
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&first, 200).await;
        mount_version(&second, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let mut config = mainnet_config(&first.uri(), &db_path);
        config.beacon_nodes = vec![first.uri(), second.uri()];

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "disagreeing durations must fail closed",
        );
        assert!(err.to_string().contains("disagree"), "{err}");
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_slots_per_epoch_other_than_preset() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(
            &server,
            serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "16" }),
        )
        .await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);
        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "SLOTS_PER_EPOCH must match the preset",
        );
        assert!(err.to_string().contains("SLOTS_PER_EPOCH"), "{err}");
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_disagreeing_genesis_time() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        mount_genesis(&first, MAINNET_GVR).await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": "1",
                    "genesis_validators_root": MAINNET_GVR,
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(&second)
            .await;
        let spec = serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "32" });
        mount_spec(&first, spec.clone()).await;
        mount_spec(&second, spec).await;
        mount_version(&first, 200).await;
        mount_version(&second, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let mut config = mainnet_config(&first.uri(), &db_path);
        config.beacon_nodes = vec![first.uri(), second.uri()];
        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "genesis times must agree",
        );
        assert!(err.to_string().contains("genesis_time"), "{err}");
    }

    /// Responders agree with each other, but not with the configured genesis.
    #[tokio::test]
    async fn test_connect_beacon_rejects_genesis_time_that_is_not_configured() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": "1",
                    "genesis_validators_root": MAINNET_GVR,
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(&server)
            .await;
        mount_spec(
            &server,
            serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);
        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "BN genesis must match the configured genesis",
        );
        assert!(err.to_string().contains("configured"), "{err}");
    }

    #[tokio::test]
    async fn test_connect_beacon_named_network_skips_unreachable_bn() {
        let live = MockServer::start().await;
        mount_genesis(&live, MAINNET_GVR).await;
        mount_spec(
            &live,
            serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&live, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let mut config = mainnet_config(&live.uri(), &db_path);
        config.beacon_nodes = vec!["http://127.0.0.1:1".to_string(), live.uri()];

        let handles = connect_beacon(&config, OperationTimeouts::default(), &db)
            .await
            .expect("one unreachable BN must not block a named network");
        assert_eq!(handles.slot_duration_ms, 12_000);
        assert!(handles.genesis_confirmed);
    }

    #[tokio::test]
    async fn test_connect_beacon_custom_requires_every_bn() {
        let live = MockServer::start().await;
        mount_genesis(&live, MAINNET_GVR).await;
        mount_spec(
            &live,
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
        )
        .await;
        mount_version(&live, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let mut config = mainnet_config(&live.uri(), &db_path);
        config.network = crate::config::Network::Custom;
        config.genesis_validators_root = Some(MAINNET_GVR.to_string());
        config.genesis_time = Some(NetworkPreset::MAINNET.genesis_time);
        config.beacon_nodes = vec!["http://127.0.0.1:1".to_string(), live.uri()];

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "custom must fail when a configured BN does not respond",
        );
        assert!(err.to_string().contains("HTTP request failed"), "{err}");
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_spec_without_slot_duration() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(&server, serde_json::json!({ "SLOTS_PER_EPOCH": "32" })).await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "missing duration must fail closed",
        );
        let msg = err.to_string();
        assert!(msg.contains("SLOT_DURATION_MS") || msg.contains("SECONDS_PER_SLOT"), "{msg}");
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_conflicting_slot_duration() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(
            &server,
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SECONDS_PER_SLOT": "12" }),
        )
        .await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "conflicting keys must fail closed",
        );
        assert!(err.to_string().contains("conflicting"), "{err}");
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_zero_slot_duration() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec(&server, serde_json::json!({ "SLOT_DURATION_MS": "0" })).await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "zero duration must fail closed",
        );
        let msg = err.to_string();
        assert!(msg.contains("greater than zero"), "{msg}");
    }

    #[tokio::test]
    async fn test_connect_beacon_rejects_spec_http_error() {
        let server = MockServer::start().await;
        mount_genesis(&server, MAINNET_GVR).await;
        mount_spec_status(&server, 404).await;
        mount_version(&server, 200).await;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let config = mainnet_config(&server.uri(), &db_path);

        let err = expect_err(
            connect_beacon(&config, OperationTimeouts::default(), &db).await,
            "spec 404 must fail closed",
        );
        assert!(!err.to_string().is_empty());
    }
}
