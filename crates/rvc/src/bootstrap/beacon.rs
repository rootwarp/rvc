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
    }
}
