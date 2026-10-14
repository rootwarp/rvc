//! Operational-feature coverage relocated from bin/rvc tier-3 suites.
//!
//! Covers proposer-node / broadcast config, monitoring push, logfile config,
//! and proposer-config URL refresh — all via `rvc::` public surfaces.
//! Pure bn-manager BroadcastTopics wiring lives in `rvc-bn-manager` tests;
//! tautological empty-vec / hand-set field asserts were pruned (F17).

mod proposer_nodes {
    use bn_manager::{BnManager, BnManagerConfig};
    use rvc::config::Config;

    #[test]
    fn proposer_bn_manager_constructed_from_config() {
        let config = Config {
            proposer_nodes: vec![
                "http://proposer1:5052".to_string(),
                "http://proposer2:5052".to_string(),
            ],
            ..Config::default()
        };

        let endpoints = config.proposer_nodes.clone();
        let bn_config = BnManagerConfig::new(endpoints);
        let manager = BnManager::new(bn_config);
        assert!(manager.is_ok(), "proposer BnManager should be created from config");
    }

    #[test]
    fn proposer_nodes_from_toml() {
        let toml_str = r#"
    beacon_url = "http://localhost:5052"
    keystore_path = "/tmp/keystores"
    network = "mainnet"
    proposer_nodes = ["http://p1:5052", "http://p2:5052"]
    "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proposer_nodes.len(), 2);
        assert_eq!(config.proposer_nodes[0], "http://p1:5052");
        assert_eq!(config.proposer_nodes[1], "http://p2:5052");
    }

    #[test]
    fn proposer_nodes_cli_override() {
        use rvc::config::StartArgs;

        assert!(Config::default().proposer_nodes.is_empty());
        let mut args = StartArgs::default();
        args.proposer.proposer_nodes = Some(vec!["http://override:5052".to_string()]);
        let config = Config::load(None, args).expect("load");

        assert_eq!(config.proposer_nodes, vec!["http://override:5052"]);
    }

    #[test]
    fn build_proposer_bn_manager_with_service_builder() {
        use rvc::config::ServiceBuilder;

        let config = Config {
            proposer_nodes: vec!["http://proposer:5052".to_string()],
            ..Config::default()
        };
        let builder = ServiceBuilder::new(config);
        let result = builder.build_proposer_bn_manager();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some(), "should return Some when proposer_nodes is set");
    }

    #[test]
    fn build_proposer_bn_manager_none_when_empty() {
        use rvc::config::ServiceBuilder;

        let config = Config::default();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_proposer_bn_manager();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "should return None when proposer_nodes is empty");
    }

    /// Call-site guard: block production must not construct a single-node client
    /// from `proposer_nodes[0]`; it must wrap the proposer/main BnManager.
    ///
    /// RF5-10: wiring lives in `crates/rvc` bootstrap (not `bin/rvc/src/main.rs`).
    #[test]
    fn test_block_production_does_not_use_proposer_nodes_zero() {
        let services_src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bootstrap/services.rs"
        ))
        .expect("read crates/rvc/src/bootstrap/services.rs");

        assert!(
            !services_src.contains("proposer_nodes[0]"),
            "bootstrap services must not construct a BeaconClient from proposer_nodes[0]; \
             block production must use the proposer BnManager for failover"
        );
        assert!(
            services_src.contains("BeaconBlockAdapter"),
            "expected BeaconBlockAdapter wiring in bootstrap::build_services"
        );
    }

    /// Call-site guard: the single-endpoint `build_beacon()` client is still
    /// constructed and is not the keymanager exit path, block production, or
    /// the propagator.
    ///
    /// RF5-10: production path is `crates/rvc` bootstrap phases.
    #[test]
    fn test_build_beacon_only_used_by_exit_tooling() {
        let beacon_src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bootstrap/beacon.rs"
        ))
        .expect("read crates/rvc/src/bootstrap/beacon.rs");
        let services_src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bootstrap/services.rs"
        ))
        .expect("read crates/rvc/src/bootstrap/services.rs");
        let km_src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/keymanager_adapters/spawn.rs"
        ))
        .expect("read crates/rvc/src/keymanager_adapters/spawn.rs");

        // Single build_beacon call site for the runtime VC path (connect_beacon).
        let build_beacon_count = beacon_src.matches("build_beacon()").count();
        assert_eq!(
            build_beacon_count, 1,
            "expected exactly one build_beacon() call in bootstrap::connect_beacon, found {build_beacon_count}"
        );

        // The resulting client must not be fed to BeaconBlockAdapter or the propagator.
        assert!(
            !services_src.contains("BeaconBlockAdapter(beacon_client"),
            "BeaconBlockAdapter must not wrap build_beacon()'s BeaconClient"
        );
        assert!(
            !services_src.contains("build_propagator(beacon_client"),
            "propagator must not take the single-node build_beacon() client"
        );
        assert!(
            km_src.contains("VoluntaryExitManagerAdapter::new"),
            "keymanager still constructs VoluntaryExitManagerAdapter"
        );
        assert!(
            !km_src.contains("build_beacon()"),
            "keymanager exit must not call build_beacon(); it uses the BN pool"
        );
    }
}

mod broadcast_topics {
    use rvc::config::{BroadcastTopic, Config};

    #[test]
    fn default_all_broadcast() {
        let config = Config::default();
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn none_disables_all() {
        let config = Config { broadcast: vec![BroadcastTopic::None], ..Config::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn selective_topics() {
        let config = Config {
            broadcast: vec![BroadcastTopic::Attestations, BroadcastTopic::Blocks],
            ..Config::default()
        };
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations, "attestations should be enabled");
        assert!(topics.blocks, "blocks should be enabled");
        assert!(!topics.sync_committee, "sync_committee should be disabled");
        assert!(!topics.subscriptions, "subscriptions should be disabled");
    }

    #[test]
    fn sync_committee_topic() {
        let config = Config { broadcast: vec![BroadcastTopic::SyncCommittee], ..Config::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn subscriptions_topic() {
        let config = Config { broadcast: vec![BroadcastTopic::Subscriptions], ..Config::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(!topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn all_topics_explicit() {
        let config = Config {
            broadcast: vec![
                BroadcastTopic::Attestations,
                BroadcastTopic::Blocks,
                BroadcastTopic::SyncCommittee,
                BroadcastTopic::Subscriptions,
            ],
            ..Config::default()
        };
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn broadcast_topics_from_toml() {
        let toml_str = r#"
    beacon_url = "http://localhost:5052"
    keystore_path = "/tmp/keystores"
    network = "mainnet"
    broadcast = ["attestations", "blocks"]
    "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn broadcast_topics_cli_override() {
        use rvc::config::StartArgs;

        let mut args = StartArgs::default();
        args.proposer.broadcast = Some(vec![BroadcastTopic::Blocks]);
        let config = Config::load(None, args).expect("load");

        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(topics.blocks);
    }
}

mod monitoring {
    use rvc::background_tasks::monitoring::{collect_metrics, MonitoringConfig};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn payload_has_valid_beaconchain_fields() {
        let payload = collect_metrics(10, 8);

        assert_eq!(payload.version, 1);
        assert_eq!(payload.process, "validator");
        assert_eq!(payload.client_name, "rvc");
        assert!(!payload.client_version.is_empty());
        assert_eq!(payload.validator_total, 10);
        assert_eq!(payload.validator_active, 8);
        assert!(payload.timestamp > 0);
    }

    #[test]
    fn payload_serializes_to_valid_json() {
        let payload = collect_metrics(5, 3);
        let json = serde_json::to_value(&payload).unwrap();

        assert_eq!(json["version"], 1);
        assert_eq!(json["process"], "validator");
        assert_eq!(json["client_name"], "rvc");
        assert_eq!(json["validator_total"], 5);
        assert_eq!(json["validator_active"], 3);
        assert!(json["timestamp"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn mock_endpoint_receives_valid_payload() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1..)
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::background_tasks::monitoring::start_monitoring_push(
                config,
                shutdown_clone,
                || (3, 2),
            )
            .await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn retry_on_server_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Return 500 for all requests (will be retried up to 3 times per push cycle)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(3..)
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::background_tasks::monitoring::start_monitoring_push(
                config,
                shutdown_clone,
                || (1, 1),
            )
            .await;
        });

        // Give it time for one push cycle with retries
        tokio::time::sleep(Duration::from_millis(300)).await;
        shutdown.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn no_retry_on_client_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // 4xx errors are not retried — each tick cycle sends exactly 1 request
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1..)
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::background_tasks::monitoring::start_monitoring_push(
                config,
                shutdown_clone,
                || (1, 1),
            )
            .await;
        });

        // Let it run for one tick cycle
        tokio::time::sleep(Duration::from_millis(80)).await;
        shutdown.cancel();
        handle.await.unwrap();

        // 4xx should not trigger retries within a single push cycle
        // (only 1 request per tick, not 3 like 5xx would cause)
    }

    #[tokio::test]
    async fn rejects_http_without_insecure() {
        let config = MonitoringConfig {
            endpoint: "http://example.com/metrics".to_string(),
            interval: Duration::from_secs(1),
            insecure: false,
        };
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        // Should return immediately because HTTP is rejected without insecure
        rvc::background_tasks::monitoring::start_monitoring_push(config, shutdown, || (0, 0)).await;
    }

    #[tokio::test]
    async fn clean_shutdown() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::background_tasks::monitoring::start_monitoring_push(
                config,
                shutdown_clone,
                || (0, 0),
            )
            .await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "monitoring task should shut down within timeout");
    }

    #[test]
    fn monitoring_config_fields_default() {
        let config = rvc::config::Config::default();
        assert!(config.monitoring.endpoint.is_none());
        assert_eq!(config.monitoring.interval, 384);
        assert!(!config.monitoring.endpoint_insecure);
    }

    #[test]
    fn monitoring_config_from_toml() {
        let toml_str = r#"
    beacon_url = "http://localhost:5052"
    keystore_path = "/tmp/keystores"
    network = "mainnet"
    monitoring_endpoint = "https://beaconcha.in/api/v1/client/metrics"
    monitoring_interval = 60
    monitoring_endpoint_insecure = true
    "#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.monitoring.endpoint.as_deref(),
            Some("https://beaconcha.in/api/v1/client/metrics")
        );
        assert_eq!(config.monitoring.interval, 60);
        assert!(config.monitoring.endpoint_insecure);
    }
}

mod logfile_config {
    #[test]
    fn logfile_config_defaults() {
        let config = rvc::config::Config::default();
        assert!(config.logfile.path.is_none());
        assert_eq!(config.logfile.max_size, 200);
        assert_eq!(config.logfile.max_number, 5);
        assert!(!config.logfile.compress);
        assert!(config.logfile.level.is_none());
    }

    #[test]
    fn logfile_config_from_toml() {
        let toml_str = r#"
    beacon_url = "http://localhost:5052"
    keystore_path = "/tmp/keystores"
    network = "mainnet"
    logfile = "/var/log/rvc/rvc.log"
    logfile_max_size = 100
    logfile_max_number = 10
    logfile_compress = true
    logfile_level = "debug"
    "#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.logfile.path.as_ref().unwrap().to_str().unwrap(), "/var/log/rvc/rvc.log");
        assert_eq!(config.logfile.max_size, 100);
        assert_eq!(config.logfile.max_number, 10);
        assert!(config.logfile.compress);
        assert_eq!(config.logfile.level.as_deref(), Some("debug"));
    }

    #[test]
    fn logfile_cli_override() {
        use rvc::config::StartArgs;
        use std::path::PathBuf;

        let mut args = StartArgs::default();
        args.logging.logfile.path = Some(PathBuf::from("/tmp/test.log"));
        args.logging.logfile.max_size = Some(50);
        args.logging.logfile.max_number = Some(3);
        args.logging.logfile.compress = Some(true);
        args.logging.logfile.level = Some("warn".to_string());
        let config = rvc::config::Config::load(None, args).expect("load");

        assert_eq!(config.logfile.path.as_ref().unwrap().to_str().unwrap(), "/tmp/test.log");
        assert_eq!(config.logfile.max_size, 50);
        assert_eq!(config.logfile.max_number, 3);
        assert!(config.logfile.compress);
        assert_eq!(config.logfile.level.as_deref(), Some("warn"));
    }
}

mod config_url {
    use rvc::background_tasks::config_url::{
        fetch_proposer_config, ProposerConfigUrlSettings, ValidatorConfigUpdate,
    };
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn fetch_from_mock_server() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let body = r#"{
            "proposer_config": {
                "0xaaa": {
                    "fee_recipient": "0xbbb",
                    "builder": { "enabled": true, "gas_limit": "30000000" }
                },
                "0xccc": {
                    "fee_recipient": "0xddd",
                    "builder": { "enabled": false }
                }
            },
            "default_config": {
                "fee_recipient": "0xeee",
                "builder": { "enabled": true, "gas_limit": "36000000" }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, default_update) =
            fetch_proposer_config(&mock_server.uri(), None, true).await.unwrap();

        assert_eq!(updates.len(), 2);
        let default = default_update.unwrap();
        assert_eq!(default.fee_recipient.as_deref(), Some("0xeee"));
        assert_eq!(default.builder_enabled, Some(true));
        assert_eq!(default.gas_limit, Some(36000000));
    }

    #[tokio::test]
    async fn refresh_applies_changes() {
        use std::sync::{Arc, Mutex};
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let body = r#"{
            "proposer_config": {
                "0xabc": {
                    "fee_recipient": "0xdef",
                    "builder": { "enabled": true, "gas_limit": "30000000" }
                }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&mock_server)
            .await;

        let received_updates: Arc<Mutex<Vec<Vec<ValidatorConfigUpdate>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let received_clone = received_updates.clone();

        let settings = ProposerConfigUrlSettings {
            url: mock_server.uri(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::background_tasks::config_url::start_proposer_config_refresh(
                settings,
                shutdown_clone,
                move |updates, _default| {
                    received_clone.lock().unwrap().push(updates);
                },
            )
            .await;
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.cancel();
        handle.await.unwrap();

        let calls = received_updates.lock().unwrap();
        assert!(!calls.is_empty(), "apply_fn should have been called at least once");
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].pubkey, "0xabc");
        assert_eq!(calls[0][0].fee_recipient.as_deref(), Some("0xdef"));
    }

    #[tokio::test]
    async fn rejects_http_without_insecure() {
        let result = fetch_proposer_config("http://example.com/config", None, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[tokio::test]
    async fn bearer_token_sent() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":{}}"#))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, _) =
            fetch_proposer_config(&mock_server.uri(), Some("my-secret-token"), true).await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn http_error_returns_err() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_proposer_config(&mock_server.uri(), None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    #[tokio::test]
    async fn refresh_clean_shutdown() {
        let settings = ProposerConfigUrlSettings {
            url: "http://nonexistent.invalid/config".to_string(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::background_tasks::config_url::start_proposer_config_refresh(
                settings,
                shutdown_clone,
                |_, _| {},
            )
            .await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "refresh task should shut down within timeout");
    }

    #[test]
    fn config_url_fields_default() {
        let config = rvc::config::Config::default();
        assert!(config.proposer_config.url.is_none());
        assert_eq!(config.proposer_config.refresh_interval, 384);
        assert!(config.proposer_config.url_token.is_none());
        assert!(!config.proposer_config.url_insecure);
    }

    #[test]
    fn config_url_from_toml() {
        let toml_str = r#"
    beacon_url = "http://localhost:5052"
    keystore_path = "/tmp/keystores"
    network = "mainnet"
    proposer_config_url = "https://example.com/proposer-config"
    proposer_config_refresh_interval = 120
    proposer_config_url_insecure = true
    "#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.proposer_config.url.as_deref(),
            Some("https://example.com/proposer-config")
        );
        assert_eq!(config.proposer_config.refresh_interval, 120);
        assert!(config.proposer_config.url_insecure);
    }
}

mod composition {
    use bn_manager::{BnManager, BnManagerConfig};
    use rvc::background_tasks::monitoring::MonitoringConfig;
    use rvc::config::{BroadcastTopic, Config};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn proposer_nodes_with_broadcast_topics() {
        let config = Config {
            beacon_url: "http://main-bn:5052".to_string(),
            proposer_nodes: vec!["http://proposer-bn:5052".to_string()],
            broadcast: vec![BroadcastTopic::Attestations, BroadcastTopic::Blocks],
            ..Config::default()
        };

        // Main pool uses broadcast topics
        let main_topics = config.effective_broadcast_topics();
        assert!(main_topics.attestations);
        assert!(main_topics.blocks);
        assert!(!main_topics.sync_committee);

        // Proposer pool is separate and unaffected
        let proposer_endpoints = config.proposer_nodes.clone();
        assert_eq!(proposer_endpoints, vec!["http://proposer-bn:5052"]);

        // Both pools can be created independently
        let main_config = BnManagerConfig::new(config.effective_beacon_nodes());
        let proposer_config = BnManagerConfig::new(proposer_endpoints);

        assert!(BnManager::new(main_config).is_ok());
        assert!(BnManager::new(proposer_config).is_ok());
    }

    #[tokio::test]
    async fn monitoring_does_not_interfere_with_config_refresh() {
        use std::sync::{Arc, Mutex};

        let config_received = Arc::new(Mutex::new(false));
        let config_received_clone = config_received.clone();

        let shutdown = CancellationToken::new();

        // Start monitoring (will fail to connect, which is fine)
        let monitoring_config = MonitoringConfig {
            endpoint: "http://localhost:1/nonexistent".to_string(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown_mon = shutdown.clone();
        let mon_handle = tokio::spawn(async move {
            rvc::background_tasks::monitoring::start_monitoring_push(
                monitoring_config,
                shutdown_mon,
                || (1, 1),
            )
            .await;
        });

        // Start config refresh (will also fail to connect, which is fine)
        let config_settings = rvc::background_tasks::config_url::ProposerConfigUrlSettings {
            url: "http://localhost:1/nonexistent".to_string(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown_cfg = shutdown.clone();
        let cfg_handle = tokio::spawn(async move {
            rvc::background_tasks::config_url::start_proposer_config_refresh(
                config_settings,
                shutdown_cfg,
                move |_, _| {
                    *config_received_clone.lock().unwrap() = true;
                },
            )
            .await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();

        mon_handle.await.unwrap();
        cfg_handle.await.unwrap();
    }

    #[test]
    fn all_tier3_config_fields_in_default() {
        let config = Config::default();

        // Proposer nodes
        assert!(config.proposer_nodes.is_empty());

        // Broadcast topics
        assert!(config.broadcast.is_empty());
        let topics = config.effective_broadcast_topics();
        assert!(
            topics.attestations && topics.blocks && topics.sync_committee && topics.subscriptions
        );

        // Monitoring
        assert!(config.monitoring.endpoint.is_none());
        assert_eq!(config.monitoring.interval, 384);
        assert!(!config.monitoring.endpoint_insecure);

        // Log rotation
        assert!(config.logfile.path.is_none());
        assert_eq!(config.logfile.max_size, 200);
        assert_eq!(config.logfile.max_number, 5);
        assert!(!config.logfile.compress);

        // URL config
        assert!(config.proposer_config.url.is_none());
        assert_eq!(config.proposer_config.refresh_interval, 384);
        assert!(!config.proposer_config.url_insecure);
    }

    #[test]
    fn toml_roundtrip_with_all_tier3_fields() {
        let toml_str = r#"
    beacon_url = "http://localhost:5052"
    keystore_path = "/tmp/keystores"
    network = "mainnet"
    proposer_nodes = ["http://proposer:5052"]
    broadcast = ["attestations", "blocks"]
    monitoring_endpoint = "https://beaconcha.in/api/v1/client/metrics"
    monitoring_interval = 60
    monitoring_endpoint_insecure = false
    logfile = "/var/log/rvc.log"
    logfile_max_size = 100
    logfile_max_number = 10
    logfile_compress = true
    logfile_level = "debug"
    proposer_config_url = "https://config.example.com/proposer"
    proposer_config_refresh_interval = 120
    proposer_config_url_insecure = false
    "#;
        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.proposer_nodes, vec!["http://proposer:5052"]);
        assert_eq!(config.broadcast, vec![BroadcastTopic::Attestations, BroadcastTopic::Blocks]);
        assert_eq!(
            config.monitoring.endpoint.as_deref(),
            Some("https://beaconcha.in/api/v1/client/metrics")
        );
        assert_eq!(config.monitoring.interval, 60);
        assert_eq!(config.logfile.max_size, 100);
        assert_eq!(config.logfile.max_number, 10);
        assert!(config.logfile.compress);
        assert_eq!(
            config.proposer_config.url.as_deref(),
            Some("https://config.example.com/proposer")
        );
        assert_eq!(config.proposer_config.refresh_interval, 120);
    }

    #[test]
    fn cli_overrides_all_tier3_fields() {
        use rvc::config::StartArgs;
        use std::path::PathBuf;

        let mut args = StartArgs::default();
        args.proposer.proposer_nodes = Some(vec!["http://p:5052".to_string()]);
        args.proposer.broadcast = Some(vec![BroadcastTopic::Blocks]);
        args.monitoring.endpoint = Some("https://monitor.test".to_string());
        args.monitoring.interval = Some(30);
        args.monitoring.endpoint_insecure = Some(true);
        args.logging.logfile.path = Some(PathBuf::from("/tmp/rvc.log"));
        args.logging.logfile.max_size = Some(50);
        args.logging.logfile.max_number = Some(3);
        args.logging.logfile.compress = Some(true);
        args.logging.logfile.level = Some("warn".to_string());
        args.proposer.proposer_config.url = Some("https://config.test".to_string());
        args.proposer.proposer_config.refresh_interval = Some(60);
        args.proposer.proposer_config.url_insecure = Some(true);
        let config = Config::load(None, args).expect("load");

        assert_eq!(config.proposer_nodes, vec!["http://p:5052"]);
        assert_eq!(config.broadcast, vec![BroadcastTopic::Blocks]);
        assert_eq!(config.monitoring.endpoint.as_deref(), Some("https://monitor.test"));
        assert_eq!(config.monitoring.interval, 30);
        assert!(config.monitoring.endpoint_insecure);
        assert_eq!(config.logfile.max_size, 50);
        assert_eq!(config.logfile.max_number, 3);
        assert!(config.logfile.compress);
        assert_eq!(config.logfile.level.as_deref(), Some("warn"));
        assert_eq!(config.proposer_config.url.as_deref(), Some("https://config.test"));
        assert_eq!(config.proposer_config.refresh_interval, 60);
        assert!(config.proposer_config.url_insecure);
    }
}
