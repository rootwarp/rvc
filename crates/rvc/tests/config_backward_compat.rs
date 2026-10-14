//! RF5-12: production-config fixture + nested/flat alias parity.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use tempfile::NamedTempFile;

use rvc::config::{
    BroadcastTopic, BuilderLimits, Config, ConfigError, GrpcSignerConfig, KeymanagerConfig,
    LogfileConfig, MonitoringConfig, Network, ProposerConfigSource, SlashedAction, StartArgs,
    TracingConfig, TracingExporter,
};

fn production_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rvc-v0.6.toml")
}

fn expected_production_config() -> Config {
    Config {
        beacon_url: "http://bn.example:5052".to_string(),
        beacon_nodes: vec![
            "http://bn1.example:5052".to_string(),
            "http://bn2.example:5052".to_string(),
        ],
        keystore_path: PathBuf::from("/var/lib/rvc/keystores"),
        password_file: Some(PathBuf::from("/var/lib/rvc/passwords.txt")),
        slashing_db_path: PathBuf::from("/var/lib/rvc/slashing_protection.sqlite"),
        allow_fresh_db: false,
        metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        metrics_port: 8080,
        network: Network::Mainnet,
        graffiti: Some("rvc-prod".to_string()),
        log_level: "info".to_string(),
        doppelganger_detection: true,
        keymanager: KeymanagerConfig {
            enabled: true,
            address: Some("127.0.0.1:5062".to_string()),
            token_file: Some(PathBuf::from("/var/lib/rvc/keymanager-api-token.txt")),
            remote_signer_url: Some("https://web3signer:9000".to_string()),
            remote_signer_allowed_hosts: Some(vec!["web3signer.example".to_string()]),
            allow_insecure_remote_signer: false,
            cors_origins: vec!["https://ops.example".to_string()],
            body_limit: 10485760,
            ..Default::default()
        },
        tracing: TracingConfig {
            endpoint: Some("http://otel-collector:4318".to_string()),
            exporter: TracingExporter::Otlp,
            sample_rate: Some(0.05),
            max_queue_size: Some(4096),
            max_export_batch_size: Some(1024),
            service_name: None,
        },
        grpc_signer: GrpcSignerConfig {
            url: Some("https://signer:50051".to_string()),
            tls_cert: Some(PathBuf::from("/etc/rvc/signer-client.crt")),
            tls_key: Some(PathBuf::from("/etc/rvc/signer-client.key")),
            tls_ca_cert: Some(PathBuf::from("/etc/rvc/signer-ca.crt")),
        },
        builder_limits: BuilderLimits {
            circuit_breaker_consecutive_limit: 7,
            circuit_breaker_epoch_limit: 12,
        },
        monitoring: MonitoringConfig {
            endpoint: Some("https://monitor.example/api/v1/client/metrics".to_string()),
            interval: 192,
            endpoint_insecure: false,
        },
        proposer_config: ProposerConfigSource {
            url: Some("https://config.example/proposer.json".to_string()),
            file: None,
            refresh_interval: 96,
            url_token: Some("prod-token".to_string()),
            url_insecure: false,
        },
        logfile: LogfileConfig {
            path: Some(PathBuf::from("/var/log/rvc/rvc.log")),
            max_size: 100,
            max_number: 10,
            compress: true,
            level: Some("debug".to_string()),
        },
        disable_attesting: false,
        slashed_validators_action: SlashedAction::DisableOnly,
        broadcast: vec![BroadcastTopic::Attestations, BroadcastTopic::Blocks],
        proposer_nodes: vec!["http://proposer.example:5052".to_string()],
        block_selection_mode: validator_store::BlockSelectionMode::MaxProfit,
        validator_registration_batch_size: 500,
        validator_registration_batch_delay: 500,
        ..Config::default()
    }
}

/// Assert nested groups match between two configs for moved fields.
fn assert_moved_fields_eq(a: &Config, b: &Config) {
    assert_eq!(a.keymanager, b.keymanager);
    assert_eq!(a.tracing.endpoint, b.tracing.endpoint);
    assert_eq!(a.tracing.exporter, b.tracing.exporter);
    assert_eq!(a.tracing.sample_rate, b.tracing.sample_rate);
    assert_eq!(a.tracing.max_queue_size, b.tracing.max_queue_size);
    assert_eq!(a.tracing.max_export_batch_size, b.tracing.max_export_batch_size);
    assert_eq!(a.grpc_signer, b.grpc_signer);
    assert_eq!(a.builder_limits, b.builder_limits);
    assert_eq!(a.monitoring, b.monitoring);
    assert_eq!(a.proposer_config, b.proposer_config);
    assert_eq!(a.logfile, b.logfile);
}

#[test]
fn test_production_config_fixture_loads_with_flat_keys() {
    let path = production_fixture_path();
    let loaded = Config::from_file(&path).expect("fixture must load");
    let expected = expected_production_config();

    assert_eq!(loaded.beacon_url, expected.beacon_url);
    assert_eq!(loaded.beacon_nodes, expected.beacon_nodes);
    assert_eq!(loaded.network, expected.network);
    assert_eq!(loaded.graffiti, expected.graffiti);
    assert_moved_fields_eq(&loaded, &expected);

    assert!(loaded.keymanager.enabled);
    assert_eq!(loaded.tracing.sample_rate, Some(0.05));
    assert_eq!(loaded.logfile.max_size, 100);
    assert_eq!(
        loaded.logfile.path.as_ref().map(|p| p.to_str().unwrap()),
        Some("/var/log/rvc/rvc.log")
    );
}

#[test]
fn test_nested_keys_and_flat_aliases_produce_identical_config() {
    let flat = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
network = "mainnet"

keymanager_enabled = true
keymanager_address = "0.0.0.0:5062"
tracing_endpoint = "http://localhost:4318"
tracing_exporter = "gcp"
tracing_sample_rate = 0.2
grpc_signer_url = "https://signer:50051"
builder_circuit_breaker_consecutive_limit = 9
builder_circuit_breaker_epoch_limit = 11
monitoring_endpoint = "https://mon.example/metrics"
monitoring_interval = 64
proposer_config_url = "https://cfg.example/p.json"
proposer_config_refresh_interval = 48
logfile = "/tmp/rvc.log"
logfile_max_size = 50
logfile_max_number = 3
logfile_compress = true
logfile_level = "warn"
"#;

    let nested = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
network = "mainnet"

[keymanager]
enabled = true
address = "0.0.0.0:5062"

[tracing]
endpoint = "http://localhost:4318"
exporter = "gcp"
sample_rate = 0.2

[grpc_signer]
url = "https://signer:50051"

[builder_limits]
circuit_breaker_consecutive_limit = 9
circuit_breaker_epoch_limit = 11

[monitoring]
endpoint = "https://mon.example/metrics"
interval = 64

[proposer_config]
url = "https://cfg.example/p.json"
refresh_interval = 48

[logfile]
path = "/tmp/rvc.log"
max_size = 50
max_number = 3
compress = true
level = "warn"
"#;

    let from_flat: Config = toml::from_str(flat).expect("flat keys");
    let from_nested: Config = toml::from_str(nested).expect("nested keys");
    assert_moved_fields_eq(&from_flat, &from_nested);
}

#[test]
fn test_default_config_field_values_unchanged() {
    let c = Config::default();
    assert_eq!(c.beacon_url, "http://localhost:5052");
    assert_eq!(c.metrics_port, 8080);
    assert_eq!(c.network, Network::Mainnet);
    assert!(c.doppelganger_detection);
    assert!(!c.keymanager.enabled);
    // RF5-15: unset sample_rate is None; resolved default remains 0.01.
    assert!(c.tracing.sample_rate.is_none());
    assert!((c.tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
    assert_eq!(c.logfile.max_size, 200);
    assert_eq!(c.logfile.max_number, 5);
    assert_eq!(c.monitoring.interval, 384);
    assert_eq!(c.proposer_config.refresh_interval, 384);
    assert_eq!(c.builder_limits.circuit_breaker_consecutive_limit, 3);
    assert_eq!(c.builder_limits.circuit_breaker_epoch_limit, 5);
    assert_eq!(c.keymanager.body_limit, 10 * 1024 * 1024);
    assert!(c.logfile.path.is_none());
    assert!(c.grpc_signer.url.is_none());
}

#[test]
fn test_unknown_key_behavior_unchanged() {
    // Serde default for toml: unknown keys are ignored (not deny_unknown_fields).
    let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
network = "mainnet"
this_key_has_never_existed = "still-ok"
"#;
    let config: Config = toml::from_str(toml).expect("unknown keys must still be ignored");
    assert_eq!(config.beacon_url, "http://localhost:5052");
}

const REMOVED_GRPC_TOML: &str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
network = "mainnet"
grpc_port = 50051
"#;

fn write_toml(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temp config");
    file.write_all(contents.as_bytes()).expect("write config");
    file
}

fn assert_removed_grpc_key(err: ConfigError, key: &str) {
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::RemovedKey { key: k, .. } if k == key),
        "expected RemovedKey({key}), got {err:?}"
    );
    assert!(msg.contains(key), "{msg}");
    assert!(msg.contains("/health"), "{msg}");
    assert!(msg.contains("/readyz"), "{msg}");
}

#[test]
fn test_removed_grpc_keys_are_rejected_at_startup() {
    let file = write_toml(REMOVED_GRPC_TOML);
    let err = Config::from_file(file.path()).expect_err("grpc_port must fail startup");
    assert_removed_grpc_key(err, "grpc_port");

    let err = Config::load(Some(file.path()), StartArgs::default())
        .expect_err("Config::load must not wrap RemovedKey away");
    assert_removed_grpc_key(err, "grpc_port");

    let file = write_toml(
        r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
network = "mainnet"
grpc_address = "127.0.0.1"
"#,
    );
    let err = Config::from_file(file.path()).expect_err("grpc_address must fail startup");
    assert_removed_grpc_key(err, "grpc_address");

    let file = write_toml(
        r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
network = "mainnet"

[server]
grpc_port = 50051
"#,
    );
    let err = Config::from_file(file.path()).expect_err("nested [server] grpc_port must fail");
    assert_removed_grpc_key(err, "grpc_port");
}

#[test]
fn test_config_without_grpc_keys_starts_clean() {
    let file = write_toml(
        r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
network = "mainnet"
metrics_port = 8080
"#,
    );
    let loaded = Config::from_file(file.path()).expect("config without grpc keys must load");
    loaded.validate().expect("config without grpc keys must validate");
    Config::load(Some(file.path()), StartArgs::default())
        .expect("Config::load without grpc keys must succeed")
        .validate()
        .expect("loaded config must validate");
}
