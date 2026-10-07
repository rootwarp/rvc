//! ARCH-4d: freeze the current TOML wire surface before any section collapse.
//!
//! Parsed [`Config`] snapshots in `tests/fixtures/config/snapshots/` are the
//! binding contract for later Stream-A issues. ARCH-4j extended the corpus with
//! the four BN timeout knobs (65 → 69); ARCH-7e disposed the healthz bind knobs
//! (69 → 67). RR2-02 adds the two `[duties]` concurrency knobs (70 → 72).
//! RR2-10 adds the three `[keymanager]` import KDF knobs (72 → 75).
//! Remaining snapshots stay byte-identical: default `[duties]` and default
//! import-KDF fields are omitted.
//!
//! KAT-first: no test name here ends in `_root` / `tree_hash` / `signing_root`
//! (the knob `genesis_validators_root` is in the corpus).

use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use rvc::config::{
    BroadcastTopic, Config, Network, SlashedAction, StartArgs, TracingExporter, OPERATOR_KNOB_NAMES,
};
use validator_store::BlockSelectionMode;

fn cli_override_field_names() -> Vec<&'static str> {
    OPERATOR_KNOB_NAMES.to_vec()
}

/// TOML keys that cover a CLI-only / renamed operator knob.
fn toml_keys_covering_alias(cli_field: &str) -> Option<&'static [&'static str]> {
    match cli_field {
        "init_slashing_db" => Some(&["allow_fresh_db"]),
        "gcp_project_id" => Some(&["secret_provider.gcp.project_id"]),
        "gcp_secret_prefix" => Some(&["secret_provider.gcp.secret_prefix"]),
        "secret_refresh_interval" => Some(&["secret_provider.refresh_interval"]),
        "secret_provider_strict" => Some(&["secret_provider.strict"]),
        _ => None,
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config")
}

fn fixture_path(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

fn load_fixture(name: &str) -> Config {
    Config::from_file(fixture_path(name)).unwrap_or_else(|e| {
        panic!("corpus fixture {name} must parse: {e}");
    })
}

fn snapshot_path(name: &str) -> PathBuf {
    fixtures_dir().join("snapshots").join(format!("{name}.json"))
}

fn config_snapshot_json(config: &Config) -> String {
    let mut json = serde_json::to_string_pretty(config).expect("Config must serialize");
    json.push('\n');
    json
}

fn assert_config_snapshot(name: &str, config: &Config) {
    let actual = config_snapshot_json(config);
    let path = snapshot_path(name);
    if std::env::var("UPDATE_CONFIG_WIRE_SNAPSHOTS").as_deref() == Ok("1") {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create snapshot dir");
        }
        fs::write(&path, &actual).unwrap_or_else(|e| {
            panic!("write snapshot {}: {e}", path.display());
        });
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing snapshot {} ({e}); rerun with UPDATE_CONFIG_WIRE_SNAPSHOTS=1",
            path.display()
        );
    });
    assert_eq!(expected, actual, "snapshot contract drifted for {name}");
}

fn collect_toml_keys(value: &toml::Value, prefix: &str, out: &mut BTreeSet<String>) {
    let toml::Value::Table(table) = value else {
        return;
    };
    for (key, child) in table {
        let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
        out.insert(key.clone());
        out.insert(path.clone());
        collect_toml_keys(child, &path, out);
    }
}

fn corpus_toml_keys() -> BTreeSet<String> {
    let dir = fixtures_dir();
    let mut keys = BTreeSet::new();
    let entries = fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("corpus dir {} must exist: {e}", dir.display());
    });
    for entry in entries {
        let entry = entry.expect("read corpus dir");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read {}: {e}", path.display());
        });
        let value: toml::Value = toml::from_str(&text).unwrap_or_else(|e| {
            panic!("parse {}: {e}", path.display());
        });
        collect_toml_keys(&value, "", &mut keys);
    }
    keys
}

fn knob_appears_in_corpus(cli_field: &str, keys: &BTreeSet<String>) -> bool {
    match toml_keys_covering_alias(cli_field) {
        Some(aliases) => aliases.iter().any(|k| keys.contains(*k)),
        None => keys.contains(cli_field),
    }
}

const REQUIRED_CORPUS: &[&str] = &[
    "flat_legacy_full.toml",
    "nested_full.toml",
    "collision.toml",
    "logfile_flat_string.toml",
    "logfile_table.toml",
    "top_level_28.toml",
    "beacon_timeouts.toml",
    "slashing_group_commit.toml",
    "duties.toml",
    "keymanager_kdf.toml",
];

#[test]
fn every_knob_appears_in_the_parity_corpus() {
    let names = cli_override_field_names();
    assert_eq!(names.len(), 75, "operator knob count is 75 after the [keymanager] KDF knobs");
    let unique: BTreeSet<_> = names.iter().copied().collect();
    assert_eq!(unique.len(), 75, "operator knob names must be unique");

    for name in REQUIRED_CORPUS {
        let path = fixture_path(name);
        assert!(path.is_file(), "required corpus fixture missing: {}", path.display());
    }

    let keys = corpus_toml_keys();
    let missing: Vec<&str> =
        names.iter().copied().filter(|n| !knob_appears_in_corpus(n, &keys)).collect();
    assert!(
        missing.is_empty(),
        "every operator knob must appear in the parity corpus; missing: {missing:?}"
    );
}

#[test]
fn flat_legacy_keys_still_parse() {
    let config = load_fixture("flat_legacy_full.toml");
    assert_legacy_group_values(&config);
    assert_config_snapshot("legacy_groups", &config);
}

#[test]
fn nested_tables_match_flat_legacy_snapshot() {
    let flat = load_fixture("flat_legacy_full.toml");
    let nested = load_fixture("nested_full.toml");
    assert_legacy_group_values(&nested);
    assert_eq!(
        config_snapshot_json(&flat),
        config_snapshot_json(&nested),
        "flat legacy keys and nested tables must produce the same Config"
    );
    assert_config_snapshot("legacy_groups", &nested);
}

#[test]
fn flat_key_wins_over_nested_table() {
    let config = load_fixture("collision.toml");
    assert!(config.keymanager.enabled);
    assert_eq!(config.keymanager.address.as_deref(), Some("10.0.0.1:5062"));
    assert_eq!(config.keymanager.token_file.as_deref(), Some(Path::new("/flat/km.token")));
    assert_eq!(config.keymanager.remote_signer_url.as_deref(), Some("https://flat-signer:9000"));
    assert_eq!(
        config.keymanager.remote_signer_allowed_hosts.as_deref(),
        Some(["flat.host".to_string()].as_slice())
    );
    assert!(config.keymanager.allow_insecure_remote_signer);
    assert_eq!(config.keymanager.cors_origins, vec!["https://flat.cors".to_string()]);
    assert_eq!(config.keymanager.body_limit, 2_222_222);
    assert_eq!(config.tracing.endpoint.as_deref(), Some("http://flat-otel:4318"));
    assert_eq!(config.tracing.exporter, TracingExporter::Gcp);
    assert_eq!(config.tracing.sample_rate, Some(0.77));
    assert_eq!(config.tracing.max_queue_size, Some(7777));
    assert_eq!(config.tracing.max_export_batch_size, Some(777));
    assert_eq!(config.tracing.service_name.as_deref(), Some("rvc-flat"));
    assert_eq!(config.grpc_signer.url.as_deref(), Some("https://flat-grpc:50051"));
    assert_eq!(config.grpc_signer.tls_cert.as_deref(), Some(Path::new("/flat/client.crt")));
    assert_eq!(config.grpc_signer.tls_key.as_deref(), Some(Path::new("/flat/client.key")));
    assert_eq!(config.grpc_signer.tls_ca_cert.as_deref(), Some(Path::new("/flat/ca.crt")));
    assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 8);
    assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 13);
    assert_eq!(config.monitoring.endpoint.as_deref(), Some("https://flat.monitor/metrics"));
    assert_eq!(config.monitoring.interval, 77);
    assert!(config.monitoring.endpoint_insecure);
    assert_eq!(config.proposer_config.url.as_deref(), Some("https://flat.proposer/config.json"));
    assert_eq!(config.proposer_config.file.as_deref(), Some("/flat/proposer.json"));
    assert_eq!(config.proposer_config.refresh_interval, 47);
    assert_eq!(config.proposer_config.url_token.as_deref(), Some("flat-token"));
    assert!(config.proposer_config.url_insecure);
    assert_eq!(config.logfile.path.as_deref(), Some(Path::new("/nested/rvc.log")));
    assert_eq!(config.logfile.max_size, 77);
    assert_eq!(config.logfile.max_number, 4);
    assert!(config.logfile.compress);
    assert_eq!(config.logfile.level.as_deref(), Some("warn"));
    assert_config_snapshot("collision", &config);
}

#[test]
fn logfile_accepts_string_or_table() {
    let from_string = load_fixture("logfile_flat_string.toml");
    let from_table = load_fixture("logfile_table.toml");
    assert_eq!(from_string.logfile.path.as_deref(), Some(Path::new("/var/log/rvc/wire.log")));
    assert_eq!(from_table.logfile.path.as_deref(), Some(Path::new("/var/log/rvc/wire.log")));
    assert_eq!(from_string.logfile.max_size, 200);
    assert_eq!(from_table.logfile.max_size, 200);
    assert_eq!(
        config_snapshot_json(&from_string),
        config_snapshot_json(&from_table),
        "logfile string and [logfile] table must produce the same Config"
    );
    assert_config_snapshot("logfile_dual_shape", &from_string);
}

#[test]
fn toml_metrics_port_9090_survives_absent_cli_flag() {
    let from_file = load_fixture("cli_precedence.toml");
    assert_eq!(from_file.metrics_port, 9090);
    // Absent clap flag ≡ default StartArgs. ADR-009: file value must stand.
    let config = Config::load(Some(&fixture_path("cli_precedence.toml")), StartArgs::default())
        .expect("load file + empty CLI");
    assert_eq!(config.metrics_port, 9090);
    assert_config_snapshot("cli_precedence_file_only", &config);
}

#[test]
fn defaults_lose_to_file_lose_to_cli() {
    let defaults = Config::default();
    assert_eq!(defaults.metrics_port, 8080);
    assert_eq!(defaults.log_level, "info");
    assert!(defaults.graffiti.is_none());
    assert!(!defaults.keymanager.enabled);
    assert!(defaults.tracing.sample_rate.is_none());
    assert!(defaults.logfile.path.is_none());
    assert_eq!(defaults.beacon_url, "http://localhost:5052");

    let file_only = Config::load(Some(&fixture_path("cli_precedence.toml")), StartArgs::default())
        .expect("file only");
    assert_eq!(file_only.metrics_port, 9090);
    assert_eq!(file_only.log_level, "debug");
    assert_eq!(file_only.graffiti.as_deref(), Some("from-file"));
    assert!(file_only.keymanager.enabled);
    assert_eq!(file_only.tracing.sample_rate, Some(0.25));
    assert_eq!(file_only.logfile.path.as_deref(), Some(Path::new("/tmp/from-file.log")));
    assert_eq!(file_only.beacon_url, "http://file-only:5052");

    let mut cli = StartArgs::default();
    cli.server.metrics_port = Some(9100);
    cli.logging.log_level = Some("trace".to_string());
    cli.network.graffiti = Some("from-cli".to_string());
    cli.keymanager.no_keymanager = true;
    cli.tracing.sample_rate = Some(0.9);
    cli.logging.logfile.path = Some(PathBuf::from("/tmp/from-cli.log"));
    cli.beacon.url = Some("http://cli-only:5052".to_string());
    let with_cli = Config::load(Some(&fixture_path("cli_precedence.toml")), cli).expect("file+cli");
    assert_eq!(with_cli.metrics_port, 9100);
    assert_eq!(with_cli.log_level, "trace");
    assert_eq!(with_cli.graffiti.as_deref(), Some("from-cli"));
    assert!(!with_cli.keymanager.enabled);
    assert_eq!(with_cli.tracing.sample_rate, Some(0.9));
    assert_eq!(with_cli.logfile.path.as_deref(), Some(Path::new("/tmp/from-cli.log")));
    assert_eq!(with_cli.beacon_url, "http://cli-only:5052");
    assert_config_snapshot("cli_precedence_cli_wins", &with_cli);
}

#[test]
fn genesis_validators_root_parses_from_flat_key() {
    let config = load_fixture("top_level_28.toml");
    assert_eq!(
        config.genesis_validators_root.as_deref(),
        Some("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
    );
}

#[test]
fn top_level_bare_knobs_still_parse() {
    let config = load_fixture("top_level_28.toml");
    assert_eq!(config.beacon_url, "http://top-level:5052");
    assert_eq!(
        config.beacon_nodes,
        vec!["http://bn-a:5052".to_string(), "http://bn-b:5052".to_string()]
    );
    assert_eq!(config.keystore_path, PathBuf::from("/tmp/top/keystores"));
    assert_eq!(config.password_file.as_deref(), Some(Path::new("/tmp/top/passwords.txt")));
    assert_eq!(config.slashing_db_path, PathBuf::from("/tmp/top/slashing.sqlite"));
    assert!(config.allow_fresh_db);
    assert!(config.allow_unsupported_fork);
    assert_eq!(config.metrics_address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(config.metrics_port, 9091);
    assert_eq!(config.network, Network::Hoodi);
    assert_eq!(config.genesis_time, Some(1_606_824_023));
    assert_eq!(config.graffiti.as_deref(), Some("top-level"));
    assert_eq!(config.log_level, "debug");
    assert!(!config.doppelganger_detection);
    assert_eq!(config.key_decrypt_threads, Some(4));
    assert!(config.disable_attesting);
    assert_eq!(config.slashed_validators_action, SlashedAction::Shutdown);
    assert!(config.disable_keystore_locking);
    assert_eq!(config.proposer_nodes, vec!["http://proposer-top:5052".to_string()]);
    assert_eq!(config.broadcast, vec![BroadcastTopic::SyncCommittee]);
    assert_eq!(config.block_selection_mode, BlockSelectionMode::BuilderOnly);
    assert_eq!(config.validator_registration_batch_size, 250);
    assert_eq!(config.validator_registration_batch_delay, 100);
    assert_eq!(config.validators_config.as_deref(), Some(Path::new("/tmp/top/validators.toml")));
    assert_eq!(config.beacon_max_body_bytes, 1_048_576);
    assert_config_snapshot("top_level_28", &config);
}

#[test]
fn promoted_beacon_timeouts_appear_in_corpus_snapshot() {
    let config = load_fixture("beacon_timeouts.toml");
    assert_eq!(config.block_production_timeout, Some(11));
    assert_eq!(config.attestation_timeout, Some(12));
    assert_eq!(config.aggregate_timeout, Some(13));
    assert_eq!(config.duty_fetch_timeout, Some(14));
    let timeouts = config.operation_timeouts();
    assert_eq!(timeouts.block_production, std::time::Duration::from_secs(11));
    assert_eq!(timeouts.attestation_fetch, std::time::Duration::from_secs(12));
    assert_eq!(timeouts.aggregate_fetch, std::time::Duration::from_secs(13));
    assert_eq!(timeouts.aggregate_submit, std::time::Duration::from_secs(13));
    assert_eq!(timeouts.duty_fetch, std::time::Duration::from_secs(14));
    assert_config_snapshot("beacon_timeouts", &config);
}

#[test]
fn duties_section_parses_from_corpus() {
    let config = load_fixture("duties.toml");
    assert_eq!(config.duties.duty_dispatch_concurrency, 16);
    assert_eq!(config.duties.duty_publish_concurrency, 4);
    assert!(config.validate().is_ok());
    let defaults = Config::default();
    assert_eq!(defaults.duties.duty_dispatch_concurrency, 32);
    assert_eq!(defaults.duties.duty_publish_concurrency, 2);
    assert!(!config_snapshot_json(&defaults).contains("duty_dispatch_concurrency"));
}

#[test]
fn keymanager_kdf_section_parses_from_corpus() {
    let config = load_fixture("keymanager_kdf.toml");
    assert_eq!(config.keymanager.keymanager_import_kdf_concurrency, 4);
    assert_eq!(config.keymanager.keymanager_import_kdf_total_mib, 256);
    assert_eq!(config.keymanager.keymanager_import_kdf_max_keystore_mib, 1024);
    assert!(config.validate().is_ok());
    let defaults = Config::default();
    assert_eq!(defaults.keymanager.keymanager_import_kdf_concurrency, 2);
    assert_eq!(defaults.keymanager.keymanager_import_kdf_total_mib, 512);
    assert_eq!(defaults.keymanager.keymanager_import_kdf_max_keystore_mib, 8192);
    let snapshot = config_snapshot_json(&defaults);
    assert!(!snapshot.contains("keymanager_import_kdf_concurrency"));
    assert!(!snapshot.contains("keymanager_import_kdf_total_mib"));
    assert!(!snapshot.contains("keymanager_import_kdf_max_keystore_mib"));
}

#[test]
fn secret_provider_table_still_parses() {
    let config = load_fixture("secret_provider.toml");
    assert_eq!(config.secret_provider.providers, vec!["gcp".to_string()]);
    assert_eq!(config.secret_provider.refresh_interval, Some(321));
    assert!(config.secret_provider.strict);
    assert_eq!(config.secret_provider.gcp.project_id.as_deref(), Some("wire-gcp-project"));
    assert_eq!(config.secret_provider.gcp.secret_prefix, "wire-validator-key-");
    assert_config_snapshot("secret_provider", &config);
}

fn assert_legacy_group_values(config: &Config) {
    assert!(config.keymanager.enabled);
    assert_eq!(config.keymanager.address.as_deref(), Some("10.0.0.8:5062"));
    assert_eq!(
        config.keymanager.token_file.as_deref(),
        Some(Path::new("/var/lib/rvc/wire/km.token"))
    );
    assert_eq!(config.keymanager.remote_signer_url.as_deref(), Some("https://wire-signer:9000"));
    assert_eq!(
        config.keymanager.remote_signer_allowed_hosts.as_deref(),
        Some(["wire.signer.example".to_string()].as_slice())
    );
    assert!(config.keymanager.allow_insecure_remote_signer);
    assert_eq!(config.keymanager.cors_origins, vec!["https://wire.cors.example".to_string()]);
    assert_eq!(config.keymanager.body_limit, 424_242);
    assert_eq!(config.tracing.endpoint.as_deref(), Some("http://wire-otel:4318"));
    assert_eq!(config.tracing.exporter, TracingExporter::Gcp);
    assert_eq!(config.tracing.sample_rate, Some(0.37));
    assert_eq!(config.tracing.max_queue_size, Some(3333));
    assert_eq!(config.tracing.max_export_batch_size, Some(444));
    assert_eq!(config.tracing.service_name.as_deref(), Some("rvc-wire"));
    assert_eq!(config.grpc_signer.url.as_deref(), Some("https://wire-grpc:50051"));
    assert_eq!(config.grpc_signer.tls_cert.as_deref(), Some(Path::new("/etc/rvc/wire/client.crt")));
    assert_eq!(config.grpc_signer.tls_key.as_deref(), Some(Path::new("/etc/rvc/wire/client.key")));
    assert_eq!(config.grpc_signer.tls_ca_cert.as_deref(), Some(Path::new("/etc/rvc/wire/ca.crt")));
    assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 8);
    assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 13);
    assert_eq!(config.monitoring.endpoint.as_deref(), Some("https://wire.monitor/metrics"));
    assert_eq!(config.monitoring.interval, 96);
    assert!(config.monitoring.endpoint_insecure);
    assert_eq!(config.proposer_config.url.as_deref(), Some("https://wire.proposer/config.json"));
    assert_eq!(config.proposer_config.file.as_deref(), Some("/etc/rvc/wire/proposer.json"));
    assert_eq!(config.proposer_config.refresh_interval, 48);
    assert_eq!(config.proposer_config.url_token.as_deref(), Some("wire-token"));
    assert!(config.proposer_config.url_insecure);
    assert_eq!(config.logfile.path.as_deref(), Some(Path::new("/var/log/rvc/wire.log")));
    assert_eq!(config.logfile.max_size, 77);
    assert_eq!(config.logfile.max_number, 4);
    assert!(config.logfile.compress);
    assert_eq!(config.logfile.level.as_deref(), Some("warn"));
}
