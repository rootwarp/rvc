//! ARCH-4g: partial-section migration guards.
//!
//! Test names do not end in `_root` (KAT scan).

use std::fs;
use std::path::{Path, PathBuf};

use rvc::config::{BroadcastTopic, Config};
use validator_store::BlockSelectionMode;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config")
}

fn load_fixture(name: &str) -> Config {
    Config::from_file(fixtures_dir().join(name)).unwrap_or_else(|e| {
        panic!("ARCH-4d fixture {name} must still parse after ARCH-4g: {e}");
    })
}

fn config_snapshot_json(config: &Config) -> String {
    let mut json = serde_json::to_string_pretty(config).expect("Config must serialize");
    json.push('\n');
    json
}

#[test]
fn logfile_string_or_table_survives_the_move() {
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
    let expected = fs::read_to_string(fixtures_dir().join("snapshots/logfile_dual_shape.json"))
        .expect("ARCH-4d logfile snapshot must exist");
    assert_eq!(
        expected,
        config_snapshot_json(&from_string),
        "ARCH-4d logfile snapshot must stay byte-identical"
    );
}

#[test]
fn bare_knobs_of_partial_groups_keep_top_level_toml_spelling() {
    let config: Config = toml::from_str(
        r#"
log_level = "debug"
proposer_nodes = ["http://proposer-top:5052"]
broadcast = ["sync-committee"]
block_selection_mode = "builder-only"
validator_registration_batch_size = 250
validator_registration_batch_delay = 100
"#,
    )
    .expect("bare knobs of partial groups must parse from top-level TOML");
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.proposer_nodes, vec!["http://proposer-top:5052".to_string()]);
    assert_eq!(config.broadcast, vec![BroadcastTopic::SyncCommittee]);
    assert_eq!(config.block_selection_mode, BlockSelectionMode::BuilderOnly);
    assert_eq!(config.validator_registration_batch_size, 250);
    assert_eq!(config.validator_registration_batch_delay, 100);
}

#[test]
fn nested_table_flat_legacy_names_do_not_bind_in_partial_sections() {
    let nested: Config = toml::from_str(
        r#"
[logfile]
logfile = "/nested-must-not-bind.log"
logfile_max_size = 1
logfile_max_number = 1
logfile_compress = true
logfile_level = "error"

[proposer_config]
proposer_config_url = "https://nested-must-not-bind"
proposer_config_refresh_interval = 1

[builder_limits]
builder_circuit_breaker_consecutive_limit = 99
builder_circuit_breaker_epoch_limit = 99

[secret_provider.gcp]
gcp_project_id = "nested-must-not-bind"
gcp_secret_prefix = "nested-"
"#,
    )
    .expect("unknown prefixed keys inside nested tables are ignored (no deny on *Config)");
    assert!(nested.logfile.path.is_none(), "prefixed names inside [logfile] must not bind");
    assert_eq!(nested.logfile.max_size, 200);
    assert!(nested.proposer_config.url.is_none());
    assert_eq!(nested.proposer_config.refresh_interval, 384);
    assert_eq!(nested.builder_limits.circuit_breaker_consecutive_limit, 3);
    assert_eq!(nested.builder_limits.circuit_breaker_epoch_limit, 5);
    assert!(nested.secret_provider.gcp.project_id.is_none());
    assert_eq!(nested.secret_provider.gcp.secret_prefix, "validator-key-");

    let section: Config = toml::from_str(
        r#"
[logfile]
path = "/var/log/rvc/ok.log"
max_size = 77

[proposer_config]
url = "https://ok"
refresh_interval = 48

[builder_limits]
circuit_breaker_consecutive_limit = 8
circuit_breaker_epoch_limit = 13

[secret_provider.gcp]
project_id = "ok-project"
secret_prefix = "ok-"
"#,
    )
    .expect("section-relative nested names must parse");
    assert_eq!(section.logfile.path.as_deref(), Some(Path::new("/var/log/rvc/ok.log")));
    assert_eq!(section.logfile.max_size, 77);
    assert_eq!(section.proposer_config.url.as_deref(), Some("https://ok"));
    assert_eq!(section.proposer_config.refresh_interval, 48);
    assert_eq!(section.builder_limits.circuit_breaker_consecutive_limit, 8);
    assert_eq!(section.builder_limits.circuit_breaker_epoch_limit, 13);
    assert_eq!(section.secret_provider.gcp.project_id.as_deref(), Some("ok-project"));
    assert_eq!(section.secret_provider.gcp.secret_prefix, "ok-");
}
