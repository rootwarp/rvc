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
    // One document per table, and one key per document, so a later alias cannot
    // hide behind the first unknown-field error.
    for (doc, key) in [
        ("[logfile]\nlogfile = \"/nested-must-not-bind.log\"\n", "logfile"),
        ("[logfile]\nlogfile_max_size = 1\n", "logfile_max_size"),
        ("[logfile]\nlogfile_max_number = 1\n", "logfile_max_number"),
        ("[logfile]\nlogfile_compress = true\n", "logfile_compress"),
        ("[logfile]\nlogfile_level = \"error\"\n", "logfile_level"),
        (
            "[proposer_config]\nproposer_config_url = \"https://nested-must-not-bind\"\n",
            "proposer_config_url",
        ),
        (
            "[proposer_config]\nproposer_config_refresh_interval = 1\n",
            "proposer_config_refresh_interval",
        ),
        (
            "[builder_limits]\nbuilder_circuit_breaker_consecutive_limit = 99\n",
            "builder_circuit_breaker_consecutive_limit",
        ),
        (
            "[builder_limits]\nbuilder_circuit_breaker_epoch_limit = 99\n",
            "builder_circuit_breaker_epoch_limit",
        ),
        ("[secret_provider.gcp]\ngcp_project_id = \"nested-must-not-bind\"\n", "gcp_project_id"),
        ("[secret_provider.gcp]\ngcp_secret_prefix = \"nested-\"\n", "gcp_secret_prefix"),
    ] {
        let err = toml::from_str::<Config>(doc).expect_err(key);
        let msg = err.to_string();
        assert!(msg.contains(key), "{key} must be rejected, got {msg}");
    }

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
