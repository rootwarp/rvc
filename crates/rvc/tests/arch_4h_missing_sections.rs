//! ARCH-4h: invented `[beacon]` / `[server]` / `[network]` / `[safety]` /
//! `[slashing]` tables and finished `[keys]`.
//!
//! Test names do not end in `_root` (KAT scan / A-4.9).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use rvc::config::{BeaconConfig, BnRole, Config};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config")
}

fn load_fixture(name: &str) -> Config {
    Config::from_file(fixtures_dir().join(name)).unwrap_or_else(|e| {
        panic!("ARCH-4d fixture {name} must still parse after ARCH-4h: {e}");
    })
}

fn config_snapshot_json(config: &Config) -> String {
    let mut json = serde_json::to_string_pretty(config).expect("Config must serialize");
    json.push('\n');
    json
}

/// RED-then-green contract: flat `top_level_28.toml` still yields the 4d snapshot.
///
/// VD-4.1 demo: a section-only type (`BeaconConfig`) ignores the flat key
/// `beacon_url` (see `naive_section_struct_does_not_bind_flat_keys`). ConfigWire
/// is the lift that keeps this test green.
#[test]
fn top_level_flat_keys_still_parse_after_sectioning() {
    let config = load_fixture("top_level_28.toml");
    let expected = fs::read_to_string(fixtures_dir().join("snapshots/top_level_28.json"))
        .expect("ARCH-4d top_level_28 snapshot must exist");
    assert_eq!(
        expected,
        config_snapshot_json(&config),
        "ARCH-4d top_level_28 snapshot must stay byte-identical after sectioning"
    );
}

/// Same knobs under invented `[beacon]` / `[server]` / … tables.
#[test]
fn new_section_spelling_also_parses() {
    let config: Config = toml::from_str(
        r#"
log_level = "debug"
proposer_nodes = ["http://proposer-top:5052"]
broadcast = ["sync-committee"]
block_selection_mode = "builder-only"
validator_registration_batch_size = 250
validator_registration_batch_delay = 100

[beacon]
url = "http://top-level:5052"
nodes = ["http://bn-a:5052", "http://bn-b:5052"]
max_body_bytes = 1048576

[keys]
keystore_path = "/tmp/top/keystores"
password_file = "/tmp/top/passwords.txt"
key_decrypt_threads = 4
disable_keystore_locking = true
validators_config = "/tmp/top/validators.toml"

[server]
metrics_address = "0.0.0.0"
metrics_port = 9091

[network]
network = "hoodi"
genesis_time = 1606824023
genesis_validators_root = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
graffiti = "top-level"

[safety]
allow_unsupported_fork = true
doppelganger_detection = false
disable_attesting = true
slashed_validators_action = "shutdown"

[slashing]
slashing_db_path = "/tmp/top/slashing.sqlite"
allow_fresh_db = true
"#,
    )
    .expect("new [beacon]/[server]/[network]/[safety]/[slashing]/[keys] spelling must parse");

    let expected = fs::read_to_string(fixtures_dir().join("snapshots/top_level_28.json"))
        .expect("ARCH-4d top_level_28 snapshot must exist");
    assert_eq!(
        expected,
        config_snapshot_json(&config),
        "section spelling must produce the same Config as flat top_level_28"
    );
}

#[test]
fn toml_only_knobs_survive() {
    let flat: Config = toml::from_str(
        r#"
bn_sync_tolerances = "4,4,16"

[[beacon_nodes_config]]
url = "http://bn-flat:5052"
roles = ["proposal"]
"#,
    )
    .expect("flat toml-only knobs must still parse");
    assert_eq!(flat.bn_sync_tolerances.as_deref(), Some("4,4,16"));
    assert_eq!(flat.beacon_nodes_config.len(), 1);
    assert_eq!(flat.beacon_nodes_config[0].url, "http://bn-flat:5052");
    assert_eq!(flat.beacon_nodes_config[0].roles, vec![BnRole::Proposal]);

    let nested = load_fixture("beacon_toml_only.toml");
    assert_eq!(nested.bn_sync_tolerances.as_deref(), Some("4,4,16"));
    assert_eq!(nested.beacon_nodes_config.len(), 1);
    assert_eq!(nested.beacon_nodes_config[0].url, "http://bn-section:5052");
    assert_eq!(nested.beacon_nodes_config[0].roles, vec![BnRole::Proposal]);
}

/// VD-4.1: a nested *Config has no path-scoped alias, so a flat key is ignored.
/// ConfigWire is what lifts `beacon_url` into the section.
#[test]
fn naive_section_struct_does_not_bind_flat_keys() {
    let section: BeaconConfig = toml::from_str(r#"beacon_url = "http://flat-must-not-bind:5052""#)
        .expect("unknown keys on BeaconConfig are ignored (no deny_unknown_fields)");
    assert!(
        section.url.is_none(),
        "flat beacon_url must not bind on BeaconConfig; that is why ConfigWire exists"
    );
}

#[test]
fn nested_table_prefixed_names_do_not_bind_in_new_sections() {
    let nested: Config = toml::from_str(
        r#"
[beacon]
beacon_url = "http://nested-must-not-bind:5052"
beacon_nodes = ["http://nested-must-not-bind:5052"]
beacon_max_body_bytes = 1

[server]
# section-relative names are metrics_address (no server_ prefix)

[keys]
# keystore_path is already section-relative
"#,
    )
    .expect("unknown prefixed keys inside nested tables are ignored");
    assert_eq!(
        nested.beacon_url, "http://localhost:5052",
        "prefixed names inside [beacon] must not bind"
    );
    assert!(nested.beacon_nodes.is_empty());
    assert_eq!(nested.beacon_max_body_bytes, 32 * 1024 * 1024);

    let section: Config = toml::from_str(
        r#"
[beacon]
url = "http://section-ok:5052"
nodes = ["http://bn-ok:5052"]
max_body_bytes = 4096
"#,
    )
    .expect("section-relative [beacon] names must parse");
    assert_eq!(section.beacon_url, "http://section-ok:5052");
    assert_eq!(section.beacon_nodes, vec!["http://bn-ok:5052".to_string()]);
    assert_eq!(section.beacon_max_body_bytes, 4096);
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
fn genesis_validators_root_parses_from_network_table() {
    let config: Config = toml::from_str(
        r#"
[network]
genesis_validators_root = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
"#,
    )
    .expect("[network] genesis_validators_root must parse");
    assert_eq!(
        config.genesis_validators_root.as_deref(),
        Some("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
    );
}

#[test]
fn flat_key_wins_over_new_section_table() {
    let config: Config = toml::from_str(
        r#"
beacon_url = "http://flat-wins:5052"
metrics_port = 9090
disable_keystore_locking = true

[beacon]
url = "http://nested-loses:5052"

[server]
metrics_port = 1111

[keys]
disable_keystore_locking = false
"#,
    )
    .expect("collision of flat + section must parse");
    assert_eq!(config.beacon_url, "http://flat-wins:5052");
    assert_eq!(config.metrics_port, 9090);
    assert!(config.disable_keystore_locking);
}

#[test]
fn timing_toml_round_trip_is_observable_on_config() {
    let config: Config = toml::from_str(
        r#"
[timing]
attestation_due_bps = 2500
aggregate_due_bps = 4000
"#,
    )
    .expect("[timing] TOML must round-trip onto Config");
    assert_eq!(config.timing.attestation_due_bps, 2500);
    assert_eq!(config.timing.aggregate_due_bps, 4000);
    assert_eq!(config.timing.aggregate_due_bps_gloas, 5000);
}

#[test]
fn absent_timing_section_uses_pre_gloas_defaults() {
    let config: Config =
        toml::from_str("log_level = \"debug\"").expect("missing [timing] must parse");
    assert_eq!(config.timing.attestation_due_bps, 3333);
    assert_eq!(config.timing.aggregate_due_bps, 6667);
    assert_eq!(config.timing.attestation_due_bps_gloas, 2500);
    assert_eq!(config.timing.aggregate_due_bps_gloas, 5000);
    assert_eq!(config.timing.sync_message_due_bps_gloas, 2500);
    assert_eq!(config.timing.contribution_due_bps_gloas, 5000);
    assert_eq!(config.timing.payload_due_bps, 5000);
    assert_eq!(config.timing.payload_attestation_due_bps, 7500);
}

// ---------------------------------------------------------------------------
// M4: exactly one clap/section declaration per knob across rvc-config (+ leftover cli groups)
// ---------------------------------------------------------------------------

const KNOBS_69: &[&str] = &[
    "beacon_url",
    "beacon_nodes",
    "keystore_path",
    "password_file",
    "slashing_db_path",
    "init_slashing_db",
    "group_commit_batch_size",
    "group_commit_wait_to_fill_ms",
    "allow_unsupported_fork",
    "metrics_address",
    "metrics_port",
    "network",
    "genesis_time",
    "genesis_validators_root",
    "graffiti",
    "log_level",
    "doppelganger_detection",
    "keymanager_enabled",
    "keymanager_address",
    "keymanager_token_file",
    "remote_signer_url",
    "remote_signer_allowed_hosts",
    "key_decrypt_threads",
    "tracing_endpoint",
    "tracing_exporter",
    "tracing_sample_rate",
    "tracing_max_queue_size",
    "tracing_max_export_batch_size",
    "secret_provider",
    "gcp_project_id",
    "gcp_secret_prefix",
    "secret_refresh_interval",
    "secret_provider_strict",
    "allow_insecure_remote_signer",
    "keymanager_cors_origins",
    "keymanager_body_limit",
    "grpc_signer_url",
    "grpc_signer_tls_cert",
    "grpc_signer_tls_key",
    "grpc_signer_tls_ca_cert",
    "disable_attesting",
    "slashed_validators_action",
    "builder_circuit_breaker_consecutive_limit",
    "builder_circuit_breaker_epoch_limit",
    "disable_keystore_locking",
    "proposer_nodes",
    "broadcast",
    "proposer_config_url",
    "proposer_config_file",
    "proposer_config_refresh_interval",
    "proposer_config_url_token",
    "proposer_config_url_insecure",
    "monitoring_endpoint",
    "monitoring_interval",
    "monitoring_endpoint_insecure",
    "logfile",
    "logfile_max_size",
    "logfile_max_number",
    "logfile_compress",
    "logfile_level",
    "block_selection_mode",
    "validator_registration_batch_size",
    "validator_registration_batch_delay",
    "validators_config",
    "beacon_max_body_bytes",
    "block_production_timeout",
    "attestation_timeout",
    "aggregate_timeout",
    "duty_fetch_timeout",
];

const NOT_A_KNOB: &[&str] = &[
    "no_keymanager",
    "enable_log_reload",
    "log_format",
    "strict_permissions",
    "strict_slashing_semantics",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn struct_body<'a>(src: &'a str, struct_name: &str) -> Option<&'a str> {
    let needle = format!("struct {struct_name}");
    let at = src.find(&needle)?;
    let after = &src[at + needle.len()..];
    let brace = after.find('{')?;
    let open = at + needle.len() + brace;
    let mut depth = 0i32;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn clap_id_from_attrs(attrs: &str) -> Option<String> {
    for key in ["id = \"", "long = \""] {
        if let Some(start) = attrs.find(key) {
            let rest = &attrs[start + key.len()..];
            if let Some(end) = rest.find('"') {
                let raw = &rest[..end];
                return Some(raw.replace('-', "_"));
            }
        }
    }
    None
}

fn leaf_declarations(src: &str, struct_name: &str) -> Vec<(String, String)> {
    let Some(body) = struct_body(src, struct_name) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let lines: Vec<&str> = body.lines().collect();
    let mut pending_attrs = String::new();
    let mut attr_depth = 0i32;
    for line in lines {
        let t = line.trim();
        if t.starts_with("#[") || attr_depth > 0 {
            pending_attrs.push_str(t);
            pending_attrs.push(' ');
            for ch in t.chars() {
                match ch {
                    '[' | '(' => attr_depth += 1,
                    ']' | ')' => attr_depth = attr_depth.saturating_sub(1),
                    _ => {}
                }
            }
            continue;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with("///") {
            continue;
        }
        let attrs = std::mem::take(&mut pending_attrs);
        if attrs.contains("command(flatten)") {
            continue;
        }
        let mut rest = t;
        if let Some(r) = rest.strip_prefix("pub") {
            rest = r.trim_start();
        } else {
            continue;
        }
        let name: String =
            rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if name.is_empty() {
            continue;
        }
        let after = rest[name.len()..].trim_start();
        if !after.starts_with(':') {
            continue;
        }
        let knob = clap_id_from_attrs(&attrs).unwrap_or_else(|| name.clone());
        let knob = match knob.as_str() {
            "no_doppelganger_detection" => "doppelganger_detection".to_string(),
            other => other.to_string(),
        };
        out.push((struct_name.to_string(), knob));
    }
    out
}

#[test]
fn every_one_of_the_69_knobs_has_exactly_one_declaration() {
    assert_eq!(KNOBS_69.len(), 69);
    let unique: BTreeSet<_> = KNOBS_69.iter().copied().collect();
    assert_eq!(unique.len(), 69);

    let root = workspace_root();
    let section_dir = root.join("crates/rvc-config/src/sections");
    let mut srcs = Vec::new();
    for entry in fs::read_dir(&section_dir).expect("rvc-config sections dir") {
        let path = entry.expect("read section").path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            srcs.push(fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("read {}: {e}", path.display());
            }));
        }
    }
    srcs.push(fs::read_to_string(root.join("bin/rvc/src/cli.rs")).expect("cli.rs"));
    srcs.push(fs::read_to_string(root.join("crates/rvc/src/config/start.rs")).expect("start.rs"));

    let args_structs = [
        "TracingArgs",
        "KeymanagerArgs",
        "GrpcSignerArgs",
        "MonitoringArgs",
        "LogfileArgs",
        "ProposerConfigArgs",
        "BuilderLimitsArgs",
        "SecretProviderArgs",
        "GcpSecretArgs",
        "KeysArgs",
        "BeaconArgs",
        "ServerArgs",
        "NetworkArgs",
        "SafetyArgs",
        "SlashingArgs",
        "LoggingArgs",
        "BuilderArgs",
        "ProposerArgs",
    ];

    let mut counts: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for k in KNOBS_69 {
        counts.insert(*k, Vec::new());
    }
    let mut extras = Vec::new();
    for src in &srcs {
        for st in args_structs {
            for (struct_name, knob) in leaf_declarations(src, st) {
                if NOT_A_KNOB.contains(&knob.as_str()) {
                    continue;
                }
                if let Some(list) = counts.get_mut(knob.as_str()) {
                    list.push(struct_name);
                } else {
                    extras.push(format!("{struct_name}::{knob}"));
                }
            }
        }
    }

    let missing: Vec<&str> = counts.iter().filter(|(_, v)| v.is_empty()).map(|(k, _)| *k).collect();
    let dupes: Vec<(&str, &Vec<String>)> =
        counts.iter().filter(|(_, v)| v.len() > 1).map(|(k, v)| (*k, v)).collect();
    assert!(
        extras.is_empty(),
        "scanner found clap fields that are not in the 69 knobs or NOT_A_KNOB: {extras:?}"
    );
    assert!(missing.is_empty(), "knobs with zero clap/section declarations: {missing:?}");
    assert!(dupes.is_empty(), "knobs with more than one declaration: {dupes:?}");
}
