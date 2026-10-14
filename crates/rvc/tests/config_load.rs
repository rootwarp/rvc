//! ARCH-4i: `Config::load` precedence (defaults < file < CLI).
//! ARCH-4j: promoted BN timeout knobs (TOML + CLI, defaults, zero reject).
//!
//! Test names do not end in `_root` (KAT scan / A-4.9).

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bn_manager::OperationTimeouts;
use rvc::config::{Config, ConfigSource, StartArgs};
use tempfile::NamedTempFile;

#[test]
fn config_load_applies_defaults_then_file_then_cli() {
    let defaults = Config::load(None, StartArgs::default()).expect("defaults");
    assert_eq!(defaults.metrics_port, 8080);

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "metrics_port = 9090").unwrap();
    let file_only = Config::load(Some(file.path()), StartArgs::default()).expect("file");
    assert_eq!(file_only.metrics_port, 9090);

    let mut cli = StartArgs::default();
    cli.server.metrics_port = Some(9100);
    let with_cli = Config::load(Some(file.path()), cli).expect("file+cli");
    assert_eq!(with_cli.metrics_port, 9100);
}

#[test]
fn toml_metrics_port_9090_binds_9090() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
metrics_address = "127.0.0.1"
metrics_port = 9090
"#
    )
    .unwrap();
    let cfg = Config::load(Some(file.path()), StartArgs::default()).expect("load");
    assert_eq!(cfg.metrics_port, 9090, "ADR-009: TOML 9090 must survive absent --metrics-port");
    let addr = SocketAddr::new(cfg.metrics_address, cfg.metrics_port);
    assert_eq!(addr.port(), 9090);
    assert_eq!(addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn config_load_names_file_provenance_on_missing_path() {
    let err = Config::load(Some("/nonexistent/rvc-arch-4i.toml".as_ref()), StartArgs::default())
        .expect_err("missing file");
    let rendered = err.to_string();
    assert!(rendered.contains("config"), "{rendered}");
    assert!(
        rendered.contains("/nonexistent/rvc-arch-4i.toml") || rendered.contains("file"),
        "{rendered}"
    );
    match err {
        rvc::config::ConfigError::Invalid { source_layer, .. } => {
            assert!(matches!(source_layer, ConfigSource::File(_)));
        }
        other => panic!("expected Invalid with File layer, got {other}"),
    }
}

/// Present-only TOML bools must survive an empty CLI overlay (ADR-009).
#[test]
fn toml_safety_flags_survive_empty_cli() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
allow_fresh_db = true
disable_attesting = true
allow_unsupported_fork = true
doppelganger_detection = false
disable_keystore_locking = true
"#
    )
    .unwrap();
    let cfg = Config::load(Some(file.path()), StartArgs::default()).expect("load");
    assert!(cfg.allow_fresh_db);
    assert!(cfg.disable_attesting);
    assert!(cfg.allow_unsupported_fork);
    assert!(!cfg.doppelganger_detection);
    assert!(cfg.disable_keystore_locking);
}

#[test]
fn beacon_timeouts_are_settable_from_toml() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[beacon]
block_production_timeout = 11
attestation_timeout = 12
aggregate_timeout = 13
duty_fetch_timeout = 14
"#
    )
    .unwrap();
    let cfg = Config::load(Some(file.path()), StartArgs::default()).expect("toml timeouts");
    let timeouts = cfg.operation_timeouts();
    assert_eq!(timeouts.block_production, Duration::from_secs(11));
    assert_eq!(timeouts.attestation_fetch, Duration::from_secs(12));
    assert_eq!(timeouts.aggregate_fetch, Duration::from_secs(13));
    assert_eq!(timeouts.aggregate_submit, Duration::from_secs(13));
    assert_eq!(timeouts.duty_fetch, Duration::from_secs(14));

    let mut cli = StartArgs::default();
    cli.beacon.block_production_timeout = Some(21);
    cli.beacon.attestation_timeout = Some(22);
    cli.beacon.aggregate_timeout = Some(23);
    cli.beacon.duty_fetch_timeout = Some(24);
    let with_cli = Config::load(Some(file.path()), cli).expect("cli wins");
    let timeouts = with_cli.operation_timeouts();
    assert_eq!(timeouts.block_production, Duration::from_secs(21));
    assert_eq!(timeouts.attestation_fetch, Duration::from_secs(22));
    assert_eq!(timeouts.aggregate_fetch, Duration::from_secs(23));
    assert_eq!(timeouts.aggregate_submit, Duration::from_secs(23));
    assert_eq!(timeouts.duty_fetch, Duration::from_secs(24));
}

#[test]
fn promoted_timeout_defaults_equal_operation_timeouts_default() {
    let got = Config::default().operation_timeouts();
    let expected = OperationTimeouts::default();
    assert_eq!(got.block_production, expected.block_production);
    assert_eq!(got.block_publication, expected.block_publication);
    assert_eq!(got.attestation_fetch, expected.attestation_fetch);
    assert_eq!(got.attestation_submit, expected.attestation_submit);
    assert_eq!(got.aggregate_fetch, expected.aggregate_fetch);
    assert_eq!(got.aggregate_submit, expected.aggregate_submit);
    assert_eq!(got.sync_message, expected.sync_message);
    assert_eq!(got.sync_contribution, expected.sync_contribution);
    assert_eq!(got.duty_fetch, expected.duty_fetch);
    assert_eq!(got.preparation, expected.preparation);
}

#[test]
fn zero_timeout_rejected_from_toml_as_well_as_cli() {
    let cases = [
        ("block_production_timeout", "--block-production-timeout must be greater than 0"),
        ("attestation_timeout", "--attestation-timeout must be greater than 0"),
        ("aggregate_timeout", "--aggregate-timeout must be greater than 0"),
        ("duty_fetch_timeout", "--duty-fetch-timeout must be greater than 0"),
    ];
    for (field, message) in cases {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{field} = 0").unwrap();
        let from_toml = Config::load(Some(file.path()), StartArgs::default()).expect("load toml 0");
        let err = from_toml.validate().expect_err(field);
        assert!(err.to_string().contains(message), "{field} toml 0: expected {message:?} in {err}");

        let mut cli = StartArgs::default();
        match field {
            "block_production_timeout" => cli.beacon.block_production_timeout = Some(0),
            "attestation_timeout" => cli.beacon.attestation_timeout = Some(0),
            "aggregate_timeout" => cli.beacon.aggregate_timeout = Some(0),
            "duty_fetch_timeout" => cli.beacon.duty_fetch_timeout = Some(0),
            _ => unreachable!(),
        }
        let from_cli = Config::load(None, cli).expect("load cli 0");
        let err = from_cli.validate().expect_err(field);
        assert!(err.to_string().contains(message), "{field} cli 0: expected {message:?} in {err}");
    }
}

#[test]
fn group_commit_batch_size_zero_is_rejected() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "[slashing]\ngroup_commit_batch_size = 0").unwrap();
    let from_toml = Config::load(Some(file.path()), StartArgs::default()).expect("load toml 0");
    let err = from_toml.validate().expect_err("batch_size 0");
    assert!(err.to_string().contains("group-commit batch_size must be greater than 0"), "{err}");

    let mut cli = StartArgs::default();
    cli.slashing.group_commit_batch_size = Some(0);
    let from_cli = Config::load(None, cli).expect("load cli 0");
    let err = from_cli.validate().expect_err("cli batch_size 0");
    assert!(err.to_string().contains("group-commit batch_size must be greater than 0"), "{err}");
}

#[test]
fn aggregate_timeout_sets_both_fetch_and_submit() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "aggregate_timeout = 17").unwrap();
    let from_toml = Config::load(Some(file.path()), StartArgs::default()).expect("toml");
    let timeouts = from_toml.operation_timeouts();
    assert_eq!(timeouts.aggregate_fetch, Duration::from_secs(17));
    assert_eq!(timeouts.aggregate_submit, Duration::from_secs(17));

    let mut cli = StartArgs::default();
    cli.beacon.aggregate_timeout = Some(19);
    let from_cli = Config::load(None, cli).expect("cli");
    let timeouts = from_cli.operation_timeouts();
    assert_eq!(timeouts.aggregate_fetch, Duration::from_secs(19));
    assert_eq!(timeouts.aggregate_submit, Duration::from_secs(19));
}
