//! B-033 / B-034: proposer-pool budgets and the global selection mode.
//!
//! Neither setting reads a fork schedule. The same budget and mode apply on
//! both sides of Gloas.

use std::time::Duration;

use rvc::config::{BlockSelectionMode, Config, ConfigError, ServiceBuilder, StartArgs};
use tempfile::TempDir;
use validator_store::ValidatorStore;

fn validators_file(body: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("validators.toml");
    let fee = format!("0x{}", hex::encode([0xaau8; 20]));
    std::fs::write(&path, format!("[defaults]\nfee_recipient = \"{fee}\"\n{body}")).expect("write");
    (dir, path)
}

fn pubkey_line(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 48]))
}

fn two_validators() -> String {
    format!(
        r#"
[[validators]]
pubkey = "{plain}"

[[validators]]
pubkey = "{override}"
block_selection_mode = "builder-only"
"#,
        plain = pubkey_line(0x11),
        override = pubkey_line(0x22),
    )
}

fn store_from(config: Config, validators: &str) -> std::sync::Arc<ValidatorStore> {
    let (_dir, path) = validators_file(validators);
    ServiceBuilder::new(config).build_validator_store(Some(&path)).expect("validator store")
}

fn assert_plain_and_override(
    store: &ValidatorStore,
    plain: BlockSelectionMode,
    per_validator: BlockSelectionMode,
) {
    assert_eq!(store.effective_block_selection_mode(&[0x11u8; 48]), plain);
    assert_eq!(store.effective_block_selection_mode(&[0x33u8; 48]), plain);
    assert_eq!(store.effective_block_selection_mode(&[0x22u8; 48]), per_validator);
}

#[test]
fn cli_execution_only_is_the_global_default_and_a_per_validator_mode_wins() {
    let mut args = StartArgs::default();
    args.builder.block_selection_mode = Some(BlockSelectionMode::ExecutionOnly);
    let config = Config::load(None, args).expect("cli load");
    let store = store_from(config, &two_validators());
    assert_plain_and_override(
        &store,
        BlockSelectionMode::ExecutionOnly,
        BlockSelectionMode::BuilderOnly,
    );
}

#[test]
fn toml_execution_only_is_the_global_default_and_a_per_validator_mode_wins() {
    let config: Config = toml::from_str(
        r#"
beacon_url = "http://127.0.0.1:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
block_selection_mode = "execution-only"
"#,
    )
    .expect("toml");
    let store = store_from(config, &two_validators());
    assert_plain_and_override(
        &store,
        BlockSelectionMode::ExecutionOnly,
        BlockSelectionMode::BuilderOnly,
    );
}

#[test]
fn cli_block_selection_mode_overrides_the_toml_key() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("rvc.toml");
    std::fs::write(
        &path,
        "beacon_url = \"http://127.0.0.1:5052\"\nblock_selection_mode = \"builder-only\"\n",
    )
    .expect("write");
    let mut args = StartArgs::default();
    args.builder.block_selection_mode = Some(BlockSelectionMode::ExecutionOnly);
    let config = Config::load(Some(&path), args).expect("cli wins");
    assert_eq!(config.block_selection_mode, BlockSelectionMode::ExecutionOnly);
    let store = store_from(config, &two_validators());
    assert_plain_and_override(
        &store,
        BlockSelectionMode::ExecutionOnly,
        BlockSelectionMode::BuilderOnly,
    );
}

#[test]
fn unset_block_selection_mode_stays_max_profit() {
    let config = Config::load(None, StartArgs::default()).expect("defaults");
    assert_eq!(config.block_selection_mode, BlockSelectionMode::MaxProfit);
    let store = store_from(config, &two_validators());
    assert_plain_and_override(
        &store,
        BlockSelectionMode::MaxProfit,
        BlockSelectionMode::BuilderOnly,
    );
}

#[test]
fn unknown_block_selection_mode_is_rejected() {
    let err = toml::from_str::<Config>(
        r#"
beacon_url = "http://127.0.0.1:5052"
block_selection_mode = "not-a-mode"
"#,
    )
    .expect_err("unknown mode");
    let msg = err.to_string();
    assert!(msg.contains("not-a-mode"), "{msg}");
    assert!(msg.contains("block_selection_mode"), "{msg}");
}

#[test]
fn zero_fee_recipient_does_not_publish_a_store() {
    let mut args = StartArgs::default();
    args.builder.block_selection_mode = Some(BlockSelectionMode::ExecutionOnly);
    let config = Config::load(None, args).expect("cli load");
    let result = ServiceBuilder::new(config).build_validator_store(None);
    assert!(matches!(result, Err(ConfigError::ZeroFeeRecipient)));
}

#[test]
fn malformed_builder_url_does_not_publish_a_store() {
    let mut args = StartArgs::default();
    args.builder.block_selection_mode = Some(BlockSelectionMode::ExecutionOnly);
    let mut config = Config::load(None, args).expect("cli load");
    config.builder.builders = vec!["not a url".to_string()];
    let (_dir, path) = validators_file(&two_validators());
    let result = ServiceBuilder::new(config).build_validator_store(Some(&path));
    let Err(err) = result else {
        panic!("malformed builder url must not publish a store");
    };
    match err {
        ConfigError::Invalid { field, message, .. } => {
            assert_eq!(field, "builder.builders");
            assert!(message.contains("not a url"), "{message}");
        }
        other => panic!("expected Invalid, got {other}"),
    }
}

#[test]
fn proposer_pool_reports_a_six_second_block_production_budget() {
    let config = Config {
        proposer_nodes: vec!["http://127.0.0.1:1".to_string()],
        block_production_timeout: Some(6),
        ..Config::default()
    };
    let manager = ServiceBuilder::new(config)
        .build_proposer_bn_manager()
        .expect("proposer pool")
        .expect("proposer_nodes is set");
    let budgets = manager.operation_timeouts().expect("operator budgets");
    assert_eq!(budgets.block_production, Duration::from_secs(6));
    assert_eq!(budgets.block_publication, Duration::from_secs(2));
    assert_eq!(budgets.attestation_fetch, Duration::from_secs(4));
    assert_eq!(budgets.attestation_submit, Duration::from_secs(2));
    assert_eq!(budgets.aggregate_fetch, Duration::from_secs(2));
    assert_eq!(budgets.duty_fetch, Duration::from_secs(10));
    assert_eq!(budgets.preparation, Duration::from_secs(3));
}

#[test]
fn proposer_pool_applies_each_configured_timeout() {
    let config = Config {
        proposer_nodes: vec!["http://127.0.0.1:1".to_string()],
        block_production_timeout: Some(6),
        attestation_timeout: Some(7),
        aggregate_timeout: Some(8),
        duty_fetch_timeout: Some(9),
        ..Config::default()
    };
    let budgets = ServiceBuilder::new(config)
        .build_proposer_bn_manager()
        .expect("proposer pool")
        .expect("proposer_nodes is set")
        .operation_timeouts()
        .expect("operator budgets")
        .clone();
    assert_eq!(budgets.block_production, Duration::from_secs(6));
    assert_eq!(budgets.attestation_fetch, Duration::from_secs(7));
    assert_eq!(budgets.aggregate_fetch, Duration::from_secs(8));
    assert_eq!(budgets.aggregate_submit, Duration::from_secs(8));
    assert_eq!(budgets.duty_fetch, Duration::from_secs(9));
    assert_eq!(budgets.block_publication, Duration::from_secs(2));
    assert_eq!(budgets.sync_message, Duration::from_secs(2));
    assert_eq!(budgets.sync_contribution, Duration::from_secs(2));
}

#[test]
fn proposer_pool_without_timeout_knobs_uses_the_builtin_budgets() {
    let config =
        Config { proposer_nodes: vec!["http://127.0.0.1:1".to_string()], ..Config::default() };
    let budgets = ServiceBuilder::new(config)
        .build_proposer_bn_manager()
        .expect("proposer pool")
        .expect("proposer_nodes is set")
        .operation_timeouts()
        .expect("builtin budgets are still stored")
        .clone();
    let defaults = bn_manager::OperationTimeouts::default();
    assert_eq!(budgets.block_production, defaults.block_production);
    assert_eq!(budgets.block_publication, defaults.block_publication);
    assert_eq!(budgets.attestation_fetch, defaults.attestation_fetch);
    assert_eq!(budgets.aggregate_fetch, defaults.aggregate_fetch);
    assert_eq!(budgets.duty_fetch, defaults.duty_fetch);
    assert_eq!(budgets.block_production, Duration::from_secs(3));
}

#[test]
fn empty_proposer_nodes_builds_no_pool() {
    let config = Config {
        proposer_nodes: Vec::new(),
        block_production_timeout: Some(6),
        ..Config::default()
    };
    let built = ServiceBuilder::new(config).build_proposer_bn_manager().expect("empty list");
    assert!(built.is_none());
}

#[test]
fn operation_timeouts_clamp_without_validate() {
    let config = Config {
        proposer_nodes: vec!["http://127.0.0.1:1".to_string()],
        block_production_timeout: Some(u64::MAX),
        attestation_timeout: Some(10_000),
        aggregate_timeout: Some(u64::MAX),
        duty_fetch_timeout: Some(61),
        ..Config::default()
    };
    let budgets = config.operation_timeouts();
    assert_eq!(budgets.block_production, Duration::from_secs(60));
    assert_eq!(budgets.attestation_fetch, Duration::from_secs(60));
    assert_eq!(budgets.aggregate_fetch, Duration::from_secs(60));
    assert_eq!(budgets.aggregate_submit, Duration::from_secs(60));
    assert_eq!(budgets.duty_fetch, Duration::from_secs(60));
    let stored = ServiceBuilder::new(config)
        .build_proposer_bn_manager()
        .expect("pool")
        .expect("nodes")
        .operation_timeouts()
        .expect("clamped budgets")
        .clone();
    assert_eq!(stored.block_production, Duration::from_secs(60));
    assert_eq!(stored.duty_fetch, Duration::from_secs(60));
}

#[test]
fn sixty_seconds_is_accepted_and_sixty_one_is_rejected() {
    let mut accepted = Config::load(None, StartArgs::default()).expect("defaults");
    accepted.block_production_timeout = Some(60);
    accepted.validate().expect("60s is one slot");
    assert_eq!(accepted.operation_timeouts().block_production, Duration::from_secs(60));

    for secs in [61u64, u64::MAX] {
        let mut config = Config::load(None, StartArgs::default()).expect("defaults");
        config.block_production_timeout = Some(secs);
        config.attestation_timeout = Some(secs);
        config.aggregate_timeout = Some(secs);
        config.duty_fetch_timeout = Some(secs);
        let err = config.validate().expect_err("above the slot");
        let message = err.to_string();
        assert!(message.contains("1..=60"), "{secs}: {message}");
        assert!(message.contains(&secs.to_string()), "{secs}: {message}");
    }
}

#[test]
fn proposer_pool_rejects_a_non_http_url() {
    let config = Config {
        proposer_nodes: vec!["ftp://127.0.0.1:1".to_string()],
        block_production_timeout: Some(6),
        ..Config::default()
    };
    let result = ServiceBuilder::new(config).build_proposer_bn_manager();
    let Err(err) = result else {
        panic!("a non-http proposer url must not build a manager");
    };
    assert_eq!(
        err.to_string(),
        "invalid beacon URL: failed to create proposer BnManager: invalid endpoint: endpoint must use http or https scheme: ftp://127.0.0.1:1"
    );
}

#[test]
fn proposer_budget_and_global_mode_do_not_consult_a_fork_schedule() {
    let mut args = StartArgs::default();
    args.builder.block_selection_mode = Some(BlockSelectionMode::BuilderAlways);
    let mut config = Config::load(None, args).expect("load");
    config.proposer_nodes = vec!["http://127.0.0.1:1".to_string()];
    config.block_production_timeout = Some(6);
    let manager = ServiceBuilder::new(config.clone())
        .build_proposer_bn_manager()
        .expect("pool")
        .expect("nodes");
    assert_eq!(
        manager.operation_timeouts().expect("budgets").block_production,
        Duration::from_secs(6)
    );
    let store = store_from(config, &two_validators());
    assert_plain_and_override(
        &store,
        BlockSelectionMode::BuilderAlways,
        BlockSelectionMode::BuilderOnly,
    );
}
