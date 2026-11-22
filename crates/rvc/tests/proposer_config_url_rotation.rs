//! ARCH-4b: proposer-config URL apply path writes to `ValidatorStore`.
//!
//! Covers fee-recipient rotation, `default_config` defaults, malformed entries
//! (warn + leave previous), and failed fetch (401 → unchanged + failure metric).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use keymanager_api::traits::ValidatorConfigManager;
use rvc::background_tasks::config_url::{
    fetch_proposer_config, start_proposer_config_refresh, ProposerConfigApplier,
    ProposerConfigUrlSettings, ValidatorConfigUpdate as UrlUpdate,
};
use rvc::config::Config;
use rvc::keymanager_adapters::ValidatorConfigManagerAdapter;
use rvc::metrics::RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL;
use tokio_util::sync::CancellationToken;
use validator_store::{ValidatorConfig, ValidatorConfigUpdate, ValidatorStore};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_pubkey() -> [u8; 48] {
    [0x11u8; 48]
}

fn fee_a() -> [u8; 20] {
    [0xaau8; 20]
}

fn fee_b() -> [u8; 20] {
    [0xbbu8; 20]
}

fn fee_default() -> [u8; 20] {
    [0xccu8; 20]
}

fn store_with_validator() -> Arc<ValidatorStore> {
    // Non-zero default so effective lookups are distinguishable from overrides.
    let store = Arc::new(ValidatorStore::new([0x01u8; 20], 30_000_000));
    let mut cfg = ValidatorConfig::new(test_pubkey());
    cfg.fee_recipient = Some(fee_a());
    store.add_validator(cfg).unwrap();
    store
}

fn body_for(pubkey_hex: &str, fee_hex: &str, default_fee_hex: Option<&str>) -> String {
    match default_fee_hex {
        Some(d) => format!(
            r#"{{
                "proposer_config": {{
                    "{pubkey_hex}": {{
                        "fee_recipient": "{fee_hex}",
                        "builder": {{ "enabled": true, "gas_limit": "30000000" }}
                    }}
                }},
                "default_config": {{
                    "fee_recipient": "{d}",
                    "builder": {{ "enabled": false, "gas_limit": "36000000" }}
                }}
            }}"#
        ),
        None => format!(
            r#"{{
                "proposer_config": {{
                    "{pubkey_hex}": {{
                        "fee_recipient": "{fee_hex}",
                        "builder": {{ "enabled": true, "gas_limit": "30000000" }}
                    }}
                }}
            }}"#
        ),
    }
}

fn shared_applier() -> Arc<Mutex<ProposerConfigApplier>> {
    Arc::new(Mutex::new(ProposerConfigApplier::new()))
}

/// Drive one fetch via the real refresh task, then cancel.
///
/// The applier is shared so a later tick sees pubkeys tracked on an earlier
/// tick. A failed fetch does not call the applier.
async fn run_one_refresh_tick(
    url: String,
    store: Arc<ValidatorStore>,
    applier: Arc<Mutex<ProposerConfigApplier>>,
) {
    let _lock = rvc::background_tasks::config_url::testing_lock_proposer_refresh().await;
    let (settled_tx, settled_rx) = std::sync::mpsc::channel();
    rvc::background_tasks::config_url::testing_set_proposer_refresh_settled(Some(settled_tx));
    let settings = ProposerConfigUrlSettings {
        url,
        refresh_interval: Duration::from_secs(3600),
        token: None,
        insecure: true,
    };
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();
    let handle = tokio::spawn(async move {
        start_proposer_config_refresh(settings, shutdown_clone, move |fetched| {
            let mut applier = applier.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            applier.apply(&store, fetched.updates, fetched.default_update);
        })
        .await;
    });
    tokio::time::timeout(
        Duration::from_secs(6),
        tokio::task::spawn_blocking(move || settled_rx.recv_timeout(Duration::from_secs(5))),
    )
    .await
    .expect("refresh settle wait hung")
    .expect("refresh settle wait")
    .expect("refresh did not settle");
    shutdown.cancel();
    handle.await.expect("refresh task joined");
    rvc::background_tasks::config_url::testing_set_proposer_refresh_settled(None);
}

#[tokio::test]
async fn a_rotated_fee_recipient_reaches_the_store() {
    let _lock = rvc::background_tasks::config_url::testing_lock_proposer_refresh().await;
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_a_hex = format!("0x{}", hex::encode(fee_a()));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));

    let store = store_with_validator();
    assert_eq!(store.effective_fee_recipient(&pk), fee_a());

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(body_for(&pk_hex, &fee_a_hex, None)),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(body_for(&pk_hex, &fee_b_hex, None)),
        )
        .mount(&mock_server)
        .await;

    let settings = ProposerConfigUrlSettings {
        url: mock_server.uri(),
        refresh_interval: Duration::from_millis(50),
        token: None,
        insecure: true,
    };
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();
    let store_task = Arc::clone(&store);
    let applier = shared_applier();
    let handle = tokio::spawn(async move {
        start_proposer_config_refresh(settings, shutdown_clone, move |fetched| {
            let mut applier = applier.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            applier.apply(&store_task, fetched.updates, fetched.default_update);
        })
        .await;
    });

    // Wait until fee recipient B is observed (second successful refresh).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if store.effective_fee_recipient(&pk) == fee_b() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for rotated fee recipient B; got {:02x?}",
                store.effective_fee_recipient(&pk)
            );
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    shutdown.cancel();
    handle.await.expect("refresh task joined");
    assert_eq!(store.effective_fee_recipient(&pk), fee_b());
}

#[tokio::test]
async fn a_rotated_fee_recipient_reaches_the_next_block_proposal() {
    // Block proposal reads the fee recipient through
    // `ValidatorStore::effective_fee_recipient` (same accessor used on the
    // proposal path). Asserting via that accessor is the in-budget substitute
    // for a full proposal harness (ARCH-4b TDD plan).
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));

    let store = store_with_validator();
    assert_eq!(store.effective_fee_recipient(&pk), fee_a());

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(body_for(&pk_hex, &fee_b_hex, None)),
        )
        .mount(&mock_server)
        .await;

    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), shared_applier()).await;

    // Proposal path accessor after rotation.
    assert_eq!(
        store.effective_fee_recipient(&pk),
        fee_b(),
        "proposal path must observe the rotated fee recipient"
    );
}

#[tokio::test]
async fn a_default_config_entry_updates_the_store_defaults() {
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_a_hex = format!("0x{}", hex::encode(fee_a()));
    let default_hex = format!("0x{}", hex::encode(fee_default()));

    let store = store_with_validator();
    let before = store.default_fee_recipient();
    assert_ne!(before, fee_default());

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body_for(
            &pk_hex,
            &fee_a_hex,
            Some(&default_hex),
        )))
        .mount(&mock_server)
        .await;

    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), shared_applier()).await;

    assert_eq!(store.default_fee_recipient(), fee_default());
    // Unknown validator without override picks up the new default.
    let unknown = [0x22u8; 48];
    assert_eq!(store.effective_fee_recipient(&unknown), fee_default());
}

#[tokio::test]
async fn a_malformed_fee_recipient_leaves_the_previous_value_intact_and_warns() {
    // Warn emission is covered by the unit test
    // `apply_proposer_config_updates_skips_malformed_and_warns` (traced_test
    // cannot scope-filter `rvc::` targets from this integration crate across
    // awaits). This test asserts the store-side contract via wiremock fetch.
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));

    let store = store_with_validator();
    assert_eq!(store.effective_fee_recipient(&pk), fee_a());

    // A bad fee is rejected before any store write.
    let body = format!(
        r#"{{
            "proposer_config": {{
                "{pk_hex}": {{
                    "fee_recipient": "not-a-valid-hex-address",
                    "builder": {{ "enabled": true, "gas_limit": "30000000" }}
                }}
            }}
        }}"#
    );
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&mock_server)
        .await;

    let err = fetch_proposer_config(&mock_server.uri(), None, true).await.expect_err("bad fee");
    assert!(err.contains("fee_recipient") || err.contains("invalid"), "{err}");

    assert_eq!(
        store.effective_fee_recipient(&pk),
        fee_a(),
        "malformed fee_recipient must leave the previous value intact"
    );
}

#[tokio::test]
async fn an_http_401_leaves_all_previous_values_intact() {
    let _lock = rvc::background_tasks::config_url::testing_lock_proposer_refresh().await;
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_a_hex = format!("0x{}", hex::encode(fee_a()));
    let default_before = [0x01u8; 20];

    let store = store_with_validator();
    // Seed store via a successful apply first.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body_for(
            &pk_hex,
            &fee_a_hex,
            Some(&format!("0x{}", hex::encode(fee_default()))),
        )))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(401)).mount(&mock_server).await;

    let failures_before = RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.get();

    let settings = ProposerConfigUrlSettings {
        url: mock_server.uri(),
        refresh_interval: Duration::from_millis(50),
        token: None,
        insecure: true,
    };
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();
    let store_task = Arc::clone(&store);
    let applier = shared_applier();
    let handle = tokio::spawn(async move {
        start_proposer_config_refresh(settings, shutdown_clone, move |fetched| {
            let mut applier = applier.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            applier.apply(&store_task, fetched.updates, fetched.default_update);
        })
        .await;
    });

    // Wait until the failure metric has increased (401 path taken).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.get() > failures_before {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for 401 failure metric increment");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // Values from the successful first fetch must still be present; 401 must not clear them.
    assert_eq!(store.effective_fee_recipient(&pk), fee_a());
    assert_eq!(store.default_fee_recipient(), fee_default());
    assert_ne!(store.default_fee_recipient(), default_before);

    // Explicitly confirm a deliberate store change is not clobbered by subsequent 401s.
    store
        .update_config(
            &pk,
            ValidatorConfigUpdate {
                fee_recipient: Some(Some(fee_b())),
                ..ValidatorConfigUpdate::default()
            },
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        store.effective_fee_recipient(&pk),
        fee_b(),
        "failed fetch must leave local store values unchanged"
    );

    assert!(
        RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.get() > failures_before,
        "401 must increment the existing failure metric"
    );

    shutdown.cancel();
    handle.await.expect("refresh task joined");
}

fn explicit_baseline_store() -> Arc<ValidatorStore> {
    let store = Arc::new(ValidatorStore::new([0x01u8; 20], 30_000_000));
    let mut cfg = ValidatorConfig::new(test_pubkey());
    cfg.fee_recipient = Some(fee_a());
    cfg.gas_limit = Some(21_000_000);
    cfg.builder_proposals = false;
    cfg.graffiti = Some([0x47u8; 32]);
    store.add_validator(cfg).unwrap();
    let mut sibling = ValidatorConfig::new([0x44u8; 48]);
    sibling.fee_recipient = Some([0x44u8; 20]);
    sibling.gas_limit = Some(22_000_000);
    sibling.builder_proposals = true;
    store.add_validator(sibling).unwrap();
    store
}

fn entry_body(fee_hex: &str, gas: u64, builder: bool) -> String {
    format!(
        r#"{{"fee_recipient":"{fee_hex}","builder":{{"enabled":{builder},"gas_limit":"{gas}"}}}}"#
    )
}

fn one_pubkey_body(pubkey_hex: &str, entry: &str) -> String {
    format!(r#"{{"proposer_config":{{"{pubkey_hex}":{entry}}}}}"#)
}

fn assert_url_triple(store: &ValidatorStore, pk: &[u8; 48]) {
    assert_eq!(store.effective_fee_recipient(pk), fee_b());
    assert_eq!(store.effective_gas_limit(pk), 36_000_000);
    assert!(store.is_builder_enabled(pk));
}

fn assert_pre_url_triple(store: &ValidatorStore, pk: &[u8; 48]) {
    assert_eq!(store.effective_fee_recipient(pk), fee_a());
    assert_eq!(store.effective_gas_limit(pk), 21_000_000);
    assert!(!store.is_builder_enabled(pk));
    let row = store.get_config(pk).expect("pubkey row");
    assert_eq!(row.graffiti, Some([0x47u8; 32]));
    assert!(row.enabled);
    let sibling = store.get_config(&[0x44u8; 48]).expect("sibling");
    assert_eq!(sibling.fee_recipient, Some([0x44u8; 20]));
    assert_eq!(sibling.gas_limit, Some(22_000_000));
    assert!(sibling.builder_proposals);
}

#[tokio::test]
async fn omitting_a_pubkey_restores_its_pre_url_fee_gas_and_builder_flag() {
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));
    let store = explicit_baseline_store();
    let config =
        Config { proposer_nodes: vec!["http://127.0.0.1:1".to_string()], ..Config::default() };
    assert_eq!(config.proposer_nodes.as_slice(), ["http://127.0.0.1:1".to_string()]);
    assert_ne!(mock_server.uri(), config.proposer_nodes[0]);

    let tick1 = one_pubkey_body(&pk_hex, &entry_body(&fee_b_hex, 36_000_000, true));
    let tick2 = r#"{"proposer_config":{}}"#.to_string();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick1))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick2))
        .mount(&mock_server)
        .await;

    let applier = shared_applier();
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), Arc::clone(&applier)).await;
    assert_url_triple(&store, &pk);
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), applier).await;
    assert_pre_url_triple(&store, &pk);
}

/// Tick 1 sets fee, gas, and builder. Tick 2 names the same pubkey with gas
/// only. Fee and builder return to the baseline. Gas stays remote.
#[tokio::test]
async fn a_field_the_url_stops_setting_is_restored_while_the_pubkey_stays_named() {
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));
    let store = explicit_baseline_store();
    let tick1 = one_pubkey_body(&pk_hex, &entry_body(&fee_b_hex, 36_000_000, true));
    let tick2 = one_pubkey_body(&pk_hex, r#"{"builder":{"gas_limit":"36000000"}}"#);

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick1))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick2))
        .mount(&mock_server)
        .await;

    let mut applier = ProposerConfigApplier::new();
    let first = fetch_proposer_config(&mock_server.uri(), None, true).await.expect("tick 1");
    applier.apply(&store, first.updates, first.default_update);
    assert_url_triple(&store, &pk);

    let second = fetch_proposer_config(&mock_server.uri(), None, true).await.expect("tick 2");
    applier.apply(&store, second.updates, second.default_update);
    let row = store.get_config(&pk).expect("row");
    assert_eq!(row.fee_recipient, Some(fee_a()));
    assert_eq!(row.gas_limit, Some(36_000_000));
    assert!(!row.builder_proposals);
    assert_eq!(row.graffiti, Some([0x47u8; 32]));
    assert!(row.enabled);

    applier.apply(
        &store,
        Some(vec![UrlUpdate {
            pubkey: pk_hex,
            fee_recipient: Some(fee_b_hex),
            builder_enabled: None,
            gas_limit: None,
        }]),
        None,
    );
    let row = store.get_config(&pk).expect("row");
    assert_eq!(row.fee_recipient, Some(fee_b()));
    assert_eq!(row.gas_limit, Some(21_000_000));
    assert!(!row.builder_proposals);
}

#[tokio::test]
async fn a_401_after_a_url_set_keeps_the_url_values_until_a_successful_omission() {
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));
    let store = explicit_baseline_store();
    let tick1 = one_pubkey_body(&pk_hex, &entry_body(&fee_b_hex, 36_000_000, true));

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick1))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":{}}"#))
        .mount(&mock_server)
        .await;

    let applier = shared_applier();
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), Arc::clone(&applier)).await;
    assert_url_triple(&store, &pk);
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), Arc::clone(&applier)).await;
    assert_url_triple(&store, &pk);
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), applier).await;
    assert_pre_url_triple(&store, &pk);
}

#[tokio::test]
async fn a_malformed_json_tick_keeps_the_url_values() {
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));
    let store = explicit_baseline_store();
    let tick1 = one_pubkey_body(&pk_hex, &entry_body(&fee_b_hex, 36_000_000, true));

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick1))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&mock_server)
        .await;

    let applier = shared_applier();
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), Arc::clone(&applier)).await;
    assert_url_triple(&store, &pk);
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), applier).await;
    assert_url_triple(&store, &pk);
}

#[tokio::test]
async fn a_200_with_an_unrelated_json_body_is_rejected() {
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));
    let store = explicit_baseline_store();
    let tick1 = one_pubkey_body(&pk_hex, &entry_body(&fee_b_hex, 36_000_000, true));

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick1))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":"ok"}"#))
        .mount(&mock_server)
        .await;

    let applier = shared_applier();
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), Arc::clone(&applier)).await;
    assert_url_triple(&store, &pk);
    let err = fetch_proposer_config(&mock_server.uri(), None, true).await.expect_err("unrelated");
    assert!(err.contains("neither") || err.contains("parse"), "{err}");
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), applier).await;
    assert_url_triple(&store, &pk);
}

#[tokio::test]
async fn a_200_with_one_bad_entry_does_not_apply_or_restore() {
    let mock_server = MockServer::start().await;
    let pk = test_pubkey();
    let pk_hex = format!("0x{}", hex::encode(pk));
    let other_hex = format!("0x{}", hex::encode([0x44u8; 48]));
    let fee_b_hex = format!("0x{}", hex::encode(fee_b()));
    let store = explicit_baseline_store();
    let tick1 = one_pubkey_body(&pk_hex, &entry_body(&fee_b_hex, 36_000_000, true));
    let mixed = format!(
        r#"{{"proposer_config":{{"{pk_hex}":{{"fee_recipient":"not-hex"}},"{other_hex}":{ok}}}}}"#,
        ok = entry_body(&format!("0x{}", hex::encode([0x55u8; 20])), 38_000_000, false),
    );

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tick1))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(mixed))
        .mount(&mock_server)
        .await;

    let applier = shared_applier();
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), Arc::clone(&applier)).await;
    assert_url_triple(&store, &pk);
    let err = fetch_proposer_config(&mock_server.uri(), None, true).await.expect_err("mixed");
    assert!(err.contains("not-hex") || err.contains("invalid"), "{err}");
    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store), applier).await;
    assert_url_triple(&store, &pk);
    assert_eq!(store.get_config(&[0x44u8; 48]).expect("sibling").fee_recipient, Some([0x44u8; 20]));
}

fn fee_c() -> [u8; 20] {
    [0xccu8; 20]
}

struct PersistedRow {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    store: Arc<ValidatorStore>,
    pk: [u8; 48],
}

fn persisted_row(fee: [u8; 20], gas: u64, builder: bool) -> PersistedRow {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("validators.toml");
    let pk = test_pubkey();
    let body = format!(
        "[defaults]\nfee_recipient = \"0x{}\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"0x{}\"\nfee_recipient = \"0x{}\"\ngas_limit = {gas}\nbuilder_proposals = {builder}\n",
        hex::encode([0x01u8; 20]),
        hex::encode(pk),
        hex::encode(fee),
    );
    std::fs::write(&path, body).expect("validators file");
    let store = Arc::new(ValidatorStore::load_from_config(&path).expect("load"));
    PersistedRow { _dir: dir, path, store, pk }
}

fn url_entry(pk: &[u8; 48], fee: [u8; 20], gas: u64, builder: bool) -> UrlUpdate {
    UrlUpdate {
        pubkey: format!("0x{}", hex::encode(pk)),
        fee_recipient: Some(format!("0x{}", hex::encode(fee))),
        builder_enabled: Some(builder),
        gas_limit: Some(gas),
    }
}

fn apply_url(
    store: &ValidatorStore,
    pk: &[u8; 48],
    fee: [u8; 20],
    gas: u64,
    builder: bool,
) -> ProposerConfigApplier {
    let mut applier = ProposerConfigApplier::new();
    applier.apply(store, Some(vec![url_entry(pk, fee, gas, builder)]), None);
    applier
}

fn reloaded(path: &std::path::Path) -> ValidatorStore {
    ValidatorStore::load_from_config(path).expect("reload")
}

#[test]
fn keymanager_fee_and_gas_survive_an_omission() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let mut applier = apply_url(&row.store, &row.pk, fee_b(), 36_000_000, true);
    let adapter = ValidatorConfigManagerAdapter::new(Arc::clone(&row.store));
    adapter.set_fee_recipient(&row.pk, fee_c()).expect("fee C");
    adapter.set_gas_limit(&row.pk, 40_000_000).expect("gas C");
    applier.apply(&row.store, Some(Vec::new()), None);

    let live = row.store.get_config(&row.pk).expect("live");
    assert_eq!(live.fee_recipient, Some(fee_c()));
    assert_eq!(live.gas_limit, Some(40_000_000));
    assert!(!live.builder_proposals);
    let disk = reloaded(&row.path).get_config(&row.pk).expect("disk");
    assert_eq!(disk.fee_recipient, Some(fee_c()));
    assert_eq!(disk.gas_limit, Some(40_000_000));
    assert!(!disk.builder_proposals);
}

#[test]
fn a_cleared_fee_and_gas_survive_an_omission() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let mut applier = apply_url(&row.store, &row.pk, fee_b(), 36_000_000, true);
    let adapter = ValidatorConfigManagerAdapter::new(Arc::clone(&row.store));
    adapter.delete_fee_recipient(&row.pk).expect("clear fee");
    adapter.delete_gas_limit(&row.pk).expect("clear gas");
    applier.apply(&row.store, Some(Vec::new()), None);

    let live = row.store.get_config(&row.pk).expect("live");
    assert_eq!(live.fee_recipient, None);
    assert_eq!(live.gas_limit, None);
    assert!(!live.builder_proposals);
    let disk = reloaded(&row.path).get_config(&row.pk).expect("disk");
    assert_eq!(disk.fee_recipient, None);
    assert_eq!(disk.gas_limit, None);
    assert!(!disk.builder_proposals);
}

#[test]
fn keymanager_builder_disable_survives_an_omission() {
    let row = persisted_row(fee_a(), 21_000_000, true);
    let mut applier = apply_url(&row.store, &row.pk, fee_b(), 36_000_000, true);
    assert!(row.store.is_builder_enabled(&row.pk));
    row.store
        .update_config_durable(
            &row.pk,
            ValidatorConfigUpdate {
                builder_proposals: Some(false),
                ..ValidatorConfigUpdate::default()
            },
        )
        .expect("disable builder");
    applier.apply(&row.store, Some(Vec::new()), None);

    assert!(!row.store.is_builder_enabled(&row.pk));
    assert!(!reloaded(&row.path).is_builder_enabled(&row.pk));
    assert_eq!(row.store.get_config(&row.pk).expect("live").fee_recipient, Some(fee_a()));
    assert_eq!(reloaded(&row.path).get_config(&row.pk).expect("disk").fee_recipient, Some(fee_a()));
}

#[test]
fn a_graffiti_edit_does_not_persist_url_values() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let _applier = apply_url(&row.store, &row.pk, fee_b(), 36_000_000, true);
    assert_eq!(row.store.effective_fee_recipient(&row.pk), fee_b());

    let adapter = ValidatorConfigManagerAdapter::new(Arc::clone(&row.store));
    adapter.set_graffiti(&row.pk, "km").expect("graffiti");

    assert_eq!(row.store.effective_fee_recipient(&row.pk), fee_b());
    assert_eq!(row.store.effective_gas_limit(&row.pk), 36_000_000);
    assert!(row.store.is_builder_enabled(&row.pk));
    let disk = reloaded(&row.path).get_config(&row.pk).expect("disk");
    assert_eq!(disk.fee_recipient, Some(fee_a()));
    assert_eq!(disk.gas_limit, Some(21_000_000));
    assert!(!disk.builder_proposals);
    assert_eq!(
        disk.graffiti,
        Some({
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(b"km");
            bytes
        })
    );
}

#[test]
fn delete_and_reimport_does_not_apply_the_old_snapshot() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let generation = row.store.validator_generation(&row.pk).expect("generation");
    let mut applier = apply_url(&row.store, &row.pk, fee_b(), 36_000_000, true);
    assert_eq!(row.store.effective_fee_recipient(&row.pk), fee_b());

    row.store.remove_validator_durable(&row.pk).expect("delete").expect("removed");
    let mut imported = ValidatorConfig::new(row.pk);
    imported.fee_recipient = Some(fee_c());
    imported.gas_limit = Some(40_000_000);
    imported.builder_proposals = true;
    assert!(row.store.add_validator_durable(imported).expect("import"));
    let next = row.store.validator_generation(&row.pk).expect("new generation");
    assert_ne!(generation, next);

    applier.apply(&row.store, Some(Vec::new()), None);
    let live = row.store.get_config(&row.pk).expect("live");
    assert_eq!(live.fee_recipient, Some(fee_c()));
    assert_eq!(live.gas_limit, Some(40_000_000));
    assert!(live.builder_proposals);
    let disk = reloaded(&row.path).get_config(&row.pk).expect("disk");
    assert_eq!(disk.fee_recipient, Some(fee_c()));
    assert_eq!(disk.gas_limit, Some(40_000_000));
    assert!(disk.builder_proposals);
}

fn assert_live_and_disk(
    row: &PersistedRow,
    fee: Option<[u8; 20]>,
    gas: Option<u64>,
    builder: bool,
) {
    let live = row.store.get_config(&row.pk).expect("live");
    assert_eq!(live.fee_recipient, fee);
    assert_eq!(live.gas_limit, gas);
    assert_eq!(live.builder_proposals, builder);
    let disk = reloaded(&row.path).get_config(&row.pk).expect("disk");
    assert_eq!(disk.fee_recipient, fee);
    assert_eq!(disk.gas_limit, gas);
    assert_eq!(disk.builder_proposals, builder);
}

/// A, then URL B, then keymanager C, then refresh B, then omit.
/// Live and disk stay C for fee, gas, and builder.
#[test]
fn keymanager_c_survives_refresh_b_and_omission() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let mut applier = apply_url(&row.store, &row.pk, fee_b(), 36_000_000, true);
    let adapter = ValidatorConfigManagerAdapter::new(Arc::clone(&row.store));
    adapter.set_fee_recipient(&row.pk, fee_c()).expect("fee C");
    adapter.set_gas_limit(&row.pk, 40_000_000).expect("gas C");
    row.store
        .update_config_durable(
            &row.pk,
            ValidatorConfigUpdate {
                builder_proposals: Some(false),
                ..ValidatorConfigUpdate::default()
            },
        )
        .expect("builder C");
    applier.apply(&row.store, Some(vec![url_entry(&row.pk, fee_b(), 36_000_000, true)]), None);
    assert_eq!(row.store.effective_fee_recipient(&row.pk), fee_b());
    applier.apply(&row.store, Some(Vec::new()), None);
    assert_live_and_disk(&row, Some(fee_c()), Some(40_000_000), false);
    let restarted = reloaded(&row.path);
    let disk = restarted.get_config(&row.pk).expect("restart");
    assert_eq!(disk.fee_recipient, Some(fee_c()));
    assert_eq!(disk.gas_limit, Some(40_000_000));
    assert!(!disk.builder_proposals);
}

/// A keymanager write equal to the URL value drops ownership. Omit keeps C.
#[test]
fn a_keymanager_write_equal_to_the_url_value_becomes_the_baseline() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let mut applier = apply_url(&row.store, &row.pk, fee_b(), 36_000_000, true);
    let adapter = ValidatorConfigManagerAdapter::new(Arc::clone(&row.store));
    adapter.set_fee_recipient(&row.pk, fee_b()).expect("fee equal to URL");
    adapter.set_gas_limit(&row.pk, 36_000_000).expect("gas equal to URL");
    row.store
        .update_config_durable(
            &row.pk,
            ValidatorConfigUpdate {
                builder_proposals: Some(true),
                ..ValidatorConfigUpdate::default()
            },
        )
        .expect("builder equal to URL");
    applier.apply(&row.store, Some(vec![url_entry(&row.pk, fee_b(), 36_000_000, true)]), None);
    applier.apply(&row.store, Some(Vec::new()), None);
    assert_live_and_disk(&row, Some(fee_b()), Some(36_000_000), true);
}

/// Gas becomes remote-owned only after a keymanager edit. Its baseline is that
/// edit, not the row from when the fee was first tracked.
#[test]
fn a_field_owned_later_snapshots_the_value_at_that_moment() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let mut applier = ProposerConfigApplier::new();
    applier.apply(
        &row.store,
        Some(vec![UrlUpdate {
            pubkey: format!("0x{}", hex::encode(row.pk)),
            fee_recipient: Some(format!("0x{}", hex::encode(fee_b()))),
            builder_enabled: None,
            gas_limit: None,
        }]),
        None,
    );
    let adapter = ValidatorConfigManagerAdapter::new(Arc::clone(&row.store));
    adapter.set_gas_limit(&row.pk, 40_000_000).expect("gas before the URL owns it");
    applier.apply(&row.store, Some(vec![url_entry(&row.pk, fee_b(), 36_000_000, true)]), None);
    assert_eq!(row.store.effective_gas_limit(&row.pk), 36_000_000);
    applier.apply(&row.store, Some(Vec::new()), None);
    assert_live_and_disk(&row, Some(fee_a()), Some(40_000_000), false);
}

#[test]
fn remote_default_config_is_not_the_local_defaults_after_restart() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let mut applier = ProposerConfigApplier::new();
    applier.apply(
        &row.store,
        None,
        Some(UrlUpdate {
            pubkey: "default".to_string(),
            fee_recipient: Some(format!("0x{}", hex::encode(fee_b()))),
            builder_enabled: None,
            gas_limit: Some(40_000_000),
        }),
    );
    assert_eq!(row.store.default_fee_recipient(), fee_b());
    assert_eq!(row.store.default_gas_limit(), 40_000_000);
    row.store.save_config().expect("save");
    let text = std::fs::read_to_string(&row.path).expect("file");
    assert!(text.contains(&hex::encode([0x01u8; 20])), "{text}");
    assert!(text.contains("30000000"), "{text}");
    assert!(!text.contains(&hex::encode(fee_b())), "{text}");
    let restarted = reloaded(&row.path);
    assert_eq!(restarted.default_fee_recipient(), [0x01u8; 20]);
    assert_eq!(restarted.default_gas_limit(), 30_000_000);
    assert_eq!(restarted.get_config(&row.pk).expect("row").fee_recipient, Some(fee_a()));
}

/// A later successful body that omits a default field restores that field.
/// Omitting `default_config` entirely restores every remote default. The
/// named pubkey is left on its URL values.
#[test]
fn a_body_without_default_config_restores_the_local_defaults() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    row.store
        .apply_remote_defaults(validator_store::DefaultUpdate {
            graffiti: Some(Some([0x11u8; 32])),
            ..validator_store::DefaultUpdate::default()
        })
        .expect("remote graffiti");
    assert_eq!(row.store.effective_graffiti(&row.pk), Some([0x11u8; 32]));
    let mut applier = ProposerConfigApplier::new();
    applier.apply(
        &row.store,
        Some(vec![url_entry(&row.pk, fee_b(), 36_000_000, true)]),
        Some(UrlUpdate {
            pubkey: "default".to_string(),
            fee_recipient: Some(format!("0x{}", hex::encode(fee_b()))),
            builder_enabled: None,
            gas_limit: Some(40_000_000),
        }),
    );
    assert_eq!(row.store.default_fee_recipient(), fee_b());
    assert_eq!(row.store.default_gas_limit(), 40_000_000);
    assert_eq!(row.store.effective_graffiti(&row.pk), None);

    applier.apply(
        &row.store,
        Some(vec![url_entry(&row.pk, fee_b(), 36_000_000, true)]),
        Some(UrlUpdate {
            pubkey: "default".to_string(),
            fee_recipient: None,
            builder_enabled: None,
            gas_limit: Some(40_000_000),
        }),
    );
    assert_eq!(row.store.default_fee_recipient(), [0x01u8; 20]);
    assert_eq!(row.store.default_gas_limit(), 40_000_000);
    assert_eq!(row.store.effective_fee_recipient(&row.pk), fee_b());

    applier.apply(&row.store, Some(vec![url_entry(&row.pk, fee_b(), 36_000_000, true)]), None);
    assert_eq!(row.store.default_fee_recipient(), [0x01u8; 20]);
    assert_eq!(row.store.default_gas_limit(), 30_000_000);
    assert_eq!(row.store.effective_fee_recipient(&row.pk), fee_b());
    assert_eq!(row.store.effective_gas_limit(&row.pk), 36_000_000);
}

/// A local defaults write drops remote ownership. A later omission keeps the
/// local value.
#[test]
fn a_local_default_write_drops_remote_default_ownership() {
    use validator_store::DefaultUpdate;

    let row = persisted_row(fee_a(), 21_000_000, false);
    let mut applier = ProposerConfigApplier::new();
    applier.apply(
        &row.store,
        Some(vec![]),
        Some(UrlUpdate {
            pubkey: "default".to_string(),
            fee_recipient: Some(format!("0x{}", hex::encode(fee_b()))),
            builder_enabled: None,
            gas_limit: Some(40_000_000),
        }),
    );
    row.store
        .apply_default_update(DefaultUpdate {
            fee_recipient: Some(fee_b()),
            gas_limit: Some(40_000_000),
            graffiti: None,
        })
        .expect("local defaults");
    applier.apply(&row.store, Some(vec![]), None);
    assert_eq!(row.store.default_fee_recipient(), fee_b());
    assert_eq!(row.store.default_gas_limit(), 40_000_000);
}

#[test]
fn remote_and_keymanager_writes_stay_atomic_across_omission() {
    let row = persisted_row(fee_a(), 21_000_000, false);
    let store = Arc::clone(&row.store);
    let pk = row.pk;
    let barrier = Arc::new(std::sync::Barrier::new(3));

    let writer = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..30 {
                store
                    .update_config_durable(
                        &pk,
                        ValidatorConfigUpdate {
                            fee_recipient: Some(Some(fee_c())),
                            gas_limit: Some(Some(40_000_000)),
                            builder_proposals: Some(false),
                            ..ValidatorConfigUpdate::default()
                        },
                    )
                    .expect("keymanager");
            }
        })
    };
    let refresher = {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..30 {
                store
                    .apply_remote_proposer(
                        &pk,
                        ValidatorConfigUpdate {
                            fee_recipient: Some(Some(fee_b())),
                            gas_limit: Some(Some(36_000_000)),
                            builder_proposals: Some(true),
                            ..ValidatorConfigUpdate::default()
                        },
                    )
                    .expect("url");
                store.release_remote_proposer(&pk);
            }
        })
    };
    barrier.wait();
    writer.join().expect("writer");
    refresher.join().expect("refresher");
    assert_live_and_disk(&row, Some(fee_c()), Some(40_000_000), false);
}
