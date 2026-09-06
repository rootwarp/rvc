//! ARCH-4b: proposer-config URL apply path writes to `ValidatorStore`.
//!
//! Covers fee-recipient rotation, `default_config` defaults, malformed entries
//! (warn + leave previous), and failed fetch (401 → unchanged + failure metric).

use std::sync::Arc;
use std::time::Duration;

use rvc::background_tasks::config_url::{
    apply_proposer_config_updates, fetch_proposer_config, start_proposer_config_refresh,
    ProposerConfigUrlSettings,
};
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

/// Drive one successful fetch+apply via the real refresh task, then cancel.
async fn run_one_refresh_tick(url: String, store: Arc<ValidatorStore>) {
    let settings = ProposerConfigUrlSettings {
        url,
        refresh_interval: Duration::from_secs(3600),
        token: None,
        insecure: true,
    };
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();
    let handle = tokio::spawn(async move {
        start_proposer_config_refresh(settings, shutdown_clone, move |updates, default_update| {
            apply_proposer_config_updates(&store, updates, default_update);
        })
        .await;
    });
    // Initial fetch runs immediately at task start.
    tokio::time::sleep(Duration::from_millis(150)).await;
    shutdown.cancel();
    handle.await.expect("refresh task joined");
}

#[tokio::test]
async fn a_rotated_fee_recipient_reaches_the_store() {
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
    let handle = tokio::spawn(async move {
        start_proposer_config_refresh(settings, shutdown_clone, move |updates, default_update| {
            apply_proposer_config_updates(&store_task, updates, default_update);
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

    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store)).await;

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

    run_one_refresh_tick(mock_server.uri(), Arc::clone(&store)).await;

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

    // Valid JSON / fetch path; hex mapping fails in apply (not at fetch parse).
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

    let (updates, default_update) =
        fetch_proposer_config(&mock_server.uri(), None, true).await.expect("fetch succeeds");
    apply_proposer_config_updates(&store, updates, default_update);

    assert_eq!(
        store.effective_fee_recipient(&pk),
        fee_a(),
        "malformed fee_recipient must leave the previous value intact"
    );
}

#[tokio::test]
async fn an_http_401_leaves_all_previous_values_intact() {
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
    let handle = tokio::spawn(async move {
        start_proposer_config_refresh(settings, shutdown_clone, move |updates, default_update| {
            apply_proposer_config_updates(&store_task, updates, default_update);
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
