//! Top-level `--graffiti` applied by [`rvc::config::ServiceBuilder::build_validator_store`].

use std::io::Write;
use std::sync::{Arc, Mutex};

use bn_manager::{BeaconNodeClient, MockBeaconNodeClient, ProduceBlockResponse};
use crypto::SecretKey;
use eth_types::{decode_beacon_block_body_electra, BeaconBlock, ForkSchedule, SignedBeaconBlock};
use keymanager_api::traits::ValidatorConfigManager;
use rvc::beacon_adapter::BeaconBlockAdapter;
use rvc::config::{Config, ServiceBuilder};
use rvc::keymanager_adapters::ValidatorConfigManagerAdapter;
use signer::StubValidatorSigner;
use tempfile::TempDir;
use validator_store::{parse_graffiti, DefaultUpdate, ValidatorStore};

fn fee_recipient_toml(extra: &str) -> String {
    let fr = format!("0x{}", hex::encode([0xaau8; 20]));
    format!("[defaults]\nfee_recipient = \"{fr}\"\n{extra}")
}

fn build_store(graffiti: Option<&str>, toml_body: &str) -> (TempDir, Arc<ValidatorStore>) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("validators.toml");
    std::fs::write(&path, toml_body).expect("write validators.toml");
    let config = Config { graffiti: graffiti.map(str::to_string), ..Config::default() };
    let store =
        ServiceBuilder::new(config).build_validator_store(Some(&path)).expect("validator store");
    (dir, store)
}

fn graffiti_from_query(raw: Option<String>) -> [u8; 32] {
    let Some(raw) = raw else {
        return [0xff; 32];
    };
    let hex_str = raw.strip_prefix("0x").unwrap_or(&raw);
    let bytes = hex::decode(hex_str).unwrap_or_else(|_| vec![0xee; 32]);
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// BN stamps the produce-query graffiti into the body so the published block
/// only matches when startup actually passed `--graffiti` down.
fn echoing_beacon() -> (MockBeaconNodeClient, Arc<Mutex<Vec<SignedBeaconBlock>>>) {
    let published = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&published);
    let client = MockBeaconNodeClient::new()
        .with_produce_block_v3(|slot, _randao, graffiti, _boost| {
            let mut body = eth_types::external_vector_electra_body();
            body.graffiti = graffiti_from_query(graffiti);
            let block = BeaconBlock {
                slot,
                proposer_index: 42,
                parent_root: [0x11; 32],
                state_root: [0x22; 32],
                body: body.as_ssz_bytes(),
            };
            Ok(ProduceBlockResponse {
                data: serde_json::to_value(&block).expect("block json"),
                is_blinded: false,
                consensus_version: "fulu".to_string(),
                execution_payload_value: Some("1".to_string()),
                is_ssz: false,
                ssz_bytes: None,
                payload_included: false,
                builder_url: None,
                consensus_block_value: None,
            })
        })
        .with_publish_block(move |block, _version, _url| {
            captured.lock().expect("published blocks").push(block);
            Ok(())
        });
    (client, published)
}

#[derive(Clone)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buf").extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn top_level_graffiti_reaches_effective_graffiti() {
    let pk = [0x42u8; 48];
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = Arc::clone(&buf);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || LogBuf(Arc::clone(&writer)))
        .finish();
    let hostile = "a\r\nb\u{1b}[31m";
    tracing::subscriber::with_default(subscriber, || {
        let (_dir, store) = build_store(Some("cli-graf"), &fee_recipient_toml(""));
        assert_eq!(store.effective_graffiti(&pk), Some(parse_graffiti("cli-graf")));
        let (_dir, _store) = build_store(Some(hostile), &fee_recipient_toml(""));
    });
    let logged = String::from_utf8(buf.lock().expect("log buf").clone()).expect("utf8 log");
    assert!(logged.contains(&hex::encode(parse_graffiti("cli-graf"))), "{logged}");
    assert!(logged.contains(&hex::encode(parse_graffiti(hostile))), "{logged}");
    assert!(!logged.contains('\u{1b}'), "{logged:?}");
    assert!(!logged.contains("\r\n"), "{logged:?}");
    assert_eq!(
        logged.lines().filter(|l| l.contains("Created validator store")).count(),
        2,
        "{logged:?}"
    );
}

#[tokio::test]
async fn top_level_graffiti_reaches_a_produced_block() {
    let (_dir, store) = build_store(Some("block-graf"), &fee_recipient_toml(""));
    let (client, published) = echoing_beacon();
    let beacon: Arc<dyn BeaconNodeClient> = Arc::new(client);
    let service = block_service::BlockService::new(
        Arc::new(StubValidatorSigner::new()),
        Arc::new(BeaconBlockAdapter(beacon)),
        store,
        Arc::new(ForkSchedule::unscheduled_gloas()),
        [0xaa; 32],
    );
    let pubkey = SecretKey::generate().public_key();
    service.propose_block(32, &pubkey, 42, None).await.expect("propose");

    let blocks = published.lock().expect("published blocks");
    assert_eq!(blocks.len(), 1, "publish path must receive the produced block");
    let body = decode_beacon_block_body_electra(&blocks[0].message.body).expect("electra body");
    assert_eq!(body.graffiti, parse_graffiti("block-graf"));
}

#[test]
fn per_validator_graffiti_beats_the_top_level_knob() {
    let pk = [0x11u8; 48];
    let pk_hex = format!("0x{}", hex::encode(pk));
    let toml = fee_recipient_toml(&format!(
        "graffiti = \"file-graf\"\n\n[[validators]]\npubkey = \"{pk_hex}\"\ngraffiti = \"per-val\"\n"
    ));
    let (_dir, store) = build_store(Some("cli-graf"), &toml);
    assert_eq!(store.effective_graffiti(&pk), Some(parse_graffiti("per-val")));
    assert_eq!(store.effective_graffiti(&[0x22u8; 48]), Some(parse_graffiti("cli-graf")));
}

#[test]
fn keymanager_runtime_default_beats_the_top_level_knob() {
    let pk = [0x33u8; 48];
    let (_dir, store) = build_store(Some("cli-graf"), &fee_recipient_toml(""));
    assert_eq!(store.effective_graffiti(&pk), Some(parse_graffiti("cli-graf")));
    store.apply_default_update(DefaultUpdate {
        graffiti: Some(Some(parse_graffiti("km-graf"))),
        ..DefaultUpdate::default()
    });
    assert_eq!(store.effective_graffiti(&pk), Some(parse_graffiti("km-graf")));
}

#[test]
fn keymanager_save_persists_cli_graffiti_over_the_file_default() {
    let pk = [0x55u8; 48];
    let pk_hex = format!("0x{}", hex::encode(pk));
    let body = fee_recipient_toml(&format!(
        "graffiti = \"file-graf\"\n\n[[validators]]\npubkey = \"{pk_hex}\"\n"
    ));

    let (dir, store) = build_store(Some("cli-graf"), &body);
    let path = dir.path().join("validators.toml");
    let before = std::fs::read_to_string(&path).expect("validators file");
    assert!(before.contains("file-graf"), "startup must not rewrite the file: {before}");
    assert!(!before.contains("cli-graf"), "{before}");

    let adapter = ValidatorConfigManagerAdapter::new(Arc::clone(&store));
    adapter.set_fee_recipient(&pk, [0xab; 20]).expect("keymanager save");
    let reloaded = ValidatorStore::load_from_config(&path).expect("reload");
    assert_eq!(reloaded.effective_graffiti(&[0x99; 48]), Some(parse_graffiti("cli-graf")));

    let (dir, store) = build_store(None, &body);
    let path = dir.path().join("validators.toml");
    let adapter = ValidatorConfigManagerAdapter::new(store);
    adapter.set_fee_recipient(&pk, [0xab; 20]).expect("keymanager save");
    let reloaded = ValidatorStore::load_from_config(&path).expect("reload");
    assert_eq!(reloaded.effective_graffiti(&[0x99; 48]), Some(parse_graffiti("file-graf")));
}

#[test]
fn absent_graffiti_leaves_defaults_untouched() {
    let pk = [0x44u8; 48];
    let (_dir, with_file) = build_store(None, &fee_recipient_toml("graffiti = \"file-graf\"\n"));
    assert_eq!(with_file.effective_graffiti(&pk), Some(parse_graffiti("file-graf")));

    let (_dir, without) = build_store(None, &fee_recipient_toml(""));
    assert!(without.effective_graffiti(&pk).is_none());
}
