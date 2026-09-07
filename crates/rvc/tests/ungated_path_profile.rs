//! Ungated 6.14 recordings: Gloas aggregate island sign (6.9b) and self-build
//! propose including the 6.20 envelope leg.
//!
//! No P1 1.1 column exists for these paths — do not compare to the A-9
//! attestation series. Local fixture keys; mock BN only.
//!
//! ```text
//! cargo test -p rvc --test ungated_path_profile -- --ignored --nocapture \
//!   --exact test_ungated_island_paths_report_p99 \
//!   -- --output /tmp/p6-6.14/ungated-runN.json
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use beacon::{
    HEADER_ETH_BLOB_DATA_INCLUDED, HEADER_ETH_CONSENSUS_VERSION,
    HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, PRODUCE_BLOCK_V4_PATH_PREFIX,
    PUBLISH_EXECUTION_PAYLOAD_ENVELOPES_PATH,
};
use block_service::BlockService;
use bn_manager::{BnManager, BnManagerConfig};
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
use eth_types::{
    AttestationData, BeaconBlock, Checkpoint, ElectraAggregateAndProof, ElectraAttestation,
    ForkSchedule, SLOTS_PER_EPOCH,
};
use rvc::beacon_adapter::BeaconBlockAdapter;
use signer::{always_enabled, SignerService, ValidatorSigner};
use slashing::SlashingDb;
use ssz08::Encode;
use validator_store::{ValidatorConfig, ValidatorStore};
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const GLOAS_EPOCH: u64 = 70;
const AGG_SAMPLES: usize = 50;
const PROPOSE_SAMPLES: usize = 50;

#[derive(Clone, Debug)]
struct Percentiles {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(!sorted.is_empty(), "percentile of empty sample");
    assert!((0.0..=1.0).contains(&p), "percentile p must be in [0, 1]");
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn percentiles_of(mut samples: Vec<f64>) -> Percentiles {
    assert!(!samples.is_empty(), "percentiles of empty sample");
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Percentiles {
        p50: percentile(&samples, 0.50),
        p95: percentile(&samples, 0.95),
        p99: percentile(&samples, 0.99),
        max: samples[samples.len() - 1],
    }
}

fn output_path_from_cli() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(path) = arg.strip_prefix("--output=") {
            return Some(PathBuf::from(path));
        }
        if arg == "--output" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

fn emit_json(json: &str) {
    print!("{json}");
    let _ = std::io::stdout().flush();
    if let Some(path) = output_path_from_cli() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| panic!("create parent dir {}: {e}", parent.display()));
            }
        }
        std::fs::write(&path, json.as_bytes())
            .unwrap_or_else(|e| panic!("write summary {}: {e}", path.display()));
    }
}

fn gloas_fork_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: 10,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch: 30,
        capella_fork_version: [3, 0, 0, 0],
        deneb_fork_epoch: 40,
        deneb_fork_version: [4, 0, 0, 0],
        electra_fork_epoch: 50,
        electra_fork_version: [5, 0, 0, 0],
        fulu_fork_epoch: 60,
        fulu_fork_version: [6, 0, 0, 0],
        gloas_fork_epoch: GLOAS_EPOCH,
        gloas_fork_version: [7, 0, 0, 0],
    }
}

fn local_signer_service(sk: SecretKey) -> Arc<SignerService> {
    let mut key_manager = KeyManager::new();
    key_manager.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("in-memory slashing db"));
    Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()))
}

fn electra_aggregate(slot: u64) -> ElectraAggregateAndProof {
    ElectraAggregateAndProof {
        aggregator_index: 1,
        aggregate: ElectraAttestation {
            aggregation_bits: vec![0xff, 0x01],
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: [0x11; 32],
                source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [0u8; 32] },
                target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [0u8; 32] },
            },
            signature: vec![0xab; 96],
            committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
        },
        selection_proof: vec![0xbb; 96],
    }
}

fn gloas_block(slot: u64) -> BeaconBlock {
    BeaconBlock {
        slot,
        proposer_index: 42,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body: hex::decode(rvc_gloas::test_fixtures::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ).unwrap(),
    }
}

fn contents_json(slot: u64) -> serde_json::Value {
    let envelope =
        format!("0x{}", rvc_gloas::test_fixtures::SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ);
    serde_json::json!({
        "version": "gloas",
        "data": {
            "block": gloas_block(slot),
            "execution_payload_envelope": envelope,
            "kzg_proofs": ["0xaa"],
            "blobs": ["0xbb"],
        }
    })
}

struct GloasProduce;

impl Respond for GloasProduce {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let slot: u64 = request
            .url
            .path()
            .rsplit('/')
            .next()
            .and_then(|s| s.parse().ok())
            .expect("produce path ends with slot");
        ResponseTemplate::new(200)
            .insert_header(HEADER_ETH_CONSENSUS_VERSION, "gloas")
            .insert_header(HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED, "true")
            .set_body_json(contents_json(slot))
    }
}

/// 6.9b: encode → island `gloas_aggregate_and_proof_root` → `sign_aggregate_and_proof_root`.
async fn measure_aggregate(signer: &SignerService, pk: &crypto::PublicKey) -> (Percentiles, usize) {
    let schedule = gloas_fork_schedule();
    let slot = GLOAS_EPOCH * SLOTS_PER_EPOCH;
    let gvr = [0xaau8; 32];
    let mut samples = Vec::with_capacity(AGG_SAMPLES);
    for _ in 0..AGG_SAMPLES {
        let start = Instant::now();
        let ssz = Encode::as_ssz_bytes(&electra_aggregate(slot));
        let object_root =
            rvc_gloas::gloas_aggregate_and_proof_root(&ssz).expect("island aggregate root");
        signer
            .sign_aggregate_and_proof_root(&object_root, slot, pk, &schedule, &gvr)
            .await
            .expect("sign_aggregate_and_proof_root");
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let n = samples.len();
    (percentiles_of(samples), n)
}

/// 6.20 self-build: `propose_block` (randao + island block root + header sign +
/// publish + island envelope root + envelope sign + envelope publish).
/// Unique slots so slashable block signs are not rejected.
async fn measure_propose(
    signer: Arc<SignerService>,
    pk: crypto::PublicKey,
) -> (Percentiles, usize) {
    let server = MockServer::start().await;
    let produce_re = format!(r"^{PRODUCE_BLOCK_V4_PATH_PREFIX}/\d+$");
    Mock::given(method("POST"))
        .and(path_regex(produce_re))
        .respond_with(GloasProduce)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/eth/v2/beacon/blocks"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(PUBLISH_EXECUTION_PAYLOAD_ENVELOPES_PATH))
        .and(header(HEADER_ETH_BLOB_DATA_INCLUDED, "true"))
        .and(header(HEADER_ETH_CONSENSUS_VERSION, "gloas"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let manager = BnManager::new(BnManagerConfig::new(vec![server.uri()])).expect("BnManager");
    let beacon = Arc::new(BeaconBlockAdapter(Arc::new(manager)));
    let store = ValidatorStore::new([0u8; 20], 30_000_000);
    store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
    let service = BlockService::new(
        signer,
        beacon,
        Arc::new(store),
        Arc::new(gloas_fork_schedule()),
        [0xaa; 32],
    );

    let start_slot = GLOAS_EPOCH * SLOTS_PER_EPOCH;
    // Cold HTTP/TLS handshake is not the envelope leg.
    service.propose_block(start_slot, &pk, 42, None).await.expect("propose warmup");

    let mut samples = Vec::with_capacity(PROPOSE_SAMPLES);
    for i in 0..PROPOSE_SAMPLES {
        let slot = start_slot + 1 + i as u64;
        let start = Instant::now();
        service
            .propose_block(slot, &pk, 42, None)
            .await
            .unwrap_or_else(|e| panic!("propose_block slot {slot}: {e:?}"));
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let n = samples.len();
    (percentiles_of(samples), n)
}

#[tokio::test]
#[ignore]
async fn test_ungated_island_paths_report_p99() {
    let _ = tracing_subscriber::fmt().with_writer(std::io::sink).try_init();

    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let signer = local_signer_service(sk);

    let (agg, agg_n) = measure_aggregate(signer.as_ref(), &pk).await;
    let (prop, prop_n) = measure_propose(Arc::clone(&signer), pk).await;

    let json = format!(
        "{{\n  \"issue\": \"6.14\",\n  \"gated\": false,\n  \
         \"note\": \"ungated / no P1 baseline; do not compare to A-9 attestation series\",\n  \
         \"aggregate\": {{\n    \"stage\": \"encode + gloas_aggregate_and_proof_root + sign_aggregate_and_proof_root\",\n    \
         \"path\": \"6.9b island aggregate\",\n    \"keys\": 1,\n    \"samples\": {agg_n},\n    \
         \"wall_ms\": {{ \"p50\": {ap50:.3}, \"p95\": {ap95:.3}, \"p99\": {ap99:.3}, \"max\": {amax:.3} }}\n  }},\n  \
         \"propose\": {{\n    \"stage\": \"propose_block self-build (randao + island block root + sign_block_header + publish + island envelope root + sign_execution_payload_envelope_root + publish_envelope)\",\n    \
         \"path\": \"6.20 self-build envelope\",\n    \"keys\": 1,\n    \"samples\": {prop_n},\n    \
         \"wall_ms\": {{ \"p50\": {pp50:.3}, \"p95\": {pp95:.3}, \"p99\": {pp99:.3}, \"max\": {pmax:.3} }}\n  }}\n}}\n",
        ap50 = agg.p50,
        ap95 = agg.p95,
        ap99 = agg.p99,
        amax = agg.max,
        pp50 = prop.p50,
        pp95 = prop.p95,
        pp99 = prop.p99,
        pmax = prop.max,
    );
    emit_json(&json);
}
