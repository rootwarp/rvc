//! `prepare_v3` rejects the same rows as `beacon::check_preparable` and does not sign.

use super::*;
use beacon::ShapeConstraint;
use eth_types::ForkName;

fn response(
    data: serde_json::Value,
    version: &str,
    blinded: bool,
    ssz: Option<Vec<u8>>,
) -> ProduceBlockResponse {
    ProduceBlockResponse {
        data,
        is_blinded: blinded,
        consensus_version: version.into(),
        execution_payload_value: Some("1".into()),
        is_ssz: ssz.is_some(),
        ssz_bytes: ssz,
        payload_included: false,
        builder_url: None,
        consensus_block_value: None,
        candidate_memo: beacon::CandidateMemo::arc(),
    }
}

fn hex32(byte: &str) -> String {
    format!("0x{}", byte.repeat(32))
}

fn contents(body: serde_json::Value, proofs: usize, blobs: usize) -> serde_json::Value {
    serde_json::json!({
        "block": {
            "slot": "1", "proposer_index": "1",
            "parent_root": hex32("11"), "state_root": hex32("22"),
            "body": body,
        },
        "kzg_proofs": vec!["0xab"; proofs],
        "blobs": vec!["0xcd"; blobs],
    })
}

fn deneb_contents(proofs: usize, blobs: usize) -> serde_json::Value {
    let body = serde_json::to_value(eth_types::external_vector_deneb_body()).expect("body");
    contents(body, proofs, blobs)
}

fn frame(block: &[u8], proofs: &[u8], blobs: &[u8]) -> Vec<u8> {
    let kzg = 12 + block.len() as u32;
    let blobs_at = kzg + proofs.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&12u32.to_le_bytes());
    out.extend_from_slice(&kzg.to_le_bytes());
    out.extend_from_slice(&blobs_at.to_le_bytes());
    out.extend_from_slice(block);
    out.extend_from_slice(proofs);
    out.extend_from_slice(blobs);
    out
}

fn encoded(body: Vec<u8>) -> Vec<u8> {
    eth_types::encode_beacon_block_ssz(
        &eth_types::BeaconBlock {
            slot: 1,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body,
        },
        0,
    )
}

fn blinded_json() -> serde_json::Value {
    let body = serde_json::to_value(eth_types::external_vector_blinded_deneb_body()).expect("body");
    serde_json::json!({
        "slot": "1", "proposer_index": "1",
        "parent_root": hex32("11"), "state_root": hex32("22"),
        "body": body,
    })
}

#[test]
#[rustfmt::skip]
fn prepare_v3_rejects_the_same_rows_as_check_preparable() {
    let service = build_service(MockSigner::new(), MockBeaconClient::ssz(1, 1, false), &test_pubkey());
    let electra_body = serde_json::json!(format!("0x{}", hex::encode(eth_types::external_vector_electra_body().as_ssz_bytes())));
    let deneb_block = encoded(eth_types::external_vector_deneb_body().as_ssz_bytes());
    let electra_block = encoded(eth_types::external_vector_electra_body().as_ssz_bytes());
    let mut shifted = frame(&deneb_block, &[], &[]);
    shifted[8..12].copy_from_slice(&0u32.to_le_bytes());
    let blinded_ssz = eth_types::encode_blinded_beacon_block_ssz(
        &eth_types::BlindedBeaconBlock { slot: 1, proposer_index: 1, parent_root: [0x11; 32], state_root: [0x22; 32], body: eth_types::external_vector_blinded_deneb_body().as_ssz_bytes() },
        0,
    );
    let mut hybrid = deneb_contents(0, 0);
    let slot = hybrid["block"]["slot"].clone();
    hybrid["slot"] = slot;
    let pre = serde_json::json!({"slot":"1","proposer_index":"1","parent_root":"0x11","state_root":"0x22","body":{}});
    let blinded = blinded_json();
    let mp = BlockSelectionMode::MaxProfit;
    let local = BlockSelectionMode::ExecutionOnly;
    let rows = [
        ("deneb json", response(deneb_contents(0, 0), "deneb", false, None), ForkName::Deneb, mp, true),
        ("extra proof", response(deneb_contents(2, 1), "deneb", false, None), ForkName::Deneb, mp, false),
        ("fulu one proof", response(contents(electra_body.clone(), 1, 1), "fulu", false, None), ForkName::Fulu, mp, false),
        ("fulu 128 proofs", response(contents(electra_body, 128, 1), "fulu", false, None), ForkName::Fulu, mp, true),
        ("hybrid", response(hybrid, "deneb", false, None), ForkName::Deneb, mp, false),
        ("blinded deneb", response(blinded.clone(), "deneb", true, None), ForkName::Deneb, mp, true),
        ("deneb body under fulu", response(blinded.clone(), "fulu", true, None), ForkName::Fulu, mp, false),
        ("local-only blinded", response(blinded, "deneb", true, None), ForkName::Deneb, local, false),
        ("bellatrix json", response(pre, "bellatrix", false, None), ForkName::Bellatrix, mp, false),
        ("ssz deneb", response(serde_json::Value::Null, "deneb", false, Some(frame(&deneb_block, &[], &[]))), ForkName::Deneb, mp, true),
        ("ssz extra proofs", response(serde_json::Value::Null, "deneb", false, Some(frame(&deneb_block, &[0u8; 96], &vec![0u8; 131_072]))), ForkName::Deneb, mp, false),
        ("ssz fulu short", response(serde_json::Value::Null, "fulu", false, Some(frame(&electra_block, &[0u8; 48], &vec![0u8; 131_072]))), ForkName::Fulu, mp, false),
        ("ssz bad offset", response(serde_json::Value::Null, "deneb", false, Some(shifted)), ForkName::Deneb, mp, false),
        ("ssz capella", response(serde_json::Value::Null, "capella", false, Some(encoded(vec![0u8; 8]))), ForkName::Capella, mp, false),
        ("ssz blinded", response(serde_json::Value::Null, "deneb", true, Some(blinded_ssz)), ForkName::Deneb, mp, true),
        ("gloas blinded", response(serde_json::Value::Null, "gloas", true, None), ForkName::Gloas, mp, false),
    ];
    for (name, block, fork, mode, expect_ok) in rows {
        let shape = if mode == local { ShapeConstraint::LocalOnly } else { ShapeConstraint::Any };
        let direct = beacon::check_preparable(&block, fork, shape);
        let prepared = service.prepare_v3(&block, 1, None, fork, mode);
        assert_eq!(direct.is_ok(), expect_ok, "{name} predicate {direct:?}");
        let err = prepared.as_ref().err().map(|err| err.to_string()).unwrap_or_default();
        assert_eq!(prepared.is_ok(), expect_ok, "{name} prepare_v3 {err}");
        assert!(service.signer.block_calls.lock().expect("calls").is_empty(), "{name} signed");
        assert!(service.signer.header_calls.lock().expect("headers").is_empty(), "{name} signed header");
    }
}
