//! Shared pre-sign check for one pre-Gloas produce candidate.
//!
//! bn-manager ranks with this. block-service builds the header from the same
//! [`Prepared`] value. A failure does not close the soft window and is not signed.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use eth_types::{
    body_fork_layout, expected_kzg_proof_count, BeaconBlock, BlindedBeaconBlock, BlockContents,
    ForkName,
};

use crate::shape::ShapeConstraint;
use crate::ssz_deser::{self, SszBlockFormat};
use crate::types::ProduceBlockResponse;
use crate::BeaconError;

/// One KZG proof on the SSZ wire.
const KZG_PROOF_BYTES: usize = 48;
/// One blob on the SSZ wire.
const BLOB_BYTES: usize = 131_072;

/// Prepare result for one candidate. Clones share it.
#[derive(Debug)]
pub struct CandidateMemo {
    prepare: Mutex<Option<PrepareSlot>>,
}

#[derive(Debug, Clone)]
struct PrepareSlot {
    fork: ForkName,
    shape: ShapeConstraint,
    outcome: Result<Arc<Prepared>, PrepareReject>,
}

impl CandidateMemo {
    /// Empty cache shared by clones of the response.
    pub fn arc() -> Arc<Self> {
        Arc::new(Self { prepare: Mutex::new(None) })
    }
}

/// A candidate that can be signed.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub block_root: [u8; 32],
    pub kind: PreparedKind,
}

/// Decoded body the signer and the publisher both use.
#[derive(Debug, Clone)]
pub enum PreparedKind {
    JsonFull(BlockContents),
    JsonBlinded(BlindedBeaconBlock),
    SszFull { block: BeaconBlock, block_ssz: Vec<u8>, kzg_proofs: Vec<u8>, blobs: Vec<u8> },
    SszBlinded { block: BlindedBeaconBlock, ssz: Vec<u8> },
}

/// Why a candidate is not signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrepareReject {
    /// Blinded production at a Gloas slot, or a header that says `gloas`.
    #[error("blinded block at gloas")]
    BlindedAtGloas,
    /// `Eth-Consensus-Version` is not the slot fork. `got` is the header text.
    #[error("consensus version {got} != {expected}")]
    ConsensusVersion { expected: String, got: String },
    /// [`ShapeConstraint`] rejects the blinded flag.
    #[error("shape")]
    Shape,
    /// SSZ format has no named arm for this version.
    #[error("unknown ssz consensus version {0}")]
    UnknownSszVersion(String),
    /// Decode, layout, root, or KZG cardinality.
    #[error("{0}")]
    Parse(String),
}

/// Decode `response` under `slot_fork` and `shape`.
///
/// The result is cached on the response. A later call with the same fork and
/// shape does not decode again. Poisoned cache locks keep the inner value.
///
/// # Errors
///
/// Blinded at Gloas, a version that is not `slot_fork`, a shape the constraint
/// rejects, or a body that cannot be rooted. A Gloas `slot_fork` is
/// [`PrepareReject::Parse`]: this is the pre-Gloas path.
pub fn check_preparable(
    response: &ProduceBlockResponse,
    slot_fork: ForkName,
    shape: ShapeConstraint,
) -> Result<Prepared, PrepareReject> {
    let cached = cached_prepare(response, slot_fork, shape);
    cached.map(|prepared| (*prepared).clone())
}

fn cached_prepare(
    response: &ProduceBlockResponse,
    slot_fork: ForkName,
    shape: ShapeConstraint,
) -> Result<Arc<Prepared>, PrepareReject> {
    let mut guard = response.candidate_memo.prepare.lock().unwrap_or_else(|err| err.into_inner());
    if let Some(slot) = guard.as_ref() {
        if slot.fork == slot_fork && slot.shape == shape {
            return slot.outcome.clone();
        }
    }
    let outcome = compute_preparable(response, slot_fork, shape).map(Arc::new);
    *guard = Some(PrepareSlot { fork: slot_fork, shape, outcome: outcome.clone() });
    outcome
}

fn compute_preparable(
    response: &ProduceBlockResponse,
    slot_fork: ForkName,
    shape: ShapeConstraint,
) -> Result<Prepared, PrepareReject> {
    if response.is_blinded
        && (slot_fork >= ForkName::Gloas || response.consensus_version == "gloas")
    {
        return Err(PrepareReject::BlindedAtGloas);
    }
    match ForkName::from_str(&response.consensus_version) {
        Ok(got) if got == slot_fork && slot_fork < ForkName::Gloas => {}
        Ok(_) if slot_fork >= ForkName::Gloas => {
            return Err(PrepareReject::Parse(format!(
                "full block body is unsupported for consensus version {}",
                slot_fork.as_ref()
            )));
        }
        Ok(got) => {
            return Err(PrepareReject::ConsensusVersion {
                expected: slot_fork.as_ref().to_string(),
                got: got.as_ref().to_string(),
            });
        }
        Err(_) => {
            return Err(PrepareReject::ConsensusVersion {
                expected: slot_fork.as_ref().to_string(),
                got: response.consensus_version.clone(),
            });
        }
    }
    if !shape.allows_blinded_flag(response.is_blinded) {
        return Err(PrepareReject::Shape);
    }
    if response.is_ssz {
        prepare_ssz(response)
    } else if response.is_blinded {
        prepare_blinded_json(response)
    } else {
        prepare_full_json(response)
    }
}

fn prepare_full_json(response: &ProduceBlockResponse) -> Result<Prepared, PrepareReject> {
    let contents = response.parse_full_block().map_err(parse_err)?;
    if let BlockContents::BlockAndBlobs { ref kzg_proofs, ref blobs, .. } = contents {
        check_kzg_lens(&response.consensus_version, kzg_proofs.len(), blobs.len())?;
    }
    let block = contents.block().clone();
    let root = full_root(&block, &response.consensus_version)?;
    Ok(Prepared { block_root: root, kind: PreparedKind::JsonFull(contents) })
}

fn prepare_blinded_json(response: &ProduceBlockResponse) -> Result<Prepared, PrepareReject> {
    let block = response.parse_blinded_block().map_err(parse_err)?;
    let root = blinded_root(&block, &response.consensus_version)?;
    Ok(Prepared { block_root: root, kind: PreparedKind::JsonBlinded(block) })
}

fn prepare_ssz(response: &ProduceBlockResponse) -> Result<Prepared, PrepareReject> {
    let bytes = response
        .ssz_bytes
        .as_deref()
        .ok_or_else(|| PrepareReject::Parse("SSZ response missing ssz_bytes".to_string()))?;
    let format = ssz_format(response)?;
    if response.is_blinded {
        let (block, _) = ssz_deser::deserialize_blinded_beacon_block_from_ssz(bytes, format)
            .map_err(parse_err)?;
        let root = blinded_root(&block, &response.consensus_version)?;
        return Ok(Prepared {
            block_root: root,
            kind: PreparedKind::SszBlinded { block, ssz: bytes.to_vec() },
        });
    }
    if format == SszBlockFormat::BlockContents {
        let contents =
            ssz_deser::deserialize_block_contents_ssz(bytes, format).map_err(parse_err)?;
        let (proof_count, blob_count) = ssz_kzg_counts(contents.kzg_proofs, contents.blobs)?;
        check_kzg_lens(&response.consensus_version, proof_count, blob_count)?;
        let root = full_root(&contents.block, &response.consensus_version)?;
        return Ok(Prepared {
            block_root: root,
            kind: PreparedKind::SszFull {
                block: contents.block,
                block_ssz: contents.block_ssz.to_vec(),
                kzg_proofs: contents.kzg_proofs.to_vec(),
                blobs: contents.blobs.to_vec(),
            },
        });
    }
    let (block, _) =
        ssz_deser::deserialize_beacon_block_from_ssz(bytes, format).map_err(parse_err)?;
    let root = full_root(&block, &response.consensus_version)?;
    Ok(Prepared {
        block_root: root,
        kind: PreparedKind::SszFull {
            block,
            block_ssz: bytes.to_vec(),
            kzg_proofs: Vec::new(),
            blobs: Vec::new(),
        },
    })
}

fn blinded_root(block: &BlindedBeaconBlock, version: &str) -> Result<[u8; 32], PrepareReject> {
    let layout = body_fork_layout(version).ok_or_else(|| {
        PrepareReject::Parse(format!(
            "JSON blinded block is unsupported for consensus version {version}"
        ))
    })?;
    block.try_tree_hash_root_for_layout(layout).map(|hash| hash.0).map_err(|err| {
        PrepareReject::Parse(format!("invalid blinded block body for tree_hash_root: {err}"))
    })
}

fn full_root(block: &BeaconBlock, version: &str) -> Result<[u8; 32], PrepareReject> {
    let layout = body_fork_layout(version).ok_or_else(|| {
        PrepareReject::Parse(format!(
            "full block body is unsupported for consensus version {version}"
        ))
    })?;
    block.try_tree_hash_root_for_layout(layout).map(|hash| hash.0).map_err(|err| {
        PrepareReject::Parse(format!("invalid block body for tree_hash_root: {err}"))
    })
}

fn ssz_format(response: &ProduceBlockResponse) -> Result<SszBlockFormat, PrepareReject> {
    let fork = ForkName::from_str(&response.consensus_version)
        .map_err(|_| PrepareReject::UnknownSszVersion(response.consensus_version.clone()))?;
    if response.is_blinded {
        return Ok(SszBlockFormat::BeaconBlock);
    }
    #[allow(clippy::match_same_arms)]
    Ok(match fork {
        ForkName::Deneb | ForkName::Electra | ForkName::Fulu => SszBlockFormat::BlockContents,
        ForkName::Gloas
        | ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella => SszBlockFormat::BeaconBlock,
    })
}

fn ssz_kzg_counts(proofs: &[u8], blobs: &[u8]) -> Result<(usize, usize), PrepareReject> {
    Ok((byte_count(proofs, KZG_PROOF_BYTES)?, byte_count(blobs, BLOB_BYTES)?))
}

fn byte_count(bytes: &[u8], width: usize) -> Result<usize, PrepareReject> {
    if !bytes.len().is_multiple_of(width) {
        return Err(PrepareReject::Parse(format!(
            "kzg proof cardinality: byte length {} is not a multiple of {width}",
            bytes.len()
        )));
    }
    Ok(bytes.len() / width)
}

fn check_kzg_lens(
    version: &str,
    proof_count: usize,
    blob_count: usize,
) -> Result<(), PrepareReject> {
    let fork = ForkName::from_str(version).map_err(|_| {
        PrepareReject::Parse(format!(
            "kzg proof cardinality: unknown fork {version} ({proof_count} proofs, {blob_count} blobs)"
        ))
    })?;
    let expected = expected_kzg_proof_count(fork, blob_count).map_err(|err| {
        PrepareReject::Parse(format!(
            "kzg proof cardinality is not defined for fork {version} ({proof_count} proofs, {blob_count} blobs): {err}"
        ))
    })?;
    if proof_count != expected {
        return Err(PrepareReject::Parse(format!(
            "kzg proof cardinality mismatch for fork {version}: expected {expected} proofs, got {proof_count} proofs for {blob_count} blobs"
        )));
    }
    Ok(())
}

fn parse_err(err: BeaconError) -> PrepareReject {
    match err {
        BeaconError::ParseError(message) => PrepareReject::Parse(message),
        other => PrepareReject::Parse(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            candidate_memo: CandidateMemo::arc(),
        }
    }

    fn check(
        data: serde_json::Value,
        version: &str,
        blinded: bool,
        fork: ForkName,
    ) -> Result<Prepared, PrepareReject> {
        check_preparable(&response(data, version, blinded, None), fork, ShapeConstraint::Any)
    }

    fn check_ssz(
        bytes: Vec<u8>,
        version: &str,
        blinded: bool,
        fork: ForkName,
    ) -> Result<Prepared, PrepareReject> {
        check_preparable(
            &response(serde_json::Value::Null, version, blinded, Some(bytes)),
            fork,
            ShapeConstraint::Any,
        )
    }

    fn hex32(byte: &str) -> String {
        format!("0x{}", byte.repeat(32))
    }

    fn contents(body: serde_json::Value, proofs: usize, blobs: usize) -> serde_json::Value {
        serde_json::json!({
            "block": {
                "slot": "1",
                "proposer_index": "1",
                "parent_root": hex32("11"),
                "state_root": hex32("22"),
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
        let body =
            serde_json::to_value(eth_types::external_vector_blinded_deneb_body()).expect("body");
        serde_json::json!({
            "slot": "1",
            "proposer_index": "1",
            "parent_root": hex32("11"),
            "state_root": hex32("22"),
            "body": body,
        })
    }

    #[test]
    fn check_preparable_matches_block_service_prepare() {
        assert!(check(deneb_contents(0, 0), "deneb", false, ForkName::Deneb).is_ok());
        let extra = check(deneb_contents(2, 1), "deneb", false, ForkName::Deneb).unwrap_err();
        assert!(extra.to_string().contains("kzg proof cardinality"), "{extra}");

        let electra = serde_json::json!(format!(
            "0x{}",
            hex::encode(eth_types::external_vector_electra_body().as_ssz_bytes())
        ));
        let short = check(contents(electra.clone(), 1, 1), "fulu", false, ForkName::Fulu);
        assert!(short.unwrap_err().to_string().contains("expected 128"));
        assert!(check(contents(electra, 128, 1), "fulu", false, ForkName::Fulu).is_ok());

        let mut hybrid = deneb_contents(0, 0);
        let slot = hybrid["block"]["slot"].clone();
        hybrid["slot"] = slot;
        assert!(check(hybrid, "deneb", false, ForkName::Deneb).is_err(), "hybrid");

        let blinded = blinded_json();
        assert!(check(blinded.clone(), "deneb", true, ForkName::Deneb).is_ok());
        assert!(
            check(blinded.clone(), "fulu", true, ForkName::Fulu).is_err(),
            "deneb body under fulu"
        );
        let local = check_preparable(
            &response(blinded, "deneb", true, None),
            ForkName::Deneb,
            ShapeConstraint::LocalOnly,
        );
        assert!(matches!(local, Err(PrepareReject::Shape)));

        let pre = serde_json::json!({"slot":"1","proposer_index":"1","parent_root":"0x11","state_root":"0x22","body":{}});
        assert!(check(pre, "bellatrix", false, ForkName::Bellatrix)
            .unwrap_err()
            .to_string()
            .contains("unsupported"));

        let deneb_block = encoded(eth_types::external_vector_deneb_body().as_ssz_bytes());
        assert!(check_ssz(frame(&deneb_block, &[], &[]), "deneb", false, ForkName::Deneb).is_ok());
        let bad = frame(&deneb_block, &[0u8; 96], &vec![0u8; BLOB_BYTES]);
        assert!(check_ssz(bad, "deneb", false, ForkName::Deneb)
            .unwrap_err()
            .to_string()
            .contains("kzg proof cardinality"));
        let electra_block = encoded(eth_types::external_vector_electra_body().as_ssz_bytes());
        let fulu_short = frame(&electra_block, &[0u8; KZG_PROOF_BYTES], &vec![0u8; BLOB_BYTES]);
        assert!(check_ssz(fulu_short, "fulu", false, ForkName::Fulu)
            .unwrap_err()
            .to_string()
            .contains("expected 128"));
        let mut shifted = frame(&deneb_block, &[], &[]);
        shifted[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(check_ssz(shifted, "deneb", false, ForkName::Deneb).is_err(), "blobs offset");
        assert!(check_ssz(encoded(vec![0u8; 8]), "capella", false, ForkName::Capella)
            .unwrap_err()
            .to_string()
            .contains("unsupported"));

        let blinded_ssz = eth_types::encode_blinded_beacon_block_ssz(
            &eth_types::BlindedBeaconBlock {
                slot: 1,
                proposer_index: 1,
                parent_root: [0x11; 32],
                state_root: [0x22; 32],
                body: eth_types::external_vector_blinded_deneb_body().as_ssz_bytes(),
            },
            0,
        );
        assert!(check_ssz(blinded_ssz, "deneb", true, ForkName::Deneb).is_ok());
        let gloas = check(serde_json::Value::Null, "gloas", true, ForkName::Gloas);
        assert!(matches!(gloas, Err(PrepareReject::BlindedAtGloas)));
    }
}
