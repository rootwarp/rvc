//! Fork-parameterised JSON codec for a beacon block body.
//!
//! SSZ bytes are canonical ([`crate::BeaconBlock::body`] stays `Vec<u8>`). JSON
//! is only the Beacon-API object form of a Deneb or Electra body; Fulu reuses
//! [`BodyForkLayout::Electra`]. [`BodyForkLayout::Gloas`] fails closed with
//! [`BodySszError::GloasUnsupported`] in both directions, before any parse, so
//! a parse failure cannot become a signature. Pre-Deneb forks have no layout
//! ([`crate::body_fork_layout`] returns `None`) and are unsupported.
//!
//! No production path calls this yet. RR-3.7 is the wiring.

use serde::Deserialize;
use serde_json::Value;

use crate::block::BodyForkLayout;
use crate::block_body::{
    decode_beacon_block_body_deneb, decode_beacon_block_body_electra, BeaconBlockBodyDeneb,
    BeaconBlockBodyElectra, BodySszError,
};

/// JSON object → typed body → canonical SSZ bytes.
///
/// `layout` selects the container. [`BodyForkLayout::Gloas`] returns
/// [`BodySszError::GloasUnsupported`] without reading `json`.
pub fn decode(json: &Value, layout: BodyForkLayout) -> Result<Vec<u8>, BodySszError> {
    match layout {
        BodyForkLayout::Deneb => {
            let body = BeaconBlockBodyDeneb::deserialize(json)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))?;
            Ok(body.as_ssz_bytes())
        }
        BodyForkLayout::Electra => {
            let body = BeaconBlockBodyElectra::deserialize(json)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))?;
            Ok(body.as_ssz_bytes())
        }
        BodyForkLayout::Gloas => Err(BodySszError::GloasUnsupported),
    }
}

/// Canonical SSZ bytes → Beacon-API JSON object.
///
/// The inverse of [`decode`]. [`BodyForkLayout::Gloas`] returns
/// [`BodySszError::GloasUnsupported`] without reading `ssz`.
pub fn encode(ssz: &[u8], layout: BodyForkLayout) -> Result<Value, BodySszError> {
    match layout {
        BodyForkLayout::Deneb => {
            let body = decode_beacon_block_body_deneb(ssz)?;
            serde_json::to_value(&body)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))
        }
        BodyForkLayout::Electra => {
            let body = decode_beacon_block_body_electra(ssz)?;
            serde_json::to_value(&body)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))
        }
        BodyForkLayout::Gloas => Err(BodySszError::GloasUnsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_body::{
        body_tree_hash_root_for_layout, external_vector_deneb_body, external_vector_electra_body,
        EXTERNAL_DENEB_BODY_ROOT_HEX, EXTERNAL_ELECTRA_BODY_ROOT_HEX,
    };
    use crate::body_fork_layout;
    use tree_hash::TreeHash;

    /// Beacon-API JSON of [`external_vector_electra_body`]. Not a captured block.
    const ELECTRA_BODY_JSON: &str =
        include_str!("../tests/fixtures/beacon_api/electra_block_body.json");
    /// Spec-shaped Deneb `BlockContents`. Hoodi has no retained Deneb history on
    /// the local node or `beacon.hoodi.ethpandaops.io` (both 404). The body is
    /// the external-vector Deneb body so its root stays
    /// [`EXTERNAL_DENEB_BODY_ROOT_HEX`]. Proof and blob are length-correct and
    /// non-empty; they were not captured.
    const DENEB_CONTENTS_JSON: &str =
        include_str!("../tests/fixtures/beacon_api/deneb_block_contents.json");
    /// Canonical Hoodi Fulu `BlockContents`, slot 4025699, from
    /// `https://beacon.hoodi.ethpandaops.io` (Lighthouse). The local node
    /// (`127.0.0.1:5052`, Lighthouse v8.2.2) served block bodies but not blobs
    /// (`required 64 columns, found 4`) and did not have pre-Fulu blocks.
    /// `block` is `GET /eth/v2/beacon/blocks/4025699` `message`. `blobs` is
    /// `GET /eth/v1/beacon/blobs/4025699`. `kzg_proofs` is blob-major cell
    /// proofs from data-column sidecars 0..127:
    /// `proofs[blob * 128 + cell] = column[cell].kzg_proofs[blob]`. Each blob
    /// matched cells 0..63 of those columns. Not a produce-endpoint response.
    const FULU_CONTENTS_JSON: &str =
        include_str!("../tests/fixtures/beacon_api/fulu_block_contents.json");
    /// Body captured from the local Hoodi lighthouse
    /// `GET /eth/v2/beacon/blocks/head` while that head's attestations named
    /// slot 4025760. The node then stopped, and the canonical block at that
    /// slot no longer matches this body, so it is not paired with blobs.
    const LOCAL_FULU_BODY_JSON: &str =
        include_str!("../tests/fixtures/beacon_api/hoodi_fulu_block_body.json");
    /// Not captured. Hoodi head is Fulu; there is no Gloas body to fetch.
    const GLOAS_BODY_JSON: &str =
        include_str!("../tests/fixtures/beacon_api/gloas_block_body.json");

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture json")
    }

    fn contents_body(text: &str) -> Value {
        parse(text)["data"]["block"]["body"].clone()
    }

    fn hex_root(root: tree_hash::Hash256) -> String {
        hex::encode(root.as_slice())
    }

    #[test]
    fn a_real_beacon_api_json_block_body_decodes() {
        let deneb = contents_body(DENEB_CONTENTS_JSON);
        let deneb_ssz = decode(&deneb, BodyForkLayout::Deneb).expect("deneb body decodes");
        let deneb_back = decode_beacon_block_body_deneb(&deneb_ssz).expect("deneb ssz");
        assert_eq!(deneb_back, external_vector_deneb_body());

        for (label, body) in [
            ("fulu contents", contents_body(FULU_CONTENTS_JSON)),
            ("local fulu head", parse(LOCAL_FULU_BODY_JSON)),
        ] {
            assert!(body.is_object(), "{label} body is an object, not a hex string");
            let ssz = decode(&body, BodyForkLayout::Electra)
                .unwrap_or_else(|err| panic!("{label} electra decode: {err}"));
            let back = decode_beacon_block_body_electra(&ssz).expect("electra ssz");
            assert_eq!(
                back.blob_kzg_commitments.len(),
                body["blob_kzg_commitments"].as_array().unwrap().len(),
                "{label}"
            );
            assert!(!back.attestations.is_empty(), "{label}");
            assert_eq!(back.as_ssz_bytes(), ssz);
        }
    }

    #[test]
    fn round_trip_reserializes_to_an_object_not_a_hex_string() {
        for (json, layout) in [
            (contents_body(DENEB_CONTENTS_JSON), BodyForkLayout::Deneb),
            (contents_body(FULU_CONTENTS_JSON), BodyForkLayout::Electra),
            (parse(LOCAL_FULU_BODY_JSON), BodyForkLayout::Electra),
            (parse(ELECTRA_BODY_JSON), BodyForkLayout::Electra),
        ] {
            let encoded = encode(&decode(&json, layout).expect("decode"), layout).expect("encode");
            assert!(encoded.is_object(), "body JSON must be an object, not a hex string");
            assert!(encoded["randao_reveal"].is_string());
            assert!(encoded["execution_payload"].is_object());
            assert!(!encoded.is_string());
            assert_eq!(encoded, json);
        }
    }

    #[test]
    fn gloas_body_fails_closed_in_both_directions() {
        let gloas = parse(GLOAS_BODY_JSON);
        assert!(gloas.is_object());
        assert_eq!(decode(&gloas, BodyForkLayout::Gloas), Err(BodySszError::GloasUnsupported));
        assert_eq!(
            decode(&parse(ELECTRA_BODY_JSON), BodyForkLayout::Gloas),
            Err(BodySszError::GloasUnsupported)
        );
        let electra_ssz = external_vector_electra_body().as_ssz_bytes();
        assert_eq!(
            encode(&electra_ssz, BodyForkLayout::Gloas),
            Err(BodySszError::GloasUnsupported)
        );
        assert_eq!(encode(b"not-ssz", BodyForkLayout::Gloas), Err(BodySszError::GloasUnsupported));
    }

    #[test]
    fn decode_then_tree_hash_matches_the_ssz_path_root() {
        // SEC-6c constants already pinned in this crate. Not recomputed here.
        let electra_ssz = decode(&parse(ELECTRA_BODY_JSON), BodyForkLayout::Electra).unwrap();
        let electra_root =
            body_tree_hash_root_for_layout(&electra_ssz, BodyForkLayout::Electra).unwrap();
        assert_eq!(hex_root(electra_root), EXTERNAL_ELECTRA_BODY_ROOT_HEX);
        assert_eq!(
            hex_root(external_vector_electra_body().tree_hash_root()),
            EXTERNAL_ELECTRA_BODY_ROOT_HEX
        );

        let deneb_ssz = decode(&contents_body(DENEB_CONTENTS_JSON), BodyForkLayout::Deneb).unwrap();
        let deneb_root = body_tree_hash_root_for_layout(&deneb_ssz, BodyForkLayout::Deneb).unwrap();
        assert_eq!(hex_root(deneb_root), EXTERNAL_DENEB_BODY_ROOT_HEX);
    }

    #[test]
    fn pre_deneb_layout_is_unsupported() {
        for version in ["phase0", "altair", "bellatrix", "capella"] {
            assert_eq!(body_fork_layout(version), None, "{version} has no body layout");
        }
        assert_eq!(body_fork_layout("deneb"), Some(BodyForkLayout::Deneb));
        assert_eq!(body_fork_layout("electra"), Some(BodyForkLayout::Electra));
        assert_eq!(body_fork_layout("fulu"), Some(BodyForkLayout::Electra));
        assert_eq!(body_fork_layout("gloas"), Some(BodyForkLayout::Gloas));
    }

    #[test]
    fn deneb_and_fulu_contents_fixtures_have_nonempty_proofs_and_blobs() {
        for (text, version, proofs_per_blob) in
            [(DENEB_CONTENTS_JSON, "deneb", 1usize), (FULU_CONTENTS_JSON, "fulu", 128)]
        {
            let doc = parse(text);
            assert_eq!(doc["version"], version);
            let data = &doc["data"];
            let proofs = data["kzg_proofs"].as_array().expect("kzg_proofs");
            let blobs = data["blobs"].as_array().expect("blobs");
            assert!(!proofs.is_empty(), "{version} kzg_proofs empty");
            assert!(!blobs.is_empty(), "{version} blobs empty");
            assert_eq!(proofs.len(), blobs.len() * proofs_per_blob);
            assert!(proofs
                .iter()
                .all(|proof| { proof.as_str().is_some_and(|text| text.len() == 2 + 48 * 2) }));
            assert!(blobs
                .iter()
                .all(|blob| { blob.as_str().is_some_and(|text| text.len() == 2 + 131_072 * 2) }));
        }
    }
}
