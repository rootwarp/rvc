//! Fork-parameterised JSON codec for a beacon block body.
//!
//! SSZ bytes are canonical ([`crate::BeaconBlock::body`] stays `Vec<u8>`). JSON
//! is only the Beacon-API object form of a Deneb or Electra body; Fulu reuses
//! [`BodyForkLayout::Electra`]. [`BodyForkLayout::Gloas`] fails closed with
//! [`BodySszError::GloasUnsupported`] in both directions, before any parse, so
//! a parse failure cannot become a signature. Pre-Deneb forks have no layout
//! ([`crate::body_fork_layout`] returns `None`) and are unsupported.
//!
//! Blinded bodies use the same fork split. [`decode_blinded`] and
//! [`encode_blinded`] read `BlindedBeaconBlockBody{Deneb,Electra}`
//! (`execution_payload_header` instead of `execution_payload`; Electra still
//! has `execution_requests`). A full payload object is not a blinded body.
//! Gloas returns [`BodySszError::GloasUnsupported`] without reading the input.
//!
//! `ProduceBlockResponse::parse_full_block` and `parse_blinded_block` decode
//! object bodies here. `SignedBlockContentsJson` and
//! `SignedBlindedBeaconBlockJson` encode them back on publish. SSZ stays
//! canonical.

use serde::Deserialize;
use serde_json::Value;

use crate::block::BodyForkLayout;
use crate::block_body::{
    decode_beacon_block_body_deneb, decode_beacon_block_body_electra,
    decode_blinded_beacon_block_body_deneb, decode_blinded_beacon_block_body_electra,
    BeaconBlockBodyDeneb, BeaconBlockBodyElectra, BlindedBeaconBlockBodyDeneb,
    BlindedBeaconBlockBodyElectra, BodySszError,
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

/// JSON object → typed blinded body → canonical SSZ bytes.
///
/// [`BodyForkLayout::Gloas`] returns [`BodySszError::GloasUnsupported`] without
/// reading `json`. A full `execution_payload` object is [`BodySszError::InvalidEncoding`].
///
/// After the body decodes, [`reject_keys_absent_after_round_trip`] rejects an
/// input key that the JSON re-encoded from that SSZ does not contain at the
/// same path. Shared container types stay without `deny_unknown_fields`.
pub fn decode_blinded(json: &Value, layout: BodyForkLayout) -> Result<Vec<u8>, BodySszError> {
    let ssz = match layout {
        BodyForkLayout::Gloas => return Err(BodySszError::GloasUnsupported),
        BodyForkLayout::Deneb => {
            reject_beacon_api_lenient_spellings(json)?;
            let body = BlindedBeaconBlockBodyDeneb::deserialize(json)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))?;
            body.as_ssz_bytes()
        }
        BodyForkLayout::Electra => {
            reject_beacon_api_lenient_spellings(json)?;
            let body = BlindedBeaconBlockBodyElectra::deserialize(json)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))?;
            body.as_ssz_bytes()
        }
    };
    let canonical = encode_blinded(&ssz, layout)?;
    reject_keys_absent_after_round_trip(json, &canonical)?;
    Ok(ssz)
}

/// Reject an input key that `canonical` does not contain at the same path.
///
/// Objects are compared by key. Arrays of the same length are compared by
/// index. An input array whose canonical value is not an array is rejected,
/// so a struct written as a positional JSON array cannot hide a nested key
/// when the re-encoded SSZ is an object. A flat array of scalars whose
/// canonical value is a string is kept: those elements have no keys, and a
/// byte list re-encodes as hex. An input object whose canonical value is not
/// an object is rejected. A scalar has no keys. The field name in the error
/// is at most 64 Unicode scalars. A control character, U+2028, or U+2029 in
/// that prefix is replaced with U+FFFD so the error string cannot break a
/// log line.
pub fn reject_keys_absent_after_round_trip(
    input: &Value,
    canonical: &Value,
) -> Result<(), BodySszError> {
    match (input, canonical) {
        (Value::Object(input_map), Value::Object(canon_map)) => {
            for key in input_map.keys() {
                if !canon_map.contains_key(key) {
                    return Err(BodySszError::InvalidEncoding(format!(
                        "unknown JSON field `{}`",
                        shown_json_field(key)
                    )));
                }
            }
            for (key, input_value) in input_map {
                if let Some(canon_value) = canon_map.get(key) {
                    reject_keys_absent_after_round_trip(input_value, canon_value)?;
                }
            }
            Ok(())
        }
        (Value::Array(input_items), Value::Array(canon_items)) => {
            if input_items.len() != canon_items.len() {
                return Err(BodySszError::InvalidEncoding(
                    "JSON array length does not match the re-encoded SSZ".into(),
                ));
            }
            for (input_item, canon_item) in input_items.iter().zip(canon_items.iter()) {
                reject_keys_absent_after_round_trip(input_item, canon_item)?;
            }
            Ok(())
        }
        (Value::Array(input_items), Value::String(_))
            if input_items.iter().all(json_value_is_scalar) =>
        {
            Ok(())
        }
        (Value::Array(_), _) => Err(BodySszError::InvalidEncoding(
            "JSON array was not retained by the re-encoded SSZ".into(),
        )),
        (Value::Object(_), _) => Err(BodySszError::InvalidEncoding(
            "JSON object was not retained by the re-encoded SSZ".into(),
        )),
        _ => Ok(()),
    }
}

fn json_value_is_scalar(value: &Value) -> bool {
    matches!(value, Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_))
}

fn shown_json_field(key: &str) -> String {
    key.chars()
        .take(64)
        .map(
            |ch| {
                if ch.is_control() || ch == '\u{2028}' || ch == '\u{2029}' {
                    '\u{fffd}'
                } else {
                    ch
                }
            },
        )
        .collect()
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

/// Canonical blinded SSZ bytes → Beacon-API JSON object.
///
/// The inverse of [`decode_blinded`]. [`BodyForkLayout::Gloas`] returns
/// [`BodySszError::GloasUnsupported`] without reading `ssz`.
pub fn encode_blinded(ssz: &[u8], layout: BodyForkLayout) -> Result<Value, BodySszError> {
    match layout {
        BodyForkLayout::Deneb => {
            let body = decode_blinded_beacon_block_body_deneb(ssz)?;
            serde_json::to_value(&body)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))
        }
        BodyForkLayout::Electra => {
            let body = decode_blinded_beacon_block_body_electra(ssz)?;
            serde_json::to_value(&body)
                .map_err(|err| BodySszError::InvalidEncoding(err.to_string()))
        }
        BodyForkLayout::Gloas => Err(BodySszError::GloasUnsupported),
    }
}

/// Reject Beacon-API spellings the primitive schema does not allow.
///
/// [`ethereum/beacon-APIs` `types/primitive.yaml`](https://github.com/ethereum/beacon-APIs/blob/master/types/primitive.yaml):
/// hex is `^0x[a-fA-F0-9]+$`, so the prefix is lowercase `0x` and the digits
/// are case-insensitive (`a-fA-F`; the pubkey text says "case insensitive").
/// `Uint64` and `Uint256` are strings whose example is `"1"`, with no leading
/// `+`.
///
/// Kept lenient on this seam:
/// - uppercase hex digits, because that pattern allows them
/// - a raw JSON number where a quoted integer is also accepted (`quoted_u64`
///   decodes both to the same SSZ)
///
/// [`crate::hex_fixed`] and [`crate::canonical`] still accept `0X`. Those
/// helpers are not this wire seam.
pub fn reject_beacon_api_lenient_spellings(value: &Value) -> Result<(), BodySszError> {
    match value {
        Value::String(text) => {
            if text.starts_with("0X") {
                return Err(BodySszError::InvalidEncoding(
                    "Beacon API hex prefix must be lowercase 0x".into(),
                ));
            }
            if text.len() > 1
                && text.starts_with('+')
                && text.as_bytes()[1..].iter().all(|byte| byte.is_ascii_digit())
            {
                return Err(BodySszError::InvalidEncoding(
                    "Beacon API integer must not have a leading +".into(),
                ));
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_beacon_api_lenient_spellings(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for item in map.values() {
                reject_beacon_api_lenient_spellings(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_body::{
        blinded_body_tree_hash_root_for_layout, body_tree_hash_root_for_layout,
        external_vector_blinded_deneb_body, external_vector_blinded_electra_body,
        external_vector_deneb_body, external_vector_electra_body,
        EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX, EXTERNAL_DENEB_BODY_ROOT_HEX,
        EXTERNAL_ELECTRA_BODY_ROOT_HEX,
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
    /// Beacon-API JSON of [`external_vector_blinded_deneb_body`].
    const DENEB_BLINDED_BODY_JSON: &str =
        include_str!("../tests/fixtures/beacon_api/deneb_blinded_block_body.json");
    /// Beacon-API JSON of [`external_vector_blinded_electra_body`].
    const ELECTRA_BLINDED_BODY_JSON: &str =
        include_str!("../tests/fixtures/beacon_api/electra_blinded_block_body.json");

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

    #[test]
    fn blinded_deneb_body_round_trip_matches_external_body_root() {
        let json = parse(DENEB_BLINDED_BODY_JSON);
        assert!(json["execution_payload_header"].is_object());
        assert!(json.get("execution_payload").is_none());
        assert!(json.get("execution_requests").is_none());
        let ssz = decode_blinded(&json, BodyForkLayout::Deneb).expect("deneb blinded decode");
        assert_eq!(ssz, external_vector_blinded_deneb_body().as_ssz_bytes());
        let again = encode_blinded(&ssz, BodyForkLayout::Deneb).expect("deneb blinded encode");
        assert!(again.is_object());
        assert_eq!(again, json);
        let root =
            blinded_body_tree_hash_root_for_layout(&ssz, BodyForkLayout::Deneb).expect("deneb htr");
        assert_eq!(hex_root(root), EXTERNAL_DENEB_BODY_ROOT_HEX);
        // A second parse has no stored state to drift from the first.
        let again_ssz = decode_blinded(&again, BodyForkLayout::Deneb).expect("second decode");
        assert_eq!(again_ssz, ssz);
    }

    #[test]
    fn blinded_electra_and_fulu_bodies_round_trip_to_the_external_body_root() {
        let json = parse(ELECTRA_BLINDED_BODY_JSON);
        assert!(json["execution_payload_header"].is_object());
        assert!(json["execution_requests"].is_object());
        assert!(json.get("execution_payload").is_none());
        for layout in [BodyForkLayout::Electra, body_fork_layout("fulu").expect("fulu layout")] {
            assert_eq!(layout, BodyForkLayout::Electra);
            let ssz = decode_blinded(&json, layout).expect("electra blinded decode");
            assert_eq!(ssz, external_vector_blinded_electra_body().as_ssz_bytes());
            let again = encode_blinded(&ssz, layout).expect("electra blinded encode");
            assert_eq!(again, json);
            let root = blinded_body_tree_hash_root_for_layout(&ssz, layout).expect("electra htr");
            assert_eq!(hex_root(root), EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX);
        }
    }

    #[test]
    fn blinded_gloas_fails_closed_without_reading_the_input() {
        assert_eq!(
            decode_blinded(&Value::Null, BodyForkLayout::Gloas),
            Err(BodySszError::GloasUnsupported)
        );
        assert_eq!(
            decode_blinded(&parse(ELECTRA_BLINDED_BODY_JSON), BodyForkLayout::Gloas),
            Err(BodySszError::GloasUnsupported)
        );
        assert_eq!(encode_blinded(b"", BodyForkLayout::Gloas), Err(BodySszError::GloasUnsupported));
        assert_eq!(
            encode_blinded(b"not-ssz", BodyForkLayout::Gloas),
            Err(BodySszError::GloasUnsupported)
        );
    }

    #[test]
    fn blinded_decode_rejects_a_partial_or_full_payload_body() {
        let mut missing = parse(ELECTRA_BLINDED_BODY_JSON);
        missing.as_object_mut().expect("object").remove("execution_payload_header");
        let err = decode_blinded(&missing, BodyForkLayout::Electra).expect_err("missing field");
        assert!(
            matches!(err, BodySszError::InvalidEncoding(ref msg) if msg.contains("execution_payload_header")),
            "{err}"
        );

        // `quoted_u64` accepts a JSON number. The integer is the same SSZ as
        // the quoted form. A float, a negative, or a non-integer string is not.
        let mut number = parse(DENEB_BLINDED_BODY_JSON);
        let quoted = decode_blinded(&number, BodyForkLayout::Deneb).expect("quoted block_number");
        number["execution_payload_header"]["block_number"] = serde_json::json!(12_345);
        assert_eq!(
            decode_blinded(&number, BodyForkLayout::Deneb).expect("raw u64"),
            quoted,
            "a raw u64 is the same body as the quoted form"
        );
        for bad in [serde_json::json!(1.5), serde_json::json!(-1), serde_json::json!("nope")] {
            number["execution_payload_header"]["block_number"] = bad;
            assert!(
                matches!(
                    decode_blinded(&number, BodyForkLayout::Deneb),
                    Err(BodySszError::InvalidEncoding(_))
                ),
                "block_number must be an integer"
            );
        }

        assert!(matches!(
            decode_blinded(&parse(ELECTRA_BODY_JSON), BodyForkLayout::Electra),
            Err(BodySszError::InvalidEncoding(_))
        ));
        assert!(matches!(
            decode_blinded(&Value::Array(vec![]), BodyForkLayout::Deneb),
            Err(BodySszError::InvalidEncoding(_))
        ));
        assert!(matches!(
            encode_blinded(&external_vector_deneb_body().as_ssz_bytes(), BodyForkLayout::Deneb),
            Err(BodySszError::InvalidEncoding(_))
        ));
        assert!(matches!(
            encode_blinded(&external_vector_electra_body().as_ssz_bytes(), BodyForkLayout::Electra),
            Err(BodySszError::InvalidEncoding(_))
        ));
        assert!(matches!(
            encode_blinded(&[0xbe, 0xef], BodyForkLayout::Deneb),
            Err(BodySszError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn blinded_layout_does_not_decode_the_other_forks_container() {
        let deneb = parse(DENEB_BLINDED_BODY_JSON);
        let electra = parse(ELECTRA_BLINDED_BODY_JSON);
        assert!(matches!(
            decode_blinded(&deneb, BodyForkLayout::Electra),
            Err(BodySszError::InvalidEncoding(_))
        ));
        assert!(
            matches!(
                decode_blinded(&electra, BodyForkLayout::Deneb),
                Err(BodySszError::InvalidEncoding(_))
            ),
            "execution_requests is not a Deneb field"
        );
        let mut with_payload = electra;
        with_payload["execution_payload"] = with_payload["execution_payload_header"].clone();
        let err = decode_blinded(&with_payload, BodyForkLayout::Electra)
            .expect_err("execution_payload is not a blinded field");
        let BodySszError::InvalidEncoding(msg) = err else {
            panic!("expected InvalidEncoding");
        };
        assert!(msg.contains("execution_payload"), "{msg}");
    }

    #[test]
    fn blinded_json_rejects_uppercase_prefix_and_a_leading_plus() {
        let mut body = parse(DENEB_BLINDED_BODY_JSON);
        let randao = body["randao_reveal"].as_str().expect("randao").to_string();
        assert!(randao.starts_with("0x"));
        body["randao_reveal"] = Value::String(randao.replacen("0x", "0X", 1));
        let err = decode_blinded(&body, BodyForkLayout::Deneb).expect_err("0X");
        assert!(err.to_string().contains("lowercase 0x"), "{err}");

        let mut upper = parse(DENEB_BLINDED_BODY_JSON);
        let original = upper["randao_reveal"].as_str().unwrap();
        let mut chars: Vec<char> = original.chars().collect();
        chars[2] = 'A';
        chars[3] = 'B';
        upper["randao_reveal"] = Value::String(chars.into_iter().collect());
        assert!(
            decode_blinded(&upper, BodyForkLayout::Deneb).is_ok(),
            "primitive.yaml hex digits are a-fA-F"
        );

        let mut plus = parse(DENEB_BLINDED_BODY_JSON);
        plus["execution_payload_header"]["block_number"] = Value::String("+1".into());
        let err = decode_blinded(&plus, BodyForkLayout::Deneb).expect_err("plus");
        assert!(err.to_string().contains("leading +"), "{err}");
    }

    #[test]
    fn blinded_decode_rejects_an_unknown_nested_field() {
        let mut header = parse(DENEB_BLINDED_BODY_JSON);
        header["execution_payload_header"]["not_a_header_field"] = serde_json::json!(1);
        let err = decode_blinded(&header, BodyForkLayout::Deneb).expect_err("header");
        assert!(err.to_string().contains("not_a_header_field"), "{err}");

        let mut eth1 = parse(DENEB_BLINDED_BODY_JSON);
        eth1["eth1_data"]["not_an_eth1_field"] = serde_json::json!(true);
        let err = decode_blinded(&eth1, BodyForkLayout::Deneb).expect_err("eth1");
        assert!(err.to_string().contains("not_an_eth1_field"), "{err}");

        let mut sync = parse(DENEB_BLINDED_BODY_JSON);
        sync["sync_aggregate"]["not_a_sync_field"] = serde_json::json!(1);
        let err = decode_blinded(&sync, BodyForkLayout::Deneb).expect_err("sync");
        assert!(err.to_string().contains("not_a_sync_field"), "{err}");

        let mut body = parse(ELECTRA_BLINDED_BODY_JSON);
        body["execution_requests"]["withdrawals"] = serde_json::json!([{
            "source_address": format!("0x{}", "ab".repeat(20)),
            "validator_pubkey": format!("0x{}", "cd".repeat(48)),
            "amount": "1",
            "not_a_withdrawal_field": "1"
        }]);
        let mut accepted = body.clone();
        accepted["execution_requests"]["withdrawals"][0]
            .as_object_mut()
            .expect("withdrawal")
            .remove("not_a_withdrawal_field");
        assert!(
            decode_blinded(&accepted, BodyForkLayout::Electra).is_ok(),
            "the withdrawal without the extra key decodes"
        );
        let err = decode_blinded(&body, BodyForkLayout::Electra).expect_err("withdrawal");
        assert!(err.to_string().contains("not_a_withdrawal_field"), "{err}");
    }

    /// `serde_json::Value` accepts a struct as a positional array. Re-encode
    /// writes an object, so the extra key must not survive that shape change.
    #[test]
    fn blinded_decode_rejects_positional_execution_requests_with_an_unknown_withdrawal_field() {
        let mut body = parse(ELECTRA_BLINDED_BODY_JSON);
        body["execution_requests"] = serde_json::json!([
            [],
            [{
                "source_address": format!("0x{}", "ab".repeat(20)),
                "validator_pubkey": format!("0x{}", "cd".repeat(48)),
                "amount": "1",
                "not_a_withdrawal_field": "1"
            }],
            []
        ]);
        let err = decode_blinded(&body, BodyForkLayout::Electra)
            .expect_err("positional execution_requests");
        assert!(err.to_string().contains("JSON array was not retained"), "{err}");
    }

    #[test]
    fn round_trip_keeps_a_scalar_array_encoded_as_hex_and_rejects_other_array_shapes() {
        let scalars = serde_json::json!([1, true, "0xab"]);
        let hex = serde_json::json!("0x010203");
        assert!(reject_keys_absent_after_round_trip(&scalars, &hex).is_ok());

        let nested = serde_json::json!([[1]]);
        let err = reject_keys_absent_after_round_trip(&nested, &hex).expect_err("nested array");
        assert!(err.to_string().contains("JSON array was not retained"), "{err}");

        let object = serde_json::json!({"amount": "1"});
        let err = reject_keys_absent_after_round_trip(&scalars, &object).expect_err("object");
        assert!(err.to_string().contains("JSON array was not retained"), "{err}");

        let with_key = serde_json::json!([{"not_a_field": 1}]);
        let err = reject_keys_absent_after_round_trip(&with_key, &hex).expect_err("object element");
        assert!(err.to_string().contains("JSON array was not retained"), "{err}");
    }

    #[test]
    fn unknown_nested_field_error_caps_and_replaces_control_characters() {
        let mut header = parse(DENEB_BLINDED_BODY_JSON);
        let key = format!("bad\n\u{2028}{}", "k".repeat(80));
        header["execution_payload_header"][&key] = serde_json::json!(1);
        let err = decode_blinded(&header, BodyForkLayout::Deneb).expect_err("hostile key");
        let text = err.to_string();
        let expected = format!("bad\u{fffd}\u{fffd}{}", "k".repeat(59));
        assert!(text.contains(&expected), "{text}");
        assert!(!text.contains('\n') && !text.contains('\u{2028}'), "{text}");
        assert!(!text.contains(&"k".repeat(60)), "{text}");
    }

    #[test]
    fn full_body_decode_rejects_an_unknown_top_level_field() {
        for (label, mut body, layout) in [
            ("deneb", contents_body(DENEB_CONTENTS_JSON), BodyForkLayout::Deneb),
            ("electra", parse(ELECTRA_BODY_JSON), BodyForkLayout::Electra),
        ] {
            assert!(decode(&body, layout).is_ok(), "{label} fixture decodes");
            body["not_a_body_field"] = serde_json::json!(1);
            let err = decode(&body, layout).expect_err(label);
            assert!(err.to_string().contains("not_a_body_field"), "{label}: {err}");
        }
    }

    #[test]
    fn full_body_decode_drops_an_unknown_nested_field() {
        for (label, mut body, layout) in [
            ("deneb", contents_body(DENEB_CONTENTS_JSON), BodyForkLayout::Deneb),
            ("electra", parse(ELECTRA_BODY_JSON), BodyForkLayout::Electra),
        ] {
            let clean = decode(&body, layout).expect(label);
            body["execution_payload"]["not_a_payload_field"] = serde_json::json!(1);
            body["eth1_data"]["not_an_eth1_field"] = serde_json::json!(1);
            let decoded = decode(&body, layout).unwrap_or_else(|err| {
                panic!("{label} nested unknown field is not a parse error: {err}")
            });
            assert_eq!(decoded, clean, "{label} nested unknown field is not in the SSZ");
        }
    }
}
