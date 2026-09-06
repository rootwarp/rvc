//! `produceBlockV4` wire names and request-body types.
//!
//! Source: beacon-APIs `master` as of 2026-09-05 (PR #630). The V4 shape is
//! untagged and will churn until spec freeze — every V4 field, query, and
//! header name lives in this module so a rename is a one-file edit.

use serde::{Deserialize, Serialize};

/// beacon-APIs revision this module was read from.
pub const V4_WIRE_REVISION: &str = "beacon-APIs master 2026-09-05 (PR #630)";

/// Path prefix for `POST /eth/v4/validator/blocks/{slot}`.
pub const PRODUCE_BLOCK_V4_PATH_PREFIX: &str = "/eth/v4/validator/blocks";

/// Query: proposer's RANDAO reveal (required).
pub const QUERY_RANDAO_REVEAL: &str = "randao_reveal";
/// Query: optional graffiti.
pub const QUERY_GRAFFITI: &str = "graffiti";
/// Query: skip RANDAO verification.
pub const QUERY_SKIP_RANDAO_VERIFICATION: &str = "skip_randao_verification";
/// Query: include self-build payload envelope and blobs (required).
pub const QUERY_INCLUDE_PAYLOAD: &str = "include_payload";

/// Request/response header: consensus version.
pub const HEADER_ETH_CONSENSUS_VERSION: &str = "Eth-Consensus-Version";
/// Response header: consensus block value in Wei.
pub const HEADER_ETH_CONSENSUS_BLOCK_VALUE: &str = "Eth-Consensus-Block-Value";
/// Response header: execution payload value in Wei.
pub const HEADER_ETH_EXECUTION_PAYLOAD_VALUE: &str = "Eth-Execution-Payload-Value";
/// Response header: whether the envelope is in the body.
pub const HEADER_ETH_EXECUTION_PAYLOAD_INCLUDED: &str = "Eth-Execution-Payload-Included";
/// Response header: winning builder URL to echo on publish.
pub const HEADER_ETH_BUILDER_URL: &str = "Eth-Builder-Url";

/// SSZ `MAX_BUILDER_ENTRIES`.
pub const MAX_BUILDER_ENTRIES: usize = 64;
/// SSZ `MAX_BUILDER_URL_SIZE` (UTF-8 bytes).
pub const MAX_BUILDER_URL_SIZE: usize = 2048;
/// SSZ `MAX_BUILDER_PUBKEYS`.
pub const MAX_BUILDER_PUBKEYS: usize = 64;

/// Built-in `builder_boost_factor` when neither per-validator nor global is set.
pub const FALLBACK_BUILDER_BOOST_FACTOR: u64 = 100;
/// Built-in `min_bid` when neither per-validator nor global is set.
pub const FALLBACK_MIN_BID: u64 = 0;

/// Opaque builder-request auth payload (JSON hex + slot).
///
/// SSZ / domain signing is issue 6.16; this is the V4 JSON shape only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderRequestAuth {
    pub data: String,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
}

/// Signed `BuilderRequestAuth` forwarded byte-for-byte to the builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBuilderRequestAuth {
    pub message: BuilderRequestAuth,
    pub signature: String,
}

/// Per-builder bid request on a V4 produce-block body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderEntry {
    pub url: String,
    pub auth: SignedBuilderRequestAuth,
    pub builder_pubkeys: Vec<String>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub max_execution_payment: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub min_bid: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_boost_factor: u64,
}

/// Required JSON/SSZ body for `produceBlockV4`.
///
/// An empty `builders` list is legal (local-only / p2p-only) and serializes as
/// `[]`. Top-level `min_bid` / `builder_boost_factor` apply to p2p bids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderConfig {
    #[serde(with = "serde_utils::quoted_u64")]
    pub min_bid: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_boost_factor: u64,
    pub builders: Vec<BuilderEntry>,
}

impl Default for BuilderConfig {
    fn default() -> Self {
        Self {
            min_bid: FALLBACK_MIN_BID,
            builder_boost_factor: FALLBACK_BUILDER_BOOST_FACTOR,
            builders: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_auth() -> SignedBuilderRequestAuth {
        SignedBuilderRequestAuth {
            message: BuilderRequestAuth { data: "0x1234".to_string(), slot: 32 },
            signature: format!("0x{}", "ab".repeat(96)),
        }
    }

    fn sample_entry(url: &str) -> BuilderEntry {
        BuilderEntry {
            url: url.to_string(),
            auth: sample_auth(),
            builder_pubkeys: vec![],
            max_execution_payment: 1_000_000_000,
            min_bid: 10_000_000,
            builder_boost_factor: 100,
        }
    }

    #[test]
    fn builder_config_serde_round_trip() {
        let original = BuilderConfig {
            min_bid: 10_000_000,
            builder_boost_factor: 100,
            builders: vec![sample_entry("https://builder.example.com")],
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: BuilderConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, decoded);
    }

    #[test]
    fn empty_builders_list_is_legal_and_round_trips() {
        let original = BuilderConfig { min_bid: 0, builder_boost_factor: 0, builders: Vec::new() };
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(json.contains("[]"), "empty builders must serialize as an array: {json}");
        let decoded: BuilderConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, decoded);
        assert!(decoded.builders.is_empty());
    }

    #[test]
    fn quoted_integers_round_trip_from_json_strings() {
        let value = json!({
            "min_bid": "42",
            "builder_boost_factor": "7",
            "builders": []
        });
        let decoded: BuilderConfig = serde_json::from_value(value).expect("quoted u64");
        assert_eq!(decoded.min_bid, 42);
        assert_eq!(decoded.builder_boost_factor, 7);
        assert_eq!(
            decoded,
            serde_json::from_str(&serde_json::to_string(&decoded).unwrap()).unwrap()
        );
    }
}
