//! Web3Signer `POST /api/v1/eth2/sign/{identifier}` request envelope (FR-3, FR-15/16).
//!
//! Wire types live in [`web3signer_wire`] (RF3-10/RF3-12). This module re-exports them for
//! `dispatch` / `routes` and hosts the server-side decoder conformance suite against the
//! shared types.
//!
//! One `serde` model decodes both Lighthouse and Prysm bodies. The shape is intentionally
//! lenient (research R5): a SCREAMING_SNAKE_CASE `type` discriminator, snake_case payload
//! fields, `fork_info` as `Option` (per-type enforcement lives in the dispatcher, not here —
//! `VALIDATOR_REGISTRATION` will omit it), and `signingRoot` accepted from both `signingRoot`
//! and `signing_root`, treated as absent when empty/zero.
//!
//! This module only *decodes*; the dispatcher computes the domain + signing root and
//! enforces the per-type `fork_info` requirement.

// Re-export the shared wire contract (RF3-12). No local wire type definitions remain.
// Nested payload wrappers are reached via `SignPayload` fields; re-export only what
// `dispatch` / `routes` import by name (keeps unused_imports clean under -D warnings).
pub use web3signer_wire::{SignPayload, SignRequest, WireForkInfo};

#[cfg(test)]
mod tests {
    use super::*;

    fn fork_info_json() -> &'static str {
        r#"{ "fork": { "previous_version": "0x03000000",
                       "current_version": "0x04000000",
                       "epoch": "100" },
             "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }"#
    }

    #[test]
    fn decodes_block_v2() {
        let body = format!(
            r#"{{ "type": "BLOCK_V2",
                  "fork_info": {fi},
                  "signingRoot": "0x{root}",
                  "beacon_block": {{ "version": "DENEB",
                                     "block_header": {{ "slot": "3000000",
                                                        "proposer_index": "12345",
                                                        "parent_root": "0x{r1}",
                                                        "state_root": "0x{r2}",
                                                        "body_root": "0x{r3}" }} }} }}"#,
            fi = fork_info_json(),
            root = "11".repeat(32),
            r1 = "aa".repeat(32),
            r2 = "bb".repeat(32),
            r3 = "cc".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert!(req.fork_info.is_some());
        assert_eq!(req.signing_root, Some([0x11u8; 32]));
        match req.payload {
            SignPayload::BlockV2 { beacon_block } => {
                assert_eq!(beacon_block.version, eth_types::ForkName::Deneb);
                assert_eq!(beacon_block.block_header.slot, 3_000_000);
                assert_eq!(beacon_block.block_header.proposer_index, 12_345);
                assert_eq!(beacon_block.block_header.parent_root, [0xaau8; 32]);
            }
            other => panic!("expected BlockV2, got {other:?}"),
        }
    }

    #[test]
    fn decodes_attestation() {
        let body = format!(
            r#"{{ "type": "ATTESTATION",
                  "fork_info": {fi},
                  "signingRoot": "0x{root}",
                  "attestation": {{ "slot": "5",
                                    "index": "0",
                                    "beacon_block_root": "0x{r}",
                                    "source": {{ "epoch": "1", "root": "0x{r}" }},
                                    "target": {{ "epoch": "2", "root": "0x{r}" }} }} }}"#,
            fi = fork_info_json(),
            root = "22".repeat(32),
            r = "00".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.signing_root, Some([0x22u8; 32]));
        match req.payload {
            SignPayload::Attestation { attestation } => {
                assert_eq!(attestation.slot, 5);
                assert_eq!(attestation.source.epoch, 1);
                assert_eq!(attestation.target.epoch, 2);
            }
            other => panic!("expected Attestation, got {other:?}"),
        }
    }

    #[test]
    fn decodes_randao_reveal_and_aggregation_slot() {
        let randao = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "randao_reveal": {{ "epoch": "42" }} }}"#,
            fi = fork_info_json()
        );
        let req: SignRequest = serde_json::from_str(&randao).unwrap();
        assert!(req.signing_root.is_none(), "absent signingRoot decodes to None");
        match req.payload {
            SignPayload::RandaoReveal { randao_reveal } => assert_eq!(randao_reveal.epoch, 42),
            other => panic!("expected RandaoReveal, got {other:?}"),
        }

        let agg = format!(
            r#"{{ "type": "AGGREGATION_SLOT", "fork_info": {fi},
                  "aggregation_slot": {{ "slot": "77" }} }}"#,
            fi = fork_info_json()
        );
        let req: SignRequest = serde_json::from_str(&agg).unwrap();
        match req.payload {
            SignPayload::AggregationSlot { aggregation_slot } => {
                assert_eq!(aggregation_slot.slot, 77)
            }
            other => panic!("expected AggregationSlot, got {other:?}"),
        }
    }

    #[test]
    fn signing_root_accepts_snake_case_alias() {
        let body = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "signing_root": "0x{root}",
                  "randao_reveal": {{ "epoch": "1" }} }}"#,
            fi = fork_info_json(),
            root = "33".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.signing_root, Some([0x33u8; 32]));
    }

    #[test]
    fn empty_signing_root_is_none_not_error() {
        // Prysm may send an empty signingRoot — must NOT fail to parse.
        for empty in ["\"\"", "\"0x\""] {
            let body = format!(
                r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                      "signingRoot": {empty},
                      "randao_reveal": {{ "epoch": "1" }} }}"#,
                fi = fork_info_json(),
            );
            let req: SignRequest = serde_json::from_str(&body).unwrap();
            assert!(req.signing_root.is_none(), "empty signingRoot {empty} must decode to None");
        }
    }

    #[test]
    fn unknown_type_fails_to_decode() {
        let body = r#"{ "type": "DEPOSIT", "deposit": {} }"#;
        let err = serde_json::from_str::<SignRequest>(body).unwrap_err();
        // Surfaces as a parse error the handler maps to 400.
        assert!(err.to_string().to_lowercase().contains("variant") || !err.to_string().is_empty());
    }

    #[test]
    fn malformed_signing_root_hex_errors() {
        let body = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "signingRoot": "0xZZ",
                  "randao_reveal": {{ "epoch": "1" }} }}"#,
            fi = fork_info_json(),
        );
        assert!(serde_json::from_str::<SignRequest>(&body).is_err());
    }

    #[test]
    fn fork_info_optional_absent_decodes() {
        // fork_info absent is allowed at the serde layer (dispatcher enforces it).
        let body = r#"{ "type": "RANDAO_REVEAL", "randao_reveal": { "epoch": "1" } }"#;
        let req: SignRequest = serde_json::from_str(body).unwrap();
        assert!(req.fork_info.is_none());
    }
}
