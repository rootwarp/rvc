//! HTTP thin adapter over the transport-neutral [`sign_plan`] engine (RF4-09).
//!
//! Converts a decoded Web3Signer [`SignRequest`] into a [`PlanInput`], calls the
//! shared [`plan_sign`](crate::sign_plan::plan_sign), and applies the HTTP-only
//! `signingRoot` verification policy (FR-16, ADR-007). Domain / root policy is
//! **not** owned here — it lives in `crate::sign_plan`.
//!
//! Security (SEC-INFO-01): every `BadRequest` this module emits is a fixed,
//! enumerated string. It never interpolates request bytes, serde/SSZ decoder text,
//! or filesystem paths into a client-visible body.

use tree_hash::TreeHash;

use crate::sign_plan::{self, client_signing_root_matches, PlanInput, SignPlan};

use super::request::{SignPayload, SignRequest, WireForkInfo};
use super::response::HttpSignError;
use web3signer_wire::reject_gloas_http_wire;

/// Compute the server-side signing root for `req`, enforce the per-type
/// `fork_info` requirement, and apply the `signingRoot` verification policy
/// (FR-15, FR-16, ADR-007).
///
/// `genesis_fork_version` is the server network genesis (from
/// [`super::Web3SignerState`]); it is the sole source for builder-registration
/// domain computation.
///
/// Returns the shared [`SignPlan`] for the gate, or a pre-gate `400`
/// ([`HttpSignError::BadRequest`]) that never reaches the gate.
pub(super) fn plan_sign(
    req: &SignRequest,
    genesis_fork_version: [u8; 4],
) -> Result<SignPlan, HttpSignError> {
    let input = to_plan_input(req, genesis_fork_version)?;
    let plan = sign_plan::plan_sign(&input);
    if !client_signing_root_matches(req.signing_root, plan.signing_root) {
        return Err(HttpSignError::BadRequest(
            "signingRoot does not match the server-computed signing root".to_string(),
        ));
    }
    Ok(plan)
}

/// Map a Web3Signer `SignRequest` onto the transport-neutral [`PlanInput`].
fn to_plan_input(
    req: &SignRequest,
    genesis_fork_version: [u8; 4],
) -> Result<PlanInput, HttpSignError> {
    match &req.payload {
        SignPayload::BlockV2 { beacon_block } => {
            // D19: reject Gloas before tree_hash 0.9 derivation.
            reject_gloas_http_wire(beacon_block.version, "BLOCK_V2")
                .map_err(|e| HttpSignError::BadRequest(e.to_string()))?;
            let (fork_version, gvr) = require_fork_info(req)?;
            let object_root = beacon_block.block_header.tree_hash_root().0;
            Ok(PlanInput::Block {
                object_root,
                slot: beacon_block.block_header.slot,
                fork_version,
                gvr,
            })
        }
        SignPayload::Attestation { attestation } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            Ok(PlanInput::Attestation { data: attestation.clone(), fork_version, gvr })
        }
        SignPayload::RandaoReveal { randao_reveal } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            Ok(PlanInput::Randao { epoch: randao_reveal.epoch, fork_version, gvr })
        }
        SignPayload::AggregationSlot { aggregation_slot } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            Ok(PlanInput::AggregationSlot { slot: aggregation_slot.slot, fork_version, gvr })
        }
        SignPayload::AggregateAndProof { aggregate_and_proof } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            let object_root = aggregate_and_proof.try_tree_hash_root().map_err(|_| {
                HttpSignError::BadRequest("invalid aggregate_and_proof".to_string())
            })?;
            Ok(PlanInput::AggregateAndProof { object_root: object_root.0, fork_version, gvr })
        }
        SignPayload::SyncCommitteeMessage { sync_committee_message } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            Ok(PlanInput::SyncCommitteeMessage {
                beacon_block_root: sync_committee_message.beacon_block_root,
                fork_version,
                gvr,
            })
        }
        SignPayload::SyncCommitteeContributionAndProof { contribution_and_proof } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            let object_root = contribution_and_proof.tree_hash_root().0;
            Ok(PlanInput::ContributionAndProof { object_root, fork_version, gvr })
        }
        SignPayload::SyncCommitteeSelectionProof { sync_aggregator_selection_data } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            Ok(PlanInput::SyncCommitteeSelection {
                data: eth_types::SyncAggregatorSelectionData {
                    slot: sync_aggregator_selection_data.slot,
                    subcommittee_index: sync_aggregator_selection_data.subcommittee_index,
                },
                fork_version,
                gvr,
            })
        }
        SignPayload::ValidatorRegistration { validator_registration } => {
            // NO fork_info (ADR-008): builder domain uses the server network
            // genesis fork version + zero gvr (same source as gRPC).
            let object_root = validator_registration.tree_hash_root().0;
            Ok(PlanInput::BuilderRegistration { object_root, genesis_fork_version })
        }
        SignPayload::VoluntaryExit { voluntary_exit } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            let object_root = voluntary_exit.tree_hash_root().0;
            Ok(PlanInput::VoluntaryExit { object_root, fork_version, gvr })
        }
        SignPayload::AggregateAndProofV2 { aggregate_and_proof } => {
            // D19: reject Gloas before tree_hash 0.9 derivation.
            reject_gloas_http_wire(aggregate_and_proof.version, "AGGREGATE_AND_PROOF_V2")
                .map_err(|e| HttpSignError::BadRequest(e.to_string()))?;
            let (fork_version, gvr) = require_fork_info(req)?;
            let object_root = aggregate_and_proof.data.try_tree_hash_root().map_err(|_| {
                HttpSignError::BadRequest("invalid aggregate_and_proof".to_string())
            })?;
            Ok(PlanInput::AggregateAndProof { object_root: object_root.0, fork_version, gvr })
        }
        SignPayload::PayloadAttestation { payload_attestation } => {
            // D19: Gloas PTC is in scope (unlike BLOCK_V2).
            let (fork_version, gvr) = require_fork_info(req)?;
            let object_root = payload_attestation.data.tree_hash_root().0;
            Ok(PlanInput::PayloadAttestation { object_root, fork_version, gvr })
        }
    }
}

/// Require `fork_info` and return `(current_version, gvr)`.
fn require_fork_info(req: &SignRequest) -> Result<([u8; 4], eth_types::Root), HttpSignError> {
    let fi: &WireForkInfo = req.fork_info.as_ref().ok_or_else(|| {
        HttpSignError::BadRequest("fork_info is required for this request type".to_string())
    })?;
    Ok((fi.fork.current_version, fi.genesis_validators_root))
}

#[cfg(test)]
mod tests {
    use crate::sign_plan::BUILDER_FORK_VERSION_MAINNET;

    use super::*;
    use crate::sign_plan::Slashing;
    use axum::http::StatusCode;
    use crypto::{compute_domain, compute_signing_root};
    use eth_types::{
        AttestationData, Checkpoint, ElectraAggregateAndProof, ElectraAttestation, Root,
        DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
    };

    fn fork_info_json() -> &'static str {
        r#"{ "fork": { "previous_version": "0x03000000",
                       "current_version": "0x04000000",
                       "epoch": "100" },
             "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }"#
    }

    fn parse(body: &str) -> SignRequest {
        serde_json::from_str(body).expect("request fixture decodes")
    }

    fn block_v2(signing_root: Option<&str>) -> SignRequest {
        let sr = signing_root.map(|r| format!(r#""signingRoot": "{r}","#)).unwrap_or_default();
        parse(&format!(
            r#"{{ "type": "BLOCK_V2", "fork_info": {fi}, {sr}
                  "beacon_block": {{ "version": "DENEB",
                                     "block_header": {{ "slot": "3000000",
                                                        "proposer_index": "12345",
                                                        "parent_root": "0x{r1}",
                                                        "state_root": "0x{r2}",
                                                        "body_root": "0x{r3}" }} }} }}"#,
            fi = fork_info_json(),
            r1 = "aa".repeat(32),
            r2 = "bb".repeat(32),
            r3 = "cc".repeat(32),
        ))
    }

    fn attestation() -> SignRequest {
        parse(&format!(
            r#"{{ "type": "ATTESTATION", "fork_info": {fi},
                  "attestation": {{ "slot": "5", "index": "0",
                                    "beacon_block_root": "0x{r}",
                                    "source": {{ "epoch": "1", "root": "0x{r}" }},
                                    "target": {{ "epoch": "2", "root": "0x{r}" }} }} }}"#,
            fi = fork_info_json(),
            r = "00".repeat(32),
        ))
    }

    fn randao(with_fork_info: bool) -> SignRequest {
        let fi = if with_fork_info {
            format!(r#""fork_info": {},"#, fork_info_json())
        } else {
            String::new()
        };
        parse(&format!(
            r#"{{ "type": "RANDAO_REVEAL", {fi} "randao_reveal": {{ "epoch": "42" }} }}"#
        ))
    }

    fn aggregation_slot() -> SignRequest {
        parse(&format!(
            r#"{{ "type": "AGGREGATION_SLOT", "fork_info": {fi},
                  "aggregation_slot": {{ "slot": "77" }} }}"#,
            fi = fork_info_json(),
        ))
    }

    // Expected fork inputs from `fork_info_json()`.
    const CURRENT_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    fn expected_gvr() -> Root {
        let mut g = [0u8; 32];
        g[..16].copy_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);
        g[16..].copy_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);
        g
    }

    #[test]
    fn block_v2_uses_proposer_domain_and_block_header_root() {
        let req = block_v2(None);
        let plan = plan_sign(&req, BUILDER_FORK_VERSION_MAINNET).expect("block plan");

        let SignPayload::BlockV2 { beacon_block } = &req.payload else { panic!("block payload") };
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_VERSION, expected_gvr());
        let want = compute_signing_root(&beacon_block.block_header, domain);

        assert_eq!(plan.signing_root, want);
        assert_eq!(plan.slashing, Slashing::Block { slot: 3_000_000, gvr: expected_gvr() });
    }

    #[test]
    fn attestation_uses_attester_domain_and_carries_epochs() {
        let req = attestation();
        let plan = plan_sign(&req, BUILDER_FORK_VERSION_MAINNET).expect("attestation plan");

        let SignPayload::Attestation { attestation } = &req.payload else { panic!("att payload") };
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, CURRENT_VERSION, expected_gvr());
        let want = compute_signing_root(attestation, domain);

        assert_eq!(plan.signing_root, want);
        assert_eq!(
            plan.slashing,
            Slashing::Attestation { source_epoch: 1, target_epoch: 2, gvr: expected_gvr() }
        );
    }

    #[test]
    fn randao_and_aggregation_slot_are_nonslashable_with_distinct_domains() {
        let randao_plan =
            plan_sign(&randao(true), BUILDER_FORK_VERSION_MAINNET).expect("randao plan");
        assert_eq!(randao_plan.slashing, Slashing::NonSlashable);
        let randao_want = compute_signing_root(
            &42u64,
            compute_domain(DOMAIN_RANDAO, CURRENT_VERSION, expected_gvr()),
        );
        assert_eq!(randao_plan.signing_root, randao_want);

        let agg_plan =
            plan_sign(&aggregation_slot(), BUILDER_FORK_VERSION_MAINNET).expect("aggregation plan");
        assert_eq!(agg_plan.slashing, Slashing::NonSlashable);
        let agg_want = compute_signing_root(
            &77u64,
            compute_domain(DOMAIN_SELECTION_PROOF, CURRENT_VERSION, expected_gvr()),
        );
        assert_eq!(agg_plan.signing_root, agg_want);

        let r = compute_signing_root(
            &7u64,
            compute_domain(DOMAIN_RANDAO, CURRENT_VERSION, expected_gvr()),
        );
        let a = compute_signing_root(
            &7u64,
            compute_domain(DOMAIN_SELECTION_PROOF, CURRENT_VERSION, expected_gvr()),
        );
        assert_ne!(r, a, "different domains must yield different signing roots");
    }

    #[test]
    fn matching_signing_root_proceeds() {
        let server_root =
            plan_sign(&block_v2(None), BUILDER_FORK_VERSION_MAINNET).unwrap().signing_root;
        let req = block_v2(Some(&format!("0x{}", hex::encode(server_root))));
        let plan =
            plan_sign(&req, BUILDER_FORK_VERSION_MAINNET).expect("matching signingRoot proceeds");
        assert_eq!(plan.signing_root, server_root);
    }

    #[test]
    fn mismatching_signing_root_is_400_and_no_plan() {
        let bad = format!("0x{}", "ff".repeat(32));
        let err = plan_sign(&block_v2(Some(&bad)), BUILDER_FORK_VERSION_MAINNET)
            .expect_err("mismatch must 400");
        let (status, _) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn absent_or_zero_signing_root_proceeds() {
        assert!(
            plan_sign(&block_v2(None), BUILDER_FORK_VERSION_MAINNET).is_ok(),
            "absent signingRoot proceeds"
        );
        let zero = format!("0x{}", "00".repeat(32));
        assert!(
            plan_sign(&block_v2(Some(&zero)), BUILDER_FORK_VERSION_MAINNET).is_ok(),
            "zero signingRoot proceeds"
        );
    }

    #[test]
    fn missing_fork_info_is_400() {
        let err = plan_sign(&randao(false), BUILDER_FORK_VERSION_MAINNET)
            .expect_err("missing fork_info must 400");
        let (status, _) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// SEC-INFO-01: `BadRequest` bodies are fixed, enumerated strings.
    #[test]
    fn bad_request_bodies_are_static_and_leak_free() {
        let bad_hex = "ff".repeat(32);
        let (_, mismatch_body) =
            plan_sign(&block_v2(Some(&format!("0x{bad_hex}"))), BUILDER_FORK_VERSION_MAINNET)
                .unwrap_err()
                .status_and_body();
        assert_eq!(mismatch_body, "signingRoot does not match the server-computed signing root");
        assert!(!mismatch_body.contains(&bad_hex), "must not echo the supplied root");
        assert!(!mismatch_body.contains("0x"), "no hex/material in the body");

        let (_, missing_body) =
            plan_sign(&randao(false), BUILDER_FORK_VERSION_MAINNET).unwrap_err().status_and_body();
        assert_eq!(missing_body, "fork_info is required for this request type");
    }

    fn gloas_block_v2() -> SignRequest {
        parse(&format!(
            r#"{{ "type": "BLOCK_V2", "fork_info": {fi},
                  "beacon_block": {{ "version": "GLOAS",
                                     "block_header": {{ "slot": "3000000",
                                                        "proposer_index": "12345",
                                                        "parent_root": "0x{r}",
                                                        "state_root": "0x{r}",
                                                        "body_root": "0x{r}" }} }} }}"#,
            fi = fork_info_json(),
            r = "aa".repeat(32),
        ))
    }

    #[test]
    fn gloas_block_v2_is_rejected_before_root_derivation() {
        let err = plan_sign(&gloas_block_v2(), BUILDER_FORK_VERSION_MAINNET)
            .expect_err("D19: GLOAS BLOCK_V2 must 400");
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("BLOCK_V2"), "names the HTTP type: {body}");
        assert!(body.contains("GLOAS"), "names the version: {body}");
        assert!(body.contains("Web3Signer HTTP wire"), "names the wire: {body}");
        assert!(body.contains("deferred"), "names the deferral: {body}");
    }

    #[test]
    fn gloas_aggregate_and_proof_v2_is_rejected_before_root_derivation() {
        let z = [0u8; 32];
        let unhashable = ElectraAggregateAndProof {
            aggregator_index: 1,
            aggregate: ElectraAttestation {
                // Past the Electra bitlist limit: hashing first would 400 as
                // `invalid aggregate_and_proof` instead of the D19 deferral.
                aggregation_bits: vec![0xff; 20_000],
                data: AttestationData {
                    slot: 5,
                    index: 0,
                    beacon_block_root: z,
                    source: Checkpoint { epoch: 1, root: z },
                    target: Checkpoint { epoch: 2, root: z },
                },
                signature: vec![0xab; 96],
                committee_bits: vec![0x01; 8],
            },
            selection_proof: vec![0xcd; 96],
        };
        let req = parse(&format!(
            r#"{{ "type": "AGGREGATE_AND_PROOF_V2", "fork_info": {fi},
                  "aggregate_and_proof": {{ "version": "GLOAS", "data": {data} }} }}"#,
            fi = fork_info_json(),
            data = serde_json::to_string(&unhashable).unwrap(),
        ));
        let err = plan_sign(&req, BUILDER_FORK_VERSION_MAINNET)
            .expect_err("D19: GLOAS AGGREGATE_AND_PROOF_V2 must 400");
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_ne!(body, "invalid aggregate_and_proof", "must not have hashed first");
        assert!(body.contains("AGGREGATE_AND_PROOF_V2"), "names the HTTP type: {body}");
        assert!(body.contains("Web3Signer HTTP wire"), "names the wire: {body}");
        assert!(body.contains("deferred"), "names the deferral: {body}");
    }

    fn gloas_payload_attestation() -> SignRequest {
        parse(&format!(
            r#"{{ "type": "PAYLOAD_ATTESTATION",
                  "fork_info": {{ "fork": {{ "previous_version": "0x07000000",
                                             "current_version": "0x07000001",
                                             "epoch": "0" }},
                       "genesis_validators_root": "0x{gvr}" }},
                  "payload_attestation": {{ "version": "GLOAS",
                                            "data": {{ "beacon_block_root": "0x{br}",
                                                       "slot": "1",
                                                       "payload_present": true,
                                                       "blob_data_available": false }} }} }}"#,
            gvr = "00".repeat(32),
            br = "11".repeat(32),
        ))
    }

    fn parse_kat_root(hex: &str) -> Root {
        hex::decode(hex).expect("kat hex").try_into().expect("32-byte kat root")
    }

    /// L3: HTTP adapter plans the same root as the plan engine / pyspec artifact.
    #[test]
    fn payload_attestation_plan_matches_kat_gloas_payload_attestation_signing_root() {
        let plan = plan_sign(&gloas_payload_attestation(), BUILDER_FORK_VERSION_MAINNET)
            .expect("D19: GLOAS PAYLOAD_ATTESTATION is in scope");
        assert_eq!(plan.slashing, Slashing::NonSlashable);
        assert_eq!(
            plan.signing_root,
            parse_kat_root(rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT)
        );
    }
}
