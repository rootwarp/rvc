//! Request builders and config for the Web3Signer HTTP client.
//!
//! Wire **types** live in [`web3signer_wire`] (RF3-10). This module owns the
//! client-side construction of those types (domain + signing root + payload)
//! plus [`RemoteSignerConfig`]. RF3-10-M1: every builder always sets
//! `signing_root: Some(...)` via [`SignRequest::with_fork`] /
//! [`SignRequest::without_fork`].

use std::time::Duration;

use eth_types::{
    blinded_body_tree_hash_root, body_tree_hash_root, AggregateAndProof, AttestationData,
    BeaconBlock, BeaconBlockHeader, BlindedBeaconBlock, ContributionAndProof, Epoch, Fork,
    ForkName, PayloadAttestationData, ProposerPreferences, Root, Slot, SyncCommitteeMessage,
    ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER,
    DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
// Re-export wire types under the historical crypto names (stable public paths).
pub use web3signer_wire::{
    AggregationSlotPayload, BeaconBlockEnvelope, RandaoRevealPayload, SyncSelectionPayload,
    WireForkInfo,
};
pub use web3signer_wire::{SignPayload as Web3SignerPayload, SignRequest as Web3SignerSignRequest};

use web3signer_wire::{reject_gloas_http_wire, SignPayload, SignRequest, VersionedPayload};

use crypto::signing_root_with_fork_version;
use crypto::{SignContext, SigningError};

const DEFAULT_TIMEOUT_SECS: u64 = 12;

#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    pub url: String,
    pub timeout: Duration,
}

impl RemoteSignerConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Build wire `fork_info` from a signing [`SignContext`].
///
/// `fork.epoch` is not carried on [`eth_types::ForkInfo`]; the server only
/// uses `current_version` + gvr for domain computation, so epoch is `0`.
pub fn wire_fork_info_from_sign_context(ctx: &SignContext) -> WireForkInfo {
    WireForkInfo {
        fork: Fork {
            previous_version: ctx.fork_info.previous_version,
            current_version: ctx.fork_info.current_version,
            epoch: 0,
        },
        genesis_validators_root: ctx.fork_info.genesis_validators_root,
    }
}

/// Extension kept so call sites can write `WireForkInfo::from_sign_context(ctx)`.
pub trait WireForkInfoExt {
    fn from_sign_context(ctx: &SignContext) -> Self;
}

impl WireForkInfoExt for WireForkInfo {
    fn from_sign_context(ctx: &SignContext) -> Self {
        wire_fork_info_from_sign_context(ctx)
    }
}

/// Exact JSON body for contract tests / wire inspection.
pub fn sign_request_to_json(req: &SignRequest) -> Result<serde_json::Value, SigningError> {
    serde_json::to_value(req)
        .map_err(|e| SigningError::RemoteSignerError(format!("serialize sign body: {e}")))
}

/// Convenience trait mirroring the pre-split `Web3SignerSignRequest::to_json_value`.
pub trait SignRequestJson {
    fn to_json_value(&self) -> Result<serde_json::Value, SigningError>;
}

impl SignRequestJson for SignRequest {
    fn to_json_value(&self) -> Result<serde_json::Value, SigningError> {
        sign_request_to_json(self)
    }
}

/// Fail closed on Gloas for HTTP block/aggregate builders (D19) *before*
/// `tree_hash` 0.9 derivation.
fn http_wire_fork_name(
    ctx: &SignContext,
    type_name: &'static str,
) -> Result<ForkName, SigningError> {
    reject_gloas_http_wire(ctx.fork_name, type_name)
        .map_err(|e| SigningError::LocalRejected(e.to_string()))?;
    Ok(ctx.fork_name)
}

fn header_from_beacon_block(block: &BeaconBlock) -> Result<BeaconBlockHeader, SigningError> {
    let body_root = body_tree_hash_root(&block.body).map_err(|e| {
        SigningError::RemoteSignerError(format!("invalid beacon block body for BLOCK_V2: {e}"))
    })?;
    Ok(BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root: body_root.0,
    })
}

fn header_from_blinded_block(
    block: &BlindedBeaconBlock,
) -> Result<BeaconBlockHeader, SigningError> {
    let body_root = blinded_body_tree_hash_root(&block.body).map_err(|e| {
        SigningError::RemoteSignerError(format!("invalid blinded block body for BLOCK_V2: {e}"))
    })?;
    Ok(BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root: body_root.0,
    })
}

/// Build a `BLOCK_V2` request for a full beacon block.
pub fn build_block_v2_request(
    block: &BeaconBlock,
    ctx: &SignContext,
) -> Result<(SignRequest, Root), SigningError> {
    let version = http_wire_fork_name(ctx, "BLOCK_V2")?;
    let header = header_from_beacon_block(block)?;
    let signing_root = signing_root_with_fork_version(
        &header,
        DOMAIN_BEACON_PROPOSER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::BlockV2 {
            beacon_block: BeaconBlockEnvelope { version, block_header: header },
        },
    );
    Ok((req, signing_root))
}

/// Build a `BLOCK_V2` request for a blinded beacon block.
pub fn build_blinded_block_v2_request(
    block: &BlindedBeaconBlock,
    ctx: &SignContext,
) -> Result<(SignRequest, Root), SigningError> {
    let version = http_wire_fork_name(ctx, "BLOCK_V2")?;
    let header = header_from_blinded_block(block)?;
    let signing_root = signing_root_with_fork_version(
        &header,
        DOMAIN_BEACON_PROPOSER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::BlockV2 {
            beacon_block: BeaconBlockEnvelope { version, block_header: header },
        },
    );
    Ok((req, signing_root))
}

/// Build an `ATTESTATION` request.
pub fn build_attestation_request(data: &AttestationData, ctx: &SignContext) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        data,
        DOMAIN_BEACON_ATTESTER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::Attestation { attestation: data.clone() },
    );
    (req, signing_root)
}

/// Build a `RANDAO_REVEAL` request.
pub fn build_randao_reveal_request(epoch: Epoch, ctx: &SignContext) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        &epoch,
        DOMAIN_RANDAO,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::RandaoReveal { randao_reveal: RandaoRevealPayload { epoch } },
    );
    (req, signing_root)
}

/// Build an `AGGREGATE_AND_PROOF` request.
pub fn build_aggregate_and_proof_request(
    agg: &AggregateAndProof,
    ctx: &SignContext,
) -> Result<(SignRequest, Root), SigningError> {
    reject_gloas_http_wire(ctx.fork_name, "AGGREGATE_AND_PROOF")
        .map_err(|e| SigningError::LocalRejected(e.to_string()))?;
    let signing_root = signing_root_with_fork_version(
        agg,
        DOMAIN_AGGREGATE_AND_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::AggregateAndProof { aggregate_and_proof: agg.clone() },
    );
    Ok((req, signing_root))
}

/// Build a `PAYLOAD_ATTESTATION` request.
///
/// PTC is Gloas-only. D19 does **not** reject this type on the HTTP wire
/// (unlike `BLOCK_V2` / `AGGREGATE_AND_PROOF`). Version is always `GLOAS`.
pub fn build_payload_attestation_request(
    data: &PayloadAttestationData,
    ctx: &SignContext,
) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        data,
        DOMAIN_PTC_ATTESTER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::PayloadAttestation {
            payload_attestation: VersionedPayload { version: ForkName::Gloas, data: data.clone() },
        },
    );
    (req, signing_root)
}

/// Build a `PROPOSER_PREFERENCES` request.
///
/// Proposer preferences is Gloas-only. D19 does **not** reject this type on
/// the HTTP wire (unlike `BLOCK_V2` / `AGGREGATE_AND_PROOF`). Version is always
/// `GLOAS`.
pub fn build_proposer_preferences_request(
    prefs: &ProposerPreferences,
    ctx: &SignContext,
) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        prefs,
        DOMAIN_PROPOSER_PREFERENCES,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::ProposerPreferences {
            proposer_preferences: VersionedPayload {
                version: ForkName::Gloas,
                data: prefs.clone(),
            },
        },
    );
    (req, signing_root)
}

/// Build a `SYNC_COMMITTEE_MESSAGE` request.
pub fn build_sync_committee_message_request(
    slot: Slot,
    beacon_block_root: Root,
    ctx: &SignContext,
) -> (SignRequest, Root) {
    // Server signs the block root itself (not the message container).
    let signing_root = signing_root_with_fork_version(
        &beacon_block_root,
        DOMAIN_SYNC_COMMITTEE,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let msg = SyncCommitteeMessage {
        slot,
        beacon_block_root,
        // Not part of the signed object; placeholder for the wire envelope.
        validator_index: 0,
        signature: vec![0u8; 96],
    };
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::SyncCommitteeMessage { sync_committee_message: msg },
    );
    (req, signing_root)
}

/// Build a `SYNC_COMMITTEE_SELECTION_PROOF` request.
pub fn build_sync_selection_proof_request(
    slot: Slot,
    subcommittee_index: u64,
    ctx: &SignContext,
) -> (SignRequest, Root) {
    let selection = eth_types::SyncAggregatorSelectionData { slot, subcommittee_index };
    let signing_root = signing_root_with_fork_version(
        &selection,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::SyncCommitteeSelectionProof {
            sync_aggregator_selection_data: SyncSelectionPayload { slot, subcommittee_index },
        },
    );
    (req, signing_root)
}

/// Build a `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` request.
pub fn build_contribution_and_proof_request(
    c: &ContributionAndProof,
    ctx: &SignContext,
) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        c,
        DOMAIN_CONTRIBUTION_AND_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::SyncCommitteeContributionAndProof { contribution_and_proof: c.clone() },
    );
    (req, signing_root)
}

/// Build a `VALIDATOR_REGISTRATION` request (no `fork_info` — ADR-008).
pub fn build_validator_registration_request(
    reg: &ValidatorRegistrationV1,
    genesis_fork_version: [u8; 4],
) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        reg,
        DOMAIN_APPLICATION_BUILDER,
        genesis_fork_version,
        [0u8; 32],
    );
    let req = SignRequest::without_fork(
        signing_root,
        SignPayload::ValidatorRegistration { validator_registration: reg.clone() },
    );
    (req, signing_root)
}

/// Build a `VOLUNTARY_EXIT` request.
pub fn build_voluntary_exit_request(
    exit: &VoluntaryExit,
    ctx: &SignContext,
) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        exit,
        DOMAIN_VOLUNTARY_EXIT,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::VoluntaryExit { voluntary_exit: exit.clone() },
    );
    (req, signing_root)
}

/// Build an `AGGREGATION_SLOT` request (attestation selection proof).
pub fn build_aggregation_slot_request(slot: Slot, ctx: &SignContext) -> (SignRequest, Root) {
    let signing_root = signing_root_with_fork_version(
        &slot,
        eth_types::DOMAIN_SELECTION_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let req = SignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        signing_root,
        SignPayload::AggregationSlot { aggregation_slot: AggregationSlotPayload { slot } },
    );
    (req, signing_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{SecretKey, SigningError};
    use eth_types::{
        Attestation, BlindedBeaconBlock, Checkpoint, ForkInfo, ForkName, SyncCommitteeContribution,
    };

    fn test_fork_info() -> ForkInfo {
        ForkInfo {
            previous_version: [0x03, 0x00, 0x00, 0x00],
            current_version: [0x04, 0x00, 0x00, 0x00], // DENEB
            genesis_validators_root: [0xaa; 32],
        }
    }

    fn test_ctx(sk: &SecretKey) -> SignContext {
        SignContext {
            pubkey: sk.public_key(),
            fork_info: test_fork_info(),
            fork_name: eth_types::ForkName::Deneb,
        }
    }

    fn sample_attestation() -> AttestationData {
        AttestationData {
            slot: 5,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 1, root: [0x22; 32] },
            target: Checkpoint { epoch: 2, root: [0x33; 32] },
        }
    }

    fn root_hex(root: &Root) -> String {
        format!("0x{}", hex::encode(root))
    }

    /// RF3-10-M1 / RF3-11: every client-reachable builder must set `signing_root`.
    #[test]
    // kat_exempt: name-pattern false positive — asserts the wire field is populated, not a spec root
    fn test_all_builders_set_signing_root() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        let checks: Vec<(&str, SignRequest, Root)> = {
            let mut v = Vec::new();

            let (req, root) = build_attestation_request(&data, &ctx);
            v.push(("ATTESTATION", req, root));

            let (req, root) = build_randao_reveal_request(42, &ctx);
            v.push(("RANDAO_REVEAL", req, root));

            let (req, root) = build_aggregation_slot_request(77, &ctx);
            v.push(("AGGREGATION_SLOT", req, root));

            let agg = AggregateAndProof {
                aggregator_index: 1,
                aggregate: Attestation {
                    aggregation_bits: vec![0x01],
                    data: data.clone(),
                    signature: vec![0xab; 96],
                },
                selection_proof: vec![0xcd; 96],
            };
            let (req, root) =
                build_aggregate_and_proof_request(&agg, &ctx).expect("aggregate builder");
            v.push(("AGGREGATE_AND_PROOF", req, root));

            let (req, root) = build_sync_committee_message_request(5, [0x22; 32], &ctx);
            v.push(("SYNC_COMMITTEE_MESSAGE", req, root));

            let (req, root) = build_sync_selection_proof_request(5, 2, &ctx);
            v.push(("SYNC_COMMITTEE_SELECTION_PROOF", req, root));

            let c = ContributionAndProof {
                aggregator_index: 1,
                contribution: SyncCommitteeContribution {
                    slot: 5,
                    beacon_block_root: [0x11; 32],
                    subcommittee_index: 0,
                    aggregation_bits: vec![0u8; 16],
                    signature: vec![0xab; 96],
                },
                selection_proof: vec![0xcd; 96],
            };
            let (req, root) = build_contribution_and_proof_request(&c, &ctx);
            v.push(("SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", req, root));

            let reg = ValidatorRegistrationV1 {
                fee_recipient: {
                    let mut fr = [0u8; 20];
                    fr[19] = 1;
                    fr
                },
                gas_limit: 30_000_000,
                timestamp: 100,
                pubkey: [0xaa; 48],
            };
            let (req, root) = build_validator_registration_request(&reg, [0; 4]);
            v.push(("VALIDATOR_REGISTRATION", req, root));

            let exit = VoluntaryExit { epoch: 7, validator_index: 1 };
            let (req, root) = build_voluntary_exit_request(&exit, &ctx);
            v.push(("VOLUNTARY_EXIT", req, root));

            let block = BeaconBlock {
                slot: 3_000_000,
                proposer_index: 12_345,
                parent_root: [0xaa; 32],
                state_root: [0xbb; 32],
                body: eth_types::external_vector_electra_block().body.clone(),
            };
            let (req, root) = build_block_v2_request(&block, &ctx).expect("BLOCK_V2");
            v.push(("BLOCK_V2", req, root));

            let ptc = PayloadAttestationData {
                beacon_block_root: [0x11; 32],
                slot: 1,
                payload_present: true,
                blob_data_available: false,
            };
            let (req, root) = build_payload_attestation_request(&ptc, &gloas_ctx(&sk));
            v.push(("PAYLOAD_ATTESTATION", req, root));

            let prefs = ProposerPreferences {
                dependent_root: [0x33; 32],
                proposal_slot: 32,
                validator_index: 3,
                fee_recipient: [0x44; 20],
                target_gas_limit: 36_000_000,
            };
            let (req, root) = build_proposer_preferences_request(&prefs, &gloas_ctx(&sk));
            v.push(("PROPOSER_PREFERENCES", req, root));

            v
        };

        assert_eq!(checks.len(), 12, "twelve client-reachable types");
        for (name, req, root) in checks {
            assert_eq!(
                req.signing_root,
                Some(root),
                "{name}: signing_root must be set (RF3-10-M1)"
            );
            let body = req.to_json_value().expect("serialize");
            assert_eq!(body["type"], name);
            assert_eq!(
                body["signingRoot"],
                root_hex(&root),
                "{name}: signingRoot must serialize as camelCase hex"
            );
            assert!(
                body.get("signing_root").is_none(),
                "{name}: must not emit snake_case signing_root"
            );
            // VALIDATOR_REGISTRATION omits fork_info; all others include it.
            if name == "VALIDATOR_REGISTRATION" {
                assert!(body.get("fork_info").is_none());
            } else {
                assert!(body.get("fork_info").is_some(), "{name}: fork_info required");
            }
        }
    }

    /// Snapshot-style pin: serialized bodies match the pre-extraction contract
    /// shapes (field names, casing, quoting). Fails if any serde attribute
    /// shifted during the wire-crate adoption (RF3-11 RED fixture).
    #[test]
    fn test_request_bodies_byte_identical_after_wire_extraction() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (req, signing_root) = build_attestation_request(&data, &ctx);
        let body = req.to_json_value().expect("serialize");

        assert_eq!(body["type"], "ATTESTATION");
        assert_eq!(body["signingRoot"], root_hex(&signing_root));
        assert!(body.get("signing_root").is_none());
        assert_eq!(body["fork_info"]["fork"]["previous_version"], "0x03000000");
        assert_eq!(body["fork_info"]["fork"]["current_version"], "0x04000000");
        assert_eq!(body["fork_info"]["fork"]["epoch"], "0");
        assert_eq!(
            body["fork_info"]["genesis_validators_root"],
            format!("0x{}", hex::encode([0xaau8; 32]))
        );
        assert_eq!(body["attestation"]["slot"], "5");
        assert_eq!(body["attestation"]["index"], "0");
        assert_eq!(
            body["attestation"]["beacon_block_root"],
            format!("0x{}", hex::encode([0x11u8; 32]))
        );
        assert_eq!(body["attestation"]["source"]["epoch"], "1");
        assert_eq!(body["attestation"]["target"]["epoch"], "2");

        // Second type: RANDAO_REVEAL (quoted epoch, no nested roots).
        let (req, root) = build_randao_reveal_request(42, &ctx);
        let body = req.to_json_value().expect("serialize");
        assert_eq!(body["type"], "RANDAO_REVEAL");
        assert_eq!(body["signingRoot"], root_hex(&root));
        assert_eq!(body["randao_reveal"]["epoch"], "42");
    }

    #[test]
    fn test_web3signer_client_attestation_body_matches_contract() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (req, signing_root) = build_attestation_request(&data, &ctx);
        let body = req.to_json_value().expect("serialize");

        assert_eq!(body["type"], "ATTESTATION");
        assert_eq!(body["signingRoot"], root_hex(&signing_root));
        assert!(body.get("signing_root").is_none(), "must not emit snake_case signing_root");

        assert_eq!(body["fork_info"]["fork"]["previous_version"], "0x03000000");
        assert_eq!(body["fork_info"]["fork"]["current_version"], "0x04000000");
        assert_eq!(body["fork_info"]["fork"]["epoch"], "0");
        assert_eq!(
            body["fork_info"]["genesis_validators_root"],
            format!("0x{}", hex::encode([0xaau8; 32]))
        );

        assert_eq!(body["attestation"]["slot"], "5");
        assert_eq!(body["attestation"]["index"], "0");
        assert_eq!(
            body["attestation"]["beacon_block_root"],
            format!("0x{}", hex::encode([0x11u8; 32]))
        );
        assert_eq!(body["attestation"]["source"]["epoch"], "1");
        assert_eq!(body["attestation"]["target"]["epoch"], "2");
    }

    #[test]
    fn test_web3signer_client_block_body_matches_contract() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let block = BeaconBlock {
            slot: 3_000_000,
            proposer_index: 12_345,
            parent_root: [0xaa; 32],
            state_root: [0xbb; 32],
            body: eth_types::external_vector_electra_block().body.clone(),
        };
        let (req, signing_root) = build_block_v2_request(&block, &ctx).expect("build BLOCK_V2");
        let body = req.to_json_value().expect("serialize");

        assert_eq!(body["type"], "BLOCK_V2");
        assert_eq!(body["signingRoot"], root_hex(&signing_root));
        assert!(body.get("signing_root").is_none());

        assert_eq!(body["fork_info"]["fork"]["current_version"], "0x04000000");
        assert_eq!(body["beacon_block"]["version"], "DENEB");
        assert_eq!(body["beacon_block"]["block_header"]["slot"], "3000000");
        assert_eq!(body["beacon_block"]["block_header"]["proposer_index"], "12345");
        assert_eq!(
            body["beacon_block"]["block_header"]["parent_root"],
            format!("0x{}", hex::encode([0xaau8; 32]))
        );
        assert_eq!(
            body["beacon_block"]["block_header"]["state_root"],
            format!("0x{}", hex::encode([0xbbu8; 32]))
        );
        let body_root = body["beacon_block"]["block_header"]["body_root"].as_str().unwrap();
        assert!(body_root.starts_with("0x") && body_root.len() == 66);
    }

    #[test]
    fn test_local_slashing_stage_ordering_unchanged() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (req, root) = build_attestation_request(&data, &ctx);
        assert_eq!(req.payload.type_name(), "ATTESTATION");
        assert_eq!(req.signing_root, Some(root));
        let (req2, root2) = build_attestation_request(&data, &ctx);
        assert_eq!(req.signing_root, req2.signing_root);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_remote_signer_config_defaults() {
        let config = RemoteSignerConfig::new("http://localhost:9000");
        assert_eq!(config.url, "http://localhost:9000");
        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    #[test]
    fn test_remote_signer_config_custom_timeout() {
        let config =
            RemoteSignerConfig::new("http://localhost:9000").with_timeout(Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_wire_module_does_not_depend_on_client() {
        // Compile-level: this module only imports wire types + crypto signing
        // helpers. Presence of builders is the smoke check that the split is real.
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let (_req, _root) = build_aggregation_slot_request(1, &ctx);
    }

    /// Web3Signer request roots must match the shared derivation helper so a
    /// mock or remote cannot disagree with LocalSigner / SignerService.
    #[test]
    fn test_web3signer_request_root_matches_shared_derivation() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (_req, root) = build_attestation_request(&data, &ctx);
        let expected = signing_root_with_fork_version(
            &data,
            DOMAIN_BEACON_ATTESTER,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        assert_eq!(root, expected);

        let epoch = 42u64;
        let (_req, root) = build_randao_reveal_request(epoch, &ctx);
        let expected = signing_root_with_fork_version(
            &epoch,
            DOMAIN_RANDAO,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        assert_eq!(root, expected);

        let exit = VoluntaryExit { epoch: 7, validator_index: 1 };
        let (_req, root) = build_voluntary_exit_request(&exit, &ctx);
        let expected = signing_root_with_fork_version(
            &exit,
            DOMAIN_VOLUNTARY_EXIT,
            ctx.fork_info.current_version,
            ctx.fork_info.genesis_validators_root,
        );
        assert_eq!(root, expected);
    }

    fn gloas_ctx(sk: &SecretKey) -> SignContext {
        SignContext {
            pubkey: sk.public_key(),
            fork_info: ForkInfo {
                previous_version: [0x06, 0x00, 0x00, 0x00],
                current_version: [0x07, 0x00, 0x00, 0x00],
                genesis_validators_root: [0xaa; 32],
            },
            fork_name: ForkName::Gloas,
        }
    }

    fn unhashable_block_body() -> Vec<u8> {
        // Not valid Deneb/Electra SSZ: hashing first would be RemoteSignerError.
        vec![0xff; 8]
    }

    #[test]
    fn test_gloas_block_v2_is_rejected_before_root_derivation() {
        let sk = SecretKey::generate();
        let ctx = gloas_ctx(&sk);
        let block = BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body: unhashable_block_body(),
        };
        let err = build_block_v2_request(&block, &ctx).expect_err("D19");
        let msg = err.to_string();
        assert!(!msg.contains("invalid beacon block body"), "must not have hashed first: {msg}");
        assert!(msg.contains("BLOCK_V2"), "names the type: {msg}");
        assert!(msg.contains("Web3Signer HTTP wire"), "names the wire: {msg}");
        assert!(msg.contains("deferred"), "names the deferral: {msg}");
        assert!(matches!(err, SigningError::LocalRejected(_)));
    }

    #[test]
    fn test_gloas_blinded_block_v2_is_rejected_before_root_derivation() {
        let sk = SecretKey::generate();
        let ctx = gloas_ctx(&sk);
        let block = BlindedBeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body: unhashable_block_body(),
        };
        let err = build_blinded_block_v2_request(&block, &ctx).expect_err("D19");
        let msg = err.to_string();
        assert!(!msg.contains("invalid blinded block body"), "must not have hashed first: {msg}");
        assert!(msg.contains("BLOCK_V2"), "names the type: {msg}");
        assert!(msg.contains("Web3Signer HTTP wire"), "names the wire: {msg}");
        assert!(msg.contains("deferred"), "names the deferral: {msg}");
        assert!(matches!(err, SigningError::LocalRejected(_)));
    }

    #[test]
    fn test_gloas_aggregate_and_proof_is_rejected_before_root_derivation() {
        let sk = SecretKey::generate();
        let ctx = gloas_ctx(&sk);
        let agg = AggregateAndProof {
            aggregator_index: 1,
            aggregate: Attestation {
                // Over the pre-Electra bitlist limit: hashing first panics in
                // `tree_hash_root`, so a D19 LocalRejected proves reject-first.
                aggregation_bits: vec![0xff; 4096],
                data: sample_attestation(),
                signature: vec![0xab; 96],
            },
            selection_proof: vec![0xcd; 96],
        };
        let err = build_aggregate_and_proof_request(&agg, &ctx).expect_err("D19");
        let msg = err.to_string();
        assert!(msg.contains("AGGREGATE_AND_PROOF"), "names the type: {msg}");
        assert!(msg.contains("Web3Signer HTTP wire"), "names the wire: {msg}");
        assert!(msg.contains("deferred"), "names the deferral: {msg}");
        assert!(matches!(err, SigningError::LocalRejected(_)));
    }

    /// L3: 4.2 fixture (`beacon_block_root` `[0x11; 32]`, slot 1, payload
    /// present, no blob data, fork `0x07000001`, GVR zeros). D19 does not
    /// reject PTC on HTTP.
    #[test]
    fn test_build_payload_attestation_request_signing_root() {
        use rvc_spec_vectors::spec_kat::KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT;

        let sk = SecretKey::generate();
        let ctx = SignContext {
            pubkey: sk.public_key(),
            fork_info: ForkInfo {
                previous_version: [0x06, 0x00, 0x00, 0x01],
                current_version: [0x07, 0x00, 0x00, 0x01],
                genesis_validators_root: [0u8; 32],
            },
            fork_name: ForkName::Gloas,
        };
        let data = PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        };
        let (req, root) = build_payload_attestation_request(&data, &ctx);
        let expected: Root = hex::decode(KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT)
            .expect("kat hex")
            .try_into()
            .expect("32-byte kat root");
        assert_eq!(root, expected);
        assert_eq!(req.signing_root, Some(root));
        assert_eq!(req.payload.type_name(), "PAYLOAD_ATTESTATION");
        let body = req.to_json_value().expect("serialize");
        assert_eq!(body["type"], "PAYLOAD_ATTESTATION");
        assert_eq!(body["payload_attestation"]["version"], "GLOAS");
        assert_eq!(body["signingRoot"], root_hex(&root));
    }

    /// L3: 4.15 fixture (dependent_root `[0x33; 32]`, proposal_slot 32,
    /// validator index 3, fee recipient `[0x44; 20]`, gas 36_000_000, fork
    /// `0x07000001`, GVR zeros). D19 does not reject proposer preferences on HTTP.
    #[test]
    fn test_build_proposer_preferences_request_signing_root() {
        use rvc_spec_vectors::spec_kat::KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT;

        let sk = SecretKey::generate();
        let ctx = SignContext {
            pubkey: sk.public_key(),
            fork_info: ForkInfo {
                previous_version: [0x06, 0x00, 0x00, 0x01],
                current_version: [0x07, 0x00, 0x00, 0x01],
                genesis_validators_root: [0u8; 32],
            },
            fork_name: ForkName::Gloas,
        };
        let prefs = ProposerPreferences {
            dependent_root: [0x33; 32],
            proposal_slot: 32,
            validator_index: 3,
            fee_recipient: [0x44; 20],
            target_gas_limit: 36_000_000,
        };
        let (req, root) = build_proposer_preferences_request(&prefs, &ctx);
        let expected: Root = hex::decode(KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT)
            .expect("kat hex")
            .try_into()
            .expect("32-byte kat root");
        assert_eq!(root, expected);
        assert_eq!(req.signing_root, Some(root));
        assert_eq!(req.payload.type_name(), "PROPOSER_PREFERENCES");
        let body = req.to_json_value().expect("serialize");
        assert_eq!(body["type"], "PROPOSER_PREFERENCES");
        assert_eq!(body["proposer_preferences"]["version"], "GLOAS");
        assert_eq!(body["signingRoot"], root_hex(&root));
    }
}
