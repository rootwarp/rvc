//! Shared gRPC request validators and proto→typed decode helpers.
//!
//! Used by both the main `SignerService` (`service.rs`) and the DVT
//! `PeerSignerService` (`dvt/peer_service.rs`) so validation and decode
//! error strings stay identical across transports.

use tonic::Status;

use crate::metrics::grpc_sign_type;
#[cfg(feature = "dvt")]
use crate::proto::signer_v2::PayloadAttestationData as ProtoPayloadAttestationData;
use crate::proto::signer_v2::{
    AttestationData as ProtoAttestationData, BeaconBlockHeader as ProtoBeaconBlockHeader, Duty,
    ForkInfo as ProtoForkInfo,
};
use crate::sign_plan::{NonSlashableOp, PlanInput};
#[cfg(feature = "dvt")]
use eth_types::PayloadAttestationData;
use eth_types::{
    decode_attestation_ssz as eth_decode_attestation_ssz,
    decode_beacon_block_ssz as eth_decode_beacon_block_ssz,
    decode_blinded_beacon_block_ssz as eth_decode_blinded_beacon_block_ssz,
    decode_sync_committee_contribution_ssz as eth_decode_sync_committee_contribution_ssz,
    Attestation, AttestationData, BeaconBlock, BeaconBlockHeader, BlindedBeaconBlock, Checkpoint,
    ForkName, SszDecodeError, SyncCommitteeContribution,
};

// ─────────────────────────────────────────────────────────────────────────────
// Field validators
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that `pubkey` is exactly 48 bytes.
#[allow(clippy::result_large_err)]
pub fn validate_pubkey(pubkey: &[u8]) -> Result<[u8; 48], Status> {
    pubkey.try_into().map_err(|_| {
        Status::invalid_argument(format!("pubkey must be 48 bytes, got {}", pubkey.len()))
    })
}

/// Validate that a byte slice is exactly 4 bytes (fork version).
#[allow(clippy::result_large_err)]
pub fn validate_fork_version(bytes: &[u8], field_name: &str) -> Result<[u8; 4], Status> {
    bytes.try_into().map_err(|_| {
        Status::invalid_argument(format!("{field_name} must be 4 bytes, got {}", bytes.len()))
    })
}

/// Validate that `gvr` is exactly 32 bytes.
#[allow(clippy::result_large_err)]
pub fn validate_gvr(gvr: &[u8]) -> Result<[u8; 32], Status> {
    gvr.try_into().map_err(|_| {
        Status::invalid_argument(format!(
            "genesis_validators_root must be 32 bytes, got {}",
            gvr.len()
        ))
    })
}

/// Validate that `selection_proof` is exactly 96 bytes (a BLS signature share).
///
/// The proto schema for `AggregateAndProof` and `ContributionAndProof` documents
/// `selection_proof` as a 96-byte BLS signature. The server does NOT verify the
/// signature itself — that is the client's responsibility — but the length must
/// be enforced because `vec_u8_tree_hash_root` is permissive and would silently
/// produce a wrong signing root for any other length.
#[allow(clippy::result_large_err)]
pub fn validate_selection_proof(bytes: &[u8]) -> Result<Vec<u8>, Status> {
    if bytes.len() != 96 {
        return Err(Status::invalid_argument(format!(
            "selection_proof must be 96 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

/// Validate that `bytes` is exactly 32 bytes (a hash-tree-root / signing root leaf).
#[allow(clippy::result_large_err)]
pub fn validate_root32(bytes: &[u8], field_name: &str) -> Result<[u8; 32], Status> {
    bytes.try_into().map_err(|_| {
        Status::invalid_argument(format!("{field_name} must be 32 bytes, got {}", bytes.len()))
    })
}

/// Transport fork identity for Gloas-safe RPCs (no SSZ bytes).
///
/// Accepts [`ForkName`] ids 0..=7 (Gloas=7 after 2.5b) and rejects 8 / `u32::MAX`.
/// Distinct from `validate_fork_id` (`0..=6`) used by the four SSZ decoders.
#[allow(clippy::result_large_err)]
pub fn validate_transport_fork_id(fork_id: u32) -> Result<ForkName, Status> {
    ForkName::try_from(fork_id).map_err(|e| Status::invalid_argument(e.to_string()))
}

/// Convert a `SszDecodeError` to a gRPC `Status::invalid_argument`.
pub fn ssz_err(e: SszDecodeError) -> Status {
    Status::invalid_argument(format!("SSZ decode error: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Proto → typed decode
// ─────────────────────────────────────────────────────────────────────────────

/// Decode and validate a required `ForkInfo` proto message.
///
/// Returns `(current_version, genesis_validators_root)`.
/// `previous_version` and `epoch` are accepted but not validated/returned —
/// callers only need the domain inputs.
#[allow(clippy::result_large_err)]
pub fn decode_fork_info(fork_info: Option<ProtoForkInfo>) -> Result<([u8; 4], [u8; 32]), Status> {
    let fork_info = fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
    let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
    let gvr = validate_gvr(&fork_info.genesis_validators_root)?;
    Ok((current_version, gvr))
}

/// Decode proto `AttestationData` into the eth-types struct.
///
/// Returns `(att_data, source_epoch, target_epoch)` so callers can record span
/// fields without re-destructuring.
#[allow(clippy::result_large_err)]
pub fn decode_attestation_data(
    data: Option<ProtoAttestationData>,
) -> Result<(AttestationData, u64, u64), Status> {
    let proto_data = data.ok_or_else(|| Status::invalid_argument("attestation data required"))?;
    let proto_source =
        proto_data.source.ok_or_else(|| Status::invalid_argument("source checkpoint required"))?;
    let proto_target =
        proto_data.target.ok_or_else(|| Status::invalid_argument("target checkpoint required"))?;

    let source_root = validate_root32(&proto_source.root, "source.root")?;
    let target_root = validate_root32(&proto_target.root, "target.root")?;
    let beacon_block_root = validate_root32(&proto_data.beacon_block_root, "beacon_block_root")?;

    let source_epoch = proto_source.epoch;
    let target_epoch = proto_target.epoch;

    let att_data = AttestationData {
        slot: proto_data.slot,
        index: proto_data.index,
        beacon_block_root,
        source: Checkpoint { epoch: source_epoch, root: source_root },
        target: Checkpoint { epoch: target_epoch, root: target_root },
    };

    Ok((att_data, source_epoch, target_epoch))
}

/// Decode proto `BeaconBlockHeader` into the eth-types 5-leaf header.
///
/// Each root must be exactly 32 bytes so the server hashes the same object the
/// client constructed; a short/long leaf cannot produce the expected HTR.
#[allow(clippy::result_large_err)]
pub fn decode_beacon_block_header(
    header: Option<ProtoBeaconBlockHeader>,
) -> Result<BeaconBlockHeader, Status> {
    let header = header.ok_or_else(|| Status::invalid_argument("header required"))?;
    let parent_root = validate_root32(&header.parent_root, "parent_root")?;
    let state_root = validate_root32(&header.state_root, "state_root")?;
    let body_root = validate_root32(&header.body_root, "body_root")?;
    Ok(BeaconBlockHeader {
        slot: header.slot,
        proposer_index: header.proposer_index,
        parent_root,
        state_root,
        body_root,
    })
}

/// Planned non-slashable input for `SignRoot` / `PartialSignRoot`.
///
/// `UNSPECIFIED` and unknown enum values fail closed; duties this server does
/// not yet serve return `UNIMPLEMENTED` (never a signature).
#[derive(Debug)]
pub struct RootDutyPlan {
    pub input: PlanInput,
    pub rpc_type: &'static str,
    pub op: NonSlashableOp,
}

#[allow(clippy::result_large_err)]
pub fn root_duty_plan(
    duty: i32,
    object_root: [u8; 32],
    fork_version: [u8; 4],
    gvr: [u8; 32],
    genesis_fork_version: [u8; 4],
) -> Result<RootDutyPlan, Status> {
    match Duty::try_from(duty) {
        Ok(Duty::Unspecified) => Err(Status::invalid_argument("duty must not be UNSPECIFIED")),
        Ok(Duty::AggregateAndProof) => Ok(RootDutyPlan {
            input: PlanInput::AggregateAndProof { object_root, fork_version, gvr },
            rpc_type: grpc_sign_type::AGGREGATE_AND_PROOF,
            op: NonSlashableOp::AggregateAndProof,
        }),
        Ok(Duty::ContributionAndProof) => Ok(RootDutyPlan {
            input: PlanInput::ContributionAndProof { object_root, fork_version, gvr },
            rpc_type: grpc_sign_type::CONTRIBUTION_AND_PROOF,
            op: NonSlashableOp::ContributionAndProof,
        }),
        Ok(Duty::PayloadAttestation) => Ok(RootDutyPlan {
            input: PlanInput::PayloadAttestation { object_root, fork_version, gvr },
            rpc_type: grpc_sign_type::PAYLOAD_ATTESTATION,
            op: NonSlashableOp::PayloadAttestation,
        }),
        Ok(Duty::ProposerPreferences) => Ok(RootDutyPlan {
            input: PlanInput::ProposerPreferences { object_root, fork_version, gvr },
            rpc_type: grpc_sign_type::PROPOSER_PREFERENCES,
            op: NonSlashableOp::ProposerPreferences,
        }),
        Ok(Duty::ExecutionPayloadEnvelope) => {
            Err(Status::unimplemented("EXECUTION_PAYLOAD_ENVELOPE (issue 6.19)"))
        }
        Ok(Duty::BuilderRequestAuth) => Ok(RootDutyPlan {
            input: PlanInput::BuilderRequestAuth { object_root, genesis_fork_version },
            rpc_type: grpc_sign_type::BUILDER_REQUEST_AUTH,
            op: NonSlashableOp::BuilderRequestAuth,
        }),
        Err(_) => Err(Status::invalid_argument(format!("unknown duty: {duty}"))),
    }
}

/// Decode proto `PayloadAttestationData` into the eth-types struct.
#[cfg(feature = "dvt")]
#[allow(clippy::result_large_err)]
pub fn decode_payload_attestation_data(
    data: Option<ProtoPayloadAttestationData>,
) -> Result<PayloadAttestationData, Status> {
    let proto_data =
        data.ok_or_else(|| Status::invalid_argument("payload attestation data required"))?;
    let beacon_block_root = validate_root32(&proto_data.beacon_block_root, "beacon_block_root")?;
    Ok(PayloadAttestationData {
        beacon_block_root,
        slot: proto_data.slot,
        payload_present: proto_data.payload_present,
        blob_data_available: proto_data.blob_data_available,
    })
}

/// Decode SSZ-encoded `BeaconBlock`, mapping errors to `Status`.
#[allow(clippy::result_large_err)]
pub fn decode_beacon_block(bytes: &[u8], fork_id: u32) -> Result<BeaconBlock, Status> {
    eth_decode_beacon_block_ssz(bytes, fork_id).map_err(ssz_err)
}

/// Decode SSZ-encoded `BlindedBeaconBlock`, mapping errors to `Status`.
#[allow(clippy::result_large_err)]
pub fn decode_blinded_beacon_block(
    bytes: &[u8],
    fork_id: u32,
) -> Result<BlindedBeaconBlock, Status> {
    eth_decode_blinded_beacon_block_ssz(bytes, fork_id).map_err(ssz_err)
}

/// Decode SSZ-encoded `Attestation`, mapping errors to `Status`.
#[allow(clippy::result_large_err)]
pub fn decode_attestation(bytes: &[u8], fork_id: u32) -> Result<Attestation, Status> {
    eth_decode_attestation_ssz(bytes, fork_id).map_err(ssz_err)
}

/// Decode SSZ-encoded `SyncCommitteeContribution`, mapping errors to `Status`.
#[allow(clippy::result_large_err)]
pub fn decode_sync_committee_contribution(
    bytes: &[u8],
    fork_id: u32,
) -> Result<SyncCommitteeContribution, Status> {
    eth_decode_sync_committee_contribution_ssz(bytes, fork_id).map_err(ssz_err)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::signer_v2::ForkInfo;
    use eth_types::ForkName;

    /// Characterization: both gRPC surfaces (SignerService + PeerSignerService)
    /// must share this single `validate_pubkey` definition — not local copies.
    #[test]
    fn test_dvt_and_signer_service_share_one_pubkey_validator() {
        // Behaviour pins: short / long / exact lengths.
        assert!(validate_pubkey(&[0u8; 48]).is_ok());
        let short = validate_pubkey(&[0u8; 47]).expect_err("47 bytes must fail");
        assert_eq!(short.message(), "pubkey must be 48 bytes, got 47");
        let long = validate_pubkey(&[0u8; 49]).expect_err("49 bytes must fail");
        assert_eq!(long.message(), "pubkey must be 48 bytes, got 49");

        // Source-level uniqueness is asserted by the standing AC
        // (`rg 'fn validate_pubkey' == 1`). This test pins the shared
        // behaviour both transports import.
        let empty = validate_pubkey(&[]).expect_err("empty must fail");
        assert_eq!(empty.message(), "pubkey must be 48 bytes, got 0");
    }

    #[test]
    fn test_validator_error_messages_unchanged() {
        // Table of (description, Status message) — byte-identical to the
        // pre-extraction strings so gRPC clients see no change.
        let cases: &[(&str, String)] = &[
            ("pubkey short", validate_pubkey(&[0u8; 1]).unwrap_err().message().to_string()),
            (
                "fork version short",
                validate_fork_version(&[0u8; 3], "current_version")
                    .unwrap_err()
                    .message()
                    .to_string(),
            ),
            (
                "fork version long",
                validate_fork_version(&[0u8; 5], "current_version")
                    .unwrap_err()
                    .message()
                    .to_string(),
            ),
            ("gvr short", validate_gvr(&[0u8; 31]).unwrap_err().message().to_string()),
            ("gvr empty", validate_gvr(&[]).unwrap_err().message().to_string()),
            (
                "selection_proof short",
                validate_selection_proof(&[0u8; 95]).unwrap_err().message().to_string(),
            ),
            (
                "selection_proof long",
                validate_selection_proof(&[0u8; 97]).unwrap_err().message().to_string(),
            ),
            (
                "selection_proof empty",
                validate_selection_proof(&[]).unwrap_err().message().to_string(),
            ),
            (
                "root32 short",
                validate_root32(&[0u8; 16], "beacon_block_root").unwrap_err().message().to_string(),
            ),
        ];

        let expected = [
            ("pubkey short", "pubkey must be 48 bytes, got 1"),
            ("fork version short", "current_version must be 4 bytes, got 3"),
            ("fork version long", "current_version must be 4 bytes, got 5"),
            ("gvr short", "genesis_validators_root must be 32 bytes, got 31"),
            ("gvr empty", "genesis_validators_root must be 32 bytes, got 0"),
            ("selection_proof short", "selection_proof must be 96 bytes, got 95"),
            ("selection_proof long", "selection_proof must be 96 bytes, got 97"),
            ("selection_proof empty", "selection_proof must be 96 bytes, got 0"),
            ("root32 short", "beacon_block_root must be 32 bytes, got 16"),
        ];

        for ((desc, got), (exp_desc, exp_msg)) in cases.iter().zip(expected.iter()) {
            assert_eq!(desc, exp_desc);
            assert_eq!(got, exp_msg, "error string drift for {desc}");
        }

        // Happy paths still accept exact lengths.
        assert!(validate_pubkey(&[0u8; 48]).is_ok());
        assert!(validate_fork_version(&[0u8; 4], "current_version").is_ok());
        assert!(validate_gvr(&[0u8; 32]).is_ok());
        assert!(validate_selection_proof(&[0u8; 96]).is_ok());
        assert!(validate_root32(&[0u8; 32], "beacon_block_root").is_ok());
    }

    #[test]
    fn test_decode_fork_info_rejects_short_fork_version() {
        let err = decode_fork_info(None).expect_err("missing fork_info");
        assert_eq!(err.message(), "fork_info required");

        let short = ForkInfo {
            previous_version: vec![0x00; 4],
            current_version: vec![0x04, 0x00, 0x00], // 3 bytes
            epoch: 0,
            genesis_validators_root: vec![0x00; 32],
        };
        let err = decode_fork_info(Some(short)).expect_err("short current_version");
        assert_eq!(err.message(), "current_version must be 4 bytes, got 3");

        let bad_gvr = ForkInfo {
            previous_version: vec![0x00; 4],
            current_version: vec![0x04, 0x00, 0x00, 0x00],
            epoch: 0,
            genesis_validators_root: vec![0x00; 16],
        };
        let err = decode_fork_info(Some(bad_gvr)).expect_err("short gvr");
        assert_eq!(err.message(), "genesis_validators_root must be 32 bytes, got 16");

        let ok = ForkInfo {
            previous_version: vec![0x03; 4],
            current_version: vec![0x04, 0x00, 0x00, 0x00],
            epoch: 0,
            genesis_validators_root: vec![0xAB; 32],
        };
        let (cv, gvr) = decode_fork_info(Some(ok)).expect("valid fork_info");
        assert_eq!(cv, [0x04, 0x00, 0x00, 0x00]);
        assert_eq!(gvr, [0xAB; 32]);
    }

    #[test]
    fn test_decode_rejects_oversized_ssz_body() {
        // Empty / garbage SSZ bodies must surface as invalid_argument with the
        // shared "SSZ decode error: …" prefix — never panic or succeed.
        let err = decode_beacon_block(&[], 4).expect_err("empty block SSZ");
        assert!(err.message().starts_with("SSZ decode error:"), "msg: {}", err.message());
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // A huge arbitrary buffer is not a valid block either.
        let huge = vec![0xFFu8; 64 * 1024];
        let err = decode_beacon_block(&huge, 4).expect_err("garbage block SSZ");
        assert!(err.message().starts_with("SSZ decode error:"), "msg: {}", err.message());

        let err = decode_blinded_beacon_block(&[], 4).expect_err("empty blinded");
        assert!(err.message().starts_with("SSZ decode error:"));

        let err = decode_attestation(&[], 4).expect_err("empty attestation");
        assert!(err.message().starts_with("SSZ decode error:"));

        let err = decode_sync_committee_contribution(&[], 4).expect_err("empty contribution");
        assert!(err.message().starts_with("SSZ decode error:"));
    }

    #[test]
    fn test_validate_selection_proof_accepts_96_bytes() {
        let buf = [0u8; 96];
        let result = validate_selection_proof(&buf).expect("96 bytes should pass");
        assert_eq!(result.len(), 96);
    }

    #[test]
    fn test_validate_selection_proof_rejects_short() {
        let err = validate_selection_proof(&[0u8; 95]).expect_err("95 bytes must fail");
        assert!(err.message().contains("96 bytes"), "msg: {}", err.message());
        assert!(err.message().contains("95"));
    }

    #[test]
    fn test_validate_selection_proof_rejects_long() {
        let err = validate_selection_proof(&[0u8; 97]).expect_err("97 bytes must fail");
        assert!(err.message().contains("96 bytes"), "msg: {}", err.message());
    }

    #[test]
    fn test_validate_selection_proof_rejects_empty() {
        let err = validate_selection_proof(&[]).expect_err("empty must fail");
        assert!(err.message().contains("96 bytes"));
    }

    #[test]
    fn test_decode_attestation_data_happy_and_missing_fields() {
        use crate::proto::signer_v2::Checkpoint as ProtoCheckpoint;

        let err = decode_attestation_data(None).expect_err("missing data");
        assert_eq!(err.message(), "attestation data required");

        let missing_source = ProtoAttestationData {
            slot: 1,
            index: 0,
            beacon_block_root: vec![0xAB; 32],
            source: None,
            target: Some(ProtoCheckpoint { epoch: 2, root: vec![0x02; 32] }),
        };
        let err = decode_attestation_data(Some(missing_source)).unwrap_err();
        assert_eq!(err.message(), "source checkpoint required");

        let ok = ProtoAttestationData {
            slot: 10,
            index: 0,
            beacon_block_root: vec![0xAB; 32],
            source: Some(ProtoCheckpoint { epoch: 1, root: vec![0x01; 32] }),
            target: Some(ProtoCheckpoint { epoch: 2, root: vec![0x02; 32] }),
        };
        let (att, src, tgt) = decode_attestation_data(Some(ok)).expect("valid att data");
        assert_eq!(att.slot, 10);
        assert_eq!(src, 1);
        assert_eq!(tgt, 2);
        assert_eq!(att.beacon_block_root, [0xAB; 32]);
        assert_eq!(att.source.root, [0x01; 32]);
        assert_eq!(att.target.root, [0x02; 32]);
    }

    #[cfg(feature = "dvt")]
    #[test]
    fn test_decode_payload_attestation_data_happy_and_missing_fields() {
        let err = decode_payload_attestation_data(None).expect_err("missing data");
        assert_eq!(err.message(), "payload attestation data required");

        let short_root = ProtoPayloadAttestationData {
            beacon_block_root: vec![0x11; 16],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        };
        let err = decode_payload_attestation_data(Some(short_root)).unwrap_err();
        assert_eq!(err.message(), "beacon_block_root must be 32 bytes, got 16");

        let ok = ProtoPayloadAttestationData {
            beacon_block_root: vec![0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        };
        let data =
            decode_payload_attestation_data(Some(ok)).expect("valid payload attestation data");
        assert_eq!(data.beacon_block_root, [0x11; 32]);
        assert_eq!(data.slot, 1);
        assert!(data.payload_present);
        assert!(!data.blob_data_available);
    }

    /// Phase-2 fail-closed: `grpc-signer` sends `fork_id = ctx.fork_name.id()`,
    /// so a Gloas `SignContext` produces 7. This decode path still rejects 7
    /// (`UnknownForkId`) even though `ForkName::try_from(7)` is `Ok(Gloas)`.
    /// Phase 4 replaces this with a Gloas-safe gRPC signing contract (D11).
    #[test]
    fn test_gloas_fork_id_decode_is_unknown_fork_id_fail_closed() {
        assert!(ForkName::try_from(7u32).is_ok());
        assert_eq!(ForkName::Gloas.id(), 7);

        let result = eth_decode_beacon_block_ssz(&[], ForkName::Gloas.id());
        assert!(
            matches!(result, Err(SszDecodeError::UnknownForkId(7))),
            "Gloas fork_id must fail closed, got {result:?}"
        );

        let err = decode_beacon_block(&[], 7).expect_err("Gloas fork_id must fail closed");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains("unknown fork_id: 7"),
            "signer-server decode must surface UnknownForkId(7), got: {}",
            err.message()
        );
    }

    #[test]
    fn test_validate_transport_fork_id_accepts_0_through_7_rejects_8_and_max() {
        for id in 0u32..=7 {
            validate_transport_fork_id(id)
                .unwrap_or_else(|e| panic!("fork_id={id} should be accepted: {e}"));
        }
        assert_eq!(validate_transport_fork_id(7).unwrap(), ForkName::Gloas);
        for id in [8u32, u32::MAX] {
            let err = validate_transport_fork_id(id).expect_err("unknown fork id");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            assert!(
                err.message().contains(&id.to_string()),
                "typed unknown-fork status must name {id}, got: {}",
                err.message()
            );
        }
    }

    #[test]
    fn test_decode_beacon_block_header_requires_32_byte_roots() {
        let err = decode_beacon_block_header(None).expect_err("missing header");
        assert_eq!(err.message(), "header required");

        let short = ProtoBeaconBlockHeader {
            slot: 1,
            proposer_index: 0,
            parent_root: vec![0x11; 32],
            state_root: vec![0x22; 32],
            body_root: vec![0x33; 31],
        };
        let err = decode_beacon_block_header(Some(short)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "body_root must be 32 bytes, got 31");

        let ok = ProtoBeaconBlockHeader {
            slot: 42,
            proposer_index: 7,
            parent_root: vec![0x11; 32],
            state_root: vec![0x22; 32],
            body_root: vec![0x33; 32],
        };
        let header = decode_beacon_block_header(Some(ok)).expect("valid header");
        assert_eq!(header.slot, 42);
        assert_eq!(header.body_root, [0x33; 32]);
    }

    #[test]
    fn test_root_duty_plan_fail_closed_and_unimplemented() {
        let root = [0x11u8; 32];
        let fv = [0x07, 0x00, 0x00, 0x01];
        let gvr = [0u8; 32];

        let genesis = [0u8; 4];
        let err = root_duty_plan(Duty::Unspecified as i32, root, fv, gvr, genesis).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("UNSPECIFIED"));

        let err = root_duty_plan(99, root, fv, gvr, genesis).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unknown duty: 99"));

        let err = root_duty_plan(Duty::ExecutionPayloadEnvelope as i32, root, fv, gvr, genesis)
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let plan = root_duty_plan(Duty::BuilderRequestAuth as i32, root, fv, gvr, genesis).unwrap();
        assert_eq!(plan.rpc_type, grpc_sign_type::BUILDER_REQUEST_AUTH);
        assert!(matches!(
            plan.input,
            PlanInput::BuilderRequestAuth { genesis_fork_version, .. }
                if genesis_fork_version == genesis
        ));

        let plan = root_duty_plan(Duty::PayloadAttestation as i32, root, fv, gvr, genesis).unwrap();
        assert_eq!(plan.rpc_type, grpc_sign_type::PAYLOAD_ATTESTATION);
        assert!(matches!(plan.input, PlanInput::PayloadAttestation { .. }));
    }
}
