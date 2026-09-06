//! Gloas `BeaconBlockBody` progressive container (EIP-7688 + EIP-7732).
//!
//! First production callers land in later island issues (5.11).

#![allow(dead_code)]

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::ProgressiveList;

use super::attestation::{Attestation, AttesterSlashing};
use super::body_leaves::{Deposit, SignedBlsToExecutionChange, SignedVoluntaryExit, SyncAggregate};
use super::leaves::{Eth1Data, ProposerSlashing};
use super::payload::{PayloadAttestation, SignedExecutionPayloadBid};
use super::requests::ExecutionRequests;
use crate::error::GloasError;

/// Gloas `BeaconBlockBody` at consensus-specs `SPEC_TAG` (`v1.7.0-beta.0`).
///
/// Spec `class BeaconBlockBody(ProgressiveContainer)` with
/// `ACTIVE_FIELDS = active_fields(width=13)`. Electra ordering is used only as
/// a starting point: `execution_payload`, `blob_kzg_commitments`, and
/// `execution_requests` are out of the VC root surface; Gloas appends
/// `signed_execution_payload_bid`, `payload_attestations`, and
/// `parent_execution_requests`.
///
/// ProgressiveList fields at the frozen tag: `proposer_slashings`,
/// `attester_slashings`, `attestations`, `deposits`, `voluntary_exits`,
/// `bls_to_execution_changes`, `payload_attestations`.
///
/// `COMMITTEES` is `MAX_COMMITTEES_PER_SLOT` (minimal 4, mainnet 64),
/// `SYNC` is `SYNC_COMMITTEE_SIZE` (minimal 32, mainnet 512),
/// `PTC` is `PTC_SIZE` (minimal 16, mainnet 512). Nested types are island
/// declarations — never `eth_types::` containers.
#[derive(Clone, Debug, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])]
pub(crate) struct BeaconBlockBody<const COMMITTEES: usize, const SYNC: usize, const PTC: usize> {
    pub(crate) randao_reveal: [u8; 96],
    pub(crate) eth1_data: Eth1Data,
    pub(crate) graffiti: [u8; 32],
    pub(crate) proposer_slashings: ProgressiveList<ProposerSlashing>,
    pub(crate) attester_slashings: ProgressiveList<AttesterSlashing>,
    pub(crate) attestations: ProgressiveList<Attestation<COMMITTEES>>,
    pub(crate) deposits: ProgressiveList<Deposit>,
    pub(crate) voluntary_exits: ProgressiveList<SignedVoluntaryExit>,
    pub(crate) sync_aggregate: SyncAggregate<SYNC>,
    pub(crate) bls_to_execution_changes: ProgressiveList<SignedBlsToExecutionChange>,
    pub(crate) signed_execution_payload_bid: SignedExecutionPayloadBid,
    pub(crate) payload_attestations: ProgressiveList<PayloadAttestation<PTC>>,
    pub(crate) parent_execution_requests: ExecutionRequests,
}

/// Decode BN body SSZ. Failure is [`GloasError::InvalidBody`] — never a
/// zero, guessed, or fallback body.
///
/// Inherent `BeaconBlockBody::from_ssz_bytes` would shadow `SszDecode` and
/// break libssz-derive's `ssz_decode_fixed_vec`.
pub(crate) fn from_ssz_bytes<const COMMITTEES: usize, const SYNC: usize, const PTC: usize>(
    bytes: &[u8],
) -> Result<BeaconBlockBody<COMMITTEES, SYNC, PTC>, GloasError> {
    <BeaconBlockBody<COMMITTEES, SYNC, PTC> as libssz::SszDecode>::from_ssz_bytes(bytes)
        .map_err(|err| GloasError::InvalidBody { reason: format!("{err:?}") })
}

#[cfg(test)]
mod tests {
    use super::from_ssz_bytes;
    use crate::containers::attestation::{Attestation, AttesterSlashing};
    use crate::containers::body_leaves::{
        Deposit, SignedBlsToExecutionChange, SignedVoluntaryExit, SyncAggregate,
    };
    use crate::containers::leaves::{Eth1Data, ProposerSlashing};
    use crate::containers::payload::{PayloadAttestation, SignedExecutionPayloadBid};
    use crate::containers::requests::ExecutionRequests;
    use crate::error::GloasError;
    use crate::spec_kat::{mainnet, minimal};
    use libssz::{SszDecode, SszEncode};
    use libssz_derive::{HashTreeRoot, SszDecode};
    use libssz_merkle::{HashTreeRoot as _, Sha2Hasher};
    use libssz_types::ProgressiveList;

    /// Spec field names at `SPEC_TAG`. A preferences-family name is a spec signal.
    const BEACON_BLOCK_BODY_FIELDS: &[&str] = &[
        "randao_reveal",
        "eth1_data",
        "graffiti",
        "proposer_slashings",
        "attester_slashings",
        "attestations",
        "deposits",
        "voluntary_exits",
        "sync_aggregate",
        "bls_to_execution_changes",
        "signed_execution_payload_bid",
        "payload_attestations",
        "parent_execution_requests",
    ];

    fn parse_hex(hex: &str) -> Vec<u8> {
        assert!(!hex.starts_with("0x"), "SPEC_* hex follows EXTERNAL_* style (no 0x prefix)");
        assert_eq!(hex.len() % 2, 0, "SPEC_* hex must have even length, got {}", hex.len());
        hex.as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let s = core::str::from_utf8(chunk).expect("hex digits are utf8");
                u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s}: {e}"))
            })
            .collect()
    }

    fn parse_root(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64, "SPEC_* hex must be 64 chars, got {} ({hex:?})", hex.len());
        parse_hex(hex).try_into().expect("64 hex chars decode to 32 bytes")
    }

    fn assert_body_matches_spec_root<const C: usize, const S: usize, const P: usize>(
        ssz_hex: &str,
        root_hex: &str,
    ) {
        let bytes = parse_hex(ssz_hex);
        let decoded = from_ssz_bytes::<C, S, P>(&bytes).expect("SSZ decode");
        let got = decoded.hash_tree_root(&Sha2Hasher);
        assert_eq!(got, parse_root(root_hex));
    }

    #[test]
    fn test_beacon_block_body_hash_tree_root() {
        assert_body_matches_spec_root::<4, 32, 16>(
            minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ,
            minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT,
        );
        assert_body_matches_spec_root::<64, 512, 512>(
            mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ,
            mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT,
        );
        assert_ne!(
            minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT,
            mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT,
        );
    }

    #[test]
    fn test_beacon_block_body_ssz_round_trip() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        let decoded = from_ssz_bytes::<4, 32, 16>(&bytes).expect("SSZ decode");
        assert_eq!(decoded.to_ssz(), bytes);

        let bytes = parse_hex(mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        let decoded = from_ssz_bytes::<64, 512, 512>(&bytes).expect("SSZ decode");
        assert_eq!(decoded.to_ssz(), bytes);
    }

    #[test]
    fn test_active_fields_beacon_block_body_width() {
        assert_eq!(crate::ACTIVE_FIELDS_BEACON_BLOCK_BODY.len(), 13);
        assert_eq!(BEACON_BLOCK_BODY_FIELDS.len(), crate::ACTIVE_FIELDS_BEACON_BLOCK_BODY.len());
        assert!(
            crate::ACTIVE_FIELDS_BEACON_BLOCK_BODY.iter().all(|bit| *bit),
            "v1.7.0-beta.0 BeaconBlockBody ACTIVE_FIELDS is all-ones width 13"
        );
        for name in BEACON_BLOCK_BODY_FIELDS {
            let lower = name.to_ascii_lowercase();
            assert!(
                !lower.contains("preference"),
                "ProposerPreferences-family field `{name}` at SPEC_TAG {} is a spec signal — \
                 do not add an island leaf silently; record it in the phase notes",
                crate::SPEC_TAG
            );
            assert_ne!(
                *name, "execution_payload",
                "ExecutionPayload is out of the VC root surface (P0-10); it lives on the envelope (5.16)"
            );
            assert!(
                !lower.contains("beacon_state"),
                "BeaconState is excluded from the VC root surface"
            );
        }
    }

    #[test]
    fn test_beacon_block_body_from_ssz_bytes_rejects_truncated() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        assert!(bytes.len() > 16);
        let err =
            from_ssz_bytes::<4, 32, 16>(&bytes[..16]).expect_err("truncated body must fail decode");
        assert!(matches!(err, GloasError::InvalidBody { .. }), "expected InvalidBody, got {err:?}");
        let err = from_ssz_bytes::<4, 32, 16>(&[]).expect_err("empty body must fail decode");
        assert!(matches!(err, GloasError::InvalidBody { .. }));
    }

    #[test]
    fn test_beacon_block_body_from_ssz_bytes_rejects_overlong() {
        let mut bytes = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        bytes.push(0xff);
        let err = from_ssz_bytes::<4, 32, 16>(&bytes).expect_err("over-long body must fail decode");
        assert!(matches!(err, GloasError::InvalidBody { .. }), "expected InvalidBody, got {err:?}");
    }

    /// Width 14 with an inactive slot: same thirteen fields, different mix-in.
    #[derive(SszDecode, HashTreeRoot)]
    #[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1])]
    struct BeaconBlockBodyWrongWidth<const COMMITTEES: usize, const SYNC: usize, const PTC: usize> {
        randao_reveal: [u8; 96],
        eth1_data: Eth1Data,
        graffiti: [u8; 32],
        proposer_slashings: ProgressiveList<ProposerSlashing>,
        attester_slashings: ProgressiveList<AttesterSlashing>,
        attestations: ProgressiveList<Attestation<COMMITTEES>>,
        deposits: ProgressiveList<Deposit>,
        voluntary_exits: ProgressiveList<SignedVoluntaryExit>,
        sync_aggregate: SyncAggregate<SYNC>,
        bls_to_execution_changes: ProgressiveList<SignedBlsToExecutionChange>,
        signed_execution_payload_bid: SignedExecutionPayloadBid,
        payload_attestations: ProgressiveList<PayloadAttestation<PTC>>,
        parent_execution_requests: ExecutionRequests,
    }

    #[test]
    fn test_beacon_block_body_wrong_width_active_fields_differs_from_spec_root() {
        let bytes = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        let wrong =
            BeaconBlockBodyWrongWidth::<4, 32, 16>::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT)
        );
        let bytes = parse_hex(mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
        let wrong =
            BeaconBlockBodyWrongWidth::<64, 512, 512>::from_ssz_bytes(&bytes).expect("SSZ decode");
        assert_ne!(
            wrong.hash_tree_root(&Sha2Hasher),
            parse_root(mainnet::SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT)
        );
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn test_beacon_block_body_from_ssz_bytes_truncated_or_overlong(
                cut in 0usize..64,
                extra in proptest::collection::vec(any::<u8>(), 1..32),
            ) {
                let bytes = parse_hex(minimal::SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ);
                let truncated_len = cut.min(bytes.len().saturating_sub(1));
                let err = from_ssz_bytes::<4, 32, 16>(&bytes[..truncated_len])
                    .expect_err("truncated body must fail decode");
                let truncated_ok = matches!(err, GloasError::InvalidBody { .. });
                prop_assert!(truncated_ok);

                let mut overlong = bytes;
                overlong.extend_from_slice(&extra);
                let err = from_ssz_bytes::<4, 32, 16>(&overlong)
                    .expect_err("over-long body must fail decode");
                let overlong_ok = matches!(err, GloasError::InvalidBody { .. });
                prop_assert!(overlong_ok);
            }
        }
    }
}
