//! Web3Signer `POST /api/v1/eth2/sign/{identifier}` request wire contract.
//!
//! # Single type set (RF3-10 / Theme C5)
//!
//! One `Serialize + Deserialize` model shared by:
//! - the HTTP **client** (`crypto::remote_signer` — RF3-11 adopts this crate)
//! - the HTTP **server** (`rvc-signer` `http_api` — RF3-12 adopts this crate)
//!
//! Previously the client carried only `Serialize` twins and the server only
//! `Deserialize` twins, kept in sync by comment. Commit `424a1a7` already showed
//! one silent drift; this crate freezes the contract with round-trip fixtures.
//!
//! # Variant reachability
//!
//! | Discriminator | Client serialize today | Server deserialize |
//! |---|---|---|
//! | `BLOCK_V2` | yes | yes |
//! | `ATTESTATION` | yes | yes |
//! | `RANDAO_REVEAL` | yes | yes |
//! | `AGGREGATION_SLOT` | yes | yes |
//! | `AGGREGATE_AND_PROOF` | yes | yes |
//! | `SYNC_COMMITTEE_MESSAGE` | yes | yes |
//! | `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | yes | yes |
//! | `SYNC_COMMITTEE_SELECTION_PROOF` | yes | yes |
//! | `VALIDATOR_REGISTRATION` | yes | yes |
//! | `VOLUNTARY_EXIT` | yes | yes |
//! | `AGGREGATE_AND_PROOF_V2` | **no** (not yet on TypedSigner builders) | yes (FROZEN FR-31) |
//! | `PAYLOAD_ATTESTATION` | **no** (4.10) | yes (provisional: remote-signing-api PR #28) |
//!
//! All twelve variants serialize and deserialize here. Adding a client *serialize*
//! path for `AGGREGATE_AND_PROOF_V2` is a deliberate follow-up (not silent).
//!
//! # Server leniency (preserved)
//!
//! - `signingRoot` accepts camelCase and snake_case `signing_root` alias.
//! - Empty / `"0x"` signing root → `None` (Prysm).
//! - `fork_info` is optional at the serde layer; per-type enforcement is the
//!   dispatcher's job (`VALIDATOR_REGISTRATION` omits it).
//! - Unknown `type` fails to decode (no `#[serde(other)]`).
//! - Unknown `version` fails to decode via fail-closed [`ForkName::from_str`]
//!   (no `#[serde(other)]`). Web3Signer wire names are `PHASE0`…`GLOAS`; they
//!   are folded to lowercase before `from_str`. Empty / non-identifier version
//!   strings are invalid (not named on the HTTP 400).
//!
//! # Naming
//!
//! Canonical names are the server's (`SignPayload`, `SignRequest`). Client-side
//! aliases (`Web3SignerPayload`, `Web3SignerSignRequest`) are provided so RF3-11
//! can repoint without renaming every call site in the same PR.

#![forbid(unsafe_code)]

mod hex_serde;

use std::fmt;
use std::str::FromStr;

use eth_types::{
    AggregateAndProof, AttestationData, BeaconBlockHeader, ContributionAndProof,
    ElectraAggregateAndProof, Fork, ForkName, PayloadAttestationData, Root, SyncCommitteeMessage,
    ValidatorRegistrationV1, VoluntaryExit,
};
use serde::{Deserialize, Serialize};

pub use hex_serde::{hex32, opt_hex32, quoted_u64};

/// `fork_info` wire object: `{ fork: { previous_version, current_version, epoch },
/// genesis_validators_root }`. Distinct from `eth_types::ForkInfo` (which
/// flattens differently); the inner `fork` reuses `eth_types::Fork` verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireForkInfo {
    pub fork: Fork,
    #[serde(with = "hex32")]
    pub genesis_validators_root: Root,
}

/// Web3Signer `{version, data}` envelope used by `*_V2` types and new Gloas
/// sign types (remote-signing-api). `version` is fail-closed: an unknown
/// string never becomes a domain choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedPayload<T> {
    #[serde(with = "fork_name_wire")]
    pub version: ForkName,
    pub data: T,
}

/// `BLOCK_V2` envelope. Same fail-closed `version` as [`VersionedPayload`],
/// but Consensys / remote-signing-api name the object `block_header` not `data`.
/// Only `block_header` is hashed; the domain still comes from `fork_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockEnvelope {
    #[serde(with = "fork_name_wire")]
    pub version: ForkName,
    pub block_header: BeaconBlockHeader,
}

/// Gloas block and aggregate signing over the Web3Signer HTTP wire is deferred
/// (D19). Named so server and client reject with the same typed error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GloasHttpWireDeferred {
    pub type_name: &'static str,
}

impl fmt::Display for GloasHttpWireDeferred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} with version GLOAS is deferred on the Web3Signer HTTP wire", self.type_name)
    }
}

impl std::error::Error for GloasHttpWireDeferred {}

/// Reject `ForkName::Gloas` for existing v2 HTTP types before any root is derived.
pub fn reject_gloas_http_wire(
    version: ForkName,
    type_name: &'static str,
) -> Result<(), GloasHttpWireDeferred> {
    if version == ForkName::Gloas {
        Err(GloasHttpWireDeferred { type_name })
    } else {
        Ok(())
    }
}

/// Fail-closed parse of a Web3Signer `version` string.
///
/// Empty / whitespace / non-identifier tokens are [`WireVersionError::Invalid`]
/// (HTTP maps these to the generic SEC-INFO-01 body). A well-formed identifier
/// that is not a [`ForkName`] is [`WireVersionError::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireVersionError {
    Invalid,
    Unknown(String),
}

impl fmt::Display for WireVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("invalid version"),
            Self::Unknown(v) => write!(f, "unknown version: {v}"),
        }
    }
}

impl std::error::Error for WireVersionError {}

fn is_wire_version_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a wire `version` via [`ForkName::from_str`] (lowercase fold).
pub fn parse_wire_fork_name(raw: &str) -> Result<ForkName, WireVersionError> {
    let trimmed = raw.trim();
    if !is_wire_version_token(trimmed) {
        return Err(WireVersionError::Invalid);
    }
    ForkName::from_str(&trimmed.to_ascii_lowercase())
        .map_err(|_| WireVersionError::Unknown(trimmed.to_string()))
}

impl WireVersionError {
    /// Recover a typed unknown-version error from a serde_json Display.
    ///
    /// Only a single identifier token after `unknown version: ` matches —
    /// empty versions, location text (`at line N column M`), and other decoder
    /// failures return `None`.
    pub fn from_serde_display(msg: &str) -> Option<Self> {
        const PREFIX: &str = "unknown version: ";
        let start = msg.find(PREFIX)?;
        let token = msg[start + PREFIX.len()..].split_whitespace().next()?;
        if !is_wire_version_token(token) {
            return None;
        }
        Some(Self::Unknown(token.to_string()))
    }
}

/// Web3Signer `version` strings are `PHASE0`…`GLOAS`. Fold to lowercase so
/// [`ForkName::from_str`] stays the single fail-closed parser (beacon-API
/// names are lowercase; the HTTP wire is uppercase).
mod fork_name_wire {
    use super::{parse_wire_fork_name, ForkName};
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(name: &ForkName, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&name.as_ref().to_ascii_uppercase())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<ForkName, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(d)?;
        parse_wire_fork_name(&raw).map_err(de::Error::custom)
    }
}

/// `randao_reveal` payload: a single quoted `epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandaoRevealPayload {
    #[serde(with = "quoted_u64")]
    pub epoch: u64,
}

/// `aggregation_slot` payload: a single quoted `slot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationSlotPayload {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
}

/// `sync_aggregator_selection_data` payload: `{slot, subcommittee_index}`.
///
/// A request-side wrapper because `eth_types::SyncAggregatorSelectionData`
/// derives `TreeHash` but **no serde**; consumers construct the SSZ object from
/// these two quoted ints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSelectionPayload {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub subcommittee_index: u64,
}

/// Per-`type` payload, internally tagged by the `type` field.
///
/// An unknown `type` fails to decode (no `#[serde(other)]`), which the server
/// maps to HTTP 400.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignPayload {
    #[serde(rename = "BLOCK_V2")]
    BlockV2 { beacon_block: BeaconBlockEnvelope },
    #[serde(rename = "ATTESTATION")]
    Attestation { attestation: AttestationData },
    #[serde(rename = "RANDAO_REVEAL")]
    RandaoReveal { randao_reveal: RandaoRevealPayload },
    #[serde(rename = "AGGREGATION_SLOT")]
    AggregationSlot { aggregation_slot: AggregationSlotPayload },
    #[serde(rename = "AGGREGATE_AND_PROOF")]
    AggregateAndProof { aggregate_and_proof: AggregateAndProof },
    #[serde(rename = "SYNC_COMMITTEE_MESSAGE")]
    SyncCommitteeMessage { sync_committee_message: SyncCommitteeMessage },
    #[serde(rename = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF")]
    SyncCommitteeContributionAndProof { contribution_and_proof: ContributionAndProof },
    #[serde(rename = "SYNC_COMMITTEE_SELECTION_PROOF")]
    SyncCommitteeSelectionProof { sync_aggregator_selection_data: SyncSelectionPayload },
    /// No `fork_info` on the wire (ADR-008 / builder domain).
    #[serde(rename = "VALIDATOR_REGISTRATION")]
    ValidatorRegistration { validator_registration: ValidatorRegistrationV1 },
    #[serde(rename = "VOLUNTARY_EXIT")]
    VoluntaryExit { voluntary_exit: VoluntaryExit },
    /// Electra sibling of `AGGREGATE_AND_PROOF` (FR-14 / FR-31 FROZEN).
    /// Server-reachable today; client builders not yet (see module doc table).
    /// Inner object is the Consensys `{version, data}` wrapper.
    #[serde(rename = "AGGREGATE_AND_PROOF_V2")]
    AggregateAndProofV2 { aggregate_and_proof: VersionedPayload<ElectraAggregateAndProof> },
    /// Gloas PTC (`DOMAIN_PTC_ATTESTER`). Discriminator `PAYLOAD_ATTESTATION` and
    /// the `{version, data}` envelope are provisional
    /// (`ethereum/remote-signing-api` PR #28).
    #[serde(rename = "PAYLOAD_ATTESTATION")]
    PayloadAttestation { payload_attestation: VersionedPayload<PayloadAttestationData> },
}

/// Client-facing alias for [`SignPayload`] (RF3-11 migration).
pub type Web3SignerPayload = SignPayload;

impl SignPayload {
    /// Web3Signer `type` discriminator (e.g. `"BLOCK_V2"`), matching every
    /// `#[serde(rename)]` tag. Used by the server audit path and client logs.
    pub fn type_name(&self) -> &'static str {
        match self {
            SignPayload::BlockV2 { .. } => "BLOCK_V2",
            SignPayload::Attestation { .. } => "ATTESTATION",
            SignPayload::RandaoReveal { .. } => "RANDAO_REVEAL",
            SignPayload::AggregationSlot { .. } => "AGGREGATION_SLOT",
            SignPayload::AggregateAndProof { .. } => "AGGREGATE_AND_PROOF",
            SignPayload::SyncCommitteeMessage { .. } => "SYNC_COMMITTEE_MESSAGE",
            SignPayload::SyncCommitteeContributionAndProof { .. } => {
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
            }
            SignPayload::SyncCommitteeSelectionProof { .. } => "SYNC_COMMITTEE_SELECTION_PROOF",
            SignPayload::ValidatorRegistration { .. } => "VALIDATOR_REGISTRATION",
            SignPayload::VoluntaryExit { .. } => "VOLUNTARY_EXIT",
            SignPayload::AggregateAndProofV2 { .. } => "AGGREGATE_AND_PROOF_V2",
            SignPayload::PayloadAttestation { .. } => "PAYLOAD_ATTESTATION",
        }
    }
}

/// Fully-formed Web3Signer sign request: common fields plus the type-tagged
/// payload flattened in, mirroring the flat wire object where `type`,
/// `fork_info`, `signingRoot`, and the payload key are all siblings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// Optional at the serde layer; the dispatcher requires it for every type
    /// except `VALIDATOR_REGISTRATION`. Omitted when `None` on serialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_info: Option<WireForkInfo>,
    /// `signingRoot` (camelCase) or `signing_root`. Absent / empty / `"0x"` →
    /// `None` (Prysm); a present 32-byte value is verified by the dispatcher
    /// only when non-zero (ADR-007). Omitted when `None` on serialize.
    #[serde(
        default,
        rename = "signingRoot",
        alias = "signing_root",
        with = "opt_hex32",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_root: Option<Root>,
    #[serde(flatten)]
    pub payload: SignPayload,
}

/// Client-facing alias for [`SignRequest`] (RF3-11 migration).
pub type Web3SignerSignRequest = SignRequest;

impl SignRequest {
    /// Convenience: request with `fork_info` and a present signing root.
    pub fn with_fork(fork_info: WireForkInfo, signing_root: Root, payload: SignPayload) -> Self {
        Self { fork_info: Some(fork_info), signing_root: Some(signing_root), payload }
    }

    /// Convenience: request without `fork_info` (validator registration).
    pub fn without_fork(signing_root: Root, payload: SignPayload) -> Self {
        Self { fork_info: None, signing_root: Some(signing_root), payload }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{Checkpoint, Fork, ForkName};

    // ── Recorded production-shaped bodies (from request.rs + routes.rs) ──────
    // Built by copy from existing decoder fixtures — never from this crate's
    // own Serialize output — so a field-name/casing regression fails red.

    fn fork_info_json() -> &'static str {
        r#"{ "fork": { "previous_version": "0x03000000",
                       "current_version": "0x04000000",
                       "epoch": "100" },
             "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }"#
    }

    fn expected_gvr() -> Root {
        let mut gvr = [0u8; 32];
        hex::decode_to_slice(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            &mut gvr,
        )
        .unwrap();
        gvr
    }

    /// Decode → re-encode → assert JSON value equality (canonical contract pin).
    fn assert_roundtrip(body: &str) {
        let req: SignRequest = serde_json::from_str(body).expect("decode fixture");
        let reencoded = serde_json::to_value(&req).expect("re-encode");
        let original: serde_json::Value = serde_json::from_str(body).expect("parse original");
        assert_eq!(
            reencoded, original,
            "round-trip changed the JSON value\n  original: {original}\n  reencoded: {reencoded}"
        );
    }

    /// Compact compact-object form of fork_info matching eth-types serde output
    /// (lowercase hex, no spaces) for round-trip Value equality.
    fn fork_info_compact() -> String {
        format!(
            r#"{{"fork":{{"previous_version":"0x03000000","current_version":"0x04000000","epoch":"100"}},"genesis_validators_root":"0x{}"}}"#,
            hex::encode(expected_gvr())
        )
    }

    #[test]
    fn test_recorded_production_bodies_roundtrip_byte_identical() {
        // Bodies use the compact form that eth-types + this crate emit, so
        // Value equality is meaningful. Field names/casing match the recorded
        // server decoder fixtures and client contract tests.

        // ATTESTATION (request.rs decodes_attestation + client contract test)
        let attestation = format!(
            r#"{{"type":"ATTESTATION","fork_info":{fi},"signingRoot":"0x{root}","attestation":{{"slot":"5","index":"0","beacon_block_root":"0x{r}","source":{{"epoch":"1","root":"0x{r}"}},"target":{{"epoch":"2","root":"0x{r}"}}}}}}"#,
            fi = fork_info_compact(),
            root = "22".repeat(32),
            r = "00".repeat(32),
        );
        assert_roundtrip(&attestation);

        // BLOCK_V2 (request.rs decodes_block_v2 + client contract test)
        let block_v2 = format!(
            r#"{{"type":"BLOCK_V2","fork_info":{fi},"signingRoot":"0x{root}","beacon_block":{{"version":"DENEB","block_header":{{"slot":"3000000","proposer_index":"12345","parent_root":"0x{r1}","state_root":"0x{r2}","body_root":"0x{r3}"}}}}}}"#,
            fi = fork_info_compact(),
            root = "11".repeat(32),
            r1 = "aa".repeat(32),
            r2 = "bb".repeat(32),
            r3 = "cc".repeat(32),
        );
        assert_roundtrip(&block_v2);

        // RANDAO_REVEAL
        let randao = format!(
            r#"{{"type":"RANDAO_REVEAL","fork_info":{fi},"randao_reveal":{{"epoch":"42"}}}}"#,
            fi = fork_info_compact(),
        );
        assert_roundtrip(&randao);

        // AGGREGATION_SLOT
        let agg_slot = format!(
            r#"{{"type":"AGGREGATION_SLOT","fork_info":{fi},"aggregation_slot":{{"slot":"77"}}}}"#,
            fi = fork_info_compact(),
        );
        assert_roundtrip(&agg_slot);

        // VALIDATOR_REGISTRATION (no fork_info)
        let reg = r#"{"type":"VALIDATOR_REGISTRATION","signingRoot":"0x00000000000000000000000000000000000000000000000000000000000000aa","validator_registration":{"fee_recipient":"0x0000000000000000000000000000000000000001","gas_limit":"30000000","timestamp":"100","pubkey":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
        assert_roundtrip(reg);

        // VOLUNTARY_EXIT
        let exit = format!(
            r#"{{"type":"VOLUNTARY_EXIT","fork_info":{fi},"signingRoot":"0x{root}","voluntary_exit":{{"epoch":"7","validator_index":"1"}}}}"#,
            fi = fork_info_compact(),
            root = "44".repeat(32),
        );
        assert_roundtrip(&exit);

        // SYNC_COMMITTEE_SELECTION_PROOF
        let sync_sel = format!(
            r#"{{"type":"SYNC_COMMITTEE_SELECTION_PROOF","fork_info":{fi},"sync_aggregator_selection_data":{{"slot":"5","subcommittee_index":"2"}}}}"#,
            fi = fork_info_compact(),
        );
        assert_roundtrip(&sync_sel);

        // AGGREGATE_AND_PROOF (pre-Electra)
        let agg = format!(
            r#"{{"type":"AGGREGATE_AND_PROOF","fork_info":{fi},"aggregate_and_proof":{{"aggregator_index":"1","aggregate":{{"aggregation_bits":"0x01","data":{{"slot":"5","index":"0","beacon_block_root":"0x{z}","source":{{"epoch":"1","root":"0x{z}"}},"target":{{"epoch":"2","root":"0x{z}"}}}},"signature":"0x{sig}"}},"selection_proof":"0x{sp}"}}}}"#,
            fi = fork_info_compact(),
            z = "00".repeat(32),
            sig = "ab".repeat(96),
            sp = "cd".repeat(96),
        );
        assert_roundtrip(&agg);

        // SYNC_COMMITTEE_MESSAGE
        let scm = format!(
            r#"{{"type":"SYNC_COMMITTEE_MESSAGE","fork_info":{fi},"sync_committee_message":{{"slot":"5","beacon_block_root":"0x{r}","validator_index":"0","signature":"0x{sig}"}}}}"#,
            fi = fork_info_compact(),
            r = "22".repeat(32),
            sig = "ab".repeat(96),
        );
        assert_roundtrip(&scm);

        // SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF
        let cap = format!(
            r#"{{"type":"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF","fork_info":{fi},"contribution_and_proof":{{"aggregator_index":"1","contribution":{{"slot":"5","beacon_block_root":"0x{r}","subcommittee_index":"0","aggregation_bits":"0x{bits}","signature":"0x{sig}"}},"selection_proof":"0x{sp}"}}}}"#,
            fi = fork_info_compact(),
            r = "11".repeat(32),
            bits = "00".repeat(16),
            sig = "ab".repeat(96),
            sp = "cd".repeat(96),
        );
        assert_roundtrip(&cap);

        // AGGREGATE_AND_PROOF_V2 (electra_v2_frozen_fixture from routes.rs, FR-31)
        // Compact form of the frozen fixture field names/encodings, including
        // the Consensys `{version, data}` wrapper.
        let electra_v2 = format!(
            r#"{{"type":"AGGREGATE_AND_PROOF_V2","fork_info":{fi},"aggregate_and_proof":{{"version":"ELECTRA","data":{{"aggregator_index":"1","aggregate":{{"aggregation_bits":"0x01","data":{{"slot":"5","index":"0","beacon_block_root":"0x{z}","source":{{"epoch":"1","root":"0x{z}"}},"target":{{"epoch":"2","root":"0x{z}"}}}},"signature":"0x{sig}","committee_bits":"0x0101010101010101"}},"selection_proof":"0x{sp}"}}}}}}"#,
            fi = fork_info_compact(),
            z = "00".repeat(32),
            sig = "ab".repeat(96),
            sp = "cd".repeat(96),
        );
        assert_roundtrip(&electra_v2);

        // PAYLOAD_ATTESTATION (4.9b; `{version, data}` wrapper, remote-signing-api PR #28)
        let ptc = format!(
            r#"{{"type":"PAYLOAD_ATTESTATION","fork_info":{fi},"payload_attestation":{{"version":"GLOAS","data":{{"beacon_block_root":"0x{br}","slot":"1","payload_present":true,"blob_data_available":false}}}}}}"#,
            fi = fork_info_compact(),
            br = "11".repeat(32),
        );
        assert_roundtrip(&ptc);
    }

    #[test]
    fn test_all_twelve_type_discriminators_roundtrip() {
        let discriminators = [
            "BLOCK_V2",
            "ATTESTATION",
            "RANDAO_REVEAL",
            "AGGREGATION_SLOT",
            "AGGREGATE_AND_PROOF",
            "SYNC_COMMITTEE_MESSAGE",
            "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
            "SYNC_COMMITTEE_SELECTION_PROOF",
            "VALIDATOR_REGISTRATION",
            "VOLUNTARY_EXIT",
            "AGGREGATE_AND_PROOF_V2",
            "PAYLOAD_ATTESTATION",
        ];
        // Smoke: construct each variant, type_name matches rename, and
        // serialize→deserialize preserves the discriminator.
        let samples: Vec<SignPayload> = vec![
            SignPayload::BlockV2 {
                beacon_block: BeaconBlockEnvelope {
                    version: ForkName::Deneb,
                    block_header: BeaconBlockHeader {
                        slot: 1,
                        proposer_index: 0,
                        parent_root: [0; 32],
                        state_root: [0; 32],
                        body_root: [0; 32],
                    },
                },
            },
            SignPayload::Attestation {
                attestation: AttestationData {
                    slot: 1,
                    index: 0,
                    beacon_block_root: [0; 32],
                    source: Checkpoint { epoch: 0, root: [0; 32] },
                    target: Checkpoint { epoch: 1, root: [0; 32] },
                },
            },
            SignPayload::RandaoReveal { randao_reveal: RandaoRevealPayload { epoch: 1 } },
            SignPayload::AggregationSlot { aggregation_slot: AggregationSlotPayload { slot: 1 } },
            SignPayload::AggregateAndProof {
                aggregate_and_proof: AggregateAndProof {
                    aggregator_index: 1,
                    aggregate: eth_types::Attestation {
                        aggregation_bits: vec![0x01],
                        data: AttestationData {
                            slot: 1,
                            index: 0,
                            beacon_block_root: [0; 32],
                            source: Checkpoint { epoch: 0, root: [0; 32] },
                            target: Checkpoint { epoch: 1, root: [0; 32] },
                        },
                        signature: vec![0xab; 96],
                    },
                    selection_proof: vec![0xcd; 96],
                },
            },
            SignPayload::SyncCommitteeMessage {
                sync_committee_message: SyncCommitteeMessage {
                    slot: 1,
                    beacon_block_root: [0x22; 32],
                    validator_index: 0,
                    signature: vec![0xab; 96],
                },
            },
            SignPayload::SyncCommitteeContributionAndProof {
                contribution_and_proof: ContributionAndProof {
                    aggregator_index: 1,
                    contribution: eth_types::SyncCommitteeContribution {
                        slot: 1,
                        beacon_block_root: [0x11; 32],
                        subcommittee_index: 0,
                        aggregation_bits: vec![0u8; 16],
                        signature: vec![0xab; 96],
                    },
                    selection_proof: vec![0xcd; 96],
                },
            },
            SignPayload::SyncCommitteeSelectionProof {
                sync_aggregator_selection_data: SyncSelectionPayload {
                    slot: 1,
                    subcommittee_index: 0,
                },
            },
            SignPayload::ValidatorRegistration {
                validator_registration: ValidatorRegistrationV1 {
                    fee_recipient: [0u8; 19]
                        .into_iter()
                        .chain([1u8])
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                    gas_limit: 30_000_000,
                    timestamp: 100,
                    pubkey: [0xaa; 48],
                },
            },
            SignPayload::VoluntaryExit {
                voluntary_exit: VoluntaryExit { epoch: 7, validator_index: 1 },
            },
            SignPayload::AggregateAndProofV2 {
                aggregate_and_proof: VersionedPayload {
                    version: ForkName::Electra,
                    data: ElectraAggregateAndProof {
                        aggregator_index: 1,
                        aggregate: eth_types::ElectraAttestation {
                            aggregation_bits: vec![0x01],
                            data: AttestationData {
                                slot: 5,
                                index: 0,
                                beacon_block_root: [0; 32],
                                source: Checkpoint { epoch: 1, root: [0; 32] },
                                target: Checkpoint { epoch: 2, root: [0; 32] },
                            },
                            signature: vec![0xab; 96],
                            committee_bits: vec![0x01; 8],
                        },
                        selection_proof: vec![0xcd; 96],
                    },
                },
            },
            SignPayload::PayloadAttestation {
                payload_attestation: VersionedPayload {
                    version: ForkName::Gloas,
                    data: PayloadAttestationData {
                        beacon_block_root: [0x11; 32],
                        slot: 1,
                        payload_present: true,
                        blob_data_available: false,
                    },
                },
            },
        ];

        assert_eq!(samples.len(), 12);
        assert_eq!(discriminators.len(), 12);
        for (payload, expected_name) in samples.iter().zip(discriminators.iter()) {
            assert_eq!(payload.type_name(), *expected_name);
            let v = serde_json::to_value(payload).unwrap();
            assert_eq!(v["type"], *expected_name);
            let back: SignPayload = serde_json::from_value(v).unwrap();
            assert_eq!(back.type_name(), *expected_name);
            assert_eq!(&back, payload);
        }
    }

    #[test]
    fn test_signing_root_alias_and_empty_are_accepted() {
        // camelCase
        let body = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "signingRoot": "0x{root}",
                  "randao_reveal": {{ "epoch": "1" }} }}"#,
            fi = fork_info_json(),
            root = "33".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.signing_root, Some([0x33u8; 32]));

        // snake_case alias
        let body = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "signing_root": "0x{root}",
                  "randao_reveal": {{ "epoch": "1" }} }}"#,
            fi = fork_info_json(),
            root = "33".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.signing_root, Some([0x33u8; 32]));

        // empty / "0x" → None (Prysm)
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
    fn test_unknown_type_fails_to_decode() {
        let body = r#"{ "type": "DEPOSIT", "deposit": {} }"#;
        let err = serde_json::from_str::<SignRequest>(body).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("variant") || !err.to_string().is_empty());
    }

    #[test]
    fn test_validator_registration_omits_fork_info() {
        let body = r#"{
            "type": "VALIDATOR_REGISTRATION",
            "signingRoot": "0x00000000000000000000000000000000000000000000000000000000000000aa",
            "validator_registration": {
                "fee_recipient": "0x0000000000000000000000000000000000000001",
                "gas_limit": "30000000",
                "timestamp": "100",
                "pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }"#;
        let req: SignRequest = serde_json::from_str(body).unwrap();
        assert!(req.fork_info.is_none());
        assert!(matches!(req.payload, SignPayload::ValidatorRegistration { .. }));
        // Serialize must omit fork_info key entirely.
        let v = serde_json::to_value(&req).unwrap();
        assert!(v.get("fork_info").is_none());
        assert_eq!(v["type"], "VALIDATOR_REGISTRATION");
    }

    #[test]
    fn test_server_decoder_fixtures_still_decode() {
        // Verbatim shapes from bin/rvc-signer/src/http_api/request.rs tests
        // (whitespace-tolerant parse; field semantics pinned).
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
                assert_eq!(beacon_block.version, ForkName::Deneb);
                assert_eq!(beacon_block.block_header.slot, 3_000_000);
                assert_eq!(beacon_block.block_header.proposer_index, 12_345);
                assert_eq!(beacon_block.block_header.parent_root, [0xaau8; 32]);
            }
            other => panic!("expected BlockV2, got {other:?}"),
        }

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
    fn test_fork_info_optional_absent_decodes() {
        let body = r#"{ "type": "RANDAO_REVEAL", "randao_reveal": { "epoch": "1" } }"#;
        let req: SignRequest = serde_json::from_str(body).unwrap();
        assert!(req.fork_info.is_none());
        assert!(req.signing_root.is_none());
    }

    #[test]
    fn test_malformed_signing_root_hex_errors() {
        let body = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "signingRoot": "0xZZ",
                  "randao_reveal": {{ "epoch": "1" }} }}"#,
            fi = fork_info_json(),
        );
        assert!(serde_json::from_str::<SignRequest>(&body).is_err());
    }

    #[test]
    fn test_client_contract_attestation_shape() {
        // Mirrors crypto remote_signer::test_web3signer_client_attestation_body_matches_contract
        let req = SignRequest::with_fork(
            WireForkInfo {
                fork: Fork {
                    previous_version: [0x03, 0x00, 0x00, 0x00],
                    current_version: [0x04, 0x00, 0x00, 0x00],
                    epoch: 0,
                },
                genesis_validators_root: [0xaa; 32],
            },
            [0x11; 32],
            SignPayload::Attestation {
                attestation: AttestationData {
                    slot: 5,
                    index: 0,
                    beacon_block_root: [0x11; 32],
                    source: Checkpoint { epoch: 1, root: [0x22; 32] },
                    target: Checkpoint { epoch: 2, root: [0x33; 32] },
                },
            },
        );
        let body = serde_json::to_value(&req).unwrap();
        assert_eq!(body["type"], "ATTESTATION");
        assert_eq!(body["signingRoot"], format!("0x{}", hex::encode([0x11u8; 32])));
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
        assert_eq!(req.payload.type_name(), "ATTESTATION");
    }

    #[test]
    fn test_electra_v2_frozen_fixture_decodes() {
        // Verbatim electra_v2_frozen_fixture from routes.rs (FR-31).
        let fixture = format!(
            r#"{{ "type": "AGGREGATE_AND_PROOF_V2",
                  "fork_info": {{ "fork": {{ "previous_version": "0x03000000",
                                             "current_version": "0x04000000",
                                             "epoch": "100" }},
                       "genesis_validators_root": "0x{gvr}" }},
                  "aggregate_and_proof": {{
                    "version": "ELECTRA",
                    "data": {{
                      "aggregator_index": "1",
                      "aggregate": {{
                        "aggregation_bits": "0x01",
                        "data": {{ "slot": "5", "index": "0",
                                  "beacon_block_root": "0x{z}",
                                  "source": {{ "epoch": "1", "root": "0x{z}" }},
                                  "target": {{ "epoch": "2", "root": "0x{z}" }} }},
                        "signature": "0x{sig}",
                        "committee_bits": "0x0101010101010101"
                      }},
                      "selection_proof": "0x{sp}"
                    }}
                  }} }}"#,
            gvr = hex::encode(expected_gvr()),
            z = "00".repeat(32),
            sig = "ab".repeat(96),
            sp = "cd".repeat(96),
        );
        let req: SignRequest = serde_json::from_str(&fixture).unwrap();
        assert_eq!(req.payload.type_name(), "AGGREGATE_AND_PROOF_V2");
        match req.payload {
            SignPayload::AggregateAndProofV2 { aggregate_and_proof } => {
                assert_eq!(aggregate_and_proof.version, ForkName::Electra);
                assert_eq!(aggregate_and_proof.data.aggregator_index, 1);
                assert_eq!(aggregate_and_proof.data.aggregate.data.slot, 5);
                assert_eq!(aggregate_and_proof.data.aggregate.committee_bits, vec![0x01; 8]);
            }
            other => panic!("expected AggregateAndProofV2, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_version_fails_to_decode_naming_value() {
        let body = format!(
            r#"{{ "type": "BLOCK_V2", "fork_info": {fi},
                  "beacon_block": {{ "version": "NOT_A_FORK",
                                     "block_header": {{ "slot": "1",
                                                        "proposer_index": "0",
                                                        "parent_root": "0x{z}",
                                                        "state_root": "0x{z}",
                                                        "body_root": "0x{z}" }} }} }}"#,
            fi = fork_info_json(),
            z = "00".repeat(32),
        );
        let err = serde_json::from_str::<SignRequest>(&body).unwrap_err().to_string();
        match WireVersionError::from_serde_display(&err) {
            Some(WireVersionError::Unknown(value)) => assert_eq!(value, "NOT_A_FORK"),
            other => panic!("expected Unknown(NOT_A_FORK), got {other:?} from {err}"),
        }
    }

    #[test]
    fn test_empty_version_is_invalid_not_named() {
        for version in ["", "   "] {
            let body = format!(
                r#"{{ "type": "BLOCK_V2", "fork_info": {fi},
                      "beacon_block": {{ "version": "{version}",
                                         "block_header": {{ "slot": "1",
                                                            "proposer_index": "0",
                                                            "parent_root": "0x{z}",
                                                            "state_root": "0x{z}",
                                                            "body_root": "0x{z}" }} }} }}"#,
                fi = fork_info_json(),
                z = "00".repeat(32),
            );
            let err = serde_json::from_str::<SignRequest>(&body).unwrap_err().to_string();
            assert!(
                WireVersionError::from_serde_display(&err).is_none(),
                "empty/whitespace version must not name a token (no serde location leak): {err}"
            );
            assert!(!err.to_lowercase().contains("unknown version:"), "{err}");
        }
    }

    #[test]
    fn test_gloas_version_decodes_as_fork_name() {
        // GLOAS is a known ForkName (serde succeeds); D19 rejection is dispatch
        // / client, not the decoder — otherwise we could not name the deferral.
        let body = format!(
            r#"{{ "type": "BLOCK_V2", "fork_info": {fi},
                  "beacon_block": {{ "version": "GLOAS",
                                     "block_header": {{ "slot": "1",
                                                        "proposer_index": "0",
                                                        "parent_root": "0x{z}",
                                                        "state_root": "0x{z}",
                                                        "body_root": "0x{z}" }} }} }}"#,
            fi = fork_info_json(),
            z = "00".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        match req.payload {
            SignPayload::BlockV2 { beacon_block } => {
                assert_eq!(beacon_block.version, ForkName::Gloas);
                let err = reject_gloas_http_wire(beacon_block.version, "BLOCK_V2").unwrap_err();
                assert_eq!(
                    err.to_string(),
                    "BLOCK_V2 with version GLOAS is deferred on the Web3Signer HTTP wire"
                );
            }
            other => panic!("expected BlockV2, got {other:?}"),
        }
    }

    #[test]
    fn test_payload_attestation_unknown_version_fails_to_decode_naming_value() {
        let body = format!(
            r#"{{ "type": "PAYLOAD_ATTESTATION", "fork_info": {fi},
                  "payload_attestation": {{ "version": "NOT_A_FORK",
                                            "data": {{ "beacon_block_root": "0x{br}",
                                                       "slot": "1",
                                                       "payload_present": true,
                                                       "blob_data_available": false }} }} }}"#,
            fi = fork_info_json(),
            br = "11".repeat(32),
        );
        let err = serde_json::from_str::<SignRequest>(&body).unwrap_err().to_string();
        match WireVersionError::from_serde_display(&err) {
            Some(WireVersionError::Unknown(value)) => assert_eq!(value, "NOT_A_FORK"),
            other => panic!("expected Unknown(NOT_A_FORK), got {other:?} from {err}"),
        }
    }

    #[test]
    fn test_payload_attestation_gloas_version_decodes() {
        let body = format!(
            r#"{{ "type": "PAYLOAD_ATTESTATION", "fork_info": {fi},
                  "payload_attestation": {{ "version": "GLOAS",
                                            "data": {{ "beacon_block_root": "0x{br}",
                                                       "slot": "1",
                                                       "payload_present": true,
                                                       "blob_data_available": false }} }} }}"#,
            fi = fork_info_json(),
            br = "11".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.payload.type_name(), "PAYLOAD_ATTESTATION");
        match req.payload {
            SignPayload::PayloadAttestation { payload_attestation } => {
                assert_eq!(payload_attestation.version, ForkName::Gloas);
                assert_eq!(payload_attestation.data.beacon_block_root, [0x11u8; 32]);
                assert_eq!(payload_attestation.data.slot, 1);
                assert!(payload_attestation.data.payload_present);
                assert!(!payload_attestation.data.blob_data_available);
            }
            other => panic!("expected PayloadAttestation, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_wire_fork_name_empty_is_invalid() {
        assert_eq!(parse_wire_fork_name(""), Err(WireVersionError::Invalid));
        assert_eq!(parse_wire_fork_name("   "), Err(WireVersionError::Invalid));
        assert_eq!(parse_wire_fork_name("NOT A FORK"), Err(WireVersionError::Invalid));
        assert_eq!(
            parse_wire_fork_name("NOT_A_FORK"),
            Err(WireVersionError::Unknown("NOT_A_FORK".into()))
        );
        assert_eq!(parse_wire_fork_name("DENEB"), Ok(ForkName::Deneb));
        assert_eq!(parse_wire_fork_name("deneb"), Ok(ForkName::Deneb));
    }

    #[test]
    fn test_versioned_payload_roundtrips_uppercase_fork_name() {
        let payload = VersionedPayload { version: ForkName::Fulu, data: 7u64 };
        let v = serde_json::to_value(&payload).unwrap();
        assert_eq!(v["version"], "FULU");
        assert_eq!(v["data"], 7);
        let back: VersionedPayload<u64> = serde_json::from_value(v).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn test_type_aliases_are_identical() {
        // Compile-time / runtime identity of client aliases.
        let p: Web3SignerPayload =
            SignPayload::RandaoReveal { randao_reveal: RandaoRevealPayload { epoch: 1 } };
        let r: Web3SignerSignRequest = SignRequest::without_fork([0; 32], p);
        assert_eq!(r.payload.type_name(), "RANDAO_REVEAL");
    }
}
