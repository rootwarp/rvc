use std::collections::HashMap;

use eth_types::{
    BlindedBeaconBlock, BlockContents, Epoch, ForkSchedule, SyncCommitteeContribution,
    SyncCommitteeDuty, Version,
};
use serde::{Deserialize, Serialize};

use crate::BeaconError;

/// A checkpoint in the beacon chain consisting of an epoch and block root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub epoch: String,
    pub root: String,
}

/// Data for an attestation, containing the vote information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationData {
    pub slot: String,
    pub index: String,
    pub beacon_block_root: String,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

/// A single attestation in the Electra (v2) `SingleAttestation` format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleAttestation {
    pub committee_index: u64,
    pub attester_index: u64,
    pub data: AttestationData,
    pub signature: String,
}

/// A pre-Electra (Phase 0 through Deneb) attestation with aggregation bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyAttestation {
    pub aggregation_bits: String,
    pub data: AttestationData,
    pub signature: String,
}

/// Fork-versioned attestation for submission endpoints.
#[derive(Debug, Clone, Serialize)]
pub enum VersionedAttestation {
    PreElectra(Vec<LegacyAttestation>),
    Electra(Vec<SingleAttestation>),
    Fulu(Vec<SingleAttestation>),
}

/// Fork-versioned aggregate attestation for fetch responses.
#[derive(Debug, Clone)]
pub enum VersionedAggregateAttestation {
    PreElectra(eth_types::Attestation),
    Electra(eth_types::ElectraAttestation),
    Fulu(eth_types::ElectraAttestation),
}

/// Fork-versioned signed aggregate and proof for submission.
#[derive(Debug, Clone)]
pub enum VersionedSignedAggregateAndProof {
    PreElectra(Vec<eth_types::SignedAggregateAndProof>),
    Electra(Vec<eth_types::SignedElectraAggregateAndProof>),
    Fulu(Vec<eth_types::SignedElectraAggregateAndProof>),
}

/// Header of a beacon block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    pub slot: String,
    pub proposer_index: String,
    pub parent_root: String,
    pub state_root: String,
    pub body_root: String,
}

/// Attester duty information for a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttesterDuty {
    pub pubkey: String,
    pub validator_index: String,
    pub committee_index: String,
    pub committee_length: String,
    pub committees_at_slot: String,
    pub validator_committee_index: String,
    pub slot: String,
}

/// Wrapper for beacon API data responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResponse<T> {
    pub data: T,
}

/// Wrapper for beacon API data responses with dependent root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependentRootResponse<T> {
    pub dependent_root: String,
    pub execution_optimistic: bool,
    pub data: T,
}

/// Wrapper for beacon API responses with execution optimistic flag (no dependent root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionOptimisticResponse<T> {
    pub execution_optimistic: bool,
    pub data: T,
}

/// Response type for attester duties endpoint.
pub type AttesterDutiesResponse = DependentRootResponse<Vec<AttesterDuty>>;

/// Proposer duty information for a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerDuty {
    pub pubkey: String,
    pub validator_index: String,
    pub slot: String,
}

/// Response type for proposer duties endpoint.
pub type ProposerDutiesResponse = DependentRootResponse<Vec<ProposerDuty>>;

/// Response from the produce block v3 endpoint, including header metadata.
///
/// Supports both JSON and SSZ content types. When the BN responds with SSZ,
/// `is_ssz` is `true` and `ssz_bytes` contains the raw SSZ-encoded block.
/// When JSON, `data` contains the parsed JSON value.
#[derive(Debug, Clone)]
pub struct ProduceBlockResponse {
    pub data: serde_json::Value,
    pub is_blinded: bool,
    pub consensus_version: String,
    pub execution_payload_value: Option<String>,
    /// Whether the response was received as SSZ (`application/octet-stream`).
    pub is_ssz: bool,
    /// Raw SSZ bytes when the BN responded with SSZ content type.
    pub ssz_bytes: Option<Vec<u8>>,
}

impl ProduceBlockResponse {
    /// Parses the raw `data` field into a full block with blob sidecars.
    pub fn parse_full_block(&self) -> Result<BlockContents, BeaconError> {
        serde_json::from_value(self.data.clone())
            .map_err(|e| BeaconError::ParseError(format!("invalid block contents: {}", e)))
    }

    /// Parses the raw `data` field into a blinded block.
    pub fn parse_blinded_block(&self) -> Result<BlindedBeaconBlock, BeaconError> {
        serde_json::from_value(self.data.clone())
            .map_err(|e| BeaconError::ParseError(format!("invalid blinded block: {}", e)))
    }
}

/// Response type for attestation data endpoint.
pub type AttestationDataResponse = DataResponse<AttestationData>;

/// Response type for sync committee duties endpoint.
pub type SyncCommitteeDutiesResponse = ExecutionOptimisticResponse<Vec<SyncCommitteeDuty>>;

/// Response type for sync committee contribution endpoint.
pub type SyncCommitteeContributionResponse = DataResponse<SyncCommitteeContribution>;

/// Block root data from the beacon API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRootData {
    pub root: String,
}

/// Response type for the block root endpoint.
pub type BlockRootResponse = DataResponse<BlockRootData>;

pub use eth_types::SignedAggregateAndProof;
pub use eth_types::SignedContributionAndProof;
pub use eth_types::SyncCommitteeMessage;

/// Validator information from the beacon state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorData {
    pub index: String,
    pub status: String,
    pub validator: ValidatorInfo,
}

/// Public key information for a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub pubkey: String,
}

/// Response type for the validators state endpoint.
pub type ValidatorsResponse = DataResponse<Vec<ValidatorData>>;

/// Genesis information from the beacon chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisData {
    pub genesis_time: String,
    pub genesis_validators_root: String,
    pub genesis_fork_version: String,
}

/// Response type for the genesis endpoint.
pub type GenesisResponse = DataResponse<GenesisData>;

/// Response type for the config spec endpoint.
pub type ConfigSpecResponse = DataResponse<HashMap<String, serde_json::Value>>;

/// Fork information from the beacon state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFork {
    pub previous_version: String,
    pub current_version: String,
    pub epoch: String,
}

/// Wrapper for beacon API state responses with execution optimistic and finalized flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateResponse<T> {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: T,
}

/// Response type for the beacon state fork endpoint.
pub type StateForkResponse = StateResponse<StateFork>;

/// Parses a `/eth/v1/config/spec` map into a [`ForkSchedule`].
///
/// Extracts fork epoch and version fields. Version fields are hex-encoded
/// (e.g. `"0x00000000"`) and epoch fields are decimal strings (e.g. `"74240"`).
/// `FULU_*` and `GLOAS_*` are optional: a missing key uses the unscheduled
/// sentinels `u64::MAX` / `[0xFF; 4]`. A present but malformed value is a
/// parse error naming that key.
///
/// There is no `/eth/v1/config/fork_schedule` client method —
/// [`crate::BeaconClient::get_config_spec`] (`/eth/v1/config/spec`) and
/// [`crate::BeaconClient::get_fork_schedule`] (which derives from it) are
/// the only schedule sources. This function is the BN half of the two-source
/// contract; issue 2.10 reconciles the spec-derived schedule against a local
/// `rvc-config` pair.
pub fn parse_fork_schedule(
    spec: &HashMap<String, serde_json::Value>,
) -> Result<ForkSchedule, BeaconError> {
    Ok(ForkSchedule {
        genesis_fork_version: parse_version(spec, "GENESIS_FORK_VERSION")?,
        altair_fork_epoch: parse_epoch(spec, "ALTAIR_FORK_EPOCH")?,
        altair_fork_version: parse_version(spec, "ALTAIR_FORK_VERSION")?,
        bellatrix_fork_epoch: parse_epoch(spec, "BELLATRIX_FORK_EPOCH")?,
        bellatrix_fork_version: parse_version(spec, "BELLATRIX_FORK_VERSION")?,
        capella_fork_epoch: parse_epoch(spec, "CAPELLA_FORK_EPOCH")?,
        capella_fork_version: parse_version(spec, "CAPELLA_FORK_VERSION")?,
        deneb_fork_epoch: parse_epoch(spec, "DENEB_FORK_EPOCH")?,
        deneb_fork_version: parse_version(spec, "DENEB_FORK_VERSION")?,
        electra_fork_epoch: parse_epoch(spec, "ELECTRA_FORK_EPOCH")?,
        electra_fork_version: parse_version(spec, "ELECTRA_FORK_VERSION")?,
        fulu_fork_epoch: parse_epoch_optional(spec, "FULU_FORK_EPOCH", u64::MAX)?,
        fulu_fork_version: parse_version_optional(
            spec,
            "FULU_FORK_VERSION",
            [0xFF, 0xFF, 0xFF, 0xFF],
        )?,
        gloas_fork_epoch: parse_epoch_optional(spec, "GLOAS_FORK_EPOCH", u64::MAX)?,
        gloas_fork_version: parse_version_optional(
            spec,
            "GLOAS_FORK_VERSION",
            [0xFF, 0xFF, 0xFF, 0xFF],
        )?,
    })
}

/// Parses slot duration in milliseconds from a `/eth/v1/config/spec` map.
///
/// Accepts either BN wire spelling:
///
/// - `SLOT_DURATION_MS` (milliseconds, used as-is)
/// - `SECONDS_PER_SLOT` (seconds, converted as `seconds * 1000`)
///
/// Exactly one key is sufficient. Both may be present during a deprecation
/// window and are accepted when they agree exactly. Neither key, or both
/// present with unequal values, is a parse error. Extra keys such as
/// `INTERVALS_PER_SLOT` are ignored.
pub fn parse_slot_duration_ms(
    spec: &HashMap<String, serde_json::Value>,
) -> Result<u64, BeaconError> {
    const SLOT_DURATION_MS_KEY: &str = "SLOT_DURATION_MS";
    const SECONDS_PER_SLOT_KEY: &str = "SECONDS_PER_SLOT";

    match (spec.get(SLOT_DURATION_MS_KEY), spec.get(SECONDS_PER_SLOT_KEY)) {
        (None, None) => Err(BeaconError::ParseError(format!(
            "missing config keys: {SLOT_DURATION_MS_KEY} and {SECONDS_PER_SLOT_KEY}"
        ))),
        (Some(value), None) => parse_positive_u64(value, SLOT_DURATION_MS_KEY),
        (None, Some(value)) => seconds_per_slot_to_ms(value),
        (Some(ms_value), Some(seconds_value)) => {
            let slot_duration_ms = parse_positive_u64(ms_value, SLOT_DURATION_MS_KEY)?;
            let from_seconds = seconds_per_slot_to_ms(seconds_value)?;
            if slot_duration_ms == from_seconds {
                Ok(slot_duration_ms)
            } else {
                let ms_raw = value_to_string(ms_value, SLOT_DURATION_MS_KEY)?;
                let seconds_raw = value_to_string(seconds_value, SECONDS_PER_SLOT_KEY)?;
                Err(BeaconError::ParseError(format!(
                    "conflicting slot duration: {SECONDS_PER_SLOT_KEY}={seconds_raw} {SLOT_DURATION_MS_KEY}={ms_raw}"
                )))
            }
        }
    }
}

fn parse_positive_u64(value: &serde_json::Value, key: &str) -> Result<u64, BeaconError> {
    let s = value_to_string(value, key)?;
    let n = s
        .parse::<u64>()
        .map_err(|e| BeaconError::ParseError(format!("invalid slot duration for {key}: {e}")))?;
    if n == 0 {
        return Err(BeaconError::ParseError(format!(
            "slot duration must be greater than zero for {key}"
        )));
    }
    Ok(n)
}

fn seconds_per_slot_to_ms(value: &serde_json::Value) -> Result<u64, BeaconError> {
    let seconds = parse_positive_u64(value, "SECONDS_PER_SLOT")?;
    seconds.checked_mul(1000).ok_or_else(|| {
        BeaconError::ParseError(format!("slot duration overflow for SECONDS_PER_SLOT: {seconds}"))
    })
}

fn value_to_string(value: &serde_json::Value, key: &str) -> Result<String, BeaconError> {
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        other => Err(BeaconError::ParseError(format!(
            "unsupported value type for {}: expected string or number, got {}",
            key,
            json_type_name(other)
        ))),
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn parse_epoch(spec: &HashMap<String, serde_json::Value>, key: &str) -> Result<Epoch, BeaconError> {
    let value = spec
        .get(key)
        .ok_or_else(|| BeaconError::ParseError(format!("missing config key: {}", key)))?;
    let s = value_to_string(value, key)?;
    s.parse::<u64>()
        .map_err(|e| BeaconError::ParseError(format!("invalid epoch for {}: {}", key, e)))
}

fn parse_version(
    spec: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Version, BeaconError> {
    let value = spec
        .get(key)
        .ok_or_else(|| BeaconError::ParseError(format!("missing config key: {}", key)))?;
    parse_version_value(value, key)
}

fn parse_version_value(value: &serde_json::Value, key: &str) -> Result<Version, BeaconError> {
    let s = value_to_string(value, key)?;
    let hex_str = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(hex_str)
        .map_err(|e| BeaconError::ParseError(format!("invalid hex for {}: {}", key, e)))?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| BeaconError::ParseError(format!("version must be 4 bytes for {}", key)))?;
    Ok(arr)
}

fn parse_epoch_optional(
    spec: &HashMap<String, serde_json::Value>,
    key: &str,
    default: u64,
) -> Result<Epoch, BeaconError> {
    match spec.get(key) {
        None => Ok(default),
        Some(value) => {
            let s = value_to_string(value, key)?;
            s.parse::<u64>()
                .map_err(|e| BeaconError::ParseError(format!("invalid epoch for {}: {}", key, e)))
        }
    }
}

fn parse_version_optional(
    spec: &HashMap<String, serde_json::Value>,
    key: &str,
    default: Version,
) -> Result<Version, BeaconError> {
    match spec.get(key) {
        None => Ok(default),
        Some(value) => parse_version_value(value, key),
    }
}

/// Proposer preparation data sent to the beacon node to register fee recipients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerPreparation {
    pub validator_index: String,
    pub fee_recipient: String,
}

/// Beacon committee subscription data for attestation subnet management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconCommitteeSubscription {
    pub validator_index: String,
    pub committee_index: String,
    pub committees_at_slot: String,
    pub slot: String,
    pub is_aggregator: bool,
}

/// Validator liveness data from the beacon node.
///
/// Per the standard Eth2 Beacon API (`POST /eth/v1/validator/liveness/{epoch}`),
/// only `index` and `is_live` are returned. The epoch is already a parameter
/// to the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorLiveness {
    pub index: String,
    pub is_live: bool,
}

/// Response type for the validator liveness endpoint.
pub type ValidatorLivenessResponse = DataResponse<Vec<ValidatorLiveness>>;

/// Sync status data from the beacon node's `/eth/v1/node/syncing` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncingData {
    pub head_slot: String,
    pub sync_distance: String,
    pub is_syncing: bool,
    pub is_optimistic: bool,
    pub el_offline: bool,
}

/// Response type for the node syncing endpoint.
pub type SyncingResponse = DataResponse<SyncingData>;

/// Node version data from the beacon node's `/eth/v1/node/version` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NodeVersionData {
    pub version: String,
}

/// Response type for the node version v1 endpoint.
pub type NodeVersionResponse = DataResponse<NodeVersionData>;

/// Engine-API `ClientVersionV1` object used by `/eth/v2/node/version`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ClientVersionV1 {
    pub code: String,
    pub name: String,
    pub version: String,
    pub commit: String,
}

/// Node version data from `/eth/v2/node/version`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NodeVersionV2Data {
    pub beacon_node: ClientVersionV1,
    #[serde(default)]
    pub execution_client: Option<ClientVersionV1>,
}

impl NodeVersionV2Data {
    /// User-agent-style string for logs (`{name}/{version}`).
    pub fn version_string(&self) -> String {
        format!("{}/{}", self.beacon_node.name, self.beacon_node.version)
    }
}

/// Response type for the node version v2 endpoint.
pub type NodeVersionV2Response = DataResponse<NodeVersionV2Data>;

/// Error details for a single attestation that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedAttestationError {
    pub index: u32,
    pub message: String,
}

/// Result of submitting attestations to the beacon node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitAttestationResult {
    Success,
    PartialFailure { failures: Vec<IndexedAttestationError> },
}

impl SubmitAttestationResult {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn failures(&self) -> &[IndexedAttestationError] {
        match self {
            Self::Success => &[],
            Self::PartialFailure { failures } => failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::ForkName;
    use serde_json::json;

    #[test]
    fn test_checkpoint_deserialize() {
        let json = r#"{
            "epoch": "123456",
            "root": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        }"#;

        let checkpoint: Checkpoint = serde_json::from_str(json).unwrap();
        assert_eq!(checkpoint.epoch, "123456");
        assert_eq!(
            checkpoint.root,
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn test_checkpoint_serialize() {
        let checkpoint = Checkpoint { epoch: "123456".to_string(), root: "0x1234".to_string() };

        let json = serde_json::to_string(&checkpoint).unwrap();
        assert!(json.contains("\"epoch\":\"123456\""));
        assert!(json.contains("\"root\":\"0x1234\""));
    }

    #[test]
    fn test_attestation_data_deserialize() {
        let json = r#"{
            "slot": "1000",
            "index": "1",
            "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "source": {
                "epoch": "100",
                "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
            },
            "target": {
                "epoch": "101",
                "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
            }
        }"#;

        let data: AttestationData = serde_json::from_str(json).unwrap();
        assert_eq!(data.slot, "1000");
        assert_eq!(data.index, "1");
        assert_eq!(data.source.epoch, "100");
        assert_eq!(data.target.epoch, "101");
    }

    #[test]
    fn test_attestation_deserialize() {
        let json = r#"{
            "committee_index": 1,
            "attester_index": 42,
            "data": {
                "slot": "1000",
                "index": "1",
                "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "source": {
                    "epoch": "100",
                    "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
                },
                "target": {
                    "epoch": "101",
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                }
            },
            "signature": "0xsignature"
        }"#;

        let attestation: SingleAttestation = serde_json::from_str(json).unwrap();
        assert_eq!(attestation.committee_index, 1);
        assert_eq!(attestation.attester_index, 42);
        assert_eq!(attestation.data.slot, "1000");
        assert_eq!(attestation.signature, "0xsignature");
    }

    #[test]
    fn test_beacon_block_header_deserialize() {
        let json = r#"{
            "slot": "5000",
            "proposer_index": "123",
            "parent_root": "0xparentroot",
            "state_root": "0xstateroot",
            "body_root": "0xbodyroot"
        }"#;

        let header: BeaconBlockHeader = serde_json::from_str(json).unwrap();
        assert_eq!(header.slot, "5000");
        assert_eq!(header.proposer_index, "123");
        assert_eq!(header.parent_root, "0xparentroot");
        assert_eq!(header.state_root, "0xstateroot");
        assert_eq!(header.body_root, "0xbodyroot");
    }

    #[test]
    fn test_attester_duty_deserialize() {
        let json = r#"{
            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
            "validator_index": "1234",
            "committee_index": "1",
            "committee_length": "128",
            "committees_at_slot": "64",
            "validator_committee_index": "25",
            "slot": "10000"
        }"#;

        let duty: AttesterDuty = serde_json::from_str(json).unwrap();
        assert_eq!(duty.validator_index, "1234");
        assert_eq!(duty.committee_index, "1");
        assert_eq!(duty.committee_length, "128");
        assert_eq!(duty.committees_at_slot, "64");
        assert_eq!(duty.validator_committee_index, "25");
        assert_eq!(duty.slot, "10000");
    }

    #[test]
    fn test_data_response_deserialize() {
        let json = r#"{
            "data": {
                "epoch": "123",
                "root": "0xroot"
            }
        }"#;

        let response: DataResponse<Checkpoint> = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.epoch, "123");
        assert_eq!(response.data.root, "0xroot");
    }

    #[test]
    fn test_dependent_root_response_deserialize() {
        let json = r#"{
            "dependent_root": "0xdeproot",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xpubkey",
                "validator_index": "1",
                "committee_index": "0",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "10",
                "slot": "100"
            }]
        }"#;

        let response: DependentRootResponse<Vec<AttesterDuty>> =
            serde_json::from_str(json).unwrap();
        assert_eq!(response.dependent_root, "0xdeproot");
        assert!(!response.execution_optimistic);
        assert_eq!(response.data.len(), 1);
        assert_eq!(response.data[0].validator_index, "1");
    }

    #[test]
    fn test_indexed_attestation_error_deserialize() {
        let json = r#"{
            "index": 0,
            "message": "Invalid signature"
        }"#;

        let error: IndexedAttestationError = serde_json::from_str(json).unwrap();
        assert_eq!(error.index, 0);
        assert_eq!(error.message, "Invalid signature");
    }

    #[test]
    fn test_submit_attestation_result_success() {
        let result = SubmitAttestationResult::Success;
        assert!(result.is_success());
        assert!(result.failures().is_empty());
    }

    #[test]
    fn test_genesis_data_deserialize() {
        let json = r#"{
            "genesis_time": "1606824023",
            "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            "genesis_fork_version": "0x00000000"
        }"#;

        let genesis: GenesisData = serde_json::from_str(json).unwrap();
        assert_eq!(genesis.genesis_time, "1606824023");
        assert_eq!(
            genesis.genesis_validators_root,
            "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        );
        assert_eq!(genesis.genesis_fork_version, "0x00000000");
    }

    #[test]
    fn test_genesis_data_serialize() {
        let genesis = GenesisData {
            genesis_time: "1606824023".to_string(),
            genesis_validators_root:
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
            genesis_fork_version: "0x00000000".to_string(),
        };
        let json = serde_json::to_string(&genesis).unwrap();
        assert!(json.contains("\"genesis_time\":\"1606824023\""));
        assert!(json.contains("\"genesis_fork_version\":\"0x00000000\""));
    }

    #[test]
    fn test_genesis_response_deserialize() {
        let json = r#"{
            "data": {
                "genesis_time": "1606824023",
                "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
                "genesis_fork_version": "0x00000000"
            }
        }"#;

        let response: GenesisResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.genesis_time, "1606824023");
    }

    #[test]
    fn test_config_spec_response_deserialize() {
        let json = r#"{
            "data": {
                "GENESIS_FORK_VERSION": "0x00000000",
                "ALTAIR_FORK_EPOCH": "74240",
                "ALTAIR_FORK_VERSION": "0x01000000",
                "SECONDS_PER_SLOT": "12",
                "SLOTS_PER_EPOCH": "32"
            }
        }"#;

        let response: ConfigSpecResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.get("GENESIS_FORK_VERSION").unwrap(), "0x00000000");
        assert_eq!(response.data.get("ALTAIR_FORK_EPOCH").unwrap(), "74240");
        assert_eq!(response.data.get("SECONDS_PER_SLOT").unwrap(), "12");
        assert_eq!(response.data.get("SLOTS_PER_EPOCH").unwrap(), "32");
        assert_eq!(response.data.len(), 5);
    }

    #[test]
    fn test_state_fork_deserialize() {
        let json = r#"{
            "previous_version": "0x00000000",
            "current_version": "0x04000000",
            "epoch": "269568"
        }"#;

        let fork: StateFork = serde_json::from_str(json).unwrap();
        assert_eq!(fork.previous_version, "0x00000000");
        assert_eq!(fork.current_version, "0x04000000");
        assert_eq!(fork.epoch, "269568");
    }

    #[test]
    fn test_state_fork_response_deserialize() {
        let json = r#"{
            "execution_optimistic": false,
            "finalized": true,
            "data": {
                "previous_version": "0x03000000",
                "current_version": "0x04000000",
                "epoch": "269568"
            }
        }"#;

        let response: StateForkResponse = serde_json::from_str(json).unwrap();
        assert!(!response.execution_optimistic);
        assert!(response.finalized);
        assert_eq!(response.data.previous_version, "0x03000000");
        assert_eq!(response.data.current_version, "0x04000000");
        assert_eq!(response.data.epoch, "269568");
    }

    fn mainnet_config_spec() -> HashMap<String, serde_json::Value> {
        let mut spec = HashMap::new();
        spec.insert("GENESIS_FORK_VERSION".to_string(), json!("0x00000000"));
        spec.insert("ALTAIR_FORK_EPOCH".to_string(), json!("74240"));
        spec.insert("ALTAIR_FORK_VERSION".to_string(), json!("0x01000000"));
        spec.insert("BELLATRIX_FORK_EPOCH".to_string(), json!("144896"));
        spec.insert("BELLATRIX_FORK_VERSION".to_string(), json!("0x02000000"));
        spec.insert("CAPELLA_FORK_EPOCH".to_string(), json!("194048"));
        spec.insert("CAPELLA_FORK_VERSION".to_string(), json!("0x03000000"));
        spec.insert("DENEB_FORK_EPOCH".to_string(), json!("269568"));
        spec.insert("DENEB_FORK_VERSION".to_string(), json!("0x04000000"));
        spec.insert("ELECTRA_FORK_EPOCH".to_string(), json!("364544"));
        spec.insert("ELECTRA_FORK_VERSION".to_string(), json!("0x05000000"));
        spec.insert("FULU_FORK_EPOCH".to_string(), json!("18446744073709551615"));
        spec.insert("FULU_FORK_VERSION".to_string(), json!("0x06000000"));
        spec.insert("GLOAS_FORK_EPOCH".to_string(), json!("18446744073709551615"));
        spec.insert("GLOAS_FORK_VERSION".to_string(), json!("0x07000000"));
        spec
    }

    #[test]
    fn test_parse_fork_schedule_mainnet() {
        let spec = mainnet_config_spec();
        let schedule = parse_fork_schedule(&spec).unwrap();

        assert_eq!(schedule.genesis_fork_version, [0, 0, 0, 0]);
        assert_eq!(schedule.altair_fork_epoch, 74240);
        assert_eq!(schedule.altair_fork_version, [1, 0, 0, 0]);
        assert_eq!(schedule.bellatrix_fork_epoch, 144896);
        assert_eq!(schedule.bellatrix_fork_version, [2, 0, 0, 0]);
        assert_eq!(schedule.capella_fork_epoch, 194048);
        assert_eq!(schedule.capella_fork_version, [3, 0, 0, 0]);
        assert_eq!(schedule.deneb_fork_epoch, 269568);
        assert_eq!(schedule.deneb_fork_version, [4, 0, 0, 0]);
        assert_eq!(schedule.electra_fork_epoch, 364544);
        assert_eq!(schedule.electra_fork_version, [5, 0, 0, 0]);
        assert_eq!(schedule.fulu_fork_epoch, u64::MAX);
        assert_eq!(schedule.fulu_fork_version, [6, 0, 0, 0]);
        assert_eq!(schedule.gloas_fork_epoch, u64::MAX);
        assert_eq!(schedule.gloas_fork_version, [7, 0, 0, 0]);
    }

    #[test]
    fn test_parse_fork_schedule_unscheduled_forks() {
        let mut spec = mainnet_config_spec();
        spec.insert("ELECTRA_FORK_EPOCH".to_string(), json!("18446744073709551615"));
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.electra_fork_epoch, u64::MAX);
    }

    #[test]
    fn test_parse_fork_schedule_missing_key() {
        let mut spec = mainnet_config_spec();
        spec.remove("ALTAIR_FORK_EPOCH");
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ALTAIR_FORK_EPOCH"));
    }

    #[test]
    fn test_parse_fork_schedule_invalid_epoch() {
        let mut spec = mainnet_config_spec();
        spec.insert("DENEB_FORK_EPOCH".to_string(), json!("not_a_number"));
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DENEB_FORK_EPOCH"));
    }

    #[test]
    fn test_parse_fork_schedule_invalid_version_hex() {
        let mut spec = mainnet_config_spec();
        spec.insert("CAPELLA_FORK_VERSION".to_string(), json!("0xZZZZZZZZ"));
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("CAPELLA_FORK_VERSION"));
    }

    #[test]
    fn test_parse_fork_schedule_wrong_version_length() {
        let mut spec = mainnet_config_spec();
        spec.insert("GENESIS_FORK_VERSION".to_string(), json!("0x0000"));
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("GENESIS_FORK_VERSION"));
    }

    #[test]
    fn test_parse_fork_schedule_version_without_0x_prefix() {
        let mut spec = mainnet_config_spec();
        spec.insert("GENESIS_FORK_VERSION".to_string(), json!("00000000"));
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.genesis_fork_version, [0, 0, 0, 0]);
    }

    fn assert_parse_error_contains(result: Result<u64, BeaconError>, needles: &[&str]) {
        let err = result.expect_err("expected BeaconError::ParseError");
        assert!(matches!(err, BeaconError::ParseError(_)), "expected ParseError, got {err:?}");
        let msg = err.to_string();
        for needle in needles {
            assert!(msg.contains(needle), "error {msg:?} should contain {needle:?}");
        }
    }

    #[test]
    fn test_parse_slot_duration_ms_master_keyset() {
        let mut spec = mainnet_config_spec();
        spec.insert("SLOT_DURATION_MS".to_string(), json!("12000"));
        assert!(!spec.contains_key("SECONDS_PER_SLOT"));
        assert!(!spec.contains_key("INTERVALS_PER_SLOT"));
        assert_eq!(parse_slot_duration_ms(&spec).unwrap(), 12_000);
    }

    #[test]
    fn test_parse_slot_duration_ms_legacy_keyset() {
        let mut spec = mainnet_config_spec();
        spec.insert("SECONDS_PER_SLOT".to_string(), json!("12"));
        spec.insert("INTERVALS_PER_SLOT".to_string(), json!("3"));
        assert!(!spec.contains_key("SLOT_DURATION_MS"));
        assert_eq!(parse_slot_duration_ms(&spec).unwrap(), 12_000);
    }

    #[test]
    fn test_parse_slot_duration_ms_both_agreeing() {
        let mut spec = mainnet_config_spec();
        spec.insert("SECONDS_PER_SLOT".to_string(), json!("12"));
        spec.insert("SLOT_DURATION_MS".to_string(), json!("12000"));
        assert_eq!(parse_slot_duration_ms(&spec).unwrap(), 12_000);
    }

    #[test]
    fn test_parse_slot_duration_ms_conflicting_keys_error() {
        let mut spec = mainnet_config_spec();
        spec.insert("SECONDS_PER_SLOT".to_string(), json!("12"));
        spec.insert("SLOT_DURATION_MS".to_string(), json!("13000"));
        assert_parse_error_contains(
            parse_slot_duration_ms(&spec),
            &["SECONDS_PER_SLOT", "SLOT_DURATION_MS", "12", "13000"],
        );
    }

    #[test]
    fn test_parse_slot_duration_ms_neither_key() {
        let spec = mainnet_config_spec();
        assert_parse_error_contains(
            parse_slot_duration_ms(&spec),
            &["SECONDS_PER_SLOT", "SLOT_DURATION_MS"],
        );
    }

    #[test]
    fn test_parse_slot_duration_ms_zero() {
        let mut spec = HashMap::new();
        spec.insert("SLOT_DURATION_MS".to_string(), json!(0));
        assert_parse_error_contains(parse_slot_duration_ms(&spec), &["SLOT_DURATION_MS"]);

        let mut spec = HashMap::new();
        spec.insert("SECONDS_PER_SLOT".to_string(), json!(0));
        assert_parse_error_contains(parse_slot_duration_ms(&spec), &["SECONDS_PER_SLOT"]);
    }

    #[test]
    fn test_parse_slot_duration_ms_non_numeric() {
        let mut spec = HashMap::new();
        spec.insert("SLOT_DURATION_MS".to_string(), json!("abc"));
        assert_parse_error_contains(parse_slot_duration_ms(&spec), &["SLOT_DURATION_MS"]);

        let mut spec = HashMap::new();
        spec.insert("SECONDS_PER_SLOT".to_string(), json!("abc"));
        assert_parse_error_contains(parse_slot_duration_ms(&spec), &["SECONDS_PER_SLOT"]);
    }

    #[test]
    fn test_parse_slot_duration_ms_numeric_values() {
        let mut spec = HashMap::new();
        spec.insert("SECONDS_PER_SLOT".to_string(), json!(12));
        spec.insert("SLOT_DURATION_MS".to_string(), json!(12000));
        assert_eq!(parse_slot_duration_ms(&spec).unwrap(), 12_000);
    }

    #[test]
    fn test_validator_liveness_deserialize_standard_spec() {
        let json = r#"{
            "index": "1234",
            "is_live": true
        }"#;

        let liveness: ValidatorLiveness = serde_json::from_str(json).unwrap();
        assert_eq!(liveness.index, "1234");
        assert!(liveness.is_live);
    }

    #[test]
    fn test_validator_liveness_deserialize_not_live() {
        let json = r#"{
            "index": "5678",
            "is_live": false
        }"#;

        let liveness: ValidatorLiveness = serde_json::from_str(json).unwrap();
        assert_eq!(liveness.index, "5678");
        assert!(!liveness.is_live);
    }

    #[test]
    fn test_validator_liveness_deserialize_with_extra_fields() {
        // Lighthouse returns an extra `epoch` field; serde should ignore it.
        let json = r#"{
            "index": "1234",
            "epoch": "100",
            "is_live": true
        }"#;

        let liveness: ValidatorLiveness = serde_json::from_str(json).unwrap();
        assert_eq!(liveness.index, "1234");
        assert!(liveness.is_live);
    }

    #[test]
    fn test_validator_liveness_response_deserialize() {
        let json = r#"{
            "data": [
                {
                    "index": "1234",
                    "is_live": true
                },
                {
                    "index": "5678",
                    "is_live": false
                }
            ]
        }"#;

        let response: ValidatorLivenessResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.len(), 2);
        assert!(response.data[0].is_live);
        assert!(!response.data[1].is_live);
    }

    #[test]
    fn test_submit_attestation_result_partial_failure() {
        let result = SubmitAttestationResult::PartialFailure {
            failures: vec![
                IndexedAttestationError { index: 0, message: "Invalid signature".to_string() },
                IndexedAttestationError {
                    index: 2,
                    message: "Attestation already known".to_string(),
                },
            ],
        };
        assert!(!result.is_success());
        assert_eq!(result.failures().len(), 2);
        assert_eq!(result.failures()[0].index, 0);
        assert_eq!(result.failures()[1].index, 2);
    }

    #[test]
    fn test_proposer_duty_deserialize() {
        let json = r#"{
            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
            "validator_index": "1234",
            "slot": "320000"
        }"#;

        let duty: ProposerDuty = serde_json::from_str(json).unwrap();
        assert_eq!(duty.validator_index, "1234");
        assert_eq!(duty.slot, "320000");
    }

    #[test]
    fn test_proposer_duties_response_deserialize() {
        let json = r#"{
            "dependent_root": "0xdeproot",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xpubkey",
                "validator_index": "1",
                "slot": "100"
            }]
        }"#;

        let response: ProposerDutiesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.dependent_root, "0xdeproot");
        assert_eq!(response.data.len(), 1);
        assert_eq!(response.data[0].slot, "100");
    }

    #[test]
    fn test_proposer_duties_v2_body_deserializes_as_v1_shape() {
        // beacon-APIs proposer.v2.yaml uses the same GetProposerDutiesResponse
        // schema as v1 (dependent_root, execution_optimistic, data[]).
        let json = r#"{
            "dependent_root": "0xabc",
            "execution_optimistic": true,
            "data": [{
                "pubkey": "0xpubkey",
                "validator_index": "7",
                "slot": "32"
            }]
        }"#;
        let response: ProposerDutiesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.dependent_root, "0xabc");
        assert!(response.execution_optimistic);
        assert_eq!(response.data[0].validator_index, "7");
        assert_eq!(response.data[0].slot, "32");
    }

    #[test]
    fn test_node_version_v2_deserialize_with_execution_client() {
        let json = r#"{
            "data": {
                "beacon_node": {
                    "code": "LH",
                    "name": "Lighthouse",
                    "version": "v8.0.1",
                    "commit": "0xced49dd2"
                },
                "execution_client": {
                    "code": "NM",
                    "name": "Nethermind",
                    "version": "v1.35.8",
                    "commit": "0xc066aee2"
                }
            }
        }"#;
        let response: NodeVersionV2Response = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.beacon_node.code, "LH");
        assert_eq!(response.data.version_string(), "Lighthouse/v8.0.1");
        assert_eq!(response.data.execution_client.as_ref().unwrap().name, "Nethermind");
    }

    #[test]
    fn test_node_version_v2_deserialize_without_execution_client() {
        let json = r#"{
            "data": {
                "beacon_node": {
                    "code": "LH",
                    "name": "Lighthouse",
                    "version": "v8.0.1",
                    "commit": "0xced49dd2"
                }
            }
        }"#;
        let response: NodeVersionV2Response = serde_json::from_str(json).unwrap();
        assert!(response.data.execution_client.is_none());
        assert_eq!(response.data.version_string(), "Lighthouse/v8.0.1");
    }

    #[test]
    fn test_produce_block_response_parse_full_block() {
        let block_json = serde_json::json!({
            "slot": "100",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        });

        let response = ProduceBlockResponse {
            data: block_json,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("12345".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };

        let block = response.parse_full_block().unwrap();
        assert_eq!(block.block().slot, 100);
        assert_eq!(block.block().proposer_index, 42);
    }

    #[test]
    fn test_produce_block_response_parse_blinded_block() {
        let block_json = serde_json::json!({
            "slot": "200",
            "proposer_index": "99",
            "parent_root": format!("0x{}", "03".repeat(32)),
            "state_root": format!("0x{}", "04".repeat(32)),
            "body": "0xbeef"
        });

        let response = ProduceBlockResponse {
            data: block_json,
            is_blinded: true,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
        };

        let block = response.parse_blinded_block().unwrap();
        assert_eq!(block.slot, 200);
        assert_eq!(block.proposer_index, 99);
    }

    #[test]
    fn test_produce_block_response_parse_invalid_data() {
        let response = ProduceBlockResponse {
            data: serde_json::json!({"invalid": "data"}),
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
        };

        assert!(response.parse_full_block().is_err());
    }

    #[test]
    fn test_proposer_preparation_serialize() {
        let prep = ProposerPreparation {
            validator_index: "1234".to_string(),
            fee_recipient: "0xabcf8e0d4e9587369b2301d0790347320302cc09".to_string(),
        };

        let json = serde_json::to_string(&prep).unwrap();
        assert!(json.contains("\"validator_index\":\"1234\""));
        assert!(json.contains("\"fee_recipient\":\"0xabcf8e0d4e9587369b2301d0790347320302cc09\""));
    }

    #[test]
    fn test_proposer_preparation_deserialize() {
        let json = r#"{
            "validator_index": "1234",
            "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09"
        }"#;

        let prep: ProposerPreparation = serde_json::from_str(json).unwrap();
        assert_eq!(prep.validator_index, "1234");
        assert_eq!(prep.fee_recipient, "0xabcf8e0d4e9587369b2301d0790347320302cc09");
    }

    #[test]
    fn test_beacon_committee_subscription_serialize() {
        let sub = BeaconCommitteeSubscription {
            validator_index: "1234".to_string(),
            committee_index: "1".to_string(),
            committees_at_slot: "64".to_string(),
            slot: "10000".to_string(),
            is_aggregator: true,
        };

        let json = serde_json::to_string(&sub).unwrap();
        assert!(json.contains("\"validator_index\":\"1234\""));
        assert!(json.contains("\"committee_index\":\"1\""));
        assert!(json.contains("\"committees_at_slot\":\"64\""));
        assert!(json.contains("\"slot\":\"10000\""));
        assert!(json.contains("\"is_aggregator\":true"));
    }

    #[test]
    fn test_beacon_committee_subscription_deserialize() {
        let json = r#"{
            "validator_index": "1234",
            "committee_index": "1",
            "committees_at_slot": "64",
            "slot": "10000",
            "is_aggregator": false
        }"#;

        let sub: BeaconCommitteeSubscription = serde_json::from_str(json).unwrap();
        assert_eq!(sub.validator_index, "1234");
        assert_eq!(sub.committee_index, "1");
        assert_eq!(sub.committees_at_slot, "64");
        assert_eq!(sub.slot, "10000");
        assert!(!sub.is_aggregator);
    }

    #[test]
    fn test_node_version_data_deserialize() {
        let json = r#"{"version": "Lighthouse/v7.1.0-a1b2c3d/x86_64-linux"}"#;
        let data: NodeVersionData = serde_json::from_str(json).unwrap();
        assert_eq!(data.version, "Lighthouse/v7.1.0-a1b2c3d/x86_64-linux");
    }

    #[test]
    fn test_node_version_response_deserialize() {
        let json = r#"{"data":{"version":"Lighthouse/v7.1.0-a1b2c3d/x86_64-linux"}}"#;
        let response: NodeVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.version, "Lighthouse/v7.1.0-a1b2c3d/x86_64-linux");
    }

    #[test]
    fn test_syncing_data_deserialize_synced() {
        let json = r#"{
            "head_slot": "1000",
            "sync_distance": "0",
            "is_syncing": false,
            "is_optimistic": false,
            "el_offline": false
        }"#;

        let data: SyncingData = serde_json::from_str(json).unwrap();
        assert_eq!(data.head_slot, "1000");
        assert_eq!(data.sync_distance, "0");
        assert!(!data.is_syncing);
        assert!(!data.is_optimistic);
        assert!(!data.el_offline);
    }

    #[test]
    fn test_syncing_data_deserialize_syncing() {
        let json = r#"{
            "head_slot": "500",
            "sync_distance": "500",
            "is_syncing": true,
            "is_optimistic": true,
            "el_offline": false
        }"#;

        let data: SyncingData = serde_json::from_str(json).unwrap();
        assert!(data.is_syncing);
        assert!(data.is_optimistic);
        assert_eq!(data.sync_distance, "500");
    }

    #[test]
    fn test_syncing_response_deserialize() {
        let json = r#"{
            "data": {
                "head_slot": "1000",
                "sync_distance": "0",
                "is_syncing": false,
                "is_optimistic": false,
                "el_offline": false
            }
        }"#;

        let response: SyncingResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.head_slot, "1000");
        assert!(!response.data.is_syncing);
    }

    #[test]
    fn test_legacy_attestation_serde_roundtrip() {
        let att = LegacyAttestation {
            aggregation_bits: "0xff03".to_string(),
            data: AttestationData {
                slot: "1000".to_string(),
                index: "1".to_string(),
                beacon_block_root: "0xroot".to_string(),
                source: Checkpoint { epoch: "100".to_string(), root: "0xsource".to_string() },
                target: Checkpoint { epoch: "101".to_string(), root: "0xtarget".to_string() },
            },
            signature: "0xsig".to_string(),
        };
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: LegacyAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_legacy_attestation_deserialize() {
        let json = r#"{
            "aggregation_bits": "0xff03",
            "data": {
                "slot": "1000",
                "index": "1",
                "beacon_block_root": "0xroot",
                "source": {
                    "epoch": "100",
                    "root": "0xsource"
                },
                "target": {
                    "epoch": "101",
                    "root": "0xtarget"
                }
            },
            "signature": "0xsig"
        }"#;

        let att: LegacyAttestation = serde_json::from_str(json).unwrap();
        assert_eq!(att.aggregation_bits, "0xff03");
        assert_eq!(att.data.slot, "1000");
        assert_eq!(att.signature, "0xsig");
    }

    #[test]
    fn test_versioned_attestation_pre_electra() {
        let legacy = LegacyAttestation {
            aggregation_bits: "0xff".to_string(),
            data: AttestationData {
                slot: "100".to_string(),
                index: "0".to_string(),
                beacon_block_root: "0xroot".to_string(),
                source: Checkpoint { epoch: "3".to_string(), root: "0xs".to_string() },
                target: Checkpoint { epoch: "4".to_string(), root: "0xt".to_string() },
            },
            signature: "0xsig".to_string(),
        };
        let versioned = VersionedAttestation::PreElectra(vec![legacy]);
        assert!(matches!(versioned, VersionedAttestation::PreElectra(ref v) if v.len() == 1));
    }

    #[test]
    fn test_versioned_attestation_electra() {
        let single = SingleAttestation {
            committee_index: 1,
            attester_index: 42,
            data: AttestationData {
                slot: "100".to_string(),
                index: "0".to_string(),
                beacon_block_root: "0xroot".to_string(),
                source: Checkpoint { epoch: "3".to_string(), root: "0xs".to_string() },
                target: Checkpoint { epoch: "4".to_string(), root: "0xt".to_string() },
            },
            signature: "0xsig".to_string(),
        };
        let versioned = VersionedAttestation::Electra(vec![single]);
        assert!(matches!(versioned, VersionedAttestation::Electra(ref v) if v.len() == 1));
    }

    #[test]
    fn test_versioned_aggregate_attestation_pre_electra() {
        let att = eth_types::Attestation {
            aggregation_bits: vec![0xff],
            data: eth_types::AttestationData {
                slot: 100,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
        };
        let versioned = VersionedAggregateAttestation::PreElectra(att);
        assert!(matches!(versioned, VersionedAggregateAttestation::PreElectra(_)));
    }

    #[test]
    fn test_versioned_aggregate_attestation_electra() {
        let att = eth_types::ElectraAttestation {
            aggregation_bits: vec![0xff],
            data: eth_types::AttestationData {
                slot: 100,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
            committee_bits: vec![0x01; 8],
        };
        let versioned = VersionedAggregateAttestation::Electra(att);
        assert!(matches!(versioned, VersionedAggregateAttestation::Electra(_)));
    }

    #[test]
    fn test_versioned_signed_aggregate_and_proof_pre_electra() {
        let proofs = vec![eth_types::SignedAggregateAndProof {
            message: eth_types::AggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::Attestation {
                    aggregation_bits: vec![0xff],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        }];
        let versioned = VersionedSignedAggregateAndProof::PreElectra(proofs);
        assert!(
            matches!(versioned, VersionedSignedAggregateAndProof::PreElectra(ref v) if v.len() == 1)
        );
    }

    #[test]
    fn test_versioned_signed_aggregate_and_proof_electra() {
        let proofs = vec![eth_types::SignedElectraAggregateAndProof {
            message: eth_types::ElectraAggregateAndProof {
                aggregator_index: 42,
                aggregate: eth_types::ElectraAttestation {
                    aggregation_bits: vec![0xff],
                    data: eth_types::AttestationData {
                        slot: 100,
                        index: 1,
                        beacon_block_root: [1u8; 32],
                        source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                        target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                    },
                    signature: vec![0xaa; 96],
                    committee_bits: vec![0x01; 8],
                },
                selection_proof: vec![0xbb; 96],
            },
            signature: vec![0xcc; 96],
        }];
        let versioned = VersionedSignedAggregateAndProof::Electra(proofs);
        assert!(
            matches!(versioned, VersionedSignedAggregateAndProof::Electra(ref v) if v.len() == 1)
        );
    }

    #[test]
    fn test_parse_epoch_from_number_value() {
        let mut spec = HashMap::new();
        spec.insert("ALTAIR_FORK_EPOCH".to_string(), json!(74240));
        let epoch = parse_epoch(&spec, "ALTAIR_FORK_EPOCH").unwrap();
        assert_eq!(epoch, 74240);
    }

    #[test]
    fn test_parse_epoch_from_string_value() {
        let mut spec = HashMap::new();
        spec.insert("ALTAIR_FORK_EPOCH".to_string(), json!("74240"));
        let epoch = parse_epoch(&spec, "ALTAIR_FORK_EPOCH").unwrap();
        assert_eq!(epoch, 74240);
    }

    #[test]
    fn test_parse_version_from_string_value() {
        let mut spec = HashMap::new();
        spec.insert("ALTAIR_FORK_VERSION".to_string(), json!("0x01000000"));
        let version = parse_version(&spec, "ALTAIR_FORK_VERSION").unwrap();
        assert_eq!(version, [1, 0, 0, 0]);
    }

    #[test]
    fn test_value_to_string_unsupported_type() {
        let result = value_to_string(&json!([1, 2]), "TEST_KEY");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("TEST_KEY"));
        assert!(err.contains("array"));
    }

    #[test]
    fn test_config_spec_response_deserialize_mixed_types() {
        let json_str = r#"{
            "data": {
                "ALTAIR_FORK_EPOCH": "74240",
                "SECONDS_PER_SLOT": 12,
                "GENESIS_FORK_VERSION": "0x00000000"
            }
        }"#;
        let response: ConfigSpecResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(response.data.get("ALTAIR_FORK_EPOCH").unwrap(), &json!("74240"));
        assert_eq!(response.data.get("SECONDS_PER_SLOT").unwrap(), &json!(12));
        assert_eq!(response.data.get("GENESIS_FORK_VERSION").unwrap(), &json!("0x00000000"));
    }

    #[test]
    fn test_parse_fork_schedule_with_numeric_epochs() {
        let mut spec = mainnet_config_spec();
        spec.insert("ALTAIR_FORK_EPOCH".to_string(), json!(74240));
        spec.insert("BELLATRIX_FORK_EPOCH".to_string(), json!(144896));
        spec.insert("CAPELLA_FORK_EPOCH".to_string(), json!(194048));
        spec.insert("DENEB_FORK_EPOCH".to_string(), json!(269568));
        spec.insert("ELECTRA_FORK_EPOCH".to_string(), json!(364544));
        spec.insert("FULU_FORK_EPOCH".to_string(), json!(18446744073709551615_u64));
        spec.insert("GLOAS_FORK_EPOCH".to_string(), json!(18446744073709551615_u64));
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.altair_fork_epoch, 74240);
        assert_eq!(schedule.bellatrix_fork_epoch, 144896);
        assert_eq!(schedule.capella_fork_epoch, 194048);
        assert_eq!(schedule.deneb_fork_epoch, 269568);
        assert_eq!(schedule.electra_fork_epoch, 364544);
        assert_eq!(schedule.fulu_fork_epoch, u64::MAX);
        assert_eq!(schedule.gloas_fork_epoch, u64::MAX);
    }

    #[test]
    fn test_parse_fork_schedule_with_fulu() {
        let mut spec = mainnet_config_spec();
        spec.insert("FULU_FORK_EPOCH".to_string(), json!("500000"));
        spec.insert("FULU_FORK_VERSION".to_string(), json!("0x06000000"));
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.fulu_fork_epoch, 500000);
        assert_eq!(schedule.fulu_fork_version, [6, 0, 0, 0]);
    }

    #[test]
    fn test_parse_fork_schedule_without_fulu() {
        let mut spec = mainnet_config_spec();
        spec.remove("FULU_FORK_EPOCH");
        spec.remove("FULU_FORK_VERSION");
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.fulu_fork_epoch, u64::MAX);
        assert_eq!(schedule.fulu_fork_version, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_parse_fork_schedule_without_gloas() {
        let mut spec = mainnet_config_spec();
        spec.remove("GLOAS_FORK_EPOCH");
        spec.remove("GLOAS_FORK_VERSION");
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.gloas_fork_epoch, u64::MAX);
        assert_eq!(schedule.gloas_fork_version, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_parse_fork_schedule_invalid_gloas_epoch() {
        let mut spec = mainnet_config_spec();
        spec.insert("GLOAS_FORK_EPOCH".to_string(), json!("not_a_number"));
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("GLOAS_FORK_EPOCH"));
    }

    #[test]
    fn test_parse_fork_schedule_invalid_gloas_version() {
        let mut spec = mainnet_config_spec();
        spec.insert("GLOAS_FORK_VERSION".to_string(), json!("0xZZZZZZZZ"));
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("GLOAS_FORK_VERSION"));
    }

    #[test]
    fn test_parse_fork_schedule_with_gloas() {
        let mut spec = mainnet_config_spec();
        spec.insert("FULU_FORK_EPOCH".to_string(), json!("500000"));
        spec.insert("FULU_FORK_VERSION".to_string(), json!("0x06000000"));
        spec.insert("GLOAS_FORK_EPOCH".to_string(), json!("600000"));
        spec.insert("GLOAS_FORK_VERSION".to_string(), json!("0x07000000"));
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.gloas_fork_epoch, 600000);
        assert_eq!(schedule.gloas_fork_version, [0x07, 0, 0, 0]);
        assert_eq!(ForkName::from_epoch(600000, &schedule), ForkName::Gloas);
        assert_eq!(ForkName::from_epoch(599999, &schedule), ForkName::Fulu);
    }

    #[test]
    fn test_parse_fork_schedule_omitted_fulu_and_gloas_share_version_sentinel() {
        // Both omitted keys default to [0xFF; 4]. SignContext::resolve first-matches
        // Fulu for that sentinel (`typed_signer::tests::test_resolve_sentinel_collision_first_matches_fulu`).
        // Issue 2.10's conditional fail-closed rule confines the collision to the
        // fully-unscheduled case.
        let mut spec = mainnet_config_spec();
        spec.remove("FULU_FORK_EPOCH");
        spec.remove("FULU_FORK_VERSION");
        spec.remove("GLOAS_FORK_EPOCH");
        spec.remove("GLOAS_FORK_VERSION");
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.fulu_fork_epoch, u64::MAX);
        assert_eq!(schedule.gloas_fork_epoch, u64::MAX);
        assert_eq!(schedule.fulu_fork_version, [0xFF; 4]);
        assert_eq!(schedule.gloas_fork_version, [0xFF; 4]);
    }

    #[test]
    fn test_parse_epoch_optional_missing() {
        let spec: HashMap<String, serde_json::Value> = HashMap::new();
        let result = parse_epoch_optional(&spec, "MISSING_KEY", 42).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_parse_epoch_optional_present() {
        let mut spec = HashMap::new();
        spec.insert("FULU_FORK_EPOCH".to_string(), json!("123456"));
        let result = parse_epoch_optional(&spec, "FULU_FORK_EPOCH", u64::MAX).unwrap();
        assert_eq!(result, 123456);
    }

    #[test]
    fn test_parse_epoch_optional_invalid() {
        let mut spec = HashMap::new();
        spec.insert("FULU_FORK_EPOCH".to_string(), json!("not_a_number"));
        let result = parse_epoch_optional(&spec, "FULU_FORK_EPOCH", u64::MAX);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("FULU_FORK_EPOCH"));
    }

    #[test]
    fn test_parse_version_optional_missing() {
        let spec: HashMap<String, serde_json::Value> = HashMap::new();
        let result = parse_version_optional(&spec, "MISSING_KEY", [0xAA; 4]).unwrap();
        assert_eq!(result, [0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn test_parse_version_optional_present() {
        let mut spec = HashMap::new();
        spec.insert("FULU_FORK_VERSION".to_string(), json!("0x06000000"));
        let result =
            parse_version_optional(&spec, "FULU_FORK_VERSION", [0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        assert_eq!(result, [6, 0, 0, 0]);
    }

    #[test]
    fn test_parse_version_optional_invalid() {
        let mut spec = HashMap::new();
        spec.insert("FULU_FORK_VERSION".to_string(), json!("0xZZZZZZZZ"));
        let result = parse_version_optional(&spec, "FULU_FORK_VERSION", [0xFF; 4]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("FULU_FORK_VERSION"));
    }
}
