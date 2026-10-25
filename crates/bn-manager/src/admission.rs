//! Chain-identity classification shared with the proposer pool (FU-A6).

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use beacon::{
    hex_ids_equal, BeaconError, ConfigSpecResponse, ForkScheduleAgreement, GenesisResponse,
};
use eth_types::ForkSchedule;

/// Boot-agreed chain identity. Re-admission compares against this value.
///
/// The identity set is the genesis validators root, the slot duration,
/// `SLOTS_PER_EPOCH`, the genesis time, the genesis fork version, and the
/// fork schedule (each fork epoch and fork version of `/eth/v1/config/spec`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainIdentity {
    pub slot_duration_ms: u64,
    pub slots_per_epoch: u64,
    pub genesis_time: u64,
    pub genesis_validators_root: String,
    pub genesis_fork_version: String,
    pub fork_schedule: ForkSchedule,
}

/// Result of comparing one node's spec and genesis to [`ChainIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityClass {
    Match,
    /// A parsed value disagrees. The field is the first disagreeing field.
    Mismatch(IdentityField),
    /// No identity evidence. The caller keeps the current admission bit.
    Transient,
}

/// One field of [`ChainIdentity`]. `Display` gives the name in logs and errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityField {
    ForkSchedule,
    SlotDuration,
    SlotsPerEpoch,
    GenesisTime,
    GenesisValidatorsRoot,
    GenesisForkVersion,
}

impl fmt::Display for IdentityField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ForkSchedule => "fork schedule",
            Self::SlotDuration => "slot duration",
            Self::SlotsPerEpoch => "SLOTS_PER_EPOCH",
            Self::GenesisTime => "genesis_time",
            Self::GenesisValidatorsRoot => "genesis_validators_root",
            Self::GenesisForkVersion => "genesis_fork_version",
        })
    }
}

/// A parsed disagreement on any field is [`IdentityClass::Mismatch`].
///
/// Each field is compared on its own. An error or an unparsable value does
/// not hide a contradiction in another field, on the same response or on the
/// other one. Every field must parse and match before the result is
/// [`IdentityClass::Match`]. Anything else with no parsed contradiction is
/// [`IdentityClass::Transient`].
///
/// The fork keys of the spec are compared one key at a time with
/// [`beacon::compare_fork_schedule`]. A missing `FULU_*` or `GLOAS_*` key
/// reads as unscheduled.
pub fn classify_identity(
    spec: &Result<ConfigSpecResponse, BeaconError>,
    genesis: &Result<GenesisResponse, BeaconError>,
    expected: &ChainIdentity,
) -> IdentityClass {
    let spec = spec.as_ref().ok().map(|spec| &spec.data);
    let genesis = genesis.as_ref().ok().map(|genesis| &genesis.data);
    let fields = [
        (
            IdentityField::ForkSchedule,
            spec.and_then(|data| {
                match beacon::compare_fork_schedule(data, &expected.fork_schedule) {
                    ForkScheduleAgreement::Match => Some(true),
                    ForkScheduleAgreement::Mismatch => Some(false),
                    ForkScheduleAgreement::Incomplete => None,
                }
            }),
        ),
        (
            IdentityField::SlotDuration,
            spec.and_then(|data| beacon::parse_slot_duration_ms(data).ok())
                .map(|duration_ms| duration_ms == expected.slot_duration_ms),
        ),
        (
            IdentityField::SlotsPerEpoch,
            spec.and_then(|data| beacon::parse_slots_per_epoch(data).ok())
                .map(|slots| slots == expected.slots_per_epoch),
        ),
        (
            IdentityField::GenesisTime,
            genesis
                .and_then(|data| data.genesis_time.parse::<u64>().ok())
                .map(|time| time == expected.genesis_time),
        ),
        (
            IdentityField::GenesisValidatorsRoot,
            genesis.map(|data| {
                hex_ids_equal(&expected.genesis_validators_root, &data.genesis_validators_root)
            }),
        ),
        (
            IdentityField::GenesisForkVersion,
            genesis.map(|data| {
                hex_ids_equal(&expected.genesis_fork_version, &data.genesis_fork_version)
            }),
        ),
    ];
    if let Some((field, _)) = fields.iter().find(|(_, agrees)| *agrees == Some(false)) {
        return IdentityClass::Mismatch(*field);
    }
    if fields.iter().all(|(_, agrees)| *agrees == Some(true)) {
        IdentityClass::Match
    } else {
        IdentityClass::Transient
    }
}

/// One epoch of the beacon-node slot duration. `6000` ms and `32` slots is `192` s.
pub fn sync_check_interval_for(slot_duration: Duration, slots_per_epoch: u64) -> Duration {
    let slots = u32::try_from(slots_per_epoch).unwrap_or(u32::MAX);
    slot_duration.saturating_mul(slots)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AdmissionStamp {
    pub(crate) index: usize,
    pub(crate) generation: u64,
}

pub(crate) fn stamp_still_holds(
    admitted: &[AtomicBool],
    generations: &[AtomicU64],
    stamp: AdmissionStamp,
) -> bool {
    admitted.get(stamp.index).is_some_and(|flag| flag.load(Ordering::Acquire))
        && generations
            .get(stamp.index)
            .is_some_and(|generation| generation.load(Ordering::Acquire) == stamp.generation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> ChainIdentity {
        ChainIdentity {
            slot_duration_ms: 12_000,
            slots_per_epoch: 32,
            genesis_time: 1_606_824_023,
            genesis_validators_root: "0xabc".to_string(),
            genesis_fork_version: "0x00000000".to_string(),
            fork_schedule: crate::mock::mainnet_fork_schedule(),
        }
    }

    fn spec_ok() -> ConfigSpecResponse {
        let mut data = crate::mock::mainnet_fork_spec();
        data.insert("SLOT_DURATION_MS".to_string(), serde_json::json!("12000"));
        data.insert("SLOTS_PER_EPOCH".to_string(), serde_json::json!("32"));
        ConfigSpecResponse { data }
    }

    fn spec_wrong_duration() -> ConfigSpecResponse {
        let mut spec = spec_ok();
        spec.data.insert("SLOT_DURATION_MS".to_string(), serde_json::json!("6000"));
        spec
    }

    fn genesis(root: &str) -> GenesisResponse {
        GenesisResponse {
            data: beacon::GenesisData {
                genesis_time: "1606824023".to_string(),
                genesis_validators_root: root.to_string(),
                genesis_fork_version: "0x00000000".to_string(),
            },
        }
    }

    fn unavailable() -> BeaconError {
        BeaconError::ApiError { status: 503, message: "unavailable".to_string() }
    }

    #[test]
    fn wrong_root_plus_spec_error_is_a_mismatch() {
        let spec = Err(unavailable());
        let genesis = Ok(genesis("0xdef"));
        assert_eq!(
            classify_identity(&spec, &genesis, &expected()),
            IdentityClass::Mismatch(IdentityField::GenesisValidatorsRoot),
            "a parsed root disagreement is a mismatch even when spec is 503"
        );
    }

    #[test]
    fn spec_disagreement_plus_genesis_error_is_a_mismatch() {
        let spec = Ok(spec_wrong_duration());
        let genesis = Err(unavailable());
        assert_eq!(
            classify_identity(&spec, &genesis, &expected()),
            IdentityClass::Mismatch(IdentityField::SlotDuration)
        );
    }

    #[test]
    fn both_errors_stay_transient() {
        let spec = Err(unavailable());
        let genesis = Err(unavailable());
        assert_eq!(classify_identity(&spec, &genesis, &expected()), IdentityClass::Transient);
    }

    fn spec_with(key: &str, value: &str) -> ConfigSpecResponse {
        let mut spec = spec_ok();
        spec.data.insert(key.to_string(), serde_json::json!(value));
        spec
    }

    #[test]
    fn matching_spec_and_genesis_is_a_match() {
        let genesis = Ok(genesis("0xabc"));
        assert_eq!(classify_identity(&Ok(spec_ok()), &genesis, &expected()), IdentityClass::Match);
    }

    #[test]
    fn different_future_fork_epoch_is_a_mismatch() {
        let spec = Ok(spec_with("FULU_FORK_EPOCH", "411392"));
        let genesis = Ok(genesis("0xabc"));
        assert_eq!(
            classify_identity(&spec, &genesis, &expected()),
            IdentityClass::Mismatch(IdentityField::ForkSchedule)
        );
    }

    #[test]
    fn different_fork_version_is_a_mismatch() {
        let spec = Ok(spec_with("CAPELLA_FORK_VERSION", "0x03000001"));
        let genesis = Ok(genesis("0xabc"));
        assert_eq!(
            classify_identity(&spec, &genesis, &expected()),
            IdentityClass::Mismatch(IdentityField::ForkSchedule)
        );
    }

    #[test]
    fn malformed_slot_duration_does_not_hide_a_fork_mismatch() {
        let mut spec = spec_with("GLOAS_FORK_EPOCH", "500000");
        spec.data.insert("SLOT_DURATION_MS".to_string(), serde_json::json!("not_a_number"));
        let genesis = Err(unavailable());
        assert_eq!(
            classify_identity(&Ok(spec), &genesis, &expected()),
            IdentityClass::Mismatch(IdentityField::ForkSchedule)
        );
    }

    #[test]
    fn malformed_slot_duration_does_not_hide_a_slots_per_epoch_mismatch() {
        let mut spec = spec_with("SLOTS_PER_EPOCH", "16");
        spec.data.insert("SLOT_DURATION_MS".to_string(), serde_json::json!("not_a_number"));
        let genesis = Ok(genesis("0xabc"));
        assert_eq!(
            classify_identity(&Ok(spec), &genesis, &expected()),
            IdentityClass::Mismatch(IdentityField::SlotsPerEpoch)
        );
    }

    #[test]
    fn unparsable_genesis_time_does_not_hide_a_root_mismatch() {
        let mut wrong = genesis("0xdef");
        wrong.data.genesis_time = "not_a_number".to_string();
        assert_eq!(
            classify_identity(&Ok(spec_ok()), &Ok(wrong), &expected()),
            IdentityClass::Mismatch(IdentityField::GenesisValidatorsRoot)
        );
    }

    #[test]
    fn identity_field_names_the_field() {
        assert_eq!(IdentityField::ForkSchedule.to_string(), "fork schedule");
        assert_eq!(IdentityField::SlotDuration.to_string(), "slot duration");
        assert_eq!(IdentityField::GenesisValidatorsRoot.to_string(), "genesis_validators_root");
    }

    #[test]
    fn missing_required_fork_key_stays_transient() {
        let mut spec = spec_ok();
        spec.data.remove("ALTAIR_FORK_EPOCH");
        let genesis = Ok(genesis("0xabc"));
        assert_eq!(classify_identity(&Ok(spec), &genesis, &expected()), IdentityClass::Transient);
    }

    #[test]
    fn absent_future_fork_key_disagrees_with_a_scheduled_local_fork() {
        let mut spec = spec_ok();
        spec.data.remove("GLOAS_FORK_EPOCH");
        spec.data.remove("GLOAS_FORK_VERSION");
        let genesis = Ok(genesis("0xabc"));
        let mut scheduled = expected();
        scheduled.fork_schedule.gloas_fork_epoch = 500_000;
        assert_eq!(
            classify_identity(&Ok(spec), &genesis, &scheduled),
            IdentityClass::Mismatch(IdentityField::ForkSchedule)
        );
    }

    #[test]
    fn matching_genesis_plus_spec_error_stays_transient() {
        let spec = Err(unavailable());
        let genesis = Ok(genesis("0xabc"));
        assert_eq!(classify_identity(&spec, &genesis, &expected()), IdentityClass::Transient);
    }
}
