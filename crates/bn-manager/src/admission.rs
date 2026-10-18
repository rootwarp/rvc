//! Chain-identity classification shared with the proposer pool (FU-A6).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use beacon::{hex_ids_equal, BeaconError, ConfigSpecResponse, GenesisResponse};

/// Boot-agreed chain identity. Re-admission compares against this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainIdentity {
    pub slot_duration_ms: u64,
    pub slots_per_epoch: u64,
    pub genesis_time: u64,
    pub genesis_validators_root: String,
    pub genesis_fork_version: String,
}

/// Result of comparing one node's spec and genesis to [`ChainIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityClass {
    Match,
    Mismatch,
    /// No identity evidence. The caller keeps the current admission bit.
    Transient,
}

/// A parsed disagreement on either response is [`IdentityClass::Mismatch`].
///
/// An error or an unparsable body on one side does not hide a contradiction
/// in the response that did arrive. Both sides must parse and match before
/// the result is [`IdentityClass::Match`]. Anything else with no parsed
/// contradiction is [`IdentityClass::Transient`].
pub fn classify_identity(
    spec: &Result<ConfigSpecResponse, BeaconError>,
    genesis: &Result<GenesisResponse, BeaconError>,
    expected: &ChainIdentity,
) -> IdentityClass {
    let spec_fields = spec.as_ref().ok().and_then(|spec| {
        let duration_ms = beacon::parse_slot_duration_ms(&spec.data).ok()?;
        let slots_per_epoch = beacon::parse_slots_per_epoch(&spec.data).ok()?;
        Some((duration_ms, slots_per_epoch))
    });
    let genesis_fields = genesis.as_ref().ok().and_then(|genesis| {
        let genesis_time = genesis.data.genesis_time.parse::<u64>().ok()?;
        Some((
            genesis_time,
            genesis.data.genesis_fork_version.as_str(),
            genesis.data.genesis_validators_root.as_str(),
        ))
    });
    if let Some((duration_ms, slots_per_epoch)) = spec_fields {
        if duration_ms != expected.slot_duration_ms || slots_per_epoch != expected.slots_per_epoch {
            return IdentityClass::Mismatch;
        }
    }
    if let Some((genesis_time, fork_version, validators_root)) = genesis_fields {
        if genesis_time != expected.genesis_time
            || !hex_ids_equal(&expected.genesis_fork_version, fork_version)
            || !hex_ids_equal(&expected.genesis_validators_root, validators_root)
        {
            return IdentityClass::Mismatch;
        }
    }
    if spec_fields.is_some() && genesis_fields.is_some() {
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
    use std::collections::HashMap;

    use super::*;

    fn expected() -> ChainIdentity {
        ChainIdentity {
            slot_duration_ms: 12_000,
            slots_per_epoch: 32,
            genesis_time: 1_606_824_023,
            genesis_validators_root: "0xabc".to_string(),
            genesis_fork_version: "0x00000000".to_string(),
        }
    }

    fn spec_ok() -> ConfigSpecResponse {
        let mut data = HashMap::new();
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
            IdentityClass::Mismatch,
            "a parsed root disagreement is a mismatch even when spec is 503"
        );
    }

    #[test]
    fn spec_disagreement_plus_genesis_error_is_a_mismatch() {
        let spec = Ok(spec_wrong_duration());
        let genesis = Err(unavailable());
        assert_eq!(classify_identity(&spec, &genesis, &expected()), IdentityClass::Mismatch);
    }

    #[test]
    fn both_errors_stay_transient() {
        let spec = Err(unavailable());
        let genesis = Err(unavailable());
        assert_eq!(classify_identity(&spec, &genesis, &expected()), IdentityClass::Transient);
    }

    #[test]
    fn matching_genesis_plus_spec_error_stays_transient() {
        let spec = Err(unavailable());
        let genesis = Ok(genesis("0xabc"));
        assert_eq!(classify_identity(&spec, &genesis, &expected()), IdentityClass::Transient);
    }
}
