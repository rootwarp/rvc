//! Typed duties parsed at the cache boundary.
//!
//! The five attester numeric fields, and the proposer / PTC slot and validator
//! index, are parsed once here. A malformed field is a per-duty
//! [`DutyParseError`]. `raw` keeps the beacon wire DTO (`beacon::AttesterDuty`
//! and its proposer / PTC siblings, re-exported by `bn-manager`) so a consumer
//! can still take `&AttesterDuty` without a new `duty-tracker` → `beacon` edge.

use bn_manager::{AttesterDuty, ProposerDuty, PtcDuty};
use eth_types::Slot;
use thiserror::Error;

/// Beacon field name: `slot`.
pub const FIELD_SLOT: &str = "slot";
/// Beacon field name: `committee_index`.
pub const FIELD_COMMITTEE_INDEX: &str = "committee_index";
/// Beacon field name: `validator_index`.
pub const FIELD_VALIDATOR_INDEX: &str = "validator_index";
/// Beacon field name: `committee_length`.
pub const FIELD_COMMITTEE_LENGTH: &str = "committee_length";
/// Beacon field name: `validator_committee_index`.
pub const FIELD_VALIDATOR_COMMITTEE_INDEX: &str = "validator_committee_index";

/// One duty field that did not parse as a `u64`.
///
/// The cache drops that duty and keeps the rest of the epoch.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("malformed duty field {field} ({raw})")]
pub struct DutyParseError {
    /// Wire field that failed (`slot`, `committee_length`, ...).
    pub field: &'static str,
    /// Unparsed text of [`Self::field`].
    pub raw: String,
    /// Parsed validator index when that field itself parsed.
    ///
    /// `None` when `field` is `validator_index`, or when the index text is
    /// also not a `u64`.
    pub validator_index: Option<u64>,
}

/// Attester duty with numeric fields parsed at the cache.
///
/// `committees_at_slot` stays the wire string: it is not one of the five
/// numeric fields, and committee subscriptions still send it as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedAttesterDuty {
    pub pubkey: String,
    pub slot: Slot,
    pub committee_index: u64,
    pub validator_index: u64,
    pub committee_length: u64,
    pub validator_committee_index: u64,
    pub committees_at_slot: String,
    /// Beacon wire body. Downstream code that still takes `&AttesterDuty`
    /// uses this until it switches to the typed fields.
    pub raw: AttesterDuty,
}

/// Proposer duty with `slot` and `validator_index` parsed at the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedProposerDuty {
    pub pubkey: String,
    pub slot: Slot,
    pub validator_index: u64,
    /// Beacon wire body.
    pub raw: ProposerDuty,
}

/// PTC duty with `slot` and `validator_index` parsed at the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedPtcDuty {
    pub pubkey: String,
    pub slot: Slot,
    pub validator_index: u64,
    /// Beacon wire body.
    pub raw: PtcDuty,
}

impl TryFrom<&AttesterDuty> for TypedAttesterDuty {
    type Error = DutyParseError;

    fn try_from(duty: &AttesterDuty) -> Result<Self, Self::Error> {
        let hint = parse_index_hint(&duty.validator_index);
        let slot = parse_u64(FIELD_SLOT, &duty.slot, hint)?;
        let committee_index = parse_u64(FIELD_COMMITTEE_INDEX, &duty.committee_index, hint)?;
        let validator_index = parse_u64(FIELD_VALIDATOR_INDEX, &duty.validator_index, None)?;
        let committee_length =
            parse_u64(FIELD_COMMITTEE_LENGTH, &duty.committee_length, Some(validator_index))?;
        let validator_committee_index = parse_u64(
            FIELD_VALIDATOR_COMMITTEE_INDEX,
            &duty.validator_committee_index,
            Some(validator_index),
        )?;
        Ok(Self {
            pubkey: duty.pubkey.clone(),
            slot,
            committee_index,
            validator_index,
            committee_length,
            validator_committee_index,
            committees_at_slot: duty.committees_at_slot.clone(),
            raw: duty.clone(),
        })
    }
}

impl TryFrom<&ProposerDuty> for TypedProposerDuty {
    type Error = DutyParseError;

    fn try_from(duty: &ProposerDuty) -> Result<Self, Self::Error> {
        let (slot, validator_index) = parse_slot_and_index(&duty.slot, &duty.validator_index)?;
        Ok(Self { pubkey: duty.pubkey.clone(), slot, validator_index, raw: duty.clone() })
    }
}

impl TryFrom<&PtcDuty> for TypedPtcDuty {
    type Error = DutyParseError;

    fn try_from(duty: &PtcDuty) -> Result<Self, Self::Error> {
        let (slot, validator_index) = parse_slot_and_index(&duty.slot, &duty.validator_index)?;
        Ok(Self { pubkey: duty.pubkey.clone(), slot, validator_index, raw: duty.clone() })
    }
}

fn parse_slot_and_index(slot_raw: &str, index_raw: &str) -> Result<(Slot, u64), DutyParseError> {
    let hint = parse_index_hint(index_raw);
    let slot = parse_u64(FIELD_SLOT, slot_raw, hint)?;
    let validator_index = parse_u64(FIELD_VALIDATOR_INDEX, index_raw, None)?;
    Ok((slot, validator_index))
}

fn parse_index_hint(raw: &str) -> Option<u64> {
    raw.parse().ok()
}

fn parse_u64(
    field: &'static str,
    raw: &str,
    validator_index: Option<u64>,
) -> Result<u64, DutyParseError> {
    raw.parse().map_err(|_| DutyParseError { field, raw: raw.to_owned(), validator_index })
}
