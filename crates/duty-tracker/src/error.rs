use thiserror::Error;

use bn_manager::BeaconError;

#[derive(Error, Debug)]
pub enum DutyTrackerError {
    #[error("Beacon client error: {0}")]
    BeaconError(#[from] BeaconError),

    #[error("No duties found for slot {slot}, committee index {committee_index}, validator index {validator_index}")]
    DutyNotFound { slot: u64, committee_index: u64, validator_index: u64 },

    #[error("Invalid epoch: {0}")]
    InvalidEpoch(u64),

    /// The revocation generation moved while the request was in flight.
    ///
    /// The answering node may have been revoked during the fetch, so the
    /// answer is neither cached nor returned.
    #[error("Duties for epoch {epoch} were discarded: a beacon node was revoked during the fetch")]
    RevokedDuringFetch { epoch: u64 },
}
