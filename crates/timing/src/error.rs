//! Timing service error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimingError {
    #[error("current time {current_time} is before genesis time {genesis_time}")]
    BeforeGenesis { current_time: u64, genesis_time: u64 },

    #[error("slot duration must be at least 1 second")]
    InvalidSlotDuration,

    /// Slot or genesis time conversion to milliseconds overflowed.
    ///
    /// Callers that gate safety-critical work (e.g. interchange import) must
    /// treat this as fail-closed: refuse the operation.
    #[error("slot timing arithmetic overflowed")]
    TimeOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_before_genesis_display() {
        let err = TimingError::BeforeGenesis { current_time: 100, genesis_time: 200 };
        assert_eq!(err.to_string(), "current time 100 is before genesis time 200");
    }

    #[test]
    fn test_invalid_slot_duration_display() {
        let err = TimingError::InvalidSlotDuration;
        assert_eq!(err.to_string(), "slot duration must be at least 1 second");
    }

    #[test]
    fn test_time_overflow_display() {
        let err = TimingError::TimeOverflow;
        assert_eq!(err.to_string(), "slot timing arithmetic overflowed");
    }
}
