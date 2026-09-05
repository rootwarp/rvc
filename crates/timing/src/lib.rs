//! Slot timing service for Ethereum consensus.
//!
//! This module provides slot timing functionality including:
//! - `SlotClock` trait for slot time calculations
//! - `SystemSlotClock` implementation using system time
//! - Basis-points constants and `due_ms` for intra-slot deadlines

mod clock;
mod error;

pub use clock::{MockSlotClock, SlotClock, SystemSlotClock};
pub use error::TimingError;

pub use eth_types::{SLOTS_PER_EPOCH, SLOT_DURATION_MS};

/// Denominator for the intra-slot basis-points timing model (report §4.3).
///
/// Intra-slot deadlines are expressed as `bps * slot_duration_ms / BASIS_POINTS`
/// (floor), so non-12 s and Gloas slot durations are exact rather than truncated
/// by an integer `/3` / `*2/3`.
pub const BASIS_POINTS: u64 = 10000;

/// Attestation broadcast deadline in basis points of the slot (report §4.3).
///
/// 3333 bps of a 12 s slot is `3333 * 12000 / 10000 = 3999 ms`, the spec 1/3
/// mark (not the legacy `12000 / 3 = 4000 ms`).
pub const ATTESTATION_DUE_BPS: u64 = 3333;

/// Aggregate (attestation) broadcast deadline in basis points (report §4.3).
///
/// 6667 bps of a 12 s slot is `6667 * 12000 / 10000 = 8000 ms`, the spec 2/3
/// mark (matching the legacy `12000 * 2 / 3 = 8000 ms`).
pub const AGGREGATE_DUE_BPS: u64 = 6667;

/// Intra-slot attestation and aggregation deadlines as basis points of the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineBps {
    pub attestation: u64,
    pub aggregate: u64,
}

impl Default for DeadlineBps {
    fn default() -> Self {
        Self { attestation: ATTESTATION_DUE_BPS, aggregate: AGGREGATE_DUE_BPS }
    }
}

/// Intra-slot deadline in milliseconds for a basis-points fraction of the slot.
///
/// Computes `bps * slot_duration_ms / BASIS_POINTS` with floor (integer)
/// division, matching the spec `//`. Multiply-before-divide so the floor matches
/// the spec exactly (report §4.3): `due_ms(3333, 12000) == 3999`, never
/// `3333 / 10000 * 12000 == 0`.
///
/// # Examples
///
/// ```
/// use rvc_timing::{due_ms, ATTESTATION_DUE_BPS, AGGREGATE_DUE_BPS};
/// assert_eq!(due_ms(ATTESTATION_DUE_BPS, 12000), 3999);
/// assert_eq!(due_ms(AGGREGATE_DUE_BPS, 12000), 8000);
/// ```
pub fn due_ms(bps: u64, slot_duration_ms: u64) -> u64 {
    bps * slot_duration_ms / BASIS_POINTS
}
