//! Concurrent duty-dispatch limits (RR2-02).
//!
//! `StreamExt::ready_chunks(0)` panics, so [`DispatchLimits::validated`] rejects
//! a zero in either field. [`crate::config::Config::validate`] repeats that
//! check and also enforces the operator ranges (`1..=512` / `1..=16`).

use thiserror::Error;

/// In-flight sign requests and publish waves for one attestation slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchLimits {
    /// Sign requests issued together (`buffer_unordered` / `ready_chunks`).
    pub concurrency: u32,
    /// Publish waves in flight.
    pub publish_concurrency: u32,
}

impl DispatchLimits {
    /// Default sign-request concurrency when the operator knob is unset.
    pub const DEFAULT_CONCURRENCY: u32 = 32;
    /// Default publish-wave concurrency when the operator knob is unset.
    pub const DEFAULT_PUBLISH_CONCURRENCY: u32 = 2;

    /// Reject `0` in either field.
    ///
    /// Upper bounds live on `Config::validate`. A zero here is a safety
    /// failure: `ready_chunks(0)` panics.
    pub fn validated(
        concurrency: u32,
        publish_concurrency: u32,
    ) -> Result<Self, DispatchLimitsError> {
        if concurrency < 1 {
            return Err(DispatchLimitsError::Concurrency { concurrency });
        }
        if publish_concurrency < 1 {
            return Err(DispatchLimitsError::PublishConcurrency { publish_concurrency });
        }
        Ok(Self { concurrency, publish_concurrency })
    }
}

/// `rvc-config` cannot depend on this crate. The numeric defaults are defined
/// here and repeated on the `[duties]` section; they must stay equal.
const _: () = {
    assert!(DispatchLimits::DEFAULT_CONCURRENCY == rvc_config::DEFAULT_DUTY_DISPATCH_CONCURRENCY);
    assert!(
        DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY == rvc_config::DEFAULT_DUTY_PUBLISH_CONCURRENCY
    );
};

/// Zero concurrency, which would panic inside `ready_chunks`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DispatchLimitsError {
    /// `concurrency` was `0`.
    #[error("dispatch concurrency must be >= 1, got {concurrency}")]
    Concurrency {
        /// Rejected value.
        concurrency: u32,
    },
    /// `publish_concurrency` was `0`.
    #[error("publish concurrency must be >= 1, got {publish_concurrency}")]
    PublishConcurrency {
        /// Rejected value.
        publish_concurrency: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_limits_reject_zero() {
        assert!(DispatchLimits::validated(0, 2).is_err());
        assert!(DispatchLimits::validated(32, 0).is_err());
        assert!(DispatchLimits::validated(0, 0).is_err());
    }

    #[test]
    fn dispatch_limits_defaults_are_32_and_2() {
        let limits = DispatchLimits::validated(
            DispatchLimits::DEFAULT_CONCURRENCY,
            DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY,
        )
        .expect("defaults are in range");
        assert_eq!(limits.concurrency, 32);
        assert_eq!(limits.publish_concurrency, 2);
        assert_eq!(DispatchLimits::DEFAULT_CONCURRENCY, 32);
        assert_eq!(DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY, 2);
    }
}
