//! Concurrent duty-dispatch limits (RR2-02), one attestation wave (RR2-03),
//! the sync-message publish budget (RR2-04), aggregation waves (RR2-05), and
//! payload-attestation waves (issue #608).
//!
//! `StreamExt::ready_chunks(0)` panics, so [`DispatchLimits::validated`] rejects
//! a zero in either field. [`crate::config::Config::validate`] repeats that
//! check and also enforces the operator ranges (`1..=512` / `1..=16`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use beacon::VersionedAttestation;
use eth_types::Slot;
use thiserror::Error;

/// How far past `slot_end` (the start of slot S+1) a duty publish may run.
///
/// Shared by attestation submit, sync-message submit, and aggregate submit.
/// A fresh operation timeout (default 2 s) is not this bound: a wave admitted
/// near slot end must still stop by this instant.
pub(crate) const SLOT_END_PUBLISH_OVERHANG: Duration = Duration::from_millis(500);

/// In-flight sign requests and publish waves for one attestation slot,
/// one sync-message slot, one aggregation slot, and one payload-attestation slot.
///
/// Phase 2 shares one extra cap. [`Phase2SignerPermits`] is sized to
/// `concurrency` and is acquired once per selection proof and once per
/// `*_and_proof` signature. Aggregation and sync contributions together stay
/// at that size. The 1/3 phase (attestations and sync messages) does not take
/// those permits: each of those pipelines still signs up to `concurrency`
/// requests at once, on its own `buffer_unordered`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchLimits {
    /// Sign requests issued together (`buffer_unordered` / `ready_chunks`).
    ///
    /// At phase 2 this is also the shared signer-call cap. See the struct docs.
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

/// One phase-2 permit for a single signer call.
///
/// The permit is held only while that call runs. Fetches do not take one.
/// `None` means the wait was cancelled or the deadline passed, and the caller
/// must not sign.
pub(crate) struct Phase2SignerPermits {
    inner: std::sync::Arc<tokio::sync::Semaphore>,
}

impl Phase2SignerPermits {
    /// `permits` is [`DispatchLimits::concurrency`].
    pub(crate) fn new(permits: usize) -> Self {
        Self { inner: std::sync::Arc::new(tokio::sync::Semaphore::new(permits.max(1))) }
    }

    /// Wait until `deadline` for one permit.
    ///
    /// Dropping this future cancels the wait. A deadline that has already
    /// passed does not wait. Either case returns `None` and the caller does
    /// not sign.
    pub(crate) async fn acquire_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        match tokio::time::timeout_at(deadline, std::sync::Arc::clone(&self.inner).acquire_owned())
            .await
        {
            // `timeout_at` polls the acquire first. A permit that becomes free
            // in the same poll as the deadline is dropped here.
            Ok(Ok(permit)) if tokio::time::Instant::now() < deadline => Some(permit),
            Ok(Ok(permit)) => {
                drop(permit);
                None
            }
            Ok(Err(_)) | Err(_) => None,
        }
    }
}

/// Why a phase-2 sign did not return a signature.
pub(crate) enum Phase2SignError<E> {
    /// The permit wait was cancelled or the deadline passed. Nothing was signed.
    Cancelled,
    /// Beacon-node admission did not hold at the sign.
    Revoked,
    /// The signer returned an error. The call was inside the admission scope.
    Failed(E),
}

/// Acquire one phase-2 permit, then poll `sign`.
///
/// The caller installs the admission scope on `sign` (the architecture scan
/// requires that marker in the same block as the signer call). This function
/// does not wrap `sign` a second time. The permit is dropped when this future
/// completes, including on cancel. `sign` is not polled until a permit is
/// held, the deadline is still ahead, and the fence still holds.
pub(crate) async fn sign_with_phase2_permit<T, E, Fut>(
    permits: &Phase2SignerPermits,
    deadline: tokio::time::Instant,
    fence: &beacon::DutyFence,
    sign: Fut,
) -> Result<T, Phase2SignError<E>>
where
    Fut: std::future::Future<Output = Result<T, E>>,
{
    if !fence.holds() {
        return Err(Phase2SignError::Revoked);
    }
    let _permit = match permits.acquire_until(deadline).await {
        Some(permit) => permit,
        None => return Err(Phase2SignError::Cancelled),
    };
    if tokio::time::Instant::now() >= deadline {
        return Err(Phase2SignError::Cancelled);
    }
    if !fence.holds() {
        return Err(Phase2SignError::Revoked);
    }
    match sign.await {
        Ok(value) => Ok(value),
        Err(error) => Err(Phase2SignError::Failed(error)),
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

/// Identity of one signed attestation inside a publish wave.
///
/// `IndexedAttestationError.index` is the position of this entry in the
/// merged array POST, not a beacon validator index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveAttribution {
    /// Beacon validator index carried on the duty (decimal string).
    pub validator_index: String,
    /// Duty pubkey (`0x` hex) for the per-index failure log.
    pub pubkey: String,
    /// Duty slot copied onto the attestation result.
    pub slot: Slot,
}

/// One signed attestation waiting for its wave's array POST.
#[derive(Debug, Clone)]
pub struct WaveEntry {
    /// Join key for a beacon partial-failure index.
    pub attribution: WaveAttribution,
    /// A single-item [`VersionedAttestation`]. A wave must be one variant.
    pub attestation: VersionedAttestation,
}

/// Duties not pulled onto the sign pipeline before slot end.
///
/// Cumulative for the life of the attestation service. One slot records only
/// the duties that `take_until(slot_end)` did not yield.
#[derive(Debug, Default)]
pub struct SlotEndDropCounter {
    dropped: AtomicU64,
}

impl SlotEndDropCounter {
    /// Add `n` duties dropped because slot end arrived first.
    pub fn record(&self, n: u64) {
        if n > 0 {
            self.dropped.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Duties recorded so far.
    pub fn get(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

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

    /// The permit becomes free in the same poll that the deadline is due.
    /// `timeout_at` polls the acquire first, so the permit must be dropped.
    #[tokio::test(start_paused = true)]
    async fn permit_granted_at_the_deadline_is_not_kept() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let permits = Phase2SignerPermits::new(1);
        let held = permits
            .acquire_until(tokio::time::Instant::now() + Duration::from_secs(30))
            .await
            .expect("the test holds the only permit");
        let deadline = tokio::time::Instant::now() + Duration::from_millis(40);
        let polled = Arc::new(AtomicUsize::new(0));
        let polls = Arc::clone(&polled);
        let fence = beacon::DutyFence::open();
        let sign = async move {
            polls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        };
        let run = sign_with_phase2_permit(&permits, deadline, &fence, sign);
        tokio::pin!(run);
        tokio::select! {
            biased;
            _ = &mut run => panic!("signed while the only permit is held"),
            _ = tokio::task::yield_now() => {}
        }
        drop(held);
        tokio::time::advance(Duration::from_millis(40)).await;
        let result = (&mut run).await;
        assert!(
            matches!(result, Err(Phase2SignError::Cancelled)),
            "a permit taken at the deadline must not sign"
        );
        assert_eq!(polled.load(Ordering::SeqCst), 0, "the signer must not be polled");
    }

    /// Dropping the sign future while it waits for a permit does not sign.
    #[tokio::test(start_paused = true)]
    async fn dropping_a_waiting_phase2_sign_does_not_sign() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let permits = Phase2SignerPermits::new(1);
        let held = permits
            .acquire_until(tokio::time::Instant::now() + Duration::from_secs(30))
            .await
            .expect("the test holds the only permit");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let polled = Arc::new(AtomicUsize::new(0));
        let polls = Arc::clone(&polled);
        let fence = beacon::DutyFence::open();
        {
            let sign = async move {
                polls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(())
            };
            let run = sign_with_phase2_permit(&permits, deadline, &fence, sign);
            tokio::pin!(run);
            tokio::select! {
                biased;
                _ = &mut run => panic!("signed while the only permit is held"),
                _ = tokio::task::yield_now() => {}
            }
        }
        drop(held);
        tokio::task::yield_now().await;
        assert_eq!(
            polled.load(Ordering::SeqCst),
            0,
            "dropping a permit wait must not poll the signer"
        );
    }

    /// Revocation lands after the pre-acquire check and before the permit is granted.
    #[tokio::test(start_paused = true)]
    async fn revoking_admission_during_the_permit_wait_refuses_the_sign() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::sync::Arc;

        let permits = Phase2SignerPermits::new(1);
        let held = permits
            .acquire_until(tokio::time::Instant::now() + Duration::from_secs(30))
            .await
            .expect("the test holds the only permit");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let polled = Arc::new(AtomicUsize::new(0));
        let polls = Arc::clone(&polled);
        let generation = Arc::new(AtomicU64::new(0));
        let fence = beacon::DutyFence::at(0, Arc::clone(&generation));
        let sign = async move {
            polls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        };
        let run = sign_with_phase2_permit(&permits, deadline, &fence, sign);
        tokio::pin!(run);
        tokio::select! {
            biased;
            _ = &mut run => panic!("signed while the only permit is held"),
            _ = tokio::task::yield_now() => {}
        }
        generation.store(1, Ordering::Release);
        drop(held);
        let result = (&mut run).await;
        assert!(
            matches!(result, Err(Phase2SignError::Revoked)),
            "a revocation during the permit wait must refuse the sign"
        );
        assert_eq!(polled.load(Ordering::SeqCst), 0, "the signer must not be polled");
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
