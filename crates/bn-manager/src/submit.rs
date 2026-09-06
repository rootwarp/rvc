//! Attestation submission (propagator) helpers for the beacon node pool.
//!
//! Folded from the former `rvc-propagator` crate: metrics/logging around
//! [`AttestationApi::submit_attestation`] for plain attestations. Aggregate
//! proofs and sync messages still call the manager APIs directly.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error;
use tracing::{debug, error, info, warn};

use beacon::{BeaconError, SubmitAttestationResult, VersionedAttestation};
use metrics::definitions::attestation_status;

use crate::metrics::RVC_ATTESTATIONS_TOTAL;

use crate::traits::{AttestationApi, BeaconNodeClient};

/// Errors that can occur during attestation propagation.
#[derive(Error, Debug)]
pub enum PropagatorError {
    #[error("Beacon client error: {0}")]
    BeaconError(#[from] BeaconError),

    #[error("Partial attestation failure: {success_count} succeeded, {failure_count} failed")]
    PartialFailure { success_count: usize, failure_count: usize },

    #[error("All attestations failed submission")]
    AllAttestationsFailed,
}

/// Trait for attestation submission, enabling dependency injection for testing.
pub trait AttestationSubmitter: Send + Sync {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a VersionedAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>;
}

impl<T: BeaconNodeClient + ?Sized> AttestationSubmitter for T {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a VersionedAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
    {
        Box::pin(async move { AttestationApi::submit_attestation(self, attestations).await })
    }
}

/// Result of a propagation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagationResult {
    pub total: usize,
    pub success_count: usize,
    pub failure_count: usize,
}

impl PropagationResult {
    pub fn is_success(&self) -> bool {
        self.failure_count == 0 && self.total > 0
    }

    pub fn is_partial_success(&self) -> bool {
        self.success_count > 0 && self.failure_count > 0
    }

    pub fn is_complete_failure(&self) -> bool {
        self.total > 0 && self.success_count == 0
    }
}

/// Slot and target epoch for log context (committee index is unused by callers).
fn extract_attestation_context(attestations: &VersionedAttestation) -> (String, String) {
    match attestations {
        VersionedAttestation::PreElectra(atts) => match atts.first() {
            Some(a) => (a.data.slot.clone(), a.data.target.epoch.clone()),
            None => ("unknown".into(), "unknown".into()),
        },
        VersionedAttestation::Electra(atts)
        | VersionedAttestation::Fulu(atts)
        | VersionedAttestation::Gloas(atts) => match atts.first() {
            Some(a) => (a.data.slot.clone(), a.data.target.epoch.clone()),
            None => ("unknown".into(), "unknown".into()),
        },
    }
}

/// Service responsible for propagating attestations to the beacon node.
pub struct Propagator<S: AttestationSubmitter> {
    submitter: Arc<S>,
}

impl<S: AttestationSubmitter> Propagator<S> {
    pub fn new(submitter: Arc<S>) -> Self {
        Self { submitter }
    }

    /// Propagates attestations to the beacon node.
    #[tracing::instrument(name = "propagator.propagate", skip_all, fields(count = tracing::field::Empty))]
    pub async fn propagate(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<PropagationResult, PropagatorError> {
        let total = match attestations {
            VersionedAttestation::PreElectra(a) => a.len(),
            VersionedAttestation::Electra(a)
            | VersionedAttestation::Fulu(a)
            | VersionedAttestation::Gloas(a) => a.len(),
        };

        // Late-bind the count onto the span. Uses raw record() (not
        // observability::logging::record_debug); the key "count" matches the
        // field::Empty declared on the #[instrument] above so the record lands.
        tracing::Span::current().record("count", total);

        let (batch_slot, batch_target_epoch) = extract_attestation_context(attestations);

        if total == 0 {
            debug!("No attestations to propagate");
            return Ok(PropagationResult { total: 0, success_count: 0, failure_count: 0 });
        }

        debug!(count = total, slot = %batch_slot, "Propagating attestations to beacon node");

        let result = self.submitter.submit_attestation(attestations).await?;

        match result {
            SubmitAttestationResult::Success => {
                info!(
                    slot = %batch_slot,
                    count = total,
                    target_epoch = %batch_target_epoch,
                    "Attestation submission successful"
                );
                RVC_ATTESTATIONS_TOTAL
                    .with_label_values(&[attestation_status::SUCCESS])
                    .inc_by(total as u64);

                Ok(PropagationResult { total, success_count: total, failure_count: 0 })
            }
            SubmitAttestationResult::PartialFailure { failures } => {
                let failure_count = failures.len();
                let success_count = total.saturating_sub(failure_count);

                if failure_count == 0 {
                    info!(
                        slot = %batch_slot,
                        count = total,
                        target_epoch = %batch_target_epoch,
                        "Attestation submission successful"
                    );
                    RVC_ATTESTATIONS_TOTAL
                        .with_label_values(&[attestation_status::SUCCESS])
                        .inc_by(total as u64);
                    return Ok(PropagationResult { total, success_count: total, failure_count: 0 });
                }

                for failure in &failures {
                    debug!(
                        index = failure.index,
                        message = %failure.message,
                        slot = %batch_slot,
                        "Individual attestation submission failed"
                    );
                }

                RVC_ATTESTATIONS_TOTAL
                    .with_label_values(&[attestation_status::SUCCESS])
                    .inc_by(success_count as u64);
                RVC_ATTESTATIONS_TOTAL
                    .with_label_values(&[attestation_status::FAILED])
                    .inc_by(failure_count as u64);

                if success_count == 0 {
                    error!(
                        slot = %batch_slot,
                        failure_count,
                        target_epoch = %batch_target_epoch,
                        "Attestation submission complete failure"
                    );
                    Err(PropagatorError::AllAttestationsFailed)
                } else {
                    warn!(
                        slot = %batch_slot,
                        success_count,
                        failure_count,
                        target_epoch = %batch_target_epoch,
                        "Attestation submission partial failure"
                    );
                    Err(PropagatorError::PartialFailure { success_count, failure_count })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use beacon::{AttestationData, Checkpoint, IndexedAttestationError, LegacyAttestation};

    /// The `propagator.propagate` span declares `count = field::Empty` and the run late-binds
    /// it via a raw `Span::record("count", ..)`. This proves the record lands — the key MUST
    /// match the declared field name.
    #[test]
    fn propagate_span_late_binds_count() {
        use std::sync::{Arc, Mutex};

        use tracing::field::{Field, Visit};
        use tracing::span::Record;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        #[derive(Clone, Default)]
        struct Cap(Arc<Mutex<Vec<String>>>);
        struct V<'a>(&'a mut Vec<String>);
        impl Visit for V<'_> {
            fn record_debug(&mut self, f: &Field, _v: &dyn std::fmt::Debug) {
                self.0.push(f.name().to_string());
            }
        }
        impl<S> Layer<S> for Cap
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_record(&self, _id: &tracing::Id, values: &Record<'_>, _ctx: Context<'_, S>) {
                if let Ok(mut keys) = self.0.lock() {
                    values.record(&mut V(&mut keys));
                }
            }
        }

        let cap = Cap::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("propagator.propagate", count = tracing::field::Empty);
            let _e = span.enter();
            tracing::Span::current().record("count", 5usize);
        });

        let recorded = cap.0.lock().unwrap();
        assert!(
            recorded.iter().any(|k| k == "count"),
            "late-bound count did not land on the propagate span: {recorded:?}"
        );
    }

    struct MockSubmitter {
        result: tokio::sync::Mutex<SubmitAttestationResult>,
        call_count: AtomicUsize,
        should_error: tokio::sync::Mutex<Option<BeaconError>>,
        last_submitted: tokio::sync::Mutex<Option<VersionedAttestation>>,
    }

    impl MockSubmitter {
        fn new(result: SubmitAttestationResult) -> Self {
            Self {
                result: tokio::sync::Mutex::new(result),
                call_count: AtomicUsize::new(0),
                should_error: tokio::sync::Mutex::new(None),
                last_submitted: tokio::sync::Mutex::new(None),
            }
        }

        fn with_error(error: BeaconError) -> Self {
            Self {
                result: tokio::sync::Mutex::new(SubmitAttestationResult::Success),
                call_count: AtomicUsize::new(0),
                should_error: tokio::sync::Mutex::new(Some(error)),
                last_submitted: tokio::sync::Mutex::new(None),
            }
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }

        async fn last_submitted(&self) -> Option<VersionedAttestation> {
            self.last_submitted.lock().await.clone()
        }
    }

    impl AttestationSubmitter for MockSubmitter {
        fn submit_attestation<'a>(
            &'a self,
            attestations: &'a VersionedAttestation,
        ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                *self.last_submitted.lock().await = Some(attestations.clone());

                let maybe_error = self.should_error.lock().await;
                if let Some(ref error) = *maybe_error {
                    return Err(match error {
                        BeaconError::Timeout => BeaconError::Timeout,
                        BeaconError::HttpError(msg) => BeaconError::HttpError(msg.clone()),
                        BeaconError::ApiError { status, message } => {
                            BeaconError::ApiError { status: *status, message: message.clone() }
                        }
                        BeaconError::ParseError(msg) => BeaconError::ParseError(msg.clone()),
                        BeaconError::InvalidUrl(msg) => BeaconError::InvalidUrl(msg.clone()),
                        other => panic!("Unexpected error variant in test mock: {:?}", other),
                    });
                }

                let result = self.result.lock().await;
                Ok(result.clone())
            })
        }
    }

    fn create_test_legacy_attestation(slot: &str, index: &str) -> LegacyAttestation {
        LegacyAttestation {
            aggregation_bits: "0x01".to_string(),
            data: AttestationData {
                slot: slot.to_string(),
                index: index.to_string(),
                beacon_block_root:
                    "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                source: Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                },
                target: Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                },
            },
            signature: "0xsignature".to_string(),
        }
    }

    #[tokio::test]
    async fn test_propagator_new() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let _propagator = Propagator::new(submitter);
    }

    #[tokio::test]
    async fn test_propagate_single_success() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::PreElectra(vec![create_test_legacy_attestation("1000", "1")]);
        let result = propagator.propagate(&attestations).await;

        assert!(result.is_ok());
        assert_eq!(submitter.call_count(), 1);
    }

    #[tokio::test]
    async fn test_propagate_batch_success() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations = VersionedAttestation::PreElectra(vec![
            create_test_legacy_attestation("1000", "1"),
            create_test_legacy_attestation("1000", "2"),
        ]);

        let result = propagator.propagate(&attestations).await.unwrap();

        assert!(result.is_success());
        assert_eq!(result.total, 2);
        assert_eq!(result.success_count, 2);
        assert_eq!(result.failure_count, 0);
        assert_eq!(submitter.call_count(), 1);
    }

    #[tokio::test]
    async fn test_propagate_empty() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations = VersionedAttestation::PreElectra(vec![]);
        let result = propagator.propagate(&attestations).await.unwrap();

        assert_eq!(result.total, 0);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 0);
        assert!(!result.is_success());
        assert_eq!(submitter.call_count(), 0);
    }

    #[tokio::test]
    async fn test_propagate_partial_failure() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::PartialFailure {
            failures: vec![IndexedAttestationError {
                index: 1,
                message: "Invalid signature".to_string(),
            }],
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestations = VersionedAttestation::PreElectra(vec![
            create_test_legacy_attestation("1000", "1"),
            create_test_legacy_attestation("1000", "2"),
            create_test_legacy_attestation("1000", "3"),
        ]);

        let result = propagator.propagate(&attestations).await;

        match result {
            Err(PropagatorError::PartialFailure { success_count, failure_count }) => {
                assert_eq!(success_count, 2);
                assert_eq!(failure_count, 1);
            }
            _ => panic!("Expected PartialFailure error"),
        }
    }

    #[tokio::test]
    async fn test_propagate_all_failed() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::PartialFailure {
            failures: vec![
                IndexedAttestationError { index: 0, message: "Invalid signature".to_string() },
                IndexedAttestationError { index: 1, message: "Attestation too old".to_string() },
            ],
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestations = VersionedAttestation::PreElectra(vec![
            create_test_legacy_attestation("1000", "1"),
            create_test_legacy_attestation("1000", "2"),
        ]);

        let result = propagator.propagate(&attestations).await;

        assert!(matches!(result, Err(PropagatorError::AllAttestationsFailed)));
    }

    #[tokio::test]
    async fn test_propagate_beacon_error() {
        let submitter = Arc::new(MockSubmitter::with_error(BeaconError::Timeout));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::PreElectra(vec![create_test_legacy_attestation("1000", "1")]);
        let result = propagator.propagate(&attestations).await;

        assert!(matches!(result, Err(PropagatorError::BeaconError(_))));
    }

    #[tokio::test]
    async fn test_propagate_http_error() {
        let submitter = Arc::new(MockSubmitter::with_error(BeaconError::HttpError(
            "connection refused".to_string(),
        )));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::PreElectra(vec![create_test_legacy_attestation("1000", "1")]);
        let result = propagator.propagate(&attestations).await;

        match result {
            Err(PropagatorError::BeaconError(BeaconError::HttpError(msg))) => {
                assert_eq!(msg, "connection refused");
            }
            _ => panic!("Expected HttpError"),
        }
    }

    #[tokio::test]
    async fn test_propagate_api_error() {
        let submitter = Arc::new(MockSubmitter::with_error(BeaconError::ApiError {
            status: 503,
            message: "Service unavailable".to_string(),
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::PreElectra(vec![create_test_legacy_attestation("1000", "1")]);
        let result = propagator.propagate(&attestations).await;

        match result {
            Err(PropagatorError::BeaconError(BeaconError::ApiError { status, message })) => {
                assert_eq!(status, 503);
                assert_eq!(message, "Service unavailable");
            }
            _ => panic!("Expected ApiError"),
        }
    }

    #[tokio::test]
    async fn test_propagation_result_is_success() {
        let result = PropagationResult { total: 5, success_count: 5, failure_count: 0 };
        assert!(result.is_success());
        assert!(!result.is_partial_success());
        assert!(!result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagation_result_is_partial_success() {
        let result = PropagationResult { total: 5, success_count: 3, failure_count: 2 };
        assert!(!result.is_success());
        assert!(result.is_partial_success());
        assert!(!result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagation_result_is_complete_failure() {
        let result = PropagationResult { total: 5, success_count: 0, failure_count: 5 };
        assert!(!result.is_success());
        assert!(!result.is_partial_success());
        assert!(result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagation_result_empty() {
        let result = PropagationResult { total: 0, success_count: 0, failure_count: 0 };
        assert!(!result.is_success());
        assert!(!result.is_partial_success());
        assert!(!result.is_complete_failure());
    }

    #[tokio::test]
    async fn test_propagate_partial_failure_with_empty_failures() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::PartialFailure {
            failures: vec![],
        }));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::PreElectra(vec![create_test_legacy_attestation("1000", "1")]);
        let result = propagator.propagate(&attestations).await.unwrap();

        assert!(result.is_success());
        assert_eq!(result.total, 1);
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 0);
    }

    #[tokio::test]
    async fn test_propagate_uses_submitter_correctly() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        assert_eq!(submitter.call_count(), 0);

        let attestations =
            VersionedAttestation::PreElectra(vec![create_test_legacy_attestation("1000", "1")]);
        propagator.propagate(&attestations).await.unwrap();

        assert_eq!(submitter.call_count(), 1);

        let attestations =
            VersionedAttestation::PreElectra(vec![create_test_legacy_attestation("1001", "2")]);
        propagator.propagate(&attestations).await.unwrap();

        assert_eq!(submitter.call_count(), 2);
    }

    fn create_test_single_attestation(
        slot: &str,
        committee_index: u64,
        attester_index: u64,
    ) -> beacon::SingleAttestation {
        beacon::SingleAttestation {
            committee_index,
            attester_index,
            data: AttestationData {
                slot: slot.to_string(),
                index: "0".to_string(),
                beacon_block_root:
                    "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                source: Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                },
                target: Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                },
            },
            signature: "0xsignature".to_string(),
        }
    }

    #[tokio::test]
    async fn test_propagate_electra_variant() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::Electra(vec![create_test_single_attestation("1000", 0, 42)]);

        let result = propagator.propagate(&attestations).await.unwrap();

        assert!(result.is_success());
        assert_eq!(result.total, 1);
        assert_eq!(result.success_count, 1);
        assert_eq!(submitter.call_count(), 1);

        // Field-level assertions: verify propagated data is not corrupted
        let submitted = submitter.last_submitted().await.expect("attestation was submitted");
        match submitted {
            VersionedAttestation::Electra(atts) => {
                assert_eq!(atts.len(), 1);
                let att = &atts[0];
                assert_eq!(att.committee_index, 0);
                assert_eq!(att.attester_index, 42);
                assert_eq!(att.data.slot, "1000");
                assert_eq!(att.data.index, "0");
                assert_eq!(
                    att.data.beacon_block_root,
                    "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                );
                assert_eq!(att.data.source.epoch, "100");
                assert_eq!(att.data.target.epoch, "101");
                assert_eq!(att.signature, "0xsignature");
            }
            other => panic!("Expected Electra variant, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_propagate_fulu_variant() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::Fulu(vec![create_test_single_attestation("2000000", 3, 99)]);

        let result = propagator.propagate(&attestations).await.unwrap();

        assert!(result.is_success());
        assert_eq!(result.total, 1);
        assert_eq!(result.success_count, 1);
        assert_eq!(submitter.call_count(), 1);

        // Field-level assertions: verify Fulu attestation data integrity
        let submitted = submitter.last_submitted().await.expect("attestation was submitted");
        match submitted {
            VersionedAttestation::Fulu(atts) => {
                assert_eq!(atts.len(), 1);
                let att = &atts[0];
                assert_eq!(att.committee_index, 3);
                assert_eq!(att.attester_index, 99);
                assert_eq!(att.data.slot, "2000000");
                assert_eq!(att.data.index, "0");
                assert_eq!(att.data.source.epoch, "100");
                assert_eq!(att.data.target.epoch, "101");
                assert_eq!(att.signature, "0xsignature");
            }
            other => panic!("Expected Fulu variant, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_propagate_gloas_variant() {
        let submitter = Arc::new(MockSubmitter::new(SubmitAttestationResult::Success));
        let propagator = Propagator::new(submitter.clone());

        let attestations =
            VersionedAttestation::Gloas(vec![create_test_single_attestation("2000000", 3, 99)]);

        let result = propagator.propagate(&attestations).await.unwrap();

        assert!(result.is_success());
        assert_eq!(result.total, 1);
        assert_eq!(result.success_count, 1);
        assert_eq!(submitter.call_count(), 1);

        let submitted = submitter.last_submitted().await.expect("attestation was submitted");
        match submitted {
            VersionedAttestation::Gloas(atts) => {
                assert_eq!(atts.len(), 1);
                let att = &atts[0];
                assert_eq!(att.committee_index, 3);
                assert_eq!(att.attester_index, 99);
                assert_eq!(att.data.slot, "2000000");
            }
            other => panic!("Expected Gloas variant, got {:?}", other),
        }
    }

    #[test]
    fn test_propagator_error_display_beacon_error() {
        let beacon_err = BeaconError::Timeout;
        let err = PropagatorError::BeaconError(beacon_err);
        assert_eq!(err.to_string(), "Beacon client error: Request timeout");
    }

    #[test]
    fn test_propagator_error_display_partial_failure() {
        let err = PropagatorError::PartialFailure { success_count: 5, failure_count: 2 };
        assert_eq!(err.to_string(), "Partial attestation failure: 5 succeeded, 2 failed");
    }

    #[test]
    fn test_propagator_error_display_all_failed() {
        let err = PropagatorError::AllAttestationsFailed;
        assert_eq!(err.to_string(), "All attestations failed submission");
    }

    #[test]
    fn test_from_beacon_error() {
        let beacon_err = BeaconError::HttpError("connection refused".to_string());
        let err: PropagatorError = beacon_err.into();
        assert!(matches!(err, PropagatorError::BeaconError(_)));
    }
}
