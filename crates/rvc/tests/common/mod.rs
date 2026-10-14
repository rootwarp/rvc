//! Shared integration-test helpers for `crates/rvc/tests/`.
//!
//! Each top-level `tests/*.rs` file is a separate crate; common fixtures live
//! here so RF1-02 and RF1-08 share one pipeline harness.
//!
//! `dead_code` is allowed: each integration-test binary only exercises a
//! subset of the shared knobs/handles.

#![allow(dead_code)]

pub mod import_during_duties;
pub mod pipeline_fixture;

/// Message on a [`rvc::orchestrator::AttestationOutcome::Failed`] result.
///
/// Sign, fetch, timeout, and propagate failures use that variant. A beacon-node
/// partial rejection is [`rvc::orchestrator::AttestationOutcome::RejectedByBeaconNode`]
/// and is not this message.
pub fn failed_attestation_message(result: &rvc::orchestrator::AttestationResult) -> &str {
    match &result.outcome {
        rvc::orchestrator::AttestationOutcome::Failed(message) => message,
        rvc::orchestrator::AttestationOutcome::Published => {
            panic!("expected Failed, got Published")
        }
        rvc::orchestrator::AttestationOutcome::RejectedByBeaconNode { bn, message } => {
            panic!("expected Failed, got beacon rejection bn={bn:?} message={message}")
        }
    }
}
