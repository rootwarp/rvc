//! Error types for doppelganger detection.

use thiserror::Error;

use eth_types::Epoch;

/// Errors produced by the doppelganger detection subsystem.
///
/// # `#[must_use]` contract
///
/// This type is `#[must_use]`.  Every `Result<_, DoppelgangerError>` return
/// value MUST be inspected by the caller.  Silently discarding an
/// `Err(IncompleteLiveness)` (e.g. with `let _ = observe_liveness(...)` or
/// `.ok()`) defeats the fail-closed safety guarantee: the validator would
/// remain `Pending` forever rather than being retried, or — worse — a future
/// caller might re-introduce a path that ignores the error and allows a `Safe`
/// transition despite incomplete data.  Always propagate or explicitly log and
/// retry.
#[must_use = "DoppelgangerError must be handled: IncompleteLiveness signals \
              fail-closed and MUST be retried, not suppressed"]
#[derive(Debug, Error)]
pub enum DoppelgangerError {
    /// Returned by [`crate::ForwardWindowMachine::observe_liveness`] when the
    /// beacon-node response is missing entries for one or more validators that
    /// were expected (i.e. `Pending` with a window that includes `epoch`).
    ///
    /// `epoch` is the epoch for which the check was run.
    /// `missing_count` is the number of validators absent from the response.
    ///
    /// The caller MUST treat this as a transient error and retry the liveness
    /// check for the same epoch.  Do NOT suppress this error: the absent
    /// validators will not have `epoch` recorded in their `observed_epochs`,
    /// so they cannot reach `Safe` until a complete response is received.
    #[error(
        "incomplete liveness response for epoch {epoch}: \
         {missing_count} validator(s) absent from beacon-node reply"
    )]
    IncompleteLiveness { epoch: Epoch, missing_count: usize },
}
