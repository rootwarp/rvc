//! Crate-internal Gloas decode errors.
//!
//! Public error / root surface lands in issue 5.10.

use thiserror::Error;

/// Decode failure for a Gloas container. Never a zero, guessed, or fallback body.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum GloasError {
    #[error("invalid SSZ block body: {reason}")]
    InvalidBody { reason: String },
}
