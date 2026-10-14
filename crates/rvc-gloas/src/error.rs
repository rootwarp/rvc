//! Public Gloas root-API errors.

use thiserror::Error;

/// Decode or `active_fields` failure. Never a zero, guessed, or fallback root.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GloasError {
    #[error("invalid SSZ: {reason}")]
    InvalidBody { reason: String },
    #[error("active_fields width: expected {expected}, actual {actual}")]
    ActiveFieldsWidth { expected: usize, actual: usize },
}
