use std::time::Duration;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BeaconError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("Failed to parse response: {0}")]
    ParseError(String),

    #[error("Beacon node returned error: {status} - {message}")]
    ApiError { status: u16, message: String },

    #[error("Request timeout")]
    Timeout,

    #[error("{operation} timed out after {timeout:?}")]
    OperationTimeout { operation: String, timeout: Duration },

    #[error("Invalid endpoint URL: {0}")]
    InvalidUrl(String),

    /// Response body exceeds the configured cap (H-12).
    #[error(
        "response body too large: expected \u{2264} {expected} bytes, received {got_so_far} bytes"
    )]
    BodyTooLarge { expected: usize, got_so_far: usize },

    /// No BN matched the requested role and no `All`-role fallback exists.
    #[error("no beacon nodes eligible for {operation} (role {role})")]
    NoEligibleBn { operation: String, role: String },

    /// The beacon node returned a genesis validators root other than the configured one.
    #[error("genesis validators root {root} does not match configured root")]
    GenesisValidatorsRootMismatch { root: String },

    /// No beacon node is admitted, so a duty must not be sent or signed.
    #[error("no admitted beacon node; duties halted")]
    NoAdmittedNode,

    /// A response arrived after the node's admission generation changed.
    #[error("beacon node response dropped: admission revoked in flight")]
    RevokedInFlight,

    /// Produce round failed for a reason other than a transport error.
    #[error(transparent)]
    Produce(#[from] ProduceError),
}

/// A produce round that returned no block without a transport error.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProduceError {
    /// Dropped candidates, and no transport error was stored.
    ///
    /// `reasons` is `bn {index} {label}` in index order, joined by `, `.
    /// Labels: `fork`, `unreadable`, `slot`, `proposer`, `parent`, `fee`,
    /// `shape`, or `fallback_parent` (hard checks passed, primary parent missed). Fee-only is not an entry.
    #[error("{operation}: all candidates rejected: {reasons}")]
    AllCandidatesRejected { operation: String, reasons: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_error_display() {
        let err = BeaconError::HttpError("connection refused".to_string());
        assert_eq!(err.to_string(), "HTTP request failed: connection refused");
    }

    #[test]
    fn test_parse_error_display() {
        let err = BeaconError::ParseError("invalid JSON".to_string());
        assert_eq!(err.to_string(), "Failed to parse response: invalid JSON");
    }

    #[test]
    fn test_api_error_display() {
        let err = BeaconError::ApiError { status: 404, message: "Validator not found".to_string() };
        assert_eq!(err.to_string(), "Beacon node returned error: 404 - Validator not found");
    }

    #[test]
    fn test_timeout_error_display() {
        let err = BeaconError::Timeout;
        assert_eq!(err.to_string(), "Request timeout");
    }

    #[test]
    fn test_invalid_url_error_display() {
        let err = BeaconError::InvalidUrl("not a valid url".to_string());
        assert_eq!(err.to_string(), "Invalid endpoint URL: not a valid url");
    }

    #[test]
    fn test_operation_timeout_error_display() {
        let err = BeaconError::OperationTimeout {
            operation: "produce_block_v3".to_string(),
            timeout: Duration::from_secs(3),
        };
        assert_eq!(err.to_string(), "produce_block_v3 timed out after 3s");
    }

    #[test]
    fn test_no_admitted_node_error_display() {
        let err = BeaconError::NoAdmittedNode;
        assert_eq!(err.to_string(), "no admitted beacon node; duties halted");
    }

    #[test]
    fn test_revoked_in_flight_error_display() {
        let err = BeaconError::RevokedInFlight;
        assert_eq!(err.to_string(), "beacon node response dropped: admission revoked in flight");
    }

    #[test]
    fn test_all_candidates_rejected_display() {
        let err = BeaconError::from(ProduceError::AllCandidatesRejected {
            operation: "produce_block_v3".to_string(),
            reasons: "bn 0 parent, bn 1 slot".to_string(),
        });
        assert_eq!(
            err.to_string(),
            "produce_block_v3: all candidates rejected: bn 0 parent, bn 1 slot"
        );
    }

    #[test]
    fn test_no_eligible_bn_error_display() {
        let err = BeaconError::NoEligibleBn {
            operation: "submit_attestation".to_string(),
            role: "attestation".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "no beacon nodes eligible for submit_attestation (role attestation)"
        );
    }
}
