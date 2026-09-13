//! Signer Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use crypto::SigningError;
use eth_types::ForkName;
use metrics::{define_histogram_vec, define_int_counter_vec, HistogramVec, IntCounterVec};

pub use metrics::definitions::{attestation_status, slashing_result, tx_hold_kind};

/// Bounded `reason` (and fallback `version` / `sign_type`) labels for
/// [`RVC_SIGNER_REJECTIONS_TOTAL`]. Never a raw request string.
pub mod rejection_reason {
    pub const UNSUPPORTED_TYPE: &str = "unsupported_type";
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    /// Fallback `version` / `sign_type` when the fork or duty is not known.
    pub const UNKNOWN: &str = "unknown";
}

/// Bounded `sign_type` labels for [`RVC_SIGNER_REJECTIONS_TOTAL`].
pub mod rejection_sign_type {
    pub const UNKNOWN: &str = super::rejection_reason::UNKNOWN;
    pub const BEACON_BLOCK: &str = "beacon_block";
    pub const ATTESTATION_DATA: &str = "attestation_data";
    pub const RANDAO_REVEAL: &str = "randao_reveal";
    pub const AGGREGATION_SLOT: &str = "aggregation_slot";
    pub const AGGREGATE_AND_PROOF: &str = "aggregate_and_proof";
    pub const SYNC_COMMITTEE_MESSAGE: &str = "sync_committee_message";
    pub const SYNC_AGGREGATOR_SELECTION_DATA: &str = "sync_aggregator_selection_data";
    pub const CONTRIBUTION_AND_PROOF: &str = "contribution_and_proof";
    pub const BUILDER_REGISTRATION: &str = "builder_registration";
    pub const VOLUNTARY_EXIT: &str = "voluntary_exit";
    pub const PAYLOAD_ATTESTATION: &str = "payload_attestation";
    pub const PROPOSER_PREFERENCES: &str = "proposer_preferences";
    pub const BUILDER_REQUEST_AUTH: &str = "builder_request_auth";
    pub const EXECUTION_PAYLOAD_ENVELOPE: &str = "execution_payload_envelope";

    pub const ALL: &[&str] = &[
        UNKNOWN,
        BEACON_BLOCK,
        ATTESTATION_DATA,
        RANDAO_REVEAL,
        AGGREGATION_SLOT,
        AGGREGATE_AND_PROOF,
        SYNC_COMMITTEE_MESSAGE,
        SYNC_AGGREGATOR_SELECTION_DATA,
        CONTRIBUTION_AND_PROOF,
        BUILDER_REGISTRATION,
        VOLUNTARY_EXIT,
        PAYLOAD_ATTESTATION,
        PROPOSER_PREFERENCES,
        BUILDER_REQUEST_AUTH,
        EXECUTION_PAYLOAD_ENVELOPE,
    ];
}

/// Shared attestation counter; `register_metric` de-duplicates the family.
pub static RVC_ATTESTATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_attestations_total",
        "Total number of attestation operations",
        &["status"],
    )
});

/// Histogram for signing operation latency in seconds.
pub static RVC_SIGNING_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    define_histogram_vec(
        "rvc_signing_duration_seconds",
        "Duration of signing operations in seconds",
        &[],
        &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        &[],
    )
});

/// Counter for slashing protection database checks.
/// Labels: result (safe, blocked)
pub static RVC_SLASHING_PROTECTION_CHECKS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_slashing_protection_checks_total",
        "Total number of slashing protection checks",
        &["result"],
    )
});

/// Fail-closed signer rejections by reason, sign type, and fork version.
///
/// Labels: `reason` ([`rejection_reason`]), `sign_type` ([`rejection_sign_type`]),
/// `version` ([`ForkName::as_ref`] or [`rejection_reason::UNKNOWN`]).
pub static RVC_SIGNER_REJECTIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_signer_rejections_total",
        "Fail-closed signer rejections by reason, sign type, and consensus version",
        &["reason", "sign_type", "version"],
    )
});

/// Histogram for slashing-DB transaction hold duration in milliseconds.
///
/// Labels: `kind` — either `"attestation"` or `"block"`.
pub static RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS: LazyLock<HistogramVec> = LazyLock::new(|| {
    define_histogram_vec(
        "rvc_signer_slashing_tx_hold_duration_ms",
        "Duration (ms) that the slashing-DB transaction is held per stage→commit/discard cycle",
        &["kind"],
        &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0],
        &[],
    )
});

/// Reserve-transaction-only hold duration in milliseconds (ARCH-5b / X6).
///
/// Labels: `kind` — `"attestation"` or `"block"`.
pub static RVC_SLASHING_RESERVE_TX_HOLD_DURATION_MS: LazyLock<HistogramVec> = LazyLock::new(|| {
    define_histogram_vec(
        "rvc_slashing_reserve_tx_hold_duration_ms",
        "Duration (ms) of the slashing-DB reserve write transaction (mutex acquire → COMMIT)",
        &["kind"],
        &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0],
        &[],
    )
});

pub fn init() {
    LazyLock::force(&RVC_ATTESTATIONS_TOTAL);
    LazyLock::force(&RVC_SIGNING_DURATION_SECONDS);
    LazyLock::force(&RVC_SLASHING_PROTECTION_CHECKS_TOTAL);
    LazyLock::force(&RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS);
    LazyLock::force(&RVC_SLASHING_RESERVE_TX_HOLD_DURATION_MS);
    LazyLock::force(&RVC_SIGNER_REJECTIONS_TOTAL);
}

/// `version` label: [`ForkName::as_ref`] or [`rejection_reason::UNKNOWN`].
#[must_use]
pub fn version_label(fork_name: Option<ForkName>) -> &'static str {
    let Some(name) = fork_name else {
        return rejection_reason::UNKNOWN;
    };
    ForkName::ALL
        .iter()
        .find(|n| **n == name)
        .map(AsRef::as_ref)
        .expect("all ForkName variants appear in ALL")
}

/// Map a Web3Signer `type` discriminator onto [`rejection_sign_type`].
///
/// Unknown / request-derived tokens become [`rejection_sign_type::UNKNOWN`].
#[must_use]
pub fn sign_type_from_web3signer_type(type_name: &str) -> &'static str {
    match type_name {
        "BLOCK_V2" => rejection_sign_type::BEACON_BLOCK,
        "ATTESTATION" => rejection_sign_type::ATTESTATION_DATA,
        "RANDAO_REVEAL" => rejection_sign_type::RANDAO_REVEAL,
        "AGGREGATION_SLOT" => rejection_sign_type::AGGREGATION_SLOT,
        "AGGREGATE_AND_PROOF" | "AGGREGATE_AND_PROOF_V2" => {
            rejection_sign_type::AGGREGATE_AND_PROOF
        }
        "SYNC_COMMITTEE_MESSAGE" => rejection_sign_type::SYNC_COMMITTEE_MESSAGE,
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" => rejection_sign_type::CONTRIBUTION_AND_PROOF,
        "SYNC_COMMITTEE_SELECTION_PROOF" => rejection_sign_type::SYNC_AGGREGATOR_SELECTION_DATA,
        "VALIDATOR_REGISTRATION" => rejection_sign_type::BUILDER_REGISTRATION,
        "VOLUNTARY_EXIT" => rejection_sign_type::VOLUNTARY_EXIT,
        "PAYLOAD_ATTESTATION" => rejection_sign_type::PAYLOAD_ATTESTATION,
        "PROPOSER_PREFERENCES" => rejection_sign_type::PROPOSER_PREFERENCES,
        "BUILDER_REQUEST_AUTH" => rejection_sign_type::BUILDER_REQUEST_AUTH,
        _ => rejection_sign_type::UNKNOWN,
    }
}

/// Map a core/gate `op_name` onto [`rejection_sign_type`].
#[must_use]
pub fn sign_type_from_op_name(op_name: &str) -> &'static str {
    match op_name {
        "sign_block" | "sign_block_header" => rejection_sign_type::BEACON_BLOCK,
        "sign_attestation" => rejection_sign_type::ATTESTATION_DATA,
        "randao" | "sign_randao_reveal" => rejection_sign_type::RANDAO_REVEAL,
        "selection_proof" | "sign_selection_proof" | "sync_committee_selection_proof" => {
            rejection_sign_type::SYNC_AGGREGATOR_SELECTION_DATA
        }
        "aggregate_and_proof"
        | "aggregate_and_proof_root"
        | "electra_aggregate_and_proof"
        | "sign_aggregate_and_proof" => rejection_sign_type::AGGREGATE_AND_PROOF,
        "sync_committee_message" | "sign_sync_committee_message" => {
            rejection_sign_type::SYNC_COMMITTEE_MESSAGE
        }
        "contribution_and_proof" | "sign_contribution_and_proof" => {
            rejection_sign_type::CONTRIBUTION_AND_PROOF
        }
        "builder_registration" | "sign_builder_registration" => {
            rejection_sign_type::BUILDER_REGISTRATION
        }
        "voluntary_exit" | "sign_voluntary_exit" => rejection_sign_type::VOLUNTARY_EXIT,
        "payload_attestation" | "sign_payload_attestation" => {
            rejection_sign_type::PAYLOAD_ATTESTATION
        }
        "proposer_preferences" | "sign_proposer_preferences" => {
            rejection_sign_type::PROPOSER_PREFERENCES
        }
        "builder_request_auth" | "sign_builder_request_auth" => {
            rejection_sign_type::BUILDER_REQUEST_AUTH
        }
        "execution_payload_envelope" | "sign_execution_payload_envelope" => {
            rejection_sign_type::EXECUTION_PAYLOAD_ENVELOPE
        }
        _ => rejection_sign_type::UNKNOWN,
    }
}

/// Classify a fail-closed [`SigningError`] onto [`rejection_reason`].
///
/// Type/capability gaps (`UnsupportedSigningType`, `UnsupportedDuty`,
/// `SignerLacksGloasSupport`) map to [`rejection_reason::UNSUPPORTED_TYPE`].
/// HTTP 400 / other transient remote errors return `None` (4.10).
#[must_use]
pub fn classified_rejection_reason(err: &SigningError) -> Option<&'static str> {
    match err {
        SigningError::UnsupportedSigningType(_)
        | SigningError::UnsupportedDuty { .. }
        | SigningError::SignerLacksGloasSupport { .. } => Some(rejection_reason::UNSUPPORTED_TYPE),
        SigningError::RemoteSignerError(msg) if is_unknown_version_reject(msg) => {
            Some(rejection_reason::UNSUPPORTED_VERSION)
        }
        _ => None,
    }
}

fn is_unknown_version_reject(msg: &str) -> bool {
    msg.contains("unresolvable fork version") || msg.contains("unknown version:")
}

/// Increment [`RVC_SIGNER_REJECTIONS_TOTAL`] with caller-supplied bounded labels.
pub fn record_rejection(reason: &'static str, sign_type: &'static str, version: &'static str) {
    RVC_SIGNER_REJECTIONS_TOTAL.with_label_values(&[reason, sign_type, version]).inc();
}

/// Increment when `err` is a fail-closed type/version rejection.
///
/// `sign_type` / `version` must already be bounded ([`rejection_sign_type`] /
/// [`version_label`]). No-op for transient HTTP 400 (`RemoteSignerError`).
pub fn record_signing_error(err: &SigningError, sign_type: &'static str, version: &'static str) {
    if let Some(reason) = classified_rejection_reason(err) {
        record_rejection(reason, sign_type, version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }

    #[test]
    fn test_unsupported_signing_type_increments_with_bounded_labels() {
        init();
        let err = SigningError::UnsupportedSigningType(
            "raw-root signing is not supported for Web3Signer HTTP".into(),
        );
        assert_eq!(classified_rejection_reason(&err), Some(rejection_reason::UNSUPPORTED_TYPE));
        let sign_type = rejection_sign_type::PAYLOAD_ATTESTATION;
        let version = ForkName::Gloas.as_ref();
        let before = RVC_SIGNER_REJECTIONS_TOTAL
            .with_label_values(&[rejection_reason::UNSUPPORTED_TYPE, sign_type, version])
            .get();
        record_signing_error(&err, sign_type, version);
        assert!(
            RVC_SIGNER_REJECTIONS_TOTAL
                .with_label_values(&[rejection_reason::UNSUPPORTED_TYPE, sign_type, version])
                .get()
                > before,
            "unsupported_type must increment with bounded sign_type/version"
        );
        assert!(rejection_sign_type::ALL.contains(&sign_type));
        assert_eq!(version, "gloas");
    }

    #[test]
    fn test_unknown_version_increments_unsupported_version_reason() {
        init();
        // 4.9 fail-closed unknown version (never the raw request token as a label).
        let err = SigningError::RemoteSignerError("unknown version: NOT_A_FORK".into());
        assert_eq!(classified_rejection_reason(&err), Some(rejection_reason::UNSUPPORTED_VERSION));
        let sign_type = rejection_sign_type::BEACON_BLOCK;
        let version = version_label(None);
        assert_eq!(version, rejection_reason::UNKNOWN);
        let before = RVC_SIGNER_REJECTIONS_TOTAL
            .with_label_values(&[rejection_reason::UNSUPPORTED_VERSION, sign_type, version])
            .get();
        record_signing_error(&err, sign_type, version);
        assert!(
            RVC_SIGNER_REJECTIONS_TOTAL
                .with_label_values(&[rejection_reason::UNSUPPORTED_VERSION, sign_type, version])
                .get()
                > before
        );
        let resolve_err =
            SigningError::RemoteSignerError("unresolvable fork version 0xdeadbeef".into());
        assert_eq!(
            classified_rejection_reason(&resolve_err),
            Some(rejection_reason::UNSUPPORTED_VERSION)
        );
    }

    #[test]
    fn test_http_400_does_not_increment_unsupported_type() {
        init();
        // 4.10: generic HTTP 400 stays RemoteSignerError (transient).
        let err = SigningError::RemoteSignerError(
            "Web3Signer returned 400 Bad Request: bad request".into(),
        );
        assert!(classified_rejection_reason(&err).is_none());
        let sign_type = rejection_sign_type::ATTESTATION_DATA;
        let version = ForkName::Phase0.as_ref();
        let before = RVC_SIGNER_REJECTIONS_TOTAL
            .with_label_values(&[rejection_reason::UNSUPPORTED_TYPE, sign_type, version])
            .get();
        record_signing_error(&err, sign_type, version);
        assert_eq!(
            RVC_SIGNER_REJECTIONS_TOTAL
                .with_label_values(&[rejection_reason::UNSUPPORTED_TYPE, sign_type, version])
                .get(),
            before,
            "HTTP 400 must not increment unsupported_type"
        );
    }

    #[test]
    fn test_rejection_labels_come_from_rejection_reason_module() {
        assert_eq!(rejection_reason::UNSUPPORTED_TYPE, "unsupported_type");
        assert_eq!(rejection_reason::UNSUPPORTED_VERSION, "unsupported_version");
        assert_eq!(rejection_reason::UNKNOWN, "unknown");

        let unsupported = SigningError::UnsupportedSigningType("x".into());
        assert_eq!(
            classified_rejection_reason(&unsupported),
            Some(rejection_reason::UNSUPPORTED_TYPE)
        );
        let unknown_version = SigningError::RemoteSignerError("unknown version: FUTUREFORK".into());
        assert_eq!(
            classified_rejection_reason(&unknown_version),
            Some(rejection_reason::UNSUPPORTED_VERSION)
        );
        assert_eq!(version_label(Some(ForkName::Electra)), ForkName::Electra.as_ref());
        assert_eq!(version_label(None), rejection_reason::UNKNOWN);
        assert_eq!(sign_type_from_web3signer_type("NOT_A_REAL_TYPE"), rejection_sign_type::UNKNOWN);
        assert_eq!(
            sign_type_from_web3signer_type("PAYLOAD_ATTESTATION"),
            rejection_sign_type::PAYLOAD_ATTESTATION
        );
        assert_eq!(
            classified_rejection_reason(&SigningError::UnsupportedDuty {
                duty: "payload_attestation"
            }),
            Some(rejection_reason::UNSUPPORTED_TYPE)
        );
        assert_eq!(
            classified_rejection_reason(&SigningError::SignerLacksGloasSupport {
                rpc: "SignBlockHeader",
                details: "unimplemented".into(),
            }),
            Some(rejection_reason::UNSUPPORTED_TYPE)
        );
    }
}
