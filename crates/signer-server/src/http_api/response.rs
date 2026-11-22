//! HTTP status mapping for `POST /sign/{identifier}` (FR-20..FR-24).
//!
//! Gate errors are classified once via [`signer::classify`] (shared with the
//! gRPC edge). This module maps [`signer::GateErrClass`] to HTTP statuses +
//! safe bodies — it does **not** match on `SigningGateError` variants.
//!
//! Only slashing-violation slot/epoch detail (already deemed safe on the gRPC
//! path) is surfaced; SQLite paths, rusqlite internals, and lock messages are
//! logged server-side and replaced with a generic message.
//!
//! The success / `Accept`-negotiated half (`sign_response`) shapes the body per
//! the request `Accept` header (FR-17). Both halves are consumed by the live
//! `routes::sign` handler.

use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use signer::{classify, GateErrClass, SigningGateError};

/// An error from the HTTP sign path, mapped to an exact HTTP status.
#[derive(Debug)]
pub enum HttpSignError {
    /// Pre-gate failure that never reaches the gate: parse error, unsupported
    /// `type`, missing `fork_info`, or a `signingRoot` mismatch. → `400`.
    BadRequest(String),
    /// Unknown / unloaded public key (pre-gate resolution). → `404`.
    UnknownKey,
    /// Client CN not on the primary allow-list (SEC-4). → `401`.
    ///
    /// Mirrors gRPC `Status::unauthenticated` for the same check.
    Unauthorized(String),
    /// A `SigningGate` result error, mapped per [`gate_err_to_http`].
    Gate(SigningGateError),
}

impl HttpSignError {
    /// Map to `(status, safe-body)`. The body never contains SQLite paths, lock
    /// messages, or backend internals — only the slashing-violation slot/epoch
    /// detail, which is safe to surface.
    pub fn status_and_body(&self) -> (StatusCode, String) {
        match self {
            HttpSignError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            HttpSignError::UnknownKey => (StatusCode::NOT_FOUND, "unknown public key".to_string()),
            HttpSignError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            HttpSignError::Gate(e) => gate_err_to_http(e),
        }
    }

    /// Stable, low-cardinality outcome label for the audit `result` field.
    ///
    /// Gate errors reuse [`GateErrClass::metrics_label`] so HTTP audit lines
    /// stay byte-identical to gRPC `sign_errors_total` labels. Pre-gate labels
    /// (`bad_request`, `client_cn_not_allowed`) are HTTP-only.
    pub(super) fn audit_label(&self) -> &'static str {
        match self {
            HttpSignError::BadRequest(_) => "bad_request",
            HttpSignError::UnknownKey => "key_not_found",
            HttpSignError::Unauthorized(_) => "client_cn_not_allowed",
            HttpSignError::Gate(e) => classify(e).metrics_label(),
        }
    }
}

/// Map a gate result error to `(status, safe-body)` via shared [`classify`].
///
/// # HTTP status mapping
///
/// | [`GateErrClass`] | HTTP status |
/// |---|---|
/// | `BlockedByDoppelganger` / `SlashingBlocked` | `412 Precondition Failed` |
/// | `CommitFailed` / `Internal` | `500 Internal Server Error` |
/// | `KeyNotFound` | `404 Not Found` |
///
/// `CommitFailed` → 500 matches gRPC `Internal` so same-root retry is treated
/// as a retriable server fault rather than a permanent precondition rejection.
fn gate_err_to_http(e: &SigningGateError) -> (StatusCode, String) {
    let class = classify(e);
    class.emit_server_log();
    let body = class.client_message().to_string();
    let status = match &class {
        GateErrClass::BlockedByDoppelganger | GateErrClass::SlashingBlocked { .. } => {
            StatusCode::PRECONDITION_FAILED
        }
        GateErrClass::CommitFailed { .. } | GateErrClass::Internal { .. } => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        GateErrClass::KeyNotFound => StatusCode::NOT_FOUND,
    };
    (status, body)
}

impl IntoResponse for HttpSignError {
    fn into_response(self) -> Response {
        let (status, body) = self.status_and_body();
        (status, body).into_response()
    }
}

// ── Success response shaping (Issue 2.7, FR-17) ──────────────────────────────

/// JSON success body: `{"signature":"0x.."}`.
#[derive(Debug, Serialize)]
pub(super) struct SignatureResponse {
    pub signature: String,
}

/// Shape a successful `POST /sign/{identifier}` response per the `Accept` header
/// (FR-17). `Accept: text/plain` → a bare `0x<hex>` body with a `text/plain`
/// content type; everything else (JSON, `*/*`, or absent) → `{"signature":
/// "0x.."}`. `signature` is the raw gate output (96 bytes) as `0x`+lowercase hex.
///
/// The live sign route (Issue 2.8) calls this with the gate's signature; the
/// shaper is driven directly by unit tests here, so no socket/gate is needed.
pub(super) fn sign_response(accept: Option<&str>, signature: &[u8]) -> Response {
    let hex = format!("0x{}", hex::encode(signature));
    if wants_text_plain(accept) {
        ([(CONTENT_TYPE, "text/plain")], hex).into_response()
    } else {
        Json(SignatureResponse { signature: hex }).into_response()
    }
}

/// `true` only when the client explicitly accepts `text/plain`. An absent,
/// wildcard (`*/*`), or `application/json` Accept defaults to JSON (Web3Signer
/// mirrors the content type, defaulting to JSON).
///
/// Media-type matching is case-insensitive and ignores `;`-parameters
/// (`q`/`charset`) per RFC 9110, and scans every comma-separated member so a
/// multi-value `Accept` that lists `text/plain` is honored (2.7 review).
fn wants_text_plain(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| {
        a.split(',').any(|member| {
            member.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/plain")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::gate_err_to_status;
    use slashing::{AttestationSlashingViolation, BlockSlashingViolation, SlashingError};
    use tonic::Code;

    // ── Success response shaping (Issue 2.7, FR-17) ──────────────────────────

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn content_type(resp: &Response) -> String {
        resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
    }

    #[test]
    fn wants_text_plain_is_case_insensitive_param_aware_and_multi_value() {
        assert!(wants_text_plain(Some("text/plain")));
        assert!(wants_text_plain(Some("Text/Plain")), "media types are case-insensitive");
        assert!(wants_text_plain(Some("text/plain; q=0.9")), ";-params ignored");
        assert!(wants_text_plain(Some("application/json, text/plain")), "multi-value scanned");
        assert!(!wants_text_plain(Some("application/json")));
        assert!(!wants_text_plain(Some("*/*")));
        assert!(!wants_text_plain(Some("text/plainish")), "exact media type, not a prefix");
        assert!(!wants_text_plain(None));
    }

    #[tokio::test]
    async fn text_plain_accept_returns_bare_hex_with_text_content_type() {
        let resp = sign_response(Some("text/plain"), &[0xABu8; 96]);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("text/plain"), "ct={}", content_type(&resp));
        let body = body_string(resp).await;
        assert_eq!(body, format!("0x{}", "ab".repeat(96)));
        assert!(!body.contains('{'), "text/plain must be a bare body, not JSON: {body}");
    }

    #[tokio::test]
    async fn json_accept_returns_signature_object() {
        let resp = sign_response(Some("application/json"), &[0xABu8; 96]);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("application/json"), "ct={}", content_type(&resp));
        let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(v["signature"], format!("0x{}", "ab".repeat(96)));
    }

    #[tokio::test]
    async fn absent_and_wildcard_accept_default_to_json() {
        for accept in [None, Some("*/*"), Some("application/json")] {
            let resp = sign_response(accept, &[0x01u8; 96]);
            assert!(
                content_type(&resp).starts_with("application/json"),
                "accept={accept:?} must default to JSON"
            );
            assert!(body_string(resp).await.starts_with("{\"signature\""));
        }
    }

    #[tokio::test]
    async fn signature_is_0x_lowercase_hex_of_raw_bytes() {
        // Distinct per-byte values catch a wrong/transposed encoding.
        let mut sig = [0u8; 96];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = i as u8;
        }
        let body = body_string(sign_response(Some("text/plain"), &sig)).await;
        let expected: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(body, format!("0x{expected}"));
        assert_eq!(body, body.to_lowercase(), "hex must be lowercase");
    }

    #[test]
    fn doppelganger_block_is_412() {
        let (status, _) =
            HttpSignError::Gate(SigningGateError::BlockedByDoppelganger).status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn slashable_block_is_412_with_safe_slot_detail() {
        let err = HttpSignError::Gate(SigningGateError::SlashingBlocked(
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot: 42 }),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert!(body.contains("42"), "safe slot detail must be surfaced: {body}");
    }

    #[test]
    fn slashable_attestation_is_412_with_safe_epoch_detail() {
        let err = HttpSignError::Gate(SigningGateError::SlashingBlocked(
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch: 7,
            }),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert!(body.contains('7'), "safe epoch detail must be surfaced: {body}");
    }

    #[test]
    fn generic_db_error_is_412_without_leaking_internals() {
        let secret = "/var/lib/rvc/slashing.db lock contention";
        let err = HttpSignError::Gate(SigningGateError::SlashingBlocked(
            SlashingError::MigrationFailed(secret.to_string()),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert!(!body.contains(secret), "generic DB error must NOT leak internals: {body}");
        assert!(!body.contains(".db"), "no path internals: {body}");
    }

    #[test]
    fn commit_failed_is_500_generic() {
        let secret = "/var/lib/rvc/slashing.db disk full";
        let (status, body) = HttpSignError::Gate(SigningGateError::CommitFailed {
            signing_root: [0u8; 32],
            source: SlashingError::MigrationFailed(secret.to_string()),
        })
        .status_and_body();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains(secret), "commit-failed body must not leak: {body}");
    }

    #[test]
    fn signing_failed_is_500_generic() {
        let (status, body) =
            HttpSignError::Gate(SigningGateError::SigningFailed("blst internal x0042".to_string()))
                .status_and_body();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("x0042"), "signing-failed body must not leak detail: {body}");
    }

    #[test]
    fn key_not_found_and_unknown_pubkey_are_404() {
        for e in [SigningGateError::KeyNotFound, SigningGateError::UnknownPubkey] {
            let (status, body) = HttpSignError::Gate(e).status_and_body();
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(body, "unknown public key");
        }
    }

    #[test]
    fn pre_gate_bad_request_is_400_and_unknown_key_is_404() {
        let (status, body) =
            HttpSignError::BadRequest("unsupported type".to_string()).status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "unsupported type");

        let (status, _) = HttpSignError::UnknownKey.status_and_body();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn sec4_unauthorized_cn_is_401() {
        let (status, body) =
            HttpSignError::Unauthorized("client CN 'x' is not on the allow-list".to_string())
                .status_and_body();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("not on the allow-list"));
        assert_eq!(
            HttpSignError::Unauthorized("x".to_string()).audit_label(),
            "client_cn_not_allowed"
        );
    }

    /// Corresponding status pairs for the shared [`GateErrClass`] taxonomy.
    ///
    /// gRPC and HTTP must agree on *category* (precondition / not-found /
    /// internal) and on the sanitized client message for every gate error.
    fn corresponding_http(code: Code) -> StatusCode {
        match code {
            Code::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
            Code::NotFound => StatusCode::NOT_FOUND,
            Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            other => panic!("unexpected gRPC code in gate mapping: {other:?}"),
        }
    }

    fn every_gate_error() -> Vec<SigningGateError> {
        vec![
            SigningGateError::BlockedByDoppelganger,
            SigningGateError::BeaconAdmissionRevoked,
            SigningGateError::SlashingBlocked(SlashingError::SlashableBlock(
                BlockSlashingViolation::DoubleBlockProposal { slot: 42 },
            )),
            SigningGateError::SlashingBlocked(SlashingError::SlashableAttestation(
                AttestationSlashingViolation::DoubleVote { target_epoch: 7 },
            )),
            SigningGateError::SlashingBlocked(SlashingError::MigrationFailed(
                "/var/lib/rvc/slashing.db lock contention".into(),
            )),
            SigningGateError::CommitFailed {
                signing_root: [0u8; 32],
                source: SlashingError::MigrationFailed("/var/lib/rvc/slashing.db disk full".into()),
            },
            SigningGateError::KeyNotFound,
            SigningGateError::UnknownPubkey,
            SigningGateError::SigningFailed("blst internal x0042".into()),
        ]
    }

    #[test]
    fn test_grpc_and_http_agree_on_every_gate_error_class() {
        for err in every_gate_error() {
            let class = classify(&err);
            let grpc = gate_err_to_status(clone_gate_err(&err));
            let (http_status, http_body) =
                HttpSignError::Gate(clone_gate_err(&err)).status_and_body();

            assert_eq!(
                http_status,
                corresponding_http(grpc.code()),
                "status category mismatch for {class:?}: grpc={:?} http={http_status}",
                grpc.code()
            );
            assert_eq!(http_body, grpc.message(), "sanitized body mismatch for {class:?}");
            assert_eq!(
                http_body,
                class.client_message(),
                "body must equal classifier client_message for {class:?}"
            );
            // Leak-free: no SQLite path or backend internal token on the wire.
            assert!(!http_body.contains(".db"), "path leak: {http_body}");
            assert!(!http_body.contains("x0042"), "backend leak: {http_body}");
            assert!(!http_body.contains("/var/lib"), "path leak: {http_body}");
        }
    }

    /// `SigningGateError` is not `Clone`; rebuild the variants we need for dual mapping.
    fn clone_gate_err(err: &SigningGateError) -> SigningGateError {
        match err {
            SigningGateError::BlockedByDoppelganger => SigningGateError::BlockedByDoppelganger,
            SigningGateError::BeaconAdmissionRevoked => SigningGateError::BeaconAdmissionRevoked,
            SigningGateError::SlashingBlocked(inner) => {
                SigningGateError::SlashingBlocked(match inner {
                    SlashingError::SlashableBlock(
                        BlockSlashingViolation::DoubleBlockProposal { slot },
                    ) => {
                        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                            slot: *slot,
                        })
                    }
                    SlashingError::SlashableAttestation(
                        AttestationSlashingViolation::DoubleVote { target_epoch },
                    ) => SlashingError::SlashableAttestation(
                        AttestationSlashingViolation::DoubleVote { target_epoch: *target_epoch },
                    ),
                    SlashingError::MigrationFailed(msg) => {
                        SlashingError::MigrationFailed(msg.clone())
                    }
                    other => panic!("unexpected SlashingError in test fixture: {other}"),
                })
            }
            SigningGateError::CommitFailed { signing_root, source } => {
                SigningGateError::CommitFailed {
                    signing_root: *signing_root,
                    source: match source {
                        SlashingError::MigrationFailed(msg) => {
                            SlashingError::MigrationFailed(msg.clone())
                        }
                        other => panic!("unexpected CommitFailed source: {other}"),
                    },
                }
            }
            SigningGateError::KeyNotFound => SigningGateError::KeyNotFound,
            SigningGateError::UnknownPubkey => SigningGateError::UnknownPubkey,
            SigningGateError::SigningFailed(msg) => SigningGateError::SigningFailed(msg.clone()),
        }
    }
}
