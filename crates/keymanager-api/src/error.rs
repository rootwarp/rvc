use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;
use uuid::Uuid;

use crate::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, ImportKeystoreError, ImportRemoteKeyError,
    SlashingProtectionError,
};
use crate::url_validator::UrlValidationError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Flat exhaustive match (review M-9 SF-2): avoids the previous nested
        // match's `unreachable!()` arm — a future refactor adding a variant
        // would now be a compile error rather than a runtime panic.
        match self {
            ApiError::RateLimited { retry_after_secs } => {
                let body = serde_json::json!({ "code": 429, "message": "rate limited" });
                let mut response =
                    (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
                if let Ok(val) = retry_after_secs.to_string().parse() {
                    response.headers_mut().insert("Retry-After", val);
                }
                response
            }
            ApiError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({ "message": msg })))
                    .into_response()
            }
            ApiError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "message": msg })))
                    .into_response()
            }
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({ "message": msg })),
            )
                .into_response(),
        }
    }
}

// ── Central sanitizing mapper ────────────────────────────────────────────────
//
// Trait-level errors decide exposure by *variant*. Handlers call only these
// functions; no call site may echo a Backend/internal payload to a client.

/// Escape ASCII control characters in `s` (notably `\n`, `\r`) to their
/// `\xHH` form so that an attacker cannot smuggle a forged log line through
/// a user-controllable error string when the tracing-subscriber formatter is
/// in text mode (CWE-117 / OWASP A09:2021).
fn escape_log_control_chars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() {
            out.push_str(&format!("\\x{:02x}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Log full detail server-side; return a generic `ApiError::Internal`.
fn map_backend_to_api_error(detail: &str, ctx: &str) -> ApiError {
    let req_id = Uuid::new_v4();
    let safe = escape_log_control_chars(detail);
    tracing::error!(request_id = %req_id, error = %safe, "{ctx}");
    ApiError::Internal(format!("internal error (request_id={req_id})"))
}

/// Log full detail server-side; return a generic per-item message string.
fn map_backend_to_item_message(detail: &str, ctx: &str) -> String {
    let req_id = Uuid::new_v4();
    let safe = escape_log_control_chars(detail);
    tracing::error!(request_id = %req_id, error = %safe, "{ctx}");
    format!("key error (request_id={req_id})")
}

/// Map [`SlashingProtectionError`] for import (and general) paths.
///
/// * `NotFound` → 404
/// * `InvalidInterchange` → 400 with a client-safe message
/// * `Backend` → 500 generic message; detail logged only
pub fn map_slashing_protection_error(err: SlashingProtectionError, ctx: &str) -> ApiError {
    match err {
        SlashingProtectionError::NotFound => {
            ApiError::NotFound("slashing protection data not found".into())
        }
        SlashingProtectionError::InvalidInterchange(msg) => {
            ApiError::BadRequest(format!("invalid interchange: {msg}"))
        }
        SlashingProtectionError::Backend(detail) => map_backend_to_api_error(&detail, ctx),
    }
}

/// Map a slashing-export failure on the DELETE fail-closed path (KM-1).
///
/// Preserves the fixed client message used before this refactor so operators
/// and tests can still recognise the abort reason; the backend detail is
/// logged with a request_id correlator and never returned.
pub fn map_slashing_export_error(err: SlashingProtectionError) -> ApiError {
    match err {
        SlashingProtectionError::NotFound => {
            ApiError::NotFound("slashing protection data not found".into())
        }
        SlashingProtectionError::InvalidInterchange(msg) => {
            ApiError::BadRequest(format!("invalid interchange: {msg}"))
        }
        SlashingProtectionError::Backend(detail) => {
            let req_id = Uuid::new_v4();
            let safe = escape_log_control_chars(&detail);
            tracing::error!(
                request_id = %req_id,
                error = %safe,
                "DELETE aborted: slashing-protection export failed; no keystores deleted"
            );
            ApiError::Internal(
                "slashing protection export failed; no keystores deleted".to_string(),
            )
        }
    }
}

/// Map a keystore-import per-item error to a client-safe message.
///
/// All variants may embed paths/errno from the backend, so they are sanitized.
pub fn map_import_keystore_item_error(err: ImportKeystoreError) -> String {
    match err {
        ImportKeystoreError::DeleteInProgress => "delete in progress".into(),
        other => map_backend_to_item_message(&other.to_string(), "keystore import failed"),
    }
}

/// Map a keystore-delete per-item error to a client-safe message.
pub fn map_delete_keystore_item_error(err: &DeleteKeystoreError) -> String {
    map_backend_to_item_message(&err.to_string(), "keystore delete failed")
}

/// Map a remote-key import per-item error by variant.
///
/// Client-safe variants (`InvalidUrl`, `HostNotAllowed`) surface their
/// Display; `Backend` is sanitized.
pub fn map_import_remote_key_item_error(err: ImportRemoteKeyError) -> String {
    match err {
        ImportRemoteKeyError::Duplicate => "key already exists".into(),
        ImportRemoteKeyError::InvalidUrl(_) | ImportRemoteKeyError::HostNotAllowed(_) => {
            err.to_string()
        }
        ImportRemoteKeyError::Backend(detail) => {
            map_backend_to_item_message(&detail, "remote key import failed")
        }
    }
}

/// Map a remote-key delete per-item error by variant.
pub fn map_delete_remote_key_item_error(err: &DeleteRemoteKeyError) -> String {
    match err {
        DeleteRemoteKeyError::NotFound => "not found".into(),
        DeleteRemoteKeyError::Backend(detail) => {
            map_backend_to_item_message(detail, "remote key delete failed")
        }
    }
}

/// Map a URL-validation failure to the per-item message.
///
/// All [`UrlValidationError`] variants are client-caused and safe to surface.
pub fn map_url_validation_error(err: UrlValidationError) -> String {
    debug_assert!(err.is_client_safe());
    err.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_not_found_returns_404_with_json_body() {
        let error = ApiError::NotFound("validator not found".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "validator not found");
    }

    #[tokio::test]
    async fn test_not_found_variant_maps_to_404_with_safe_message() {
        let api = map_slashing_protection_error(SlashingProtectionError::NotFound, "test");
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let msg = json["message"].as_str().unwrap_or("");
        assert!(msg.contains("not found"), "msg={msg}");
        assert!(!msg.contains('/'), "must not leak paths: {msg}");
    }

    #[tokio::test]
    async fn test_invalid_interchange_maps_to_400() {
        let api = map_slashing_protection_error(
            SlashingProtectionError::InvalidInterchange("bad version".into()),
            "test",
        );
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"].as_str().unwrap_or("").contains("invalid interchange"),
            "body={json}"
        );
    }

    #[tokio::test]
    async fn test_backend_error_containing_path_is_not_leaked_in_response() {
        let path = "/var/lib/rvc/slashing.sqlite";
        let api = map_slashing_protection_error(
            SlashingProtectionError::Backend(format!("open {path}: ENOENT")),
            "slashing protection import failed",
        );
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains(path), "backend path leaked to client: {text}");
        assert!(text.contains("internal error"), "expected generic internal error, got: {text}");
        assert!(text.contains("request_id="), "request_id correlator missing: {text}");
    }

    #[test]
    fn test_backend_item_error_path_not_leaked() {
        let path = "/tmp/secrets/keystore.db";
        let msg = map_delete_remote_key_item_error(&DeleteRemoteKeyError::Backend(format!(
            "unlink {path} failed"
        )));
        assert!(!msg.contains(path), "path leaked: {msg}");
        assert!(msg.contains("key error"), "msg={msg}");
        assert!(msg.contains("request_id="), "msg={msg}");
    }

    #[test]
    fn test_client_safe_remote_import_variants_surface_message() {
        let url_msg =
            map_import_remote_key_item_error(ImportRemoteKeyError::InvalidUrl("no scheme".into()));
        assert!(url_msg.contains("invalid remote signer URL"), "msg={url_msg}");
        assert!(!url_msg.contains("request_id="), "client-safe must not be sanitized");

        let host_msg = map_import_remote_key_item_error(ImportRemoteKeyError::HostNotAllowed(
            "evil.example".into(),
        ));
        assert!(host_msg.contains("evil.example"), "msg={host_msg}");
        assert!(host_msg.contains("allowed hosts"), "msg={host_msg}");
    }

    #[test]
    fn test_url_validation_error_is_client_safe() {
        let err = UrlValidationError::HttpNotAllowed;
        assert!(err.is_client_safe());
        let msg = map_url_validation_error(err);
        assert!(msg.contains("HTTP not allowed"), "msg={msg}");

        let err = UrlValidationError::PrivateOrReservedIp("10.0.0.1".into());
        assert!(err.is_client_safe());
        assert!(map_url_validation_error(err).contains("10.0.0.1"));
    }

    /// Table-driven: status codes produced by the central mapper for each
    /// slashing-protection variant (shapes match OpenAPI: `{ "message": "..." }`).
    #[tokio::test]
    async fn test_error_status_codes_match_openapi_spec() {
        let cases: Vec<(SlashingProtectionError, StatusCode)> = vec![
            (SlashingProtectionError::NotFound, StatusCode::NOT_FOUND),
            (SlashingProtectionError::InvalidInterchange("x".into()), StatusCode::BAD_REQUEST),
            (SlashingProtectionError::Backend("db".into()), StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (err, expected) in cases {
            let response = map_slashing_protection_error(err, "table").into_response();
            assert_eq!(response.status(), expected);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(json.get("message").and_then(|v| v.as_str()).is_some());
        }
    }

    #[tokio::test]
    async fn test_export_backend_keeps_fixed_km1_message() {
        let api = map_slashing_export_error(SlashingProtectionError::Backend(
            "/var/db/slashing.sqlite locked".into(),
        ));
        match &api {
            ApiError::Internal(msg) => {
                assert_eq!(msg, "slashing protection export failed; no keystores deleted");
                assert!(!msg.contains("/var/db"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        let response = api.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
