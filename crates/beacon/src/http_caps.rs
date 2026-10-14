//! Response-size caps for BN-facing HTTP requests (A9 / H-12).
//!
//! `ResponseCaps` holds the configurable ceiling for JSON body sizes.
//! SSE event size is capped in `bn-manager::sse::DEFAULT_MAX_SSE_EVENT_BYTES`
//! (single source of truth) while the frame is read, before the line or the
//! `data` / `event` / `id` fields grow past it. `read_body_capped` streams the
//! response body in chunks, counting bytes, and returns
//! `BeaconError::BodyTooLarge` before allocating more than the configured cap.

use bytes::Bytes;

use crate::BeaconError;

/// Per-response size limits for BN-facing HTTP traffic.
#[derive(Clone, Copy, Debug)]
pub struct ResponseCaps {
    /// Maximum bytes allowed in a JSON response body (default 32 MiB).
    pub max_body_bytes: usize,
}

impl ResponseCaps {
    /// Default maximum JSON response body (32 MiB).
    pub const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
}

impl Default for ResponseCaps {
    fn default() -> Self {
        Self { max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES }
    }
}

/// Read a response body up to `cap` bytes for diagnostic use, returning a lossy UTF-8 string.
///
/// Calls `read_body_capped` and converts the result to a `String`.  Intended for
/// error-path message extraction where the body is diagnostic-only and its exact
/// content does not matter: if the cap is exceeded or the bytes are not valid
/// UTF-8, an empty string is returned instead of propagating an error.
///
/// Default cap for error-path diagnostic bodies: 16 KiB.
pub(crate) async fn read_body_capped_lossy(response: reqwest::Response, cap: usize) -> String {
    match read_body_capped(response, cap).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
}

/// Read a response body up to `cap` bytes, streaming in chunks.
///
/// Rejects *before* any allocation when `Content-Length` header exceeds `cap`.
/// Otherwise streams chunks and returns `BeaconError::BodyTooLarge` as soon as
/// the running total would exceed `cap`.
pub(crate) async fn read_body_capped(
    response: reqwest::Response,
    cap: usize,
) -> Result<Bytes, BeaconError> {
    // Fast-reject: Content-Length header advertises too much data.
    if let Some(content_length) = response.content_length() {
        let cl = content_length as usize;
        if cl > cap {
            return Err(BeaconError::BodyTooLarge { expected: cap, got_so_far: cl });
        }
    }

    // Stream body in chunks, counting bytes.
    let mut body: Vec<u8> = Vec::new();
    let mut response = response;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let new_total = body.len() + chunk.len();
                if new_total > cap {
                    return Err(BeaconError::BodyTooLarge { expected: cap, got_so_far: new_total });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err(BeaconError::ParseError(format!(
                    "failed to read response body chunk: {e}"
                )))
            }
        }
    }
    Ok(Bytes::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_caps_values() {
        let caps = ResponseCaps::default();
        assert_eq!(caps.max_body_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn test_response_caps_is_copy() {
        let caps = ResponseCaps::default();
        let _copy = caps; // Copy trait
        let _ = caps.max_body_bytes; // original still accessible
    }

    #[test]
    fn test_response_caps_debug() {
        let caps = ResponseCaps { max_body_bytes: 1024 };
        let s = format!("{caps:?}");
        assert!(s.contains("1024"));
    }
}
