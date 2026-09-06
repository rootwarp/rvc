//! Web3Signer-compatible HTTP remote-signing API.
//!
//! A thin, stateless transport frontend over the shared [`SigningGate`]: it
//! routes, parses, computes a signing root, dispatches to one `sign_*` call, and
//! maps the result to an HTTP status — it never signs, stores keys, or touches
//! the slashing DB directly. [`router`] is pure and socket-free (testable with
//! `tower`'s in-memory `oneshot`); the TLS accept loop / `serve` is Phase 3.
//!
//! The `hyper-util` / `rustls-pemfile` direct deps are declared in `Cargo.toml`
//! (R4) but unused until the Phase-3 listener.

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::{
    routing::{get, post},
    Router,
};
use signer::{SigningGate, AUDIT_CN_DEFAULT};

/// Maximum accepted request-body size (1 MiB), mirroring the gRPC listener's
/// `MAX_DECODE_BYTES` (`main.rs`). A signing request — even a `BLOCK_V2` header —
/// is far under this; an oversized body is rejected with `413 Payload Too Large`
/// at extraction, before any parse/gate work, so a hostile client cannot force
/// unbounded buffering (Issue 2.11).
const MAX_BODY_BYTES: usize = 1 << 20;

use crate::backend::SigningBackend;

pub mod accept_loop;
pub mod tls_config;

mod dispatch;
mod pubkey;
mod request;
mod response;
mod routes;

/// Audit configuration for the HTTP API.
///
/// Phase 2 carries only the default CN (used when no client cert is present);
/// per-request CN extraction from the TLS peer cert is wired in Phase 3.
#[derive(Debug, Clone)]
pub struct AuditCfg {
    /// CN recorded for audit when the request carries no parseable client cert
    /// (Prysm / server-TLS-only). Defaults to [`AUDIT_CN_DEFAULT`].
    pub default_cn: String,
    /// Signing-backend label recorded in each audit entry (`"basic"` / `"dvt"`),
    /// matching the gRPC metrics `backend` label so both transports' audit lines
    /// are comparable. Defaults to `"basic"`.
    pub backend_name: String,
}

impl Default for AuditCfg {
    fn default() -> Self {
        Self { default_cn: AUDIT_CN_DEFAULT.to_string(), backend_name: "basic".to_string() }
    }
}

/// Shared, cheaply-cloneable application state for the Web3Signer HTTP API.
///
/// Holds only `Arc` handles, so every request clones it for free and the front
/// tier fans out across tokio workers, serializing only at the per-pubkey gate
/// lock. The `gate` is the single signing authority shared with the gRPC
/// transport (FR-26); `backend` serves `GET /publicKeys`; `audit` supplies the
/// CN for audit entries; `metrics` records the HTTP-path series (Issue 4.5) on
/// the same `SignerMetrics` registry the gRPC transport and `:9101` scrape share.
///
/// [`Self::client_cn_allow_list`] is the same optional SEC-4 list wired into
/// gRPC `SignerServiceImpl` so both transports share one authorization policy.
#[derive(Clone)]
pub struct Web3SignerState {
    pub gate: Arc<SigningGate>,
    pub backend: Arc<dyn SigningBackend>,
    pub audit: AuditCfg,
    pub metrics: Arc<crate::metrics::SignerMetrics>,
    /// Optional primary client-CN allow-list (SEC-4). Same Arc as gRPC when set.
    pub client_cn_allow_list: Option<Arc<crate::audit::ClientCnAllowList>>,
    /// Network genesis fork version ([`eth_types::NetworkPreset`]).
    ///
    /// Sole source for builder-registration domain computation (must match the
    /// gRPC service configuration for cross-transport signature equality).
    pub genesis_fork_version: [u8; 4],
}

/// Build the Web3Signer HTTP API `Router`.
///
/// Pure and socket-free: attach `state` and return the `Router`; the caller
/// (Phase 3 `run_serve`) wraps it in the TLS accept loop. Exercised in tests via
/// `tower::ServiceExt::oneshot` with no socket bound.
///
/// A [`DefaultBodyLimit`] of [`MAX_BODY_BYTES`] caps every request body (Issue
/// 2.11). The two other request-hardening layers are Phase-3 accept-loop
/// concerns and are deferred there: a **per-connection serve timeout** is applied
/// at `serve_connection`, and **panic isolation** is provided by tokio — each
/// accepted connection runs in its own `tokio::spawn`, so a panic in one
/// connection task is isolated and never reaches the gRPC listener or the process
/// accept loop (the handlers are already panic-free on attacker input).
pub fn router(state: Web3SignerState) -> Router {
    Router::new()
        .route("/upcheck", get(routes::upcheck))
        .route("/api/v1/eth2/publicKeys", get(routes::public_keys))
        .route("/api/v1/eth2/sign/:identifier", post(routes::sign))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

// ── Version-pin guard (R4) ───────────────────────────────────────────────────
//
// The HTTP transport reaches rustls via `tokio_rustls::rustls`; the gRPC/tonic
// stack and the `audit::cn` extractor bind rustls via the direct `rustls` dep.
// Both MUST resolve to the SAME rustls 0.23.x so there is a single
// `CertificateDer` / `pki_types` type across the binary — otherwise the
// accept loop's leaf client cert (Phase 3) could not be handed to `audit::cn`
// and the audit-CN plumbing would fail to compile or silently split types.
//
// This is a COMPILE-TIME identity assertion: the non-capturing closure coerces
// to a `fn` pointer only if `tokio_rustls::rustls::pki_types::CertificateDer`
// *is* `rustls::pki_types::CertificateDer` (the same type). If a transitive
// dependency (e.g. a `tokio-rustls`/`axum-server` that pulls a newer rustls)
// ever introduces a second rustls into this crate, the two paths resolve to
// different types and this line fails to compile — turning the version-skew risk
// into a build error.
const _: fn(
    tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) -> rustls::pki_types::CertificateDer<'static> = |cert| cert;

/// Shared test helpers for the `http_api` submodules.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::{AuditCfg, Web3SignerState};
    use crate::backend::{SigningBackend, SigningBackendError};

    /// A trivial in-memory backend for socket-free router tests.
    ///
    /// `sign` returns a fixed 96-byte blob for a loaded key and `KeyNotFound`
    /// otherwise — enough for routing/status tests. KAT sign tests that verify a
    /// real BLS signature use the production `BasicSigner` backend instead.
    pub struct MockBackend {
        keys: Vec<[u8; 48]>,
        sig: [u8; 96],
        sign_calls: AtomicUsize,
    }

    impl MockBackend {
        pub fn with_keys(keys: Vec<[u8; 48]>) -> Self {
            Self { keys, sig: [0xAB; 96], sign_calls: AtomicUsize::new(0) }
        }

        pub fn empty() -> Self {
            Self { keys: vec![], sig: [0xAB; 96], sign_calls: AtomicUsize::new(0) }
        }

        pub fn sign_call_count(&self) -> usize {
            self.sign_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl SigningBackend for MockBackend {
        async fn sign(
            &self,
            _signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], SigningBackendError> {
            self.sign_calls.fetch_add(1, Ordering::SeqCst);
            if self.keys.contains(pubkey) {
                Ok(self.sig)
            } else {
                Err(SigningBackendError::KeyNotFound(*pubkey))
            }
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.keys.clone()
        }
    }

    /// A backend that performs REAL BLS signing, for end-to-end KAT tests.
    ///
    /// Unlike [`MockBackend`] (fixed blob), `sign` produces a genuine BLS
    /// signature over the signing root, so a test can assert the gate returned
    /// `sk.sign(expected_root)` — proving the route computed the correct root
    /// and signed with the right key.
    pub struct RealSigningBackend {
        km: Arc<crypto::KeyManager>,
    }

    impl RealSigningBackend {
        pub fn with_key(sk: crypto::SecretKey) -> Self {
            let mut km = crypto::KeyManager::new();
            km.insert(sk);
            Self { km: Arc::new(km) }
        }
    }

    #[async_trait]
    impl SigningBackend for RealSigningBackend {
        async fn sign(
            &self,
            signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], SigningBackendError> {
            let pk = crypto::PublicKey::from_bytes(pubkey)
                .map_err(|_| SigningBackendError::KeyNotFound(*pubkey))?;
            let sk =
                self.km.get_secret_key(&pk).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;
            Ok(sk.sign(signing_root).to_bytes())
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
        }
    }

    /// A deterministic BLS keypair for KAT tests: returns the `SecretKey` and its
    /// 48-byte public key.
    pub fn test_keypair() -> (crypto::SecretKey, [u8; 48]) {
        let sk = crypto::eip2333::derive_master_sk(&[0x11u8; 32]).expect("derive master sk");
        let pk = sk.public_key().to_bytes();
        (sk, pk)
    }

    /// Build a [`Web3SignerState`] over an in-memory slashing DB and the given
    /// backend. The state type requires a gate, but the `/upcheck` and
    /// `/publicKeys` paths never invoke it.
    pub fn test_state(backend: Arc<dyn SigningBackend>) -> Web3SignerState {
        let db = Arc::new(slashing::SlashingDb::open_in_memory().expect("in-memory slashing DB"));
        let gate =
            Arc::new(crate::service::SignerServiceImpl::build_gate(Arc::clone(&backend), db));
        Web3SignerState {
            gate,
            backend,
            audit: AuditCfg::default(),
            metrics: Arc::new(crate::metrics::SignerMetrics::new()),
            client_cn_allow_list: None,
            genesis_fork_version: crate::sign_plan::BUILDER_FORK_VERSION_MAINNET,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // oneshot

    use super::test_support::{test_state, MockBackend};
    use super::*;

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn upcheck_returns_200_ok() {
        let state = test_state(Arc::new(MockBackend::with_keys(vec![[1u8; 48]])));
        let app = router(state);
        let resp = app
            .oneshot(Request::builder().uri("/upcheck").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "OK");
    }

    #[tokio::test]
    async fn upcheck_answers_without_invoking_the_gate() {
        // Even with an empty backend (no keys loaded), `/upcheck` answers 200 —
        // proving the liveness path has no gate/auth/state dependency (FR-1).
        let state = test_state(Arc::new(MockBackend::empty()));
        let app = router(state);
        let resp = app
            .oneshot(Request::builder().uri("/upcheck").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "OK");
    }

    #[tokio::test]
    async fn state_is_cheaply_cloneable() {
        let state = test_state(Arc::new(MockBackend::empty()));
        let _clone = state.clone(); // Arc clones only
        assert_eq!(state.audit.default_cn, signer::AUDIT_CN_DEFAULT);
    }

    // ── GET /api/v1/eth2/publicKeys (Issue 2.2, FR-2) ────────────────────────

    async fn public_keys(state: Web3SignerState) -> (StatusCode, Vec<String>) {
        let resp = router(state)
            .oneshot(Request::builder().uri("/api/v1/eth2/publicKeys").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let keys: Vec<String> = serde_json::from_slice(&bytes).unwrap();
        (status, keys)
    }

    #[tokio::test]
    async fn public_keys_lists_loaded_keys_as_0x_lowercase() {
        let k1 = [0x11u8; 48];
        let k2 = [0xabu8; 48];
        let state = test_state(Arc::new(MockBackend::with_keys(vec![k1, k2])));
        let (status, keys) = public_keys(state).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            keys,
            vec![format!("0x{}", "11".repeat(48)), format!("0x{}", "ab".repeat(48))],
            "keys must be 0x + lowercase hex, matching the gRPC pubkey_hex encoding"
        );
    }

    #[tokio::test]
    async fn public_keys_empty_backend_returns_empty_array() {
        let state = test_state(Arc::new(MockBackend::empty()));
        let (status, keys) = public_keys(state).await;
        assert_eq!(status, StatusCode::OK, "empty backend is 200, not 404");
        assert!(keys.is_empty());
    }

    /// Carry-forward from 2.1 review (CR-2): pin method/route negotiation now
    /// that more than one route exists.
    #[tokio::test]
    async fn unknown_route_404_and_wrong_method_405() {
        let state = test_state(Arc::new(MockBackend::empty()));
        let not_found = router(state.clone())
            .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        let wrong_method = router(state)
            .oneshot(Request::builder().method("POST").uri("/upcheck").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
