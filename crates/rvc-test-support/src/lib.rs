//! Shared, **dev-only** PKI + mTLS harness for integration tests.
//!
//! This crate MUST remain a `[dev-dependencies]` entry only (never a runtime
//! dependency of a binary or library). It is pinned in
//! `architecture_no_cycles`'s `ZERO_OUT_EDGE_IF_PRESENT` list so it cannot grow
//! workspace-internal production out-edges.
//!
//! # What it provides
//!
//! - [`TestPki`] — one-shot CA + server + client cert material (PEM + DER)
//! - [`start_mtls_server`] — bind `127.0.0.1:0`, serve a tonic service over mTLS
//! - Self-signed leaf helpers for audit-CN / unit-test fixtures
//! - On-disk PEM writers for process-boundary fixtures (`TlsConfig` paths)
//!
//! All `rcgen` usage in the workspace should live here.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

// ---------------------------------------------------------------------------
// TestPki
// ---------------------------------------------------------------------------

/// Parameters for [`TestPki::generate`].
#[derive(Debug, Clone)]
pub struct TestPkiParams {
    /// CA subject / SAN name (also used as the CA common name).
    pub ca_name: String,
    /// Server SANs (DNS and/or IP strings accepted by `CertificateParams::new`).
    /// The first entry is also used as the server certificate common name.
    pub server_sans: Vec<String>,
    /// Client subject name (SAN + common name).
    pub client_name: String,
}

impl Default for TestPkiParams {
    fn default() -> Self {
        Self {
            ca_name: "rvc-test-ca".to_string(),
            server_sans: vec!["localhost".to_string()],
            client_name: "rvc-client".to_string(),
        }
    }
}

/// CA + server + client certificate material for one test run.
///
/// PEM fields feed tonic/`Identity`; DER fields feed rustls `CertificateDer`
/// wrappers in unit tests without re-minting.
#[derive(Debug, Clone)]
pub struct TestPki {
    pub ca_cert_pem: Vec<u8>,
    pub server_cert_pem: Vec<u8>,
    pub server_key_pem: Vec<u8>,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_cert_der: Vec<u8>,
    pub server_cert_der: Vec<u8>,
    pub server_key_der: Vec<u8>,
    pub client_cert_der: Vec<u8>,
    pub client_key_der: Vec<u8>,
}

impl Default for TestPki {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPki {
    /// Default PKI: CA `rvc-test-ca`, server SAN `localhost`, client `rvc-client`.
    pub fn new() -> Self {
        Self::generate(TestPkiParams::default())
    }

    /// Server SANs only (CA/client keep defaults). Useful for SNI-pinning tests
    /// that need DNS + IP SANs (e.g. `["peer-a.local", "127.0.0.1"]`).
    pub fn with_server_sans(sans: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::generate(TestPkiParams {
            server_sans: sans.into_iter().map(Into::into).collect(),
            ..TestPkiParams::default()
        })
    }

    /// Full control over CA / server SAN / client names.
    pub fn generate(params: TestPkiParams) -> Self {
        assert!(!params.server_sans.is_empty(), "TestPki requires at least one server SAN");

        // CA (unconstrained) so it can sign server + client leaves.
        let mut ca_params =
            CertificateParams::new(vec![params.ca_name.clone()]).expect("CA CertificateParams");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params.distinguished_name.push(DnType::CommonName, params.ca_name.clone());
        let ca_key = KeyPair::generate().expect("CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");

        // Server leaf: SANs as requested; CN = first SAN for audit extractors.
        let mut server_params =
            CertificateParams::new(params.server_sans.clone()).expect("server CertificateParams");
        server_params.distinguished_name = DistinguishedName::new();
        server_params.distinguished_name.push(DnType::CommonName, params.server_sans[0].clone());
        let server_key = KeyPair::generate().expect("server key");
        let server_cert =
            server_params.signed_by(&server_key, &ca_cert, &ca_key).expect("sign server cert");

        // Client leaf signed by the same CA (mTLS client auth).
        let mut client_params = CertificateParams::new(vec![params.client_name.clone()])
            .expect("client CertificateParams");
        client_params.distinguished_name = DistinguishedName::new();
        client_params.distinguished_name.push(DnType::CommonName, params.client_name.clone());
        let client_key = KeyPair::generate().expect("client key");
        let client_cert =
            client_params.signed_by(&client_key, &ca_cert, &ca_key).expect("sign client cert");

        Self {
            ca_cert_pem: ca_cert.pem().into_bytes(),
            server_cert_pem: server_cert.pem().into_bytes(),
            server_key_pem: server_key.serialize_pem().into_bytes(),
            client_cert_pem: client_cert.pem().into_bytes(),
            client_key_pem: client_key.serialize_pem().into_bytes(),
            ca_cert_der: ca_cert.der().as_ref().to_vec(),
            server_cert_der: server_cert.der().as_ref().to_vec(),
            server_key_der: server_key.serialize_der(),
            client_cert_der: client_cert.der().as_ref().to_vec(),
            client_key_der: client_key.serialize_der(),
        }
    }

    /// tonic `ServerTlsConfig` presenting the server identity and requiring a
    /// client cert signed by this PKI's CA.
    pub fn server_tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(&self.server_cert_pem, &self.server_key_pem))
            .client_ca_root(Certificate::from_pem(&self.ca_cert_pem))
    }

    /// Write CA + server cert/key PEMs under `dir` (`ca.pem`, `server.pem`,
    /// `server.key`). Returns the three paths.
    pub fn write_server_pem(&self, dir: &Path) -> PemPaths {
        let ca_cert = dir.join("ca.pem");
        let cert = dir.join("server.pem");
        let key = dir.join("server.key");
        std::fs::write(&ca_cert, &self.ca_cert_pem).expect("write ca.pem");
        std::fs::write(&cert, &self.server_cert_pem).expect("write server.pem");
        std::fs::write(&key, &self.server_key_pem).expect("write server.key");
        PemPaths { ca_cert, cert, key }
    }

    /// Write CA + client cert/key PEMs under `dir` (`ca.pem`, `client.pem`,
    /// `client.key`). Returns the three paths.
    pub fn write_client_pem(&self, dir: &Path) -> PemPaths {
        let ca_cert = dir.join("ca.pem");
        let cert = dir.join("client.pem");
        let key = dir.join("client.key");
        std::fs::write(&ca_cert, &self.ca_cert_pem).expect("write ca.pem");
        std::fs::write(&cert, &self.client_cert_pem).expect("write client.pem");
        std::fs::write(&key, &self.client_key_pem).expect("write client.key");
        PemPaths { ca_cert, cert, key }
    }
}

/// Paths produced by [`TestPki::write_server_pem`] / [`TestPki::write_client_pem`].
#[derive(Debug, Clone)]
pub struct PemPaths {
    pub ca_cert: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

// ---------------------------------------------------------------------------
// mTLS server harness
// ---------------------------------------------------------------------------

/// Install `ring` as rustls's process-global provider.
///
/// `--workspace --all-features` unifies `aws_lc_rs` (google-cloud, via
/// `gcp-secret`) onto the same rustls that the rest of the workspace builds
/// with `ring`. tonic's `Server::tls_config` then panics in
/// `CryptoProvider::get_default_or_install_from_crate_features` unless a
/// default is already installed. Idempotent: a second call is a no-op.
fn install_ring_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Bind `127.0.0.1:0`, apply mTLS from `pki`, and spawn a tonic server.
///
/// `add_services` receives a post-TLS `Server` and must return a `Router`
/// (typically `server.add_service(...)`). The server task runs until dropped.
///
/// Returns the bound address and the join handle.
pub async fn start_mtls_server<F>(
    pki: &TestPki,
    add_services: F,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: FnOnce(Server) -> tonic::transport::server::Router + Send + 'static,
{
    // Before the spawned task applies TLS, and before the caller dials.
    install_ring_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");
    let tls = pki.server_tls_config();

    let handle = tokio::spawn(async move {
        let server = Server::builder().tls_config(tls).expect("mTLS ServerTlsConfig");
        let router = add_services(server);
        let _ = router.serve_with_incoming(TcpListenerStream::new(listener)).await;
    });

    // Yield so the spawned task can start accepting before callers dial.
    tokio::task::yield_now().await;
    // A short sleep covers slow CI hosts where yield alone is not enough.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (addr, handle)
}

// ---------------------------------------------------------------------------
// Self-signed leaf helpers (audit-CN / unit fixtures)
// ---------------------------------------------------------------------------

/// Self-signed leaf DER whose subject contains a single CN RDN.
pub fn self_signed_der_with_cn(cn: &str) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().expect("key");
    params.self_signed(&key).expect("self-sign").der().as_ref().to_vec()
}

/// Self-signed leaf DER with **two** CN RDN entries (first, then second).
///
/// rcgen's `DistinguishedName` is an `IndexMap<DnType, DnValue>`, so a second
/// `push(DnType::CommonName, …)` would overwrite the first. The second entry is
/// stored under `CustomDnType([2,5,4,3])` (same OID arcs as CN) so both survive
/// serialisation — needed by M-4 first-CN audit tests.
pub fn self_signed_der_with_two_cns(first_cn: &str, second_cn: &str) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, first_cn);
    params.distinguished_name.push(DnType::CustomDnType(vec![2, 5, 4, 3]), second_cn);
    let key = KeyPair::generate().expect("key");
    params.self_signed(&key).expect("self-sign").der().as_ref().to_vec()
}

/// Self-signed leaf DER with an Organisation but **no** CN.
pub fn self_signed_der_without_cn() -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::OrganizationName, "TestOrg");
    let key = KeyPair::generate().expect("key");
    params.self_signed(&key).expect("self-sign").der().as_ref().to_vec()
}

/// Self-signed leaf DER with an optional CN and a fixed host SAN
/// (`host.example`). When `cn` is `None` the subject has no CN RDN.
pub fn self_signed_der_optional_cn(cn: Option<&str>) -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["host.example".to_string()]).expect("params");
    params.distinguished_name = DistinguishedName::new();
    if let Some(cn) = cn {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    let key = KeyPair::generate().expect("key");
    params.self_signed(&key).expect("self-sign").der().as_ref().to_vec()
}

/// Self-signed leaf whose SAN and CN are both `cn`. Returns owned DER suitable
/// for `CertificateDer::from(...)`.
pub fn self_signed_leaf_der(cn: &str) -> Vec<u8> {
    let mut params = CertificateParams::new(vec![cn.to_string()]).expect("params");
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().expect("key");
    params.self_signed(&key).expect("self-sign").der().as_ref().to_vec()
}

/// Wiremock responder that notifies a channel when a request is recorded.
///
/// The send happens in [`Respond::respond`], after wiremock has stored the
/// request. Waiting on the receiver is the publish, not a clock.
#[derive(Clone)]
pub struct SignalOnReceipt {
    body: wiremock::ResponseTemplate,
    tx: std::sync::mpsc::Sender<()>,
}

impl SignalOnReceipt {
    /// Pair `body` with a sender. Clone the sender to share one receiver.
    #[must_use]
    pub fn new(body: wiremock::ResponseTemplate, tx: std::sync::mpsc::Sender<()>) -> Self {
        Self { body, tx }
    }
}

impl wiremock::Respond for SignalOnReceipt {
    fn respond(&self, _request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let _ = self.tx.send(());
        self.body.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pki_default_has_pem_and_der() {
        let pki = TestPki::new();
        assert!(pki.ca_cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(pki.server_cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(pki.client_cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(!pki.ca_cert_der.is_empty());
        assert!(!pki.server_key_der.is_empty());
        assert!(!pki.client_key_der.is_empty());
    }

    #[test]
    fn test_pki_with_server_sans() {
        let pki = TestPki::with_server_sans(["peer-a.local", "127.0.0.1"]);
        assert!(!pki.server_cert_pem.is_empty());
    }

    #[test]
    fn self_signed_helpers_produce_der() {
        assert!(!self_signed_der_with_cn("alice").is_empty());
        assert!(!self_signed_der_with_two_cns("a", "b").is_empty());
        assert!(!self_signed_der_without_cn().is_empty());
        assert!(!self_signed_der_optional_cn(None).is_empty());
        assert!(!self_signed_leaf_der("bob").is_empty());
    }
}
