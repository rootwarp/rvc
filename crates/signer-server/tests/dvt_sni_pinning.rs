//! Regression tests for ISSUE-4.1 / L-1: per-peer SNI pinning in DVT TLS.
//!
//! Formerly `dvt_sni_pinning_l1.rs` (audit issue L-1 / ISSUE-4.1).
//!
//! # Background
//!
//! Before this fix, `GrpcPeerRequester::connect` applied the same
//! `ClientTlsConfig` (no `domain_name`) to every peer endpoint.  A
//! certificate valid for `peer-A` under the shared CA was therefore accepted
//! when the client thought it was connecting to `peer-B`, breaking the
//! separate-identity guarantee that mTLS is meant to provide.
//!
//! # Fix
//!
//! Each `PeerConnectInfo` carries an `sni_cn` field.  `connect` now calls
//! `.domain_name(&peer.sni_cn)` on the per-peer `ClientTlsConfig` clone before
//! dialling.  rustls then verifies that the server certificate is issued for
//! that exact hostname — rejecting any cert issued for a different peer.
//!
//! # Test strategy
//!
//! - `test_wrong_peer_cert_refused` — server holds a cert for `peer-a.local`;
//!   client expects `peer-b.local`; handshake must fail.  This was the RED
//!   test before `PeerConnectInfo` existed (compile-time failure), and is now
//!   GREEN with the fix.
//!
//! - `test_correct_peer_cert_accepted` — same server; client expects
//!   `peer-a.local`; handshake must succeed.
//!
//! - `test_lookup_by_addr_roundtrip` / `test_lookup_by_addr_missing` — unit
//!   tests for the new `AllowedPeers::lookup_by_addr` helper.

#![cfg(feature = "dvt")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rvc_test_support::{TestPki, TestPkiParams};
use tempfile::TempDir;

use signer_server::backend::dvt::{PartialSignDuty, PeerRequester};
use signer_server::dvt::allow_list::{AllowedPeer, AllowedPeers};
use signer_server::dvt::peer_client::{
    build_peer_connect_infos, GrpcPeerRequester, PeerConnectInfo,
};
use signer_server::dvt::peer_service::PeerSignerServiceImpl;
use signer_server::dvt::types::ShareInfo;
use signer_server::grpc_tls::TlsConfig;
use signer_server::proto::signer_v2::{AttestationData, ForkInfo};
use signer_server::PeerSignerServiceServerV2;

// ─────────────────────────────────────────────────────────────────────────────
// Cert / TLS helpers
// ─────────────────────────────────────────────────────────────────────────────

/// All cert artifacts for one test run.
struct TestCerts {
    /// Shared PKI (CA + server + client).
    pki: TestPki,
    /// `TlsConfig` that the client passes to `GrpcPeerRequester::connect`.
    /// Points to temp files on disk (kept alive by `_dir`).
    client_tls_config: TlsConfig,
    /// Temp directory owning the client cert files; must outlive the test.
    _dir: TempDir,
}

/// Generate CA → server cert (DNS SAN = `sni_name`) → client cert.
///
/// The server cert has DNS SAN = `sni_name` and IP SAN = `127.0.0.1`.
/// The IP SAN is required to make `test_wrong_peer_cert_refused` a genuine
/// RED→GREEN regression test (see the inline comment below for the full
/// reasoning).
fn generate_test_certs(sni_name: &str) -> TestCerts {
    // Server cert: DNS SAN = sni_name + IP SAN = 127.0.0.1.
    //
    // The IP SAN is critical for making the test a genuine RED→GREEN.  Without
    // it, tonic falls back to verifying the URI host (`127.0.0.1`) against the
    // cert, which fails for missing IP SAN on BOTH old code (no domain_name)
    // AND new code — making the assertion vacuously true.
    //
    // With the IP SAN present:
    //   - Old code (no domain_name): URI host `127.0.0.1` → cert has IP SAN →
    //     connection SUCCEEDS → `test_wrong_peer_cert_refused` FAILS (RED).
    //   - New code (domain_name("peer-b.local")): cert has `peer-a.local` SAN,
    //     NOT `peer-b.local` → rustls rejects → FAILS → assertion passes (GREEN).
    let pki = TestPki::generate(TestPkiParams {
        ca_name: "test-ca.internal".to_string(),
        server_sans: vec![sni_name.to_string(), "127.0.0.1".to_string()],
        client_name: "test-client.internal".to_string(),
    });

    let dir = TempDir::new().unwrap();
    let paths = pki.write_client_pem(dir.path());
    let client_tls_config = TlsConfig::new(paths.cert, paths.key, paths.ca_cert);

    TestCerts { pki, client_tls_config, _dir: dir }
}

/// Spin up a tonic gRPC server with mTLS on `127.0.0.1:0`.
///
/// Returns the bound port.  The server task runs until dropped.
async fn start_mtls_server(pki: &TestPki) -> u16 {
    // Minimal DVT peer service — no real shares, but the TLS handshake and
    // HTTP/2 settings exchange happen before any RPC is dispatched.
    let share_map: Arc<HashMap<[u8; 48], ShareInfo>> = Arc::new(HashMap::new());
    let allow_list = Arc::new(AllowedPeers {
        peers: vec![AllowedPeer { peer_cn: "test".to_string(), share_index: 1, addr: None }],
    });
    let peer_svc = PeerSignerServiceImpl::new(share_map, allow_list, None);

    let (addr, _handle) = rvc_test_support::start_mtls_server(pki, move |mut server| {
        server.add_service(PeerSignerServiceServerV2::new(peer_svc))
    })
    .await;

    addr.port()
}

/// Body the peer service rejects before signing. Reaching this string means
/// the TLS handshake completed; a wrong SNI never gets that far.
const REACHED_PEER_SERVICE: &str = "slashing protection database is not configured";

fn attestation_duty() -> PartialSignDuty {
    PartialSignDuty::AttestationData {
        fork_info: ForkInfo {
            previous_version: vec![0, 0, 0, 0],
            current_version: vec![1, 0, 0, 0],
            epoch: 0,
            genesis_validators_root: vec![0u8; 32],
        },
        data: AttestationData {
            slot: 1,
            index: 0,
            beacon_block_root: vec![0u8; 32],
            source: None,
            target: None,
        },
        fork_id: 4,
    }
}

async fn rpc_after_lazy_connect(peer: &PeerConnectInfo, tls: &TlsConfig) -> String {
    let requester = GrpcPeerRequester::connect(
        std::slice::from_ref(peer),
        Some(tls),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .expect("lazy connect does not dial");
    requester
        .request_partial(&peer.addr, &attestation_duty(), &[0u8; 48], 1)
        .await
        .expect_err("fixture peer has no slashing DB")
        .to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 (RED → GREEN): wrong SNI — server cert for peer-A rejected for peer-B
// ─────────────────────────────────────────────────────────────────────────────

/// Regression test for L-1 SNI pinning.
///
/// The server holds a cert valid for `peer-a.local`.  The client connects
/// with `sni_cn = "peer-b.local"` (wrong peer identity).  After the fix,
/// rustls rejects the handshake because the cert is not issued for
/// `peer-b.local`.
///
/// **RED before fix**: `PeerConnectInfo` did not exist — this test did not
/// compile, proving the API did not support per-peer SNI at all.
/// **GREEN after fix**: test compiles, connection fails as required.
#[tokio::test]
async fn test_wrong_peer_cert_refused() {
    let certs = generate_test_certs("peer-a.local");
    let port = start_mtls_server(&certs.pki).await;

    // Client expects peer-b.local, but server holds a cert for peer-a.local.
    let peer =
        PeerConnectInfo { addr: format!("127.0.0.1:{}", port), sni_cn: "peer-b.local".to_string() };

    let msg = rpc_after_lazy_connect(&peer, &certs.client_tls_config).await;
    assert!(
        !msg.contains(REACHED_PEER_SERVICE),
        "wrong SNI must fail the handshake before the peer service; got {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: correct SNI — server cert for peer-A accepted for peer-A
// ─────────────────────────────────────────────────────────────────────────────

/// Sanity check: connecting with the matching SNI must succeed.
#[tokio::test]
async fn test_correct_peer_cert_accepted() {
    let certs = generate_test_certs("peer-a.local");
    let port = start_mtls_server(&certs.pki).await;

    let peer =
        PeerConnectInfo { addr: format!("127.0.0.1:{}", port), sni_cn: "peer-a.local".to_string() };

    let msg = rpc_after_lazy_connect(&peer, &certs.client_tls_config).await;
    assert!(
        msg.contains(REACHED_PEER_SERVICE),
        "matching SNI must complete the handshake and reach the peer service; got {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: unit — lookup_by_addr found
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lookup_by_addr_found() {
    let peers = AllowedPeers {
        peers: vec![
            AllowedPeer {
                peer_cn: "peer-a.local".to_string(),
                share_index: 1,
                addr: Some("127.0.0.1:50051".to_string()),
            },
            AllowedPeer {
                peer_cn: "peer-b.local".to_string(),
                share_index: 2,
                addr: Some("127.0.0.1:50052".to_string()),
            },
        ],
    };

    let hit = peers.lookup_by_addr("127.0.0.1:50051").unwrap();
    assert_eq!(hit.peer_cn, "peer-a.local");
    assert_eq!(hit.share_index, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: unit — lookup_by_addr missing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lookup_by_addr_missing() {
    let peers = AllowedPeers {
        peers: vec![AllowedPeer {
            peer_cn: "peer-a.local".to_string(),
            share_index: 1,
            addr: Some("127.0.0.1:50051".to_string()),
        }],
    };

    assert!(peers.lookup_by_addr("10.0.0.1:50051").is_none());
    assert!(peers.lookup_by_addr("127.0.0.1:50099").is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: unit — lookup_by_addr when addr field is None
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lookup_by_addr_no_addr_field() {
    let peers = AllowedPeers {
        peers: vec![AllowedPeer {
            peer_cn: "peer-a.local".to_string(),
            share_index: 1,
            addr: None, // no addr configured
        }],
    };

    // Should not match anything if addr is None
    assert!(peers.lookup_by_addr("127.0.0.1:50051").is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 (RED → GREEN): startup fails when peer addr not in allow-list
//
// Verifies Must-Fix #1: `build_peer_connect_infos` with TLS enabled must
// return an error when a dvt_peer address has no matching `addr=` entry in
// the allow-list, rather than silently falling back to no-SNI pinning.
//
// RED before fix: `build_peer_connect_infos` did not exist.
// GREEN after fix: returns Err with a clear message; L-1 bypass closed.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_startup_fails_when_peer_addr_missing_from_allowlist() {
    // Allow-list covers peer-a only; peer-b has no `addr=` entry.
    let allow_list = AllowedPeers {
        peers: vec![AllowedPeer {
            peer_cn: "peer-a.local".to_string(),
            share_index: 1,
            addr: Some("peer-a.local:50051".to_string()),
        }],
    };

    let peer_addrs = vec![
        "peer-a.local:50051".to_string(),
        "peer-b.local:50052".to_string(), /* no entry */
    ];

    let result = build_peer_connect_infos(&peer_addrs, Some(&allow_list), true /* TLS on */);

    assert!(
        result.is_err(),
        "startup must fail when a DVT peer addr is missing from the allow-list under TLS"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("peer-b.local:50052"),
        "error message must name the offending peer; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: build_peer_connect_infos — no allow-list with TLS fails at startup
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_startup_fails_without_allowlist_when_tls_enabled() {
    let peer_addrs = vec!["peer-a.local:50051".to_string()];
    let result =
        build_peer_connect_infos(&peer_addrs, None /* no allow-list */, true /* TLS */);
    assert!(result.is_err(), "startup must fail when TLS is enabled and no allow-list is provided");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: build_peer_connect_infos — no TLS, any addr is accepted without SNI
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_no_tls_accepts_any_addr() {
    let peer_addrs = vec!["peer-a.local:50051".to_string(), "peer-b.local:50052".to_string()];
    let result = build_peer_connect_infos(&peer_addrs, None, false /* TLS off */);
    assert!(result.is_ok());
    let infos = result.unwrap();
    assert_eq!(infos.len(), 2);
    // sni_cn should be empty when TLS is disabled
    assert!(infos.iter().all(|p| p.sni_cn.is_empty()));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: build_peer_connect_infos — happy path with full allow-list match
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_startup_succeeds_when_all_addrs_in_allowlist() {
    let allow_list = AllowedPeers {
        peers: vec![
            AllowedPeer {
                peer_cn: "peer-a.local".to_string(),
                share_index: 1,
                addr: Some("peer-a.local:50051".to_string()),
            },
            AllowedPeer {
                peer_cn: "peer-b.local".to_string(),
                share_index: 2,
                addr: Some("peer-b.local:50052".to_string()),
            },
        ],
    };

    let peer_addrs = vec!["peer-a.local:50051".to_string(), "peer-b.local:50052".to_string()];

    let result = build_peer_connect_infos(&peer_addrs, Some(&allow_list), true);
    assert!(result.is_ok(), "all addrs covered → must succeed; err: {:?}", result.err());

    let infos = result.unwrap();
    assert_eq!(infos[0].sni_cn, "peer-a.local");
    assert_eq!(infos[1].sni_cn, "peer-b.local");
}
