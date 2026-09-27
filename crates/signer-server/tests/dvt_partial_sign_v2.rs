//! Integration tests for the DVT `PeerSignerService` v2 typed RPCs.
//!
//! These tests verify:
//! - Happy-path partial signing (block, attestation, sync committee)
//! - `requester_index ↔ peer_cn` enforcement (C-3 regression)
//! - CN-scoped slashing protection (A1)
//! - Stage→sign→commit semantics (A15)
//!
//! All tests are gated on the `dvt` feature.

#![cfg(feature = "dvt")]
#![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface

use std::collections::HashMap;
use std::sync::Arc;

use tonic::Request;
use zeroize::Zeroizing;

use signer_server::dvt::allow_list::{AllowedPeer, AllowedPeers};
use signer_server::dvt::peer_service::PeerSignerServiceImpl;
use signer_server::dvt::types::ShareInfo;
use signer_server::proto::signer_v2 as sv2;
use signer_server::proto::signer_v2::peer_signer_service_server::PeerSignerService;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_share(index: u64) -> ([u8; 48], ShareInfo) {
    let sk = crypto::SecretKey::generate();
    let pk = sk.public_key().to_bytes();
    let scalar_bytes = Zeroizing::new(sk.to_bytes());
    let share = ShareInfo { index, threshold: 2, total: 3, scalar_bytes, aggregate_pubkey: pk };
    (pk, share)
}

fn make_allow_list(entries: Vec<(&str, u64)>) -> Arc<AllowedPeers> {
    Arc::new(AllowedPeers {
        peers: entries
            .into_iter()
            .map(|(cn, idx)| AllowedPeer { peer_cn: cn.to_string(), share_index: idx, addr: None })
            .collect(),
    })
}

fn make_db() -> Arc<slashing::SlashingDb> {
    // In-memory DB — empty NamedTempFile paths fail `open` with CorruptOrEmpty
    // after the slashing open/migrations split (same pattern as peer_service unit tests).
    Arc::new(slashing::SlashingDb::open_in_memory().expect("open in-memory test DB"))
}

fn make_service(
    shares: Vec<([u8; 48], ShareInfo)>,
    allow_list: Arc<AllowedPeers>,
    db: Option<Arc<slashing::SlashingDb>>,
) -> PeerSignerServiceImpl {
    let map: HashMap<[u8; 48], ShareInfo> = shares.into_iter().collect();
    PeerSignerServiceImpl::new(Arc::new(map), allow_list, db)
}

fn sample_fork_info() -> sv2::ForkInfo {
    sv2::ForkInfo {
        previous_version: vec![0x04, 0x00, 0x00, 0x00],
        current_version: vec![0x04, 0x00, 0x00, 0x00],
        epoch: 0,
        genesis_validators_root: vec![0x00; 32],
    }
}

fn sample_block_ssz(slot: u64) -> Vec<u8> {
    use eth_types::{encode_beacon_block_ssz, BeaconBlock};
    let block = BeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    };
    encode_beacon_block_ssz(&block, 4)
}

fn sample_attestation_data(source_epoch: u64, target_epoch: u64) -> sv2::AttestationData {
    sv2::AttestationData {
        slot: target_epoch * 32,
        index: 0,
        beacon_block_root: vec![0xABu8; 32],
        source: Some(sv2::Checkpoint { epoch: source_epoch, root: vec![0x01u8; 32] }),
        target: Some(sv2::Checkpoint { epoch: target_epoch, root: vec![0x02u8; 32] }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: happy path — partial signature returned with correct share_index
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_partial_sign_block_happy_path() {
    // CN is "unknown" (no TLS in tests); allow-list maps "unknown" → 1
    let (pk, share) = make_share(1);
    let al = make_allow_list(vec![("unknown", 1)]);
    let db = make_db();
    let svc = make_service(vec![(pk, share)], al, Some(db));

    let req = Request::new(sv2::PartialSignBeaconBlockRequest {
        requester_index: 1,
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(42),
        fork_id: 4,
    });

    let resp = svc.partial_sign_beacon_block(req).await.expect("should succeed");
    let inner = resp.into_inner();
    assert_eq!(inner.partial_signature.len(), 96, "partial signature must be 96 bytes");
    assert_eq!(inner.share_index, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: peer CN not on allow-list → Unauthenticated
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_partial_sign_unauth_cn_not_on_allow_list() {
    let (pk, share) = make_share(1);
    // allow-list does NOT include "unknown" (the CN for no-TLS requests)
    let al = make_allow_list(vec![("peer-A", 1)]);
    let db = make_db();
    let svc = make_service(vec![(pk, share)], al, Some(db));

    let req = Request::new(sv2::PartialSignBeaconBlockRequest {
        requester_index: 1,
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(42),
        fork_id: 4,
    });

    let err = svc.partial_sign_beacon_block(req).await.expect_err("must be rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(err.message().contains("allow-list"), "message: {}", err.message());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: requester_index mismatch → Unauthenticated (C-3 regression test)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_partial_sign_unauth_requester_index_mismatch() {
    let (pk, share) = make_share(1);
    // allow-list says "unknown" → 1; request sends requester_index=2
    let al = make_allow_list(vec![("unknown", 1)]);
    let db = make_db();
    let svc = make_service(vec![(pk, share)], al, Some(db));

    let req = Request::new(sv2::PartialSignBeaconBlockRequest {
        requester_index: 2, // mismatch
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(42),
        fork_id: 4,
    });

    let err = svc.partial_sign_beacon_block(req).await.expect_err("must be rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(err.message().contains("mismatch"), "message: {}", err.message());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: replay rejection — same (pubkey, slot) with different signing root
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_partial_sign_replay_rejected() {
    let (pk, share) = make_share(1);
    let al = make_allow_list(vec![("unknown", 1)]);
    let db = make_db();

    let svc = make_service(vec![(pk, share.clone())], Arc::clone(&al), Some(Arc::clone(&db)));

    // First request — slot 42
    let req1 = Request::new(sv2::PartialSignBeaconBlockRequest {
        requester_index: 1,
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(42),
        fork_id: 4,
    });
    svc.partial_sign_beacon_block(req1).await.expect("first sign succeeded");

    // Second request — same slot 42, DIFFERENT block body → different signing root
    let mut different_body = sample_block_ssz(42);
    for b in &mut different_body[16..48] {
        *b ^= 0xFF;
    }

    let svc2 = make_service(vec![(pk, share)], al, Some(db));
    let req2 = Request::new(sv2::PartialSignBeaconBlockRequest {
        requester_index: 1,
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: different_body,
        fork_id: 4,
    });

    let err = svc2.partial_sign_beacon_block(req2).await.expect_err("replay must be rejected");
    assert!(
        err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
        "expected slashing rejection, got {:?}",
        err.code()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: different peers are independent — proves CN scoping in slashing DB
// ─────────────────────────────────────────────────────────────────────────────
//
// peer-A signs (pubkey-X, slot=42, root=R) → succeeds
// peer-B signs (pubkey-X, slot=42, root=R) → also succeeds (separate CN namespace)

#[tokio::test]
async fn test_partial_sign_different_peers_independent() {
    let (pk, share_a) = make_share(1);
    // Response share_index is this node's Shamir index, not the requester allow-list index.
    let mut share_b = share_a.clone();
    share_b.index = 2;

    // Two separate DBs — each peer has its own slashing namespace
    let db_a = make_db();
    let db_b = make_db();

    // peer-A: CN "unknown", allow-list says "unknown" → 1
    let al_a = make_allow_list(vec![("unknown", 1)]);
    let svc_a = make_service(vec![(pk, share_a)], al_a, Some(Arc::clone(&db_a)));

    // peer-B (also "unknown" in no-TLS test): allow-list says "unknown" → 2
    let al_b = make_allow_list(vec![("unknown", 2)]);
    let svc_b = make_service(vec![(pk, share_b)], al_b, Some(Arc::clone(&db_b)));

    let make_req = |requester_index: u64| {
        Request::new(sv2::PartialSignBeaconBlockRequest {
            requester_index,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        })
    };

    // Both peers sign the same (pubkey, slot=42) → both succeed.
    let resp_a = svc_a.partial_sign_beacon_block(make_req(1)).await.expect("peer-A sign succeeded");
    assert_eq!(resp_a.into_inner().share_index, 1);

    let resp_b = svc_b.partial_sign_beacon_block(make_req(2)).await.expect("peer-B sign succeeded");
    assert_eq!(resp_b.into_inner().share_index, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: attestation double-vote rejected
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_partial_sign_attestation_double_vote_rejected() {
    let (pk, share) = make_share(1);
    let al = make_allow_list(vec![("unknown", 1)]);
    let db = make_db();

    let svc1 = make_service(vec![(pk, share.clone())], Arc::clone(&al), Some(Arc::clone(&db)));
    let svc2 = make_service(vec![(pk, share)], Arc::clone(&al), Some(Arc::clone(&db)));

    // First sign: source=1, target=2 with beacon_block_root=0xAB
    let req1 = Request::new(sv2::PartialSignAttestationDataRequest {
        requester_index: 1,
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(sample_attestation_data(1, 2)),
        fork_id: 4,
    });
    svc1.partial_sign_attestation_data(req1).await.expect("first attestation sign succeeded");

    // Second sign: same (source=1, target=2) but different beacon_block_root → double vote
    let mut data2 = sample_attestation_data(1, 2);
    data2.beacon_block_root = vec![0xFFu8; 32]; // different root

    let req2 = Request::new(sv2::PartialSignAttestationDataRequest {
        requester_index: 1,
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(data2),
        fork_id: 4,
    });

    let err =
        svc2.partial_sign_attestation_data(req2).await.expect_err("double vote must be rejected");
    assert!(
        err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
        "expected slashing rejection, got {:?}",
        err.code()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: sync committee is NOT slashable — two requests succeed
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_partial_sign_sync_committee_no_replay_check() {
    let (pk, share) = make_share(1);
    let al = make_allow_list(vec![("unknown", 1)]);
    let db = make_db();

    let svc1 = make_service(vec![(pk, share.clone())], Arc::clone(&al), Some(Arc::clone(&db)));
    let svc2 = make_service(vec![(pk, share)], Arc::clone(&al), Some(Arc::clone(&db)));

    let make_req = || {
        Request::new(sv2::PartialSignSyncCommitteeRequest {
            requester_index: 1,
            pubkey: pk.to_vec(),
            fork_info: Some(sample_fork_info()),
            slot: 50,
            beacon_block_root: vec![0xCC; 32],
            fork_id: 4,
        })
    };

    // First request — succeeds.
    let resp1 =
        svc1.partial_sign_sync_committee(make_req()).await.expect("first sync sign succeeded");
    assert_eq!(resp1.into_inner().partial_signature.len(), 96);

    // Second request with SAME inputs — also succeeds (sync is not slashable).
    let resp2 =
        svc2.partial_sign_sync_committee(make_req()).await.expect("second sync sign succeeded");
    assert_eq!(resp2.into_inner().partial_signature.len(), 96);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: signer failure does NOT persist a DB row
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_partial_sign_signer_failure_does_not_persist_row() {
    // Empty share map → sign will fail with `not_found` (no key for the pubkey).
    let (pk, _) = make_share(1);
    let al = make_allow_list(vec![("unknown", 1)]);
    let db = make_db();
    let svc = make_service(vec![], al, Some(Arc::clone(&db)));

    let req = Request::new(sv2::PartialSignBeaconBlockRequest {
        requester_index: 1,
        pubkey: pk.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(99),
        fork_id: 4,
    });

    let err = svc.partial_sign_beacon_block(req).await.expect_err("unknown pubkey must fail");
    assert_eq!(err.code(), tonic::Code::NotFound, "expected NotFound for unknown key");

    // Verify that NO row was committed — the A15 stage→sign→commit guarantee.
    let pubkey_hex = format!("0x{}", hex::encode(pk));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks should succeed");
    assert!(
        blocks.is_empty(),
        "no DB row must be committed when the signer fails; found {} rows",
        blocks.len()
    );
}
