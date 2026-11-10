//! Cached duties from a revoked beacon node are not served.
//!
//! The tracker is built as `bootstrap/services.rs` builds it: on the real
//! `BnManager`, through `DutyTracker::new_with_source` and the production
//! index source.

use std::collections::HashMap;
use std::sync::Arc;

use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig, DutiesProvider};
use crypto::SecretKey;
use duty_tracker::DutyTracker;
use eth_types::ForkSchedule;
use parking_lot::RwLock;
use rvc::orchestrator::PubkeyMap;
use rvc::pubkey_index::{pubkey_bytes_to_0x, PubkeyIndexRegistry, PubkeyIndexSource};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const EPOCH: u64 = 10;
const SLOT: u64 = EPOCH * 32 + 3;
const VALIDATOR_INDEX: &str = "7";
const FIRST_ROOT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const SECOND_ROOT: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

fn attester_path() -> String {
    format!("/eth/v1/validator/duties/attester/{EPOCH}")
}

async fn attester_bn(dependent_root: &str, pubkey_hex: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(attester_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": dependent_root,
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": VALIDATOR_INDEX,
                "committee_index": "0",
                "committee_length": "4",
                "committees_at_slot": "1",
                "validator_committee_index": "0",
                "slot": SLOT.to_string()
            }]
        })))
        .mount(&server)
        .await;
    server
}

async fn attester_hits(server: &MockServer) -> usize {
    let requests: Vec<Request> = server.received_requests().await.expect("requests");
    requests.iter().filter(|request| request.url.path() == attester_path()).count()
}

#[tokio::test]
async fn attester_duties_cached_from_before_a_revocation_are_not_served() {
    let pubkey = SecretKey::generate().public_key();
    let pubkey_bytes = pubkey.to_bytes();
    let pubkey_hex = pubkey_bytes_to_0x(&pubkey_bytes);
    let first = attester_bn(FIRST_ROOT, &pubkey_hex).await;
    let second = attester_bn(SECOND_ROOT, &pubkey_hex).await;
    let bn_manager = Arc::new(
        BnManager::new(BnManagerConfig::new(vec![first.uri(), second.uri()])).expect("manager"),
    );

    let mut registry = PubkeyIndexRegistry::new();
    registry.insert(pubkey_bytes, VALIDATOR_INDEX.to_string());
    let pubkey_map: PubkeyMap = Arc::new(RwLock::new(HashMap::from([(pubkey_bytes, pubkey)])));
    let index_source =
        Arc::new(PubkeyIndexSource { registry: Arc::new(RwLock::new(registry)), pubkey_map });
    let tracker = DutyTracker::new_with_source(
        Arc::clone(&bn_manager) as Arc<dyn DutiesProvider>,
        index_source,
    );

    tracker.fetch_duties_for_epoch(EPOCH).await.expect("fetch from the first node");
    assert_eq!(tracker.get_duties_for_slot(SLOT).await.len(), 1);
    assert!(tracker.is_epoch_cached(EPOCH).await);
    assert_eq!((attester_hits(&first).await, attester_hits(&second).await), (1, 0));

    bn_manager.testing_revoke_admission(0);

    assert!(
        tracker.get_duties_for_slot(SLOT).await.is_empty(),
        "duties cached from the revoked node must not be served"
    );
    assert!(!tracker.is_epoch_cached(EPOCH).await, "the revoked node's epoch reads as uncached");

    tracker.fetch_duties_for_epoch(EPOCH).await.expect("refetch from the admitted node");
    assert_eq!((attester_hits(&first).await, attester_hits(&second).await), (1, 1));
    assert_eq!(tracker.get_duties_for_slot(SLOT).await.len(), 1);
    assert_eq!(tracker.get_cached_dependent_root(EPOCH).await.as_deref(), Some(SECOND_ROOT));
}

fn proposer_path() -> String {
    format!("/eth/v1/validator/duties/proposer/{EPOCH}")
}

async fn proposer_bn(dependent_root: &str, pubkey_hex: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(proposer_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": dependent_root,
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": VALIDATOR_INDEX,
                "slot": SLOT.to_string()
            }]
        })))
        .mount(&server)
        .await;
    server
}

/// Two proposer BNs behind one `BnManager`, and a tracker built on it as
/// `bootstrap/services.rs` builds it (fork schedule included: it routes
/// proposer duties v1/v2).
struct ProposerBns {
    first: MockServer,
    second: MockServer,
    bn_manager: Arc<BnManager>,
    tracker: DutyTracker,
}

impl ProposerBns {
    async fn start() -> Self {
        let pubkey = SecretKey::generate().public_key();
        let pubkey_bytes = pubkey.to_bytes();
        let pubkey_hex = pubkey_bytes_to_0x(&pubkey_bytes);
        let first = proposer_bn(FIRST_ROOT, &pubkey_hex).await;
        let second = proposer_bn(SECOND_ROOT, &pubkey_hex).await;
        let bn_manager = Arc::new(
            BnManager::new(BnManagerConfig::new(vec![first.uri(), second.uri()])).expect("manager"),
        );

        let mut registry = PubkeyIndexRegistry::new();
        registry.insert(pubkey_bytes, VALIDATOR_INDEX.to_string());
        let pubkey_map: PubkeyMap = Arc::new(RwLock::new(HashMap::from([(pubkey_bytes, pubkey)])));
        let index_source =
            Arc::new(PubkeyIndexSource { registry: Arc::new(RwLock::new(registry)), pubkey_map });
        let tracker = DutyTracker::new_with_source(
            Arc::clone(&bn_manager) as Arc<dyn DutiesProvider>,
            index_source,
        )
        .with_fork_schedule(ForkSchedule::unscheduled_gloas());
        Self { first, second, bn_manager, tracker }
    }

    /// Proposer-duty requests received by (first, second).
    async fn hits(&self) -> (usize, usize) {
        let count = |requests: Vec<Request>| {
            requests.iter().filter(|request| request.url.path() == proposer_path()).count()
        };
        (
            count(self.first.received_requests().await.expect("requests")),
            count(self.second.received_requests().await.expect("requests")),
        )
    }
}

#[tokio::test]
async fn proposer_duty_cached_before_a_revocation_is_not_served() {
    let bns = ProposerBns::start().await;
    let tracker = &bns.tracker;

    tracker.fetch_proposer_duties(EPOCH).await.expect("fetch from the first node");
    assert!(tracker.get_proposer_duty(SLOT).await.is_some());
    assert!(tracker.is_proposer_epoch_cached(EPOCH).await);
    assert_eq!(bns.hits().await, (1, 0));

    bns.bn_manager.testing_revoke_admission(0);

    assert!(
        tracker.get_proposer_duty(SLOT).await.is_none(),
        "a proposer duty cached from the revoked node must not be served"
    );
    assert!(
        !tracker.is_proposer_epoch_cached(EPOCH).await,
        "the revoked node's epoch reads as uncached"
    );

    tracker.fetch_proposer_duties(EPOCH).await.expect("refetch from the admitted node");
    assert_eq!(bns.hits().await, (1, 1));
    assert!(tracker.get_proposer_duty(SLOT).await.is_some());
    assert_eq!(
        tracker.get_cached_proposer_dependent_root(EPOCH).await.as_deref(),
        Some(SECOND_ROOT)
    );
}

#[tokio::test]
async fn a_fence_captured_after_a_revocation_never_sees_older_duties() {
    let bns = ProposerBns::start().await;
    let tracker = &bns.tracker;
    tracker.fetch_proposer_duties(EPOCH).await.expect("cache under G");
    let seen_at_fetch = bns.bn_manager.revocation_watch().seen();

    bns.bn_manager.testing_revoke_admission(0);
    let fence = bns.bn_manager.revocation_watch();
    assert_eq!(fence.seen(), seen_at_fetch + 1, "the fence is captured after the revocation");

    assert!(
        tracker.get_proposer_duty(SLOT).await.is_none(),
        "a fence holder is never handed a duty fetched before its fence, though nothing cleared the cache"
    );

    tracker.fetch_proposer_duties(EPOCH).await.expect("refetch under G+1");
    assert!(tracker.get_proposer_duty(SLOT).await.is_some(), "the refetched duty is served");
    assert!(fence.holds(), "and it was served while the fence holds");

    bns.bn_manager.testing_revoke_admission(1);
    assert!(!fence.holds());
    assert!(tracker.get_proposer_duty(SLOT).await.is_none(), "a second revocation drops it again");
}

fn ptc_path() -> String {
    format!("/eth/v1/validator/duties/ptc/{EPOCH}")
}

fn sync_path() -> String {
    format!("/eth/v1/validator/duties/sync/{EPOCH}")
}

/// A BN that answers PTC and sync-committee duties for `VALIDATOR_INDEX`.
async fn ptc_and_sync_bn(dependent_root: &str, pubkey_hex: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(ptc_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": dependent_root,
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": VALIDATOR_INDEX,
                "slot": SLOT.to_string()
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(sync_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": VALIDATOR_INDEX,
                "validator_sync_committee_indices": ["0"]
            }]
        })))
        .mount(&server)
        .await;
    server
}

/// (PTC, sync) duty requests received by `server`.
async fn ptc_and_sync_hits(server: &MockServer) -> (usize, usize) {
    let requests: Vec<Request> = server.received_requests().await.expect("requests");
    let count =
        |route: String| requests.iter().filter(|request| request.url.path() == route).count();
    (count(ptc_path()), count(sync_path()))
}

#[tokio::test]
async fn ptc_and_sync_duties_cached_before_a_revocation_are_not_served() {
    let pubkey = SecretKey::generate().public_key();
    let pubkey_bytes = pubkey.to_bytes();
    let pubkey_hex = pubkey_bytes_to_0x(&pubkey_bytes);
    let first = ptc_and_sync_bn(FIRST_ROOT, &pubkey_hex).await;
    let second = ptc_and_sync_bn(SECOND_ROOT, &pubkey_hex).await;
    let bn_manager = Arc::new(
        BnManager::new(BnManagerConfig::new(vec![first.uri(), second.uri()])).expect("manager"),
    );

    let mut registry = PubkeyIndexRegistry::new();
    registry.insert(pubkey_bytes, VALIDATOR_INDEX.to_string());
    let pubkey_map: PubkeyMap = Arc::new(RwLock::new(HashMap::from([(pubkey_bytes, pubkey)])));
    let index_source =
        Arc::new(PubkeyIndexSource { registry: Arc::new(RwLock::new(registry)), pubkey_map });
    let tracker = DutyTracker::new_with_source(
        Arc::clone(&bn_manager) as Arc<dyn DutiesProvider>,
        index_source,
    )
    .with_fork_schedule(ForkSchedule::unscheduled_gloas());

    tracker.fetch_ptc_duties_for_epoch(EPOCH).await.expect("PTC duties from the first node");
    tracker.fetch_sync_committee_duties(EPOCH).await.expect("sync duties from the first node");
    assert_eq!(tracker.get_ptc_duties_for_slot(SLOT).await.len(), 1);
    assert_eq!(tracker.get_sync_committee_duties(SLOT).await.len(), 1);
    assert!(tracker.is_ptc_epoch_cached(EPOCH).await);
    assert!(tracker.is_sync_period_cached(EPOCH).await);
    assert_eq!(
        (ptc_and_sync_hits(&first).await, ptc_and_sync_hits(&second).await),
        ((1, 1), (0, 0))
    );

    bn_manager.testing_revoke_admission(0);

    assert!(
        tracker.get_ptc_duties_for_slot(SLOT).await.is_empty(),
        "PTC duties cached from the revoked node must not be served"
    );
    assert!(
        tracker.get_sync_committee_duties(SLOT).await.is_empty(),
        "sync duties cached from the revoked node must not be served"
    );
    assert!(
        !tracker.is_ptc_epoch_cached(EPOCH).await,
        "the revoked node's PTC epoch reads as uncached"
    );
    assert!(
        !tracker.is_sync_period_cached(EPOCH).await,
        "the revoked node's sync period reads as uncached"
    );

    tracker.fetch_ptc_duties_for_epoch(EPOCH).await.expect("PTC duties from the admitted node");
    tracker.fetch_sync_committee_duties(EPOCH).await.expect("sync duties from the admitted node");
    assert_eq!(
        (ptc_and_sync_hits(&first).await, ptc_and_sync_hits(&second).await),
        ((1, 1), (1, 1))
    );
    assert_eq!(tracker.get_ptc_duties_for_slot(SLOT).await.len(), 1);
    assert_eq!(tracker.get_sync_committee_duties(SLOT).await.len(), 1);
    assert_eq!(tracker.get_cached_ptc_dependent_root(EPOCH).await.as_deref(), Some(SECOND_ROOT));
}
