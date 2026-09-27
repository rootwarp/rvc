//! Single production writer of the pubkey→index registry (ADR-R05).
//!
//! The doppelganger liveness loop is spawned only when doppelganger detection is
//! on, and it no longer refreshes indices. [`IndexResolver`] is spawned
//! unconditionally and is the only production caller of
//! [`merge_validator_indices`](crate::liveness_loop::merge_validator_indices).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bn_manager::BeaconNodeClient;
use doppelganger::MonotonicEpochClock;
use eth_types::{SLOTS_PER_EPOCH, SLOT_DURATION_MS};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::bootstrap::executor::{ShutdownTier, TaskExecutor};
use crate::liveness_loop::merge_validator_indices;
use crate::metrics::RVC_DUTY_INDEX_SET_SIZE;
use crate::orchestrator::PubkeyMap;
use crate::pubkey_index::{parse_pubkey_bytes, pubkey_bytes_to_0x, SharedPubkeyIndexRegistry};

/// Task name registered on [`TaskExecutor`] (`rvc_tasks_running{task}`).
pub const TASK_NAME: &str = "index.resolve";

/// Inputs for [`spawn_index_resolver`] / [`IndexResolver::new`].
pub struct IndexResolverDeps {
    /// Registry this task writes.
    pub registry: SharedPubkeyIndexRegistry,
    /// Live key set. Unresolved members are queried.
    pub pubkey_map: PubkeyMap,
    /// Beacon node used for `get_validators`.
    pub beacon: Arc<dyn BeaconNodeClient>,
    /// Re-sent after a merge that grows the registry.
    pub key_gen_tx: watch::Sender<u64>,
    /// Wake signal for admission and for our own post-insert re-send.
    pub key_gen_rx: watch::Receiver<u64>,
    /// Epoch source for the per-epoch tick and per-pubkey backoff.
    pub epoch_clock: Arc<MonotonicEpochClock>,
}

/// Outcome of one [`IndexResolver::drive_once_for_test`] pass.
///
/// `key_gen_after_write` is sampled after the registry merge and before any
/// re-send, so a growth bump has a strictly greater ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvePass {
    /// Registry length before the merge.
    pub len_before: usize,
    /// Registry length immediately after the merge, before any `key_gen` re-send.
    pub len_after_write: usize,
    /// `key_gen` immediately after the merge, before any re-send.
    pub key_gen_after_write: u64,
    /// `key_gen` after the pass (incremented only when the set grew).
    pub key_gen_after: u64,
}

/// The single index writer (ADR-R05).
///
/// Owns the shared registry, the live [`PubkeyMap`](crate::orchestrator::PubkeyMap),
/// a beacon client, both ends of the `key_gen` watch, and the epoch clock.
/// Wakes on `key_gen` and once per epoch, resolves pubkeys that are not yet in
/// the registry, and merges them through [`merge_validator_indices`](crate::liveness_loop::merge_validator_indices).
/// A pubkey that does not resolve is not queried again until the next epoch.
/// When the merge grows the set, `key_gen` is re-sent **after** the registry
/// write so duty-cache invalidation observes the new index.
pub struct IndexResolver {
    registry: SharedPubkeyIndexRegistry,
    pubkey_map: PubkeyMap,
    beacon: Arc<dyn BeaconNodeClient>,
    key_gen_tx: watch::Sender<u64>,
    key_gen_rx: watch::Receiver<u64>,
    epoch_clock: Arc<MonotonicEpochClock>,
    cancel: CancellationToken,
    /// First epoch at which a missed pubkey may be queried again.
    retry_at: HashMap<[u8; 48], u64>,
}

/// Spawn [`IndexResolver`] on `executor` as [`TASK_NAME`] (Background).
///
/// Not conditional on doppelganger detection (ADR-R05).
pub fn spawn_index_resolver(deps: IndexResolverDeps, executor: &TaskExecutor) {
    let resolver = IndexResolver::new(deps, executor.token());
    executor.spawn(TASK_NAME, ShutdownTier::Background, async move {
        resolver.run().await;
    });
}

impl IndexResolver {
    /// Build a resolver. `cancel` is the process token from [`TaskExecutor`].
    pub fn new(deps: IndexResolverDeps, cancel: CancellationToken) -> Self {
        Self {
            registry: deps.registry,
            pubkey_map: deps.pubkey_map,
            beacon: deps.beacon,
            key_gen_tx: deps.key_gen_tx,
            key_gen_rx: deps.key_gen_rx,
            epoch_clock: deps.epoch_clock,
            cancel,
            retry_at: HashMap::new(),
        }
    }

    /// Run until the process token is cancelled or `key_gen` senders are dropped.
    pub async fn run(mut self) {
        info!("index resolver started");
        self.publish_gauge();
        let interval = epoch_tick_interval();
        let mut next_tick = tokio::time::Instant::now() + interval;
        loop {
            let sleep_for = next_tick.saturating_duration_since(tokio::time::Instant::now());
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    info!("index resolver cancelled");
                    break;
                }
                changed = self.key_gen_rx.changed() => {
                    if changed.is_err() {
                        info!("index resolver stopping: key_gen sender dropped");
                        break;
                    }
                    self.finish_wake(self.epoch_clock.current_epoch()).await;
                }
                _ = tokio::time::sleep(sleep_for) => {
                    next_tick = tokio::time::Instant::now() + interval;
                    self.finish_wake(self.epoch_clock.current_epoch()).await;
                }
            }
        }
    }

    /// One resolve pass at `epoch`.
    ///
    /// Tests call this instead of sleeping for an epoch. Production [`Self::run`]
    /// calls [`Self::finish_wake`] on each `key_gen` wake and on the per-epoch tick.
    pub async fn drive_once_for_test(&mut self, epoch: u64) -> ResolvePass {
        self.resolve_at(epoch).await
    }

    /// One wake: resolve, then consume this task's own `key_gen` re-send.
    ///
    /// A growth re-send whose generation is still the value just written is marked
    /// seen so the next `select` does not call this again for that echo. A newer
    /// generation, or a pubkey that appeared during the in-flight `get_validators`,
    /// is resolved in this same turn.
    async fn finish_wake(&mut self, epoch: u64) {
        loop {
            let map_before: HashSet<[u8; 48]> = self.pubkey_map.read().keys().copied().collect();
            let pass = self.resolve_at(epoch).await;
            debug!(
                len_before = pass.len_before,
                len_after_write = pass.len_after_write,
                key_gen_after_write = pass.key_gen_after_write,
                key_gen_after = pass.key_gen_after,
                "index resolver pass"
            );
            let current = *self.key_gen_tx.borrow();
            let own_send = pass.key_gen_after > pass.key_gen_after_write;
            if own_send && current == pass.key_gen_after {
                self.key_gen_rx.mark_unchanged();
            }
            let newer = current > pass.key_gen_after;
            let late =
                self.unresolved_pubkeys(epoch).into_iter().any(|pk| !map_before.contains(&pk));
            if !newer && !late {
                break;
            }
        }
    }

    async fn resolve_at(&mut self, epoch: u64) -> ResolvePass {
        let unresolved = self.unresolved_pubkeys(epoch);
        if unresolved.is_empty() {
            let len = self.registry.read().len();
            self.publish_gauge();
            let key_gen = *self.key_gen_tx.borrow();
            return ResolvePass {
                len_before: len,
                len_after_write: len,
                key_gen_after_write: key_gen,
                key_gen_after: key_gen,
            };
        }

        let hexes: Vec<String> =
            unresolved.iter().copied().map(|pk| pubkey_bytes_to_0x(&pk)).collect();
        match self.beacon.get_validators(&hexes).await {
            Ok(resp) => {
                let mut resolved: HashMap<String, String> = HashMap::new();
                let mut found: HashSet<[u8; 48]> = HashSet::new();
                for validator in resp.data {
                    if let Some(bytes) = parse_pubkey_bytes(&validator.validator.pubkey) {
                        resolved.insert(pubkey_bytes_to_0x(&bytes), validator.index);
                        found.insert(bytes);
                    }
                }
                let len_before = self.registry.read().len();
                merge_validator_indices(&self.registry, &resolved);
                let len_after_write = self.registry.read().len();
                let key_gen_after_write = *self.key_gen_tx.borrow();
                let next_epoch = epoch.saturating_add(1);
                for pk in &unresolved {
                    if found.contains(pk) {
                        self.retry_at.remove(pk);
                    } else {
                        self.retry_at.insert(*pk, next_epoch);
                    }
                }
                self.publish_gauge();
                if len_after_write > len_before {
                    self.key_gen_tx.send_modify(|gen| *gen += 1);
                    info!(
                        added = len_after_write - len_before,
                        total = len_after_write,
                        "index resolver merged validator indices"
                    );
                } else {
                    debug!(total = len_after_write, "index resolver pass added no indices");
                }
                let key_gen_after = *self.key_gen_tx.borrow();
                ResolvePass { len_before, len_after_write, key_gen_after_write, key_gen_after }
            }
            Err(e) => {
                debug!(
                    error = %e,
                    epoch,
                    count = unresolved.len(),
                    "index resolver get_validators failed; backing off one epoch"
                );
                let next_epoch = epoch.saturating_add(1);
                for pk in &unresolved {
                    self.retry_at.insert(*pk, next_epoch);
                }
                let len = self.registry.read().len();
                self.publish_gauge();
                let key_gen = *self.key_gen_tx.borrow();
                ResolvePass {
                    len_before: len,
                    len_after_write: len,
                    key_gen_after_write: key_gen,
                    key_gen_after: key_gen,
                }
            }
        }
    }

    fn publish_gauge(&self) {
        RVC_DUTY_INDEX_SET_SIZE.set(self.registry.read().len() as i64);
    }

    fn unresolved_pubkeys(&mut self, epoch: u64) -> Vec<[u8; 48]> {
        let present: HashSet<[u8; 48]> = self.pubkey_map.read().keys().copied().collect();
        self.retry_at.retain(|pk, _| present.contains(pk));
        let registry = self.registry.read();
        present
            .into_iter()
            .filter(|pk| {
                registry.index_of(pk).is_none()
                    && self.retry_at.get(pk).is_none_or(|ready| epoch >= *ready)
            })
            .collect()
    }
}

fn epoch_tick_interval() -> Duration {
    Duration::from_millis(SLOTS_PER_EPOCH.saturating_mul(SLOT_DURATION_MS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{
        wire_signing_enablement, BeaconHandles, ShutdownTier, TaskExecutor, TierBudget,
    };
    use crate::config::{Config, ServiceBuilder};
    use crate::pubkey_index::PubkeyIndexRegistry;
    use beacon::{BeaconClient, BeaconError, ValidatorData, ValidatorInfo, ValidatorsResponse};
    use bn_manager::{BnManager, MockBeaconNodeClient, OperationTimeouts};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use slashing::SlashingDb;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio_util::sync::CancellationToken;

    const GVR: eth_types::Root = [0x11u8; 32];

    fn loaded_keys_with_pubkey(pk: crypto::PublicKey) -> crate::bootstrap::LoadedKeys {
        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk.clone());
        crate::bootstrap::LoadedKeys {
            composite_signer: Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new()))),
            validator_count: 1,
            local_pubkeys: HashSet::from([pk.to_bytes()]),
            pubkey_map: Arc::new(parking_lot::RwLock::new(map)),
            secret_providers: vec![],
            grpc_signer: None,
        }
    }

    async fn mock_beacon(genesis_time: u64) -> (wiremock::MockServer, BeaconHandles) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&server)
            .await;

        let config = Config {
            beacon_url: server.uri(),
            beacon_nodes: vec![server.uri()],
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        };
        let builder = ServiceBuilder::new(config);
        let beacon_client: Arc<BeaconClient> = builder.build_beacon().expect("beacon client");
        let bn_manager: Arc<BnManager> = builder
            .build_bn_manager_with_timeouts(OperationTimeouts::default())
            .expect("bn manager");
        (
            server,
            BeaconHandles {
                beacon_client,
                bn_manager,
                genesis_validators_root: GVR,
                genesis_validators_root_hex: format!("0x{}", hex::encode(GVR)),
                genesis_time,
            },
        )
    }

    fn fresh_key() -> (crypto::PublicKey, [u8; 48], String) {
        let pk = SecretKey::generate().public_key();
        let bytes = pk.to_bytes();
        let hex = pubkey_bytes_to_0x(&bytes);
        (pk, bytes, hex)
    }

    fn map_with(pk: &crypto::PublicKey) -> PubkeyMap {
        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk.clone());
        Arc::new(parking_lot::RwLock::new(map))
    }

    fn empty_map() -> PubkeyMap {
        Arc::new(parking_lot::RwLock::new(HashMap::new()))
    }

    fn validator(pubkey: &str, index: &str) -> ValidatorData {
        ValidatorData {
            index: index.to_string(),
            status: "active_ongoing".to_string(),
            validator: ValidatorInfo { pubkey: pubkey.to_string() },
        }
    }

    fn resolver_for(
        beacon: Arc<dyn BeaconNodeClient>,
        pubkey_map: PubkeyMap,
    ) -> (IndexResolver, SharedPubkeyIndexRegistry, watch::Sender<u64>, watch::Receiver<u64>) {
        let registry = PubkeyIndexRegistry::shared();
        let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
        let resolver = IndexResolver::new(
            IndexResolverDeps {
                registry: Arc::clone(&registry),
                pubkey_map,
                beacon,
                key_gen_tx: key_gen_tx.clone(),
                key_gen_rx: key_gen_rx.clone(),
                epoch_clock: Arc::new(MonotonicEpochClock::new(0)),
            },
            CancellationToken::new(),
        );
        (resolver, registry, key_gen_tx, key_gen_rx)
    }

    fn resolve_at_body() -> &'static str {
        let src = include_str!("index_resolver.rs");
        let start = src.find("async fn resolve_at(").expect("resolve_at");
        let rest = &src[start..];
        let end = rest.find("\n    fn publish_gauge").expect("publish_gauge follows resolve_at");
        &rest[..end]
    }

    #[tokio::test]
    async fn resolves_a_new_pubkey_on_the_key_gen_bump() {
        let (pk, bytes, hex) = fresh_key();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let hex_c = hex.clone();
        let beacon = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            let data = pks.iter().filter(|p| *p == &hex_c).map(|p| validator(p, "12")).collect();
            Ok(ValidatorsResponse { data })
        }));
        let pubkey_map = empty_map();
        let (mut resolver, registry, key_gen_tx, mut key_gen_rx) =
            resolver_for(beacon, Arc::clone(&pubkey_map));

        let missed = resolver.drive_once_for_test(3).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0, "empty map must not query");
        assert_eq!(missed.len_after_write, 0);

        pubkey_map.write().insert(bytes, pk);
        key_gen_rx.borrow_and_update();
        key_gen_tx.send_modify(|gen| *gen += 1);
        assert!(key_gen_rx.has_changed().unwrap(), "admission bump is the wake");

        // Same epoch as the empty pass: the bump, not the next epoch tick.
        let pass = resolver.drive_once_for_test(3).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(registry.read().index_of(&bytes), Some("12"));
        assert!(pass.len_after_write > pass.len_before);
    }

    #[tokio::test]
    async fn runs_with_doppelganger_disabled() {
        let config = Config {
            doppelganger_detection: false,
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        };
        assert!(!config.doppelganger_detection);

        let (_server, beacon) = mock_beacon(0).await;
        let pk = SecretKey::generate().public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        let handles = wire_signing_enablement(&config, &keys, &beacon, slashing_db, &executor)
            .await
            .expect("doppelganger-off bootstrap");
        assert!(handles.liveness_task.is_none(), "doppelganger off must not spawn liveness");

        let bytes = pk.to_bytes();
        let hex = pubkey_bytes_to_0x(&bytes);
        let bn = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            let data = pks.iter().filter(|p| *p == &hex).map(|p| validator(p, "12")).collect();
            Ok(ValidatorsResponse { data })
        }));
        let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
        spawn_index_resolver(
            IndexResolverDeps {
                registry: Arc::clone(&handles.pubkey_index),
                pubkey_map: Arc::clone(&handles.pubkey_map),
                beacon: bn,
                key_gen_tx: key_gen_tx.clone(),
                key_gen_rx,
                epoch_clock: Arc::clone(&handles.epoch_clock),
            },
            &executor,
        );

        assert!(
            executor.registered_names().contains(&TASK_NAME),
            "resolver task must be registered when doppelganger is disabled; got {:?}",
            executor.registered_names()
        );
        let running = metrics::definitions::RVC_TASKS_RUNNING.with_label_values(&[TASK_NAME]).get();
        assert!(running >= 1, "index.resolve must appear in rvc_tasks_running, got {running}");

        key_gen_tx.send_modify(|gen| *gen += 1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if handles.pubkey_index.read().index_of(&bytes) == Some("12") {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("resolver did not publish an index with doppelganger disabled");
            }
            tokio::task::yield_now().await;
        }

        let prod = include_str!("bootstrap/run.rs").split("#[cfg(test)]").next().unwrap();
        assert!(
            prod.lines().any(|line| line.starts_with("    spawn_index_resolver(")),
            "run() must spawn the index resolver at function scope"
        );

        let _ =
            tokio::time::timeout(Duration::from_secs(2), executor.shutdown(TierBudget::default()))
                .await;
    }

    #[tokio::test]
    async fn unresolved_pubkey_is_retried_no_faster_than_one_epoch() {
        let (pk, _bytes, _hex) = fresh_key();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let beacon = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |_pks| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Err(BeaconError::ApiError { status: 404, message: "not found".into() })
        }));
        let (mut resolver, _registry, key_gen_tx, _key_gen_rx) =
            resolver_for(beacon, map_with(&pk));

        resolver.drive_once_for_test(5).await;
        key_gen_tx.send_modify(|gen| *gen += 1);
        resolver.drive_once_for_test(5).await;
        resolver.drive_once_for_test(5).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a 404 pubkey is queried at most once per epoch, including extra key_gen wakes"
        );

        resolver.drive_once_for_test(6).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the same pubkey is retried on the next epoch");
    }

    #[tokio::test]
    async fn set_growth_rebumps_key_gen_after_the_insert() {
        let body = resolve_at_body();
        let merge_at = body.find("merge_validator_indices(").expect("merge");
        let len_at = body.find("let len_after_write").expect("len sample");
        let gen_at = body.find("let key_gen_after_write").expect("key_gen sample");
        let bump_at = body.find("send_modify").expect("bump");
        assert!(
            merge_at < len_at && len_at < gen_at && gen_at < bump_at,
            "key_gen re-send must be ordered after the registry write"
        );

        let (pk, bytes, hex) = fresh_key();
        let beacon = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            let data = pks.iter().filter(|p| *p == &hex).map(|p| validator(p, "4")).collect();
            Ok(ValidatorsResponse { data })
        }));
        let (mut resolver, registry, key_gen_tx, mut seen) = resolver_for(beacon, map_with(&pk));
        seen.borrow_and_update();
        key_gen_tx.send_modify(|gen| *gen += 1);
        assert_eq!(*seen.borrow_and_update(), 1);
        assert!(registry.read().is_empty(), "admission bump alone does not insert an index");

        let pass = resolver.drive_once_for_test(8).await;
        assert_eq!(pass.len_before, 0);
        assert_eq!(pass.len_after_write, 1);
        assert_eq!(pass.key_gen_after_write, 1, "write is observed at the pre-bump ordinal");
        assert_eq!(pass.key_gen_after, 2, "bump ordinal follows the registry write");
        assert_eq!(*seen.borrow_and_update(), 2);
        assert_eq!(registry.read().index_of(&bytes), Some("4"));
        assert_eq!(registry.read().len(), pass.len_after_write);
    }

    /// `run` must not treat its own growth re-send as another admission.
    ///
    /// One growth performs one `get_validators` and one re-send. A pubkey inserted
    /// during that in-flight call is resolved in the same turn, not by echoing the
    /// re-send back through `select`.
    #[tokio::test]
    async fn run_one_growth_is_one_query_and_resolves_a_pubkey_inserted_mid_call() {
        let (pk_a, bytes_a, hex_a) = fresh_key();
        let (pk_b, bytes_b, hex_b) = fresh_key();
        let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
        let calls_c = Arc::clone(&calls);
        let pubkey_map = map_with(&pk_a);
        let map_during = Arc::clone(&pubkey_map);
        let pk_mid = pk_b;
        let hex_first = hex_a.clone();
        let hex_mid = hex_b.clone();
        let beacon = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            let mut log = calls_c.lock().expect("call log");
            let n = log.len();
            log.push(pks.clone());
            drop(log);
            if n == 0 {
                map_during.write().insert(bytes_b, pk_mid.clone());
            }
            let data = pks
                .iter()
                .filter(|p| *p == &hex_first || *p == &hex_mid)
                .map(|p| {
                    let index = if p == &hex_first { "12" } else { "13" };
                    validator(p, index)
                })
                .collect();
            Ok(ValidatorsResponse { data })
        }));
        let (resolver, registry, key_gen_tx, mut seen) =
            resolver_for(beacon, Arc::clone(&pubkey_map));
        seen.borrow_and_update();
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        executor.spawn(TASK_NAME, ShutdownTier::Background, async move {
            resolver.run().await;
        });

        key_gen_tx.send_modify(|gen| *gen += 1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let both = {
                let reg = registry.read();
                reg.index_of(&bytes_a) == Some("12") && reg.index_of(&bytes_b) == Some("13")
            };
            if both {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "mid-call pubkey was not resolved; calls={:?}",
                    calls.lock().expect("call log")
                );
            }
            tokio::task::yield_now().await;
        }

        let queries = calls.lock().expect("call log").clone();
        assert_eq!(queries.len(), 2, "one get_validators per growth, no echo: {queries:?}");
        assert!(
            queries[0].iter().any(|p| p == &hex_a) && !queries[0].iter().any(|p| p == &hex_b),
            "first query is only the original pubkey: {:?}",
            queries[0]
        );
        assert!(
            queries[1].iter().any(|p| p == &hex_b) && !queries[1].iter().any(|p| p == &hex_a),
            "second query is only the pubkey inserted during the first call: {:?}",
            queries[1]
        );
        assert_eq!(*seen.borrow_and_update(), 3, "admission bump plus one re-send per growth");

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            calls.lock().expect("call log").len(),
            2,
            "the task's own re-send must not query again"
        );

        let _ =
            tokio::time::timeout(Duration::from_secs(2), executor.shutdown(TierBudget::default()))
                .await;
    }

    #[test]
    fn merge_validator_indices_has_one_production_caller() {
        let resolver = include_str!("index_resolver.rs").split("#[cfg(test)]").next().unwrap();
        let liveness = include_str!("liveness_loop.rs").split("#[cfg(test)]").next().unwrap();
        let calls = |src: &str| src.matches("merge_validator_indices(").count();
        assert_eq!(calls(liveness), 1, "liveness keeps the definition only");
        assert_eq!(calls(resolver), 1, "IndexResolver is the only production caller");
    }
}
