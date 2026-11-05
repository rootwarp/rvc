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
use eth_types::SLOTS_PER_EPOCH;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn, Instrument};

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
    /// Slot length for the wakes, and the epoch for the per-pubkey backoff.
    pub epoch_clock: Arc<MonotonicEpochClock>,
}

/// Outcome of one `IndexResolver::drive_once_for_test` pass.
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
    /// `get_validators` returned `Err`; [`IndexResolver::run`] retries at the next slot.
    pub bn_error: bool,
}

/// Why a [`IndexResolver::run`] wake makes a BN pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassTrigger {
    /// The pass before the first wait.
    First,
    /// The last `get_validators` returned `Err`.
    Failed,
    /// The map has keys and the registry holds none of them.
    Empty,
    /// One epoch has passed since the last pass.
    EpochDue,
}

/// When the last pass started, and whether its `get_validators` failed.
#[derive(Debug, Clone, Copy)]
struct LastPass {
    at: tokio::time::Instant,
    bn_error: bool,
}

/// The single index writer (ADR-R05).
///
/// Owns the shared registry, the live [`PubkeyMap`](crate::orchestrator::PubkeyMap),
/// a beacon client, both ends of the `key_gen` watch, and the epoch clock.
/// Passes once at start, on every `key_gen` change, and on a slot wake that has
/// a [`PassTrigger`]. A pass resolves pubkeys that are not yet in the registry
/// and merges them through [`merge_validator_indices`](crate::liveness_loop::merge_validator_indices).
/// A pubkey missing from an `Ok` answer is not queried again until the next
/// epoch. A failed `get_validators` sets no backoff.
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
    /// First epoch at which a pubkey missing from an `Ok` answer may be queried again.
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
    ///
    /// The first pass runs before the first wait. Each pass is one
    /// `index.resolve.tick` span. A slot wake without a [`PassTrigger`] opens
    /// no span and makes no BN call.
    pub async fn run(mut self) {
        info!("index resolver started");
        self.publish_gauge();
        let epoch = self.tick_interval();
        let slot = self.retry_interval();
        let mut next_wake = tokio::time::Instant::now() + slot;
        // detached: process-lifetime loop root; the tick is the exported span.
        let loop_span = tracing::info_span!(parent: None, "index.resolve");
        let mut last = self.traced_pass(&loop_span, Some(PassTrigger::First)).await;
        loop {
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
                    last = self.traced_pass(&loop_span, None).await;
                }
                _ = tokio::time::sleep_until(next_wake) => {
                    next_wake = tokio::time::Instant::now() + slot;
                    if let Some(trigger) = self.slot_trigger(last, epoch) {
                        last = self.traced_pass(&loop_span, Some(trigger)).await;
                    }
                }
            }
        }
    }

    /// Per-epoch wake interval from the clock's slot duration.
    pub fn tick_interval(&self) -> Duration {
        slots_interval(self.epoch_clock.slot_duration_ms(), SLOTS_PER_EPOCH)
    }

    /// Per-slot wake interval, with the same bounds and cap as [`Self::tick_interval`].
    pub fn retry_interval(&self) -> Duration {
        slots_interval(self.epoch_clock.slot_duration_ms(), 1)
    }

    /// Why a slot wake makes a BN pass; `None` keeps the wake silent.
    fn slot_trigger(&self, last: LastPass, epoch: Duration) -> Option<PassTrigger> {
        if last.bn_error {
            return Some(PassTrigger::Failed);
        }
        if last.at.elapsed() >= epoch {
            return Some(PassTrigger::EpochDue);
        }
        let map = self.pubkey_map.read();
        let registry = self.registry.read();
        let empty = !map.is_empty() && map.keys().all(|pk| registry.index_of(pk).is_none());
        empty.then_some(PassTrigger::Empty)
    }

    /// One pass under a fresh `index.resolve.tick` root that follows `loop_span`.
    ///
    /// `trigger` is `None` for a `key_gen` wake, which always passes.
    async fn traced_pass(
        &mut self,
        loop_span: &tracing::Span,
        trigger: Option<PassTrigger>,
    ) -> LastPass {
        let tick = tracing::info_span!(parent: None, "index.resolve.tick");
        tick.follows_from(loop_span);
        debug!(parent: &tick, ?trigger, "index resolver pass due");
        let at = tokio::time::Instant::now();
        let pass = self.finish_wake(self.epoch_clock.current_epoch()).instrument(tick).await;
        LastPass { at, bn_error: pass.bn_error }
    }

    /// One resolve pass at `epoch`.
    ///
    /// Tests call this instead of sleeping for an epoch. Production [`Self::run`]
    /// calls [`Self::finish_wake`] for every pass.
    ///
    /// Compiled only for this crate's tests or when the `test-utils` feature
    /// is enabled. Integration tests see it through the self dev-dependency.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn drive_once_for_test(&mut self, epoch: u64) -> ResolvePass {
        self.resolve_at(epoch).await
    }

    /// One wake: resolve, then consume this task's own `key_gen` re-send.
    ///
    /// A growth re-send whose generation is still the value just written is marked
    /// seen so the next `select` does not call this again for that echo. A newer
    /// generation, or a pubkey that appeared during the in-flight `get_validators`,
    /// is resolved in this same turn. Returns the last resolve.
    async fn finish_wake(&mut self, epoch: u64) -> ResolvePass {
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
                return pass;
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
                bn_error: false,
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
                ResolvePass {
                    len_before,
                    len_after_write,
                    key_gen_after_write,
                    key_gen_after,
                    bn_error: false,
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    epoch,
                    count = unresolved.len(),
                    "index resolver get_validators failed; retrying at the next slot"
                );
                let len = self.registry.read().len();
                self.publish_gauge();
                let key_gen = *self.key_gen_tx.borrow();
                ResolvePass {
                    len_before: len,
                    len_after_write: len,
                    key_gen_after_write: key_gen,
                    key_gen_after: key_gen,
                    bn_error: true,
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

/// `slots` slots at the beacon-node slot length.
///
/// Zero is not a slot. A zero tick would spin the resolver, and assuming 12 s
/// would be wrong on a longer slot. A zero duration waits indefinitely.
fn slots_interval(slot_duration_ms: u64, slots: u64) -> Duration {
    // `Instant + Duration::MAX` panics. A zero or huge duration waits a day
    // instead of spinning or aborting the resolver.
    const CAP: Duration = Duration::from_secs(24 * 60 * 60);
    if !(eth_types::MIN_SLOT_DURATION_MS..=eth_types::MAX_SLOT_DURATION_MS)
        .contains(&slot_duration_ms)
    {
        return CAP;
    }
    let ms = slots.saturating_mul(slot_duration_ms);
    Duration::from_millis(ms).min(CAP)
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
    use bn_manager::{BnManager, MockBeaconNodeClient, MockMethod, OperationTimeouts};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use slashing::SlashingDb;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio_util::sync::CancellationToken;

    const GVR: eth_types::Root = [0x11u8; 32];
    const SLOT: Duration = Duration::from_secs(12);
    const EPOCH: Duration = Duration::from_secs(12 * SLOTS_PER_EPOCH);

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
                slot_duration_ms: 12_000,
                genesis_confirmed: true,
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
                epoch_clock: fixed_clock(),
            },
            CancellationToken::new(),
        );
        (resolver, registry, key_gen_tx, key_gen_rx)
    }

    /// Epoch 0 for 384 s of wall time, so a paused-clock test never crosses an epoch.
    fn fixed_clock() -> Arc<MonotonicEpochClock> {
        Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000))
    }

    fn unavailable() -> BeaconError {
        BeaconError::ApiError { status: 503, message: "Service Unavailable".into() }
    }

    /// `run` on its own task. Cancel the token, then await the handle.
    fn spawn_run(resolver: IndexResolver) -> (CancellationToken, tokio::task::JoinHandle<()>) {
        (resolver.cancel.clone(), tokio::spawn(resolver.run()))
    }

    /// Offsets from `start` of the mock's `get_validators` calls (paused clock).
    fn bn_calls(mock: &MockBeaconNodeClient, start: tokio::time::Instant) -> Vec<Duration> {
        let stamps = mock.call_stamps().into_iter();
        stamps
            .filter(|stamp| stamp.method == MockMethod::GetValidators)
            .map(|s| s.at - start)
            .collect()
    }

    /// Passes spaced exactly one epoch apart: slot wakes in between stayed silent.
    fn assert_one_pass_per_epoch(ticks: &[Duration]) {
        assert!(ticks.len() >= 2, "two epochs need two passes: {ticks:?}");
        assert!(
            ticks.windows(2).all(|pair| pair[1] - pair[0] == EPOCH),
            "one index.resolve.tick per epoch, none on a silent slot wake: {ticks:?}"
        );
    }

    /// WARN events (prefixed with their span) and `index.resolve.tick` close instants.
    #[derive(Clone, Default)]
    struct ResolverLog {
        warns: Arc<Mutex<Vec<String>>>,
        ticks: Arc<Mutex<Vec<tokio::time::Instant>>>,
    }

    impl ResolverLog {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            use tracing_subscriber::layer::SubscriberExt;
            tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()))
        }

        fn warns(&self) -> Vec<String> {
            self.warns.lock().expect("warn log").clone()
        }

        fn ticks(&self, start: tokio::time::Instant) -> Vec<Duration> {
            self.ticks.lock().expect("tick log").iter().map(|at| *at - start).collect()
        }
    }

    struct FieldText<'a>(&'a mut String);

    impl tracing::field::Visit for FieldText<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }

    impl<S> tracing_subscriber::Layer<S> for ResolverLog
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                let span = ctx.event_span(event);
                let mut line = span.map_or("<none>", |span| span.name()).to_string();
                event.record(&mut FieldText(&mut line));
                self.warns.lock().expect("warn log").push(line);
            }
        }

        fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
            if ctx.span(&id).is_some_and(|span| span.name() == "index.resolve.tick") {
                self.ticks.lock().expect("tick log").push(tokio::time::Instant::now());
            }
        }
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

    /// A key an `Ok` answer omits (pending activation) is asked once per epoch.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn unresolved_pubkey_is_retried_no_faster_than_one_epoch() {
        let (pk, _bytes, _hex) = fresh_key();
        let omits = |_| Ok(ValidatorsResponse { data: Vec::new() });
        let mock = Arc::new(MockBeaconNodeClient::new().with_get_validators(omits));
        let (mut resolver, _registry, key_gen_tx, _key_gen_rx) =
            resolver_for(mock.clone(), map_with(&pk));
        let start = tokio::time::Instant::now();

        assert!(!resolver.drive_once_for_test(5).await.bn_error, "an Ok answer is no failure");
        key_gen_tx.send_modify(|gen| *gen += 1);
        resolver.drive_once_for_test(5).await;
        resolver.drive_once_for_test(5).await;
        assert_eq!(
            bn_calls(&mock, start).len(),
            1,
            "an omitted pubkey is queried at most once per epoch, including extra key_gen wakes"
        );
        resolver.drive_once_for_test(6).await;
        assert_eq!(bn_calls(&mock, start).len(), 2, "the same pubkey is retried next epoch");

        let mock = Arc::new(MockBeaconNodeClient::new().with_get_validators(omits));
        let (resolver, _registry, key_gen_tx, _key_gen_rx) =
            resolver_for(mock.clone(), map_with(&pk));
        let start = tokio::time::Instant::now();
        let (cancel, task) = spawn_run(resolver);
        tokio::time::sleep(SLOT + SLOT / 2).await;
        key_gen_tx.send_modify(|gen| *gen += 1);
        tokio::time::sleep_until(start + EPOCH + SLOT / 2).await;
        assert_eq!(
            bn_calls(&mock, start).len(),
            1,
            "run: the key_gen wake, the slot wakes and the epoch pass of one clock epoch \
             ask no second time"
        );
        cancel.cancel();
        task.await.expect("resolver task");
    }

    /// `run` passes the live clock epoch: an omitted key is asked again once the
    /// clock enters the next epoch, and not before.
    ///
    /// The epoch clock reads std time, which paused tokio time does not move. So
    /// the clock starts `MARGIN` before the epoch-1 boundary, the test runs the
    /// epoch-0 slots under paused time, then blocks the thread past the boundary.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_asks_an_omitted_pubkey_again_when_the_clock_epoch_advances() {
        const MARGIN: Duration = Duration::from_secs(2);
        let log = ResolverLog::default();
        let _guard = log.install();
        let (pk, _bytes, _hex) = fresh_key();
        let omits = |_| Ok(ValidatorsResponse { data: Vec::new() });
        let mock = Arc::new(MockBeaconNodeClient::new().with_get_validators(omits));
        let (mut resolver, _registry, _tx, _rx) = resolver_for(mock.clone(), map_with(&pk));
        let before_boundary_ms = u64::try_from((EPOCH - MARGIN).as_millis()).expect("ms");
        let clock = Arc::new(MonotonicEpochClock::with_start_time_ms(
            0,
            std::time::Instant::now(),
            before_boundary_ms,
            12_000,
        ));
        resolver.epoch_clock = Arc::clone(&clock);
        let start = tokio::time::Instant::now();
        let (cancel, task) = spawn_run(resolver);

        tokio::time::sleep_until(start + 2 * SLOT + SLOT / 2).await;
        assert_eq!(clock.current_epoch(), 0, "precondition: epoch-0 slots ran within {MARGIN:?}");
        assert_eq!(
            bn_calls(&mock, start),
            [Duration::ZERO],
            "the Empty slot passes of epoch 0 ask no second time"
        );

        std::thread::sleep(MARGIN);
        assert_eq!(clock.current_epoch(), 1);
        tokio::time::sleep_until(start + 4 * SLOT + SLOT / 2).await;
        assert_eq!(
            bn_calls(&mock, start),
            [Duration::ZERO, 3 * SLOT],
            "the first slot pass in clock epoch 1 asks again, then backs off to epoch 2"
        );
        assert_eq!(log.ticks(start), [0, 1, 2, 3, 4].map(|slot| slot * SLOT));
        cancel.cancel();
        task.await.expect("resolver task");
    }

    /// #655 AC2: a 503 at boot, then data. The index is in the registry within two slots.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_boot_503_resolves_indices_within_two_slots() {
        let (pk, bytes, hex) = fresh_key();
        let attempts = AtomicUsize::new(0);
        let mock = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(unavailable());
            }
            let data = pks.iter().filter(|p| *p == &hex).map(|p| validator(p, "21")).collect();
            Ok(ValidatorsResponse { data })
        }));
        let registry = PubkeyIndexRegistry::shared();
        let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let start = tokio::time::Instant::now();
        spawn_index_resolver(
            IndexResolverDeps {
                registry: Arc::clone(&registry),
                pubkey_map: map_with(&pk),
                beacon: mock.clone(),
                key_gen_tx,
                key_gen_rx,
                epoch_clock: fixed_clock(),
            },
            &executor,
        );

        tokio::time::sleep(2 * SLOT).await;
        let calls = bn_calls(&mock, start);
        assert_eq!(registry.read().index_of(&bytes), Some("21"), "BN calls at {calls:?}");
        assert_eq!(calls, [Duration::ZERO, SLOT], "the boot 503, then one retry a slot later");
        let _ =
            tokio::time::timeout(Duration::from_secs(2), executor.shutdown(TierBudget::default()))
                .await;
    }

    /// #655 AC5: a failed pass warns once, with its epoch and key count.
    #[tokio::test(flavor = "current_thread")]
    async fn failed_pass_logs_a_warn() {
        let log = ResolverLog::default();
        let _guard = log.install();
        let (pk, _, _) = fresh_key();
        let mock = MockBeaconNodeClient::new().with_get_validators(|_| Err(unavailable()));
        let (mut resolver, _registry, _tx, _rx) = resolver_for(Arc::new(mock), map_with(&pk));

        let pass = resolver.drive_once_for_test(7).await;
        assert!(pass.bn_error, "an Err answer marks the pass failed");
        let warns = log.warns();
        assert_eq!(warns.len(), 1, "one WARN per failed pass: {warns:?}");
        for field in ["get_validators failed", "epoch=7", "count=1", "503"] {
            assert!(warns[0].contains(field), "WARN lacks `{field}`: {warns:?}");
        }
    }

    /// 503 forever: one BN call and one WARN per slot, with no per-key backoff.
    ///
    /// The registry already holds key A, so only a failure (not `Empty`) retries
    /// key B, which arrives with a `key_gen` bump while the BN is down.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn persistent_error_retries_each_slot() {
        let log = ResolverLog::default();
        let _guard = log.install();
        let (pk_a, bytes_a, _) = fresh_key();
        let (pk_b, bytes_b, hex_b) = fresh_key();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let asked_c = Arc::clone(&asked);
        let mock = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            asked_c.lock().expect("asked").push(pks);
            Err(unavailable())
        }));
        let pubkey_map = map_with(&pk_a);
        let (resolver, registry, key_gen_tx, _rx) =
            resolver_for(mock.clone(), Arc::clone(&pubkey_map));
        registry.write().insert(bytes_a, "1".to_string());
        let start = tokio::time::Instant::now();
        let (cancel, task) = spawn_run(resolver);

        tokio::time::sleep(SLOT / 2).await;
        pubkey_map.write().insert(bytes_b, pk_b);
        key_gen_tx.send_modify(|gen| *gen += 1);
        tokio::time::sleep_until(start + 3 * SLOT + SLOT / 2).await;
        assert_eq!(bn_calls(&mock, start), [SLOT / 2, SLOT, 2 * SLOT, 3 * SLOT]);
        assert!(asked.lock().expect("asked").iter().all(|pks| *pks == [hex_b.clone()]));
        let warns = log.warns();
        assert_eq!(warns.len(), 4, "one WARN per failed pass: {warns:?}");
        assert!(
            warns.iter().all(|line| line.starts_with("index.resolve.tick")
                && line.contains("get_validators failed")),
            "each failed pass warns inside its tick span: {warns:?}"
        );
        assert_eq!(registry.read().index_of(&bytes_b), None);
        cancel.cancel();
        task.await.expect("resolver task");
    }

    /// All keys resolved: one BN call, then one pass per epoch; slot wakes are silent.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn healthy_registry_keeps_the_epoch_tick() {
        let log = ResolverLog::default();
        let _guard = log.install();
        let (pk, bytes, hex) = fresh_key();
        let mock = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            let data = pks.iter().filter(|p| *p == &hex).map(|p| validator(p, "8")).collect();
            Ok(ValidatorsResponse { data })
        }));
        let (resolver, registry, _tx, _rx) = resolver_for(mock.clone(), map_with(&pk));
        let start = tokio::time::Instant::now();
        let (cancel, task) = spawn_run(resolver);

        tokio::time::sleep(2 * EPOCH + SLOT / 2).await;
        let calls = bn_calls(&mock, start);
        let ticks = log.ticks(start);
        assert_eq!(registry.read().index_of(&bytes), Some("8"));
        assert_eq!(calls.len(), 1, "later passes have nothing to ask: {calls:?}");
        assert_eq!(ticks.first(), calls.first(), "the BN call is the first pass: {ticks:?}");
        assert_one_pass_per_epoch(&ticks);
        cancel.cancel();
        task.await.expect("resolver task");
    }

    /// No keys: no BN call, and an empty map does not count as an empty registry.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn empty_map_makes_no_bn_call() {
        let log = ResolverLog::default();
        let _guard = log.install();
        let omits = |_| Ok(ValidatorsResponse { data: Vec::new() });
        let mock = Arc::new(MockBeaconNodeClient::new().with_get_validators(omits));
        let (resolver, _registry, _tx, _rx) = resolver_for(mock.clone(), empty_map());
        let start = tokio::time::Instant::now();
        let (cancel, task) = spawn_run(resolver);

        tokio::time::sleep(2 * EPOCH + SLOT / 2).await;
        assert_eq!(bn_calls(&mock, start), Vec::<Duration>::new());
        assert_one_pass_per_epoch(&log.ticks(start));
        cancel.cancel();
        task.await.expect("resolver task");
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

    /// Shape B on `IndexResolver::run`: each tick is a fresh root with exactly one
    /// `follows_from` link, and N passes close N tick spans.
    #[tokio::test(flavor = "current_thread")]
    async fn test_shape_b_tick_has_one_link_and_each_iteration_closes() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::SpanProcessor;
        use tracing_subscriber::layer::SubscriberExt;

        const N: usize = 3;
        const TICK: &str = "index.resolve.tick";

        #[derive(Debug)]
        struct RecordingProcessor {
            spans: Arc<Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>,
        }

        impl SpanProcessor for RecordingProcessor {
            fn on_start(
                &self,
                _span: &mut opentelemetry_sdk::trace::Span,
                _cx: &opentelemetry::Context,
            ) {
            }

            fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {
                self.spans.lock().expect("span log").push(span);
            }

            fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
                Ok(())
            }

            fn shutdown_with_timeout(
                &self,
                _timeout: Duration,
            ) -> opentelemetry_sdk::error::OTelSdkResult {
                Ok(())
            }
        }

        let spans = Arc::new(Mutex::new(Vec::new()));
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_sampler(opentelemetry_sdk::trace::Sampler::AlwaysOn)
            .with_span_processor(RecordingProcessor { spans: Arc::clone(&spans) })
            .build();
        let tracer = provider.tracer("rvc-shape-b");
        let subscriber =
            tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));
        let _guard = tracing::subscriber::set_default(subscriber);

        let beacon = Arc::new(
            MockBeaconNodeClient::new()
                .with_get_validators(|_| Ok(ValidatorsResponse { data: Vec::new() })),
        );
        let (pk, _, _) = fresh_key();
        let (resolver, _registry, key_gen_tx, _key_gen_rx) = resolver_for(beacon, map_with(&pk));
        let cancel = resolver.cancel.clone();
        let task = tokio::spawn(resolver.run());

        // The first pass closes tick 1 before any wake; each key_gen wake closes one more.
        wait_for_completed_ticks(&spans, 1).await;
        for i in 2..=N {
            key_gen_tx.send_modify(|gen| *gen += 1);
            wait_for_completed_ticks(&spans, i).await;
        }
        // The cancel wake runs no pass, so it closes no tick.
        cancel.cancel();
        task.await.expect("index resolver task");

        let recorded = spans.lock().expect("span log");
        let ticks: Vec<_> = recorded.iter().filter(|span| span.name == TICK).collect();
        assert_eq!(
            ticks.len(),
            N,
            "each pass closes its span: {N} passes must produce {N} completed \
             index.resolve.tick spans, not one span for the process; saw {:?}",
            recorded.iter().map(|span| span.name.as_ref()).collect::<Vec<_>>()
        );
        let parents: Vec<_> = recorded.iter().filter(|span| span.name == "index.resolve").collect();
        assert_eq!(parents.len(), 1, "one process-lifetime loop span");
        let parent_id = parents[0].span_context.span_id();
        for tick in ticks {
            assert_eq!(
                tick.links.len(),
                1,
                "tick span must carry exactly one follows_from link, got {:?}",
                tick.links.links
            );
            assert_eq!(
                tick.links[0].span_context.span_id(),
                parent_id,
                "the single link must be follows_from the loop span"
            );
            assert_eq!(
                tick.parent_span_id,
                opentelemetry::trace::SpanId::INVALID,
                "tick is a fresh root, not a child of the loop span"
            );
        }
    }

    async fn wait_for_completed_ticks(
        spans: &Arc<Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>,
        n: usize,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let (count, names) = {
                let guard = spans.lock().expect("span log");
                let count = guard.iter().filter(|span| span.name == "index.resolve.tick").count();
                let names: Vec<_> = guard.iter().map(|span| span.name.to_string()).collect();
                (count, names)
            };
            if count >= n {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {n} completed index.resolve.tick spans (have {count}): \
                 {names:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[test]
    fn merge_validator_indices_has_one_production_caller() {
        let resolver = include_str!("index_resolver.rs").split("#[cfg(test)]").next().unwrap();
        let liveness = include_str!("liveness_loop.rs").split("#[cfg(test)]").next().unwrap();
        let calls = |src: &str| src.matches("merge_validator_indices(").count();
        assert_eq!(calls(liveness), 1, "liveness keeps the definition only");
        assert_eq!(calls(resolver), 1, "IndexResolver is the only production caller");
    }

    fn resolver_at(slot_duration_ms: u64) -> IndexResolver {
        let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
        IndexResolver::new(
            IndexResolverDeps {
                registry: PubkeyIndexRegistry::shared(),
                pubkey_map: Arc::new(parking_lot::RwLock::new(HashMap::new())),
                beacon: Arc::new(MockBeaconNodeClient::new()),
                key_gen_tx,
                key_gen_rx,
                epoch_clock: Arc::new(MonotonicEpochClock::with_start_time(
                    0,
                    std::time::Instant::now(),
                    0,
                    slot_duration_ms,
                )),
            },
            CancellationToken::new(),
        )
    }

    #[test]
    fn retry_interval_is_one_slot() {
        use eth_types::{MAX_SLOT_DURATION_MS, MIN_SLOT_DURATION_MS};
        assert_eq!(resolver_at(12_000).retry_interval(), SLOT);
        assert_eq!(resolver_at(6_000).retry_interval(), Duration::from_secs(6));
        assert_eq!(resolver_at(MIN_SLOT_DURATION_MS).retry_interval(), Duration::from_secs(1));
        assert_eq!(resolver_at(MAX_SLOT_DURATION_MS).retry_interval(), Duration::from_secs(60));
        let capped = Duration::from_secs(24 * 60 * 60);
        for out_of_range in [0, MIN_SLOT_DURATION_MS - 1, MAX_SLOT_DURATION_MS + 1, u64::MAX] {
            assert_eq!(resolver_at(out_of_range).retry_interval(), capped, "{out_of_range} ms");
        }
    }

    /// A slot wake passes only after a failure, while the registry holds none of the
    /// map's keys, or once an epoch has passed since the last pass.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn slot_wake_passes_only_when_failed_empty_or_epoch_due() {
        let (pk_a, bytes_a, _) = fresh_key();
        let (pk_b, bytes_b, _) = fresh_key();
        let pubkey_map = map_with(&pk_a);
        pubkey_map.write().insert(bytes_b, pk_b);
        let mock = Arc::new(MockBeaconNodeClient::new());
        let (resolver, registry, _tx, _rx) = resolver_for(mock.clone(), pubkey_map);
        let now = |bn_error| LastPass { at: tokio::time::Instant::now(), bn_error };
        assert_eq!(resolver.slot_trigger(now(false), EPOCH), Some(PassTrigger::Empty));

        registry.write().insert(bytes_a, "3".to_string());
        assert_eq!(resolver.slot_trigger(now(false), EPOCH), None, "one of two keys resolved");
        assert_eq!(resolver.slot_trigger(now(true), EPOCH), Some(PassTrigger::Failed));
        let last = now(false);
        tokio::time::advance(EPOCH - Duration::from_millis(1)).await;
        assert_eq!(resolver.slot_trigger(last, EPOCH), None);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(resolver.slot_trigger(last, EPOCH), Some(PassTrigger::EpochDue));

        let (no_keys, _registry, _tx, _rx) = resolver_for(mock, empty_map());
        assert_eq!(
            no_keys.slot_trigger(now(false), EPOCH),
            None,
            "no keys is not an empty registry"
        );
    }

    #[test]
    fn tick_interval_follows_beacon_slot_duration() {
        assert_eq!(resolver_at(6_000).tick_interval(), Duration::from_secs(192));
        assert_eq!(resolver_at(12_000).tick_interval(), Duration::from_secs(384));
        let capped = Duration::from_secs(24 * 60 * 60);
        assert_eq!(resolver_at(0).tick_interval(), capped);
        assert_eq!(resolver_at(u64::MAX).tick_interval(), capped);
        assert!(std::time::Instant::now().checked_add(capped).is_some());
    }
}
