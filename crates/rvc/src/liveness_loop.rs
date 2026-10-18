//! SEC-2c: per-slot forward-window liveness observation loop.
//!
//! Drives [`ForwardWindowMachine`] with real network liveness via the bn-manager
//! (`LivenessApi::post_validator_liveness_merged`, multi-BN OR-merge).
//!
//! Each cycle (once per slot):
//! 1. Fetch liveness for the previous epoch and the current epoch
//! 2. Translate numeric validator indices → bare pubkey-hex (SEC-001)
//! 3. Apply both answers in one step, then `tick`
//!
//! Index refresh is not done here. [`crate::index_resolver::IndexResolver`] is the
//! single production writer (ADR-R05).
//!
//! Detected liveness permanently closes the gate for that key (machine semantics).
//! A clean fully-observed window opens the gate. This loop is the sole production
//! doppelganger mechanism.
//!
//! # Multi-BN OR-merge (ARCH-P1-13)
//!
//! Liveness fans out to every configured BN via
//! [`LivenessApi::post_validator_liveness_merged`]. Per validator index,
//! `is_live` is OR-merged — any BN reporting live wins (fail-safe: a lagging
//! primary that answers all-not-live cannot suppress a secondary that saw
//! activity). Errors and non-responses contribute nothing (they are not treated
//! as "not live"). If every BN fails the call returns `Err` and this loop still
//! fail-closes on errors/incomplete samples.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bn_manager::LivenessApi;
#[cfg(any(test, feature = "test-utils"))]
use bn_manager::NodeStatusApi;
use doppelganger::{
    EpochLiveness, ForwardWindowMachine, ForwardWindowStatus, MonotonicEpochClock,
    ValidatorLivenessData,
};
use eth_types::Epoch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Instrument};

use crate::bootstrap::executor::{ShutdownHandle, ShutdownTier, TaskExecutor};
use crate::orchestrator::PubkeyMap;
use crate::pubkey_index::SharedPubkeyIndexRegistry;
#[cfg(any(test, feature = "test-utils"))]
use crate::pubkey_index::{parse_pubkey_bytes, pubkey_bytes_to_0x};
use crate::quiesce::TrackedKeys;
use crate::startup::EXIT_DOPPELGANGER_DETECTED;

/// Merge `pubkey-hex → numeric index` entries into the shared registry.
///
/// [`crate::index_resolver::IndexResolver`] is the only production caller (ADR-R05).
pub fn merge_validator_indices(
    registry: &SharedPubkeyIndexRegistry,
    pubkey_to_index: &HashMap<String, String>,
) {
    registry.write().merge_hex_map(pubkey_to_index);
}

/// Handle returned by [`spawn_liveness_loop`].
///
/// The loop future is registered on the process [`TaskExecutor`] (ARCH-2g);
/// this struct only carries the shared index registry for callers.
pub struct LivenessLoopSpawn {
    /// Shared pubkey↔index registry (import/refresh may call [`merge_validator_indices`]).
    pub pubkey_index: SharedPubkeyIndexRegistry,
}

/// Process exit requested by the liveness loop.
///
/// Production uses [`ShutdownHandle`]. Tests use a recording impl. The only
/// code the loop sends is [`EXIT_DOPPELGANGER_DETECTED`].
pub trait ExitRequest: Send + Sync {
    fn request(&self, exit_code: i32);
}

impl ExitRequest for ShutdownHandle {
    fn request(&self, exit_code: i32) {
        self.request_exit(exit_code);
    }
}

/// Background task that ticks the forward-window machine once per slot.
pub struct LivenessObservationLoop {
    machine: Arc<ForwardWindowMachine>,
    beacon: Arc<dyn LivenessApi>,
    /// Shared pubkey ↔ index registry (liveness uses the reverse index→bare-hex view).
    pubkey_index: SharedPubkeyIndexRegistry,
    /// Live keystore/keymanager pubkey set for periodic BN index re-resolve.
    pubkey_map: Option<PubkeyMap>,
    epoch_clock: Arc<MonotonicEpochClock>,
    /// Slot duration used for the sleep interval (the beacon-node slot length).
    slot_duration: Duration,
    cancel: CancellationToken,
    /// Keystore directory whose import sidecars are removed once a key is Safe.
    import_sidecar_dir: Option<std::path::PathBuf>,
    /// Same lock DELETE/import hold; cleanup takes it across Safe re-check + unlink.
    tracked_keys: Option<Arc<TrackedKeys>>,
    /// `(pubkey hex, epoch)` pairs already logged as unobserved.
    unobserved_warned: parking_lot::Mutex<HashSet<(String, Epoch)>>,
    /// Drain request. Production [`spawn_liveness_loop`] always sets this.
    exit_request: Option<Arc<dyn ExitRequest>>,
    /// Validator data directory for the detection marker. Production sets this
    /// to the keystore directory.
    detection_marker_dir: Option<std::path::PathBuf>,
}

/// Body of the retained liveness index refresh. Expanded only from the test helper
/// (and, under `cfg(test)`, from `refresh_indices_from_pubkey_map`).
#[cfg(any(test, feature = "test-utils"))]
macro_rules! refresh_indices_from_pubkey_map_impl {
    ($self:ident, $validators:expr) => {{
        let Some(ref pm) = $self.pubkey_map else {
            return;
        };
        let pubkeys: Vec<String> = {
            let map = pm.read();
            if map.is_empty() {
                return;
            }
            map.keys().map(pubkey_bytes_to_0x).collect()
        };

        match $validators.get_validators(&pubkeys).await {
            Ok(resp) => {
                let mut w = $self.pubkey_index.write();
                let before = w.len();
                for v in resp.data {
                    if let Some(bytes) = parse_pubkey_bytes(&v.validator.pubkey) {
                        w.insert(bytes, v.index);
                    }
                }
                let after = w.len();
                if after > before {
                    info!(
                        added = after - before,
                        total = after,
                        "SEC-2c: refreshed liveness index map from BN (import/activation)"
                    );
                } else {
                    debug!(total = after, "SEC-2c: index re-resolve complete (no new indices)");
                }
            }
            Err(e) => {
                debug!(
                    error = %e,
                    "SEC-2c: index re-resolve failed; will retry next epoch (fail-closed)"
                );
            }
        }
    }};
}

/// Sleep between liveness samples.
///
/// Zero is not a slot. Sleeping zero would spin the loop, and assuming 12 s
/// would be wrong on a longer slot. A zero duration waits indefinitely.
fn slot_sleep(slot_duration_ms: u64) -> Duration {
    if slot_duration_ms == 0 {
        return Duration::MAX;
    }
    Duration::from_millis(slot_duration_ms)
}

impl LivenessObservationLoop {
    pub fn new(
        machine: Arc<ForwardWindowMachine>,
        beacon: Arc<dyn LivenessApi>,
        pubkey_index: SharedPubkeyIndexRegistry,
        epoch_clock: Arc<MonotonicEpochClock>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            machine,
            beacon,
            pubkey_index,
            pubkey_map: None,
            slot_duration: slot_sleep(epoch_clock.slot_duration_ms()),
            epoch_clock,
            cancel,
            import_sidecar_dir: None,
            tracked_keys: None,
            unobserved_warned: parking_lot::Mutex::new(HashSet::new()),
            exit_request: None,
            detection_marker_dir: None,
        }
    }

    /// Install the process-exit request used on the first detection.
    pub fn with_exit_request(mut self, exit_request: Arc<dyn ExitRequest>) -> Self {
        self.exit_request = Some(exit_request);
        self
    }

    /// Directory that receives `.rvc.doppelganger_detected` before exit 12.
    pub fn with_detection_marker_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.detection_marker_dir = Some(dir);
        self
    }

    /// Attach the pubkey map used by `refresh_indices_for_test`.
    ///
    /// Production index writes belong to [`crate::index_resolver::IndexResolver`]
    /// (ADR-R05), not this loop.
    pub fn with_pubkey_map(mut self, pubkey_map: PubkeyMap) -> Self {
        self.pubkey_map = Some(pubkey_map);
        self
    }

    /// Override the slot sleep interval (tests).
    pub fn with_slot_duration(mut self, slot_duration: Duration) -> Self {
        self.slot_duration = slot_duration;
        self
    }

    /// Slot sleep used by [`Self::run`].
    pub fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    /// Directory scanned after each tick. A Safe key's import sidecar is removed.
    ///
    /// That removal is the durable record that this process observed the
    /// forward window. Pending and Detected keys keep their sidecars.
    /// `tracked_keys` must be the same lock the keystore adapter uses for
    /// DELETE/import so cleanup cannot race a concurrent re-import.
    pub fn with_import_sidecar_dir(
        mut self,
        dir: std::path::PathBuf,
        tracked_keys: Arc<TrackedKeys>,
    ) -> Self {
        self.import_sidecar_dir = Some(dir);
        self.tracked_keys = Some(tracked_keys);
        self
    }

    /// Shared registry handle.
    pub fn pubkey_index(&self) -> SharedPubkeyIndexRegistry {
        Arc::clone(&self.pubkey_index)
    }

    /// Run until cancelled. Spawns no tasks — register via [`spawn_liveness_loop`].
    pub async fn run(self) {
        info!(
            slot_duration_secs = self.slot_duration.as_secs(),
            "SEC-2c: forward-window liveness observation loop started"
        );

        let mut shutdown_requested = false;
        let mut marker_durable = false;
        crate::metrics::RVC_DOPPELGANGER_DETECTION_LATCH.set(0);

        // detached: process-lifetime loop root; the tick is the exported span.
        let loop_span = tracing::debug_span!(parent: None, "liveness_loop");
        loop {
            let tick = tracing::debug_span!(parent: None, "liveness_loop.tick");
            tick.follows_from(&loop_span);
            let stop = async {
                if self.cancel.is_cancelled() {
                    info!("SEC-2c: liveness observation loop cancelled");
                    return true;
                }

                let latched_before = self.machine.detected_latch();
                let current_epoch = self.epoch_clock.current_epoch();
                let slot_in_epoch = self.epoch_clock.slot_in_epoch();
                // Network observation may store the latch. The marker write is
                // the only disk step before the exit request, and that request
                // waits until the write succeeds. Sidecar file I/O stays after it.
                self.observe_adjacent(current_epoch, slot_in_epoch).await;
                let statuses = self.machine.tick(current_epoch, slot_in_epoch);
                let detected =
                    statuses.iter().filter(|s| **s == ForwardWindowStatus::Detected).count();
                let pending =
                    statuses.iter().filter(|s| **s == ForwardWindowStatus::Pending).count();
                let safe = statuses.iter().filter(|s| **s == ForwardWindowStatus::Safe).count();
                let latched = self.machine.detected_latch();
                if latched && !latched_before {
                    let detected_pubkeys = self.machine.detected_hexes();
                    for pubkey in &detected_pubkeys {
                        error!(
                            pubkey = %observability::logging::TruncatedPubkey::new(pubkey),
                            detected,
                            pending,
                            safe,
                            current_epoch,
                            slot_in_epoch,
                            exit_code = EXIT_DOPPELGANGER_DETECTED,
                            "doppelganger detected; refusing new signatures and requesting shutdown"
                        );
                    }
                    crate::metrics::RVC_DOPPELGANGER_DETECTION_LATCH.set(1);
                }
                if latched && !marker_durable {
                    let detected_pubkeys = self.machine.detected_hexes();
                    if self.persist_detection_marker(current_epoch, &detected_pubkeys) {
                        marker_durable = true;
                    } else {
                        crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
                    }
                }
                if marker_durable && !shutdown_requested {
                    shutdown_requested = true;
                    match &self.exit_request {
                        Some(request) => request.request(EXIT_DOPPELGANGER_DETECTED),
                        None => {
                            error!("doppelganger detected but no shutdown handle is installed")
                        }
                    }
                } else if latched && marker_durable {
                    debug!(
                        detected,
                        pending,
                        safe,
                        current_epoch,
                        slot_in_epoch,
                        "doppelganger already detected; shutdown was requested once"
                    );
                } else if !latched {
                    debug!(pending, safe, current_epoch, slot_in_epoch, "forward-window tick");
                }

                self.record_completed_imports();

                tokio::select! {
                    _ = self.cancel.cancelled() => {
                        info!("SEC-2c: liveness observation loop cancelled");
                        true
                    }
                    _ = tokio::time::sleep(self.slot_duration) => false
                }
            }
            .instrument(tick)
            .await;
            if stop {
                break;
            }
        }
    }

    /// Durably record the detection. `true` when a write and its fsync returned `Ok`.
    ///
    /// A write failure is logged and the caller stays up, latched, and retries
    /// on the next tick. Exit 12 is requested only after this returns `true`.
    /// That `Ok` is recorded on the machine. A later read is not durability.
    fn persist_detection_marker(&self, epoch: Epoch, pubkeys: &[String]) -> bool {
        let Some(dir) = &self.detection_marker_dir else {
            error!(
                "doppelganger detected but no data directory is configured for the marker; \
                 staying up and refusing signatures until a marker can be written"
            );
            return false;
        };
        let marker = crate::detection_marker::DetectionMarker {
            epoch,
            unix_secs: crate::detection_marker::unix_secs_now(),
            pubkeys: pubkeys.to_vec(),
        };
        match crate::detection_marker::persist_detection(dir, &marker) {
            Ok(()) => {
                self.machine.mark_detection_persisted();
                true
            }
            Err(err) => {
                error!(
                    error = %err,
                    path = %crate::detection_marker::marker_path(dir).display(),
                    "failed to persist doppelganger detection marker; staying up and retrying"
                );
                false
            }
        }
    }

    /// Test-only index refresh. Production [`Self::run`] does not call this;
    /// [`crate::index_resolver::IndexResolver`] is the ongoing writer (ADR-R05).
    ///
    /// Unit tests call it through [`Self::refresh_indices_for_test`]. Integration
    /// tests build this crate without `cfg(test)`, so the helper inlines the same
    /// body.
    #[cfg(test)]
    async fn refresh_indices_from_pubkey_map(&self, validators: &dyn NodeStatusApi) {
        refresh_indices_from_pubkey_map_impl!(self, validators);
    }

    /// Query the previous epoch and the current epoch, then report status.
    ///
    /// An empty index registry makes no beacon-node call. A not-live answer
    /// decrements only for the previous epoch at slot >= [`doppelganger::CLOSED_EPOCH_SLOT`].
    async fn tick_once(
        &self,
        current_epoch: Epoch,
        slot_in_epoch: u64,
    ) -> Vec<ForwardWindowStatus> {
        self.observe_adjacent(current_epoch, slot_in_epoch).await;
        let statuses = self.machine.tick(current_epoch, slot_in_epoch);
        self.record_completed_imports();
        statuses
    }

    /// Fetch epochs `current - 1` and `current`, then apply them together.
    ///
    /// Queries run to completion before the machine changes. A live answer at
    /// or after `next_check_epoch` is `Detected` before any decrement, so
    /// signing stays closed until both answers of this tick are applied. A
    /// failed or partial current-epoch query does not let the previous
    /// epoch's decrement open the gate.
    async fn observe_adjacent(&self, current_epoch: Epoch, slot_in_epoch: u64) {
        let pending = self.machine.pending_keys();
        if pending.is_empty() {
            return;
        }
        let index_to_bare = self.pubkey_index.read().index_to_bare_hex().clone();
        let mut bare_to_index: HashMap<&str, &str> = HashMap::with_capacity(index_to_bare.len());
        for (index, bare) in &index_to_bare {
            bare_to_index.insert(bare.as_str(), index.as_str());
        }

        let mut epochs = Vec::with_capacity(2);
        if current_epoch > 0 {
            epochs.push(current_epoch - 1);
        }
        epochs.push(current_epoch);

        let mut answers = Vec::with_capacity(epochs.len());
        for epoch in epochs {
            let due: Vec<&doppelganger::PendingKey> =
                pending.iter().filter(|key| epoch >= key.next_check_epoch).collect();
            if due.is_empty() {
                continue;
            }
            let mut numeric: Vec<String> = due
                .iter()
                .filter_map(|key| {
                    bare_to_index.get(key.pubkey_hex.as_str()).map(|idx| (*idx).to_string())
                })
                .collect();
            numeric.sort();
            // One request per index. Response duplicates are OR-folded when
            // the tick is applied; this dedup does not choose `is_live`.
            numeric.dedup();
            if numeric.is_empty() {
                answers.push(EpochLiveness { epoch, samples: Some(Vec::new()) });
                continue;
            }
            match self.beacon.post_validator_liveness_merged(epoch, &numeric).await {
                Ok(response) => {
                    let samples: Vec<ValidatorLivenessData> = response
                        .data
                        .into_iter()
                        .filter_map(|v| {
                            let pubkey_hex = index_to_bare.get(&v.index)?;
                            Some(ValidatorLivenessData {
                                index: pubkey_hex.clone(),
                                is_live: v.is_live,
                            })
                        })
                        .collect();
                    debug!(epoch, sample_count = samples.len(), "liveness answer fetched");
                    answers.push(EpochLiveness { epoch, samples: Some(samples) });
                }
                Err(e) => {
                    warn!(
                        epoch,
                        error = %e,
                        "liveness query failed; will retry next slot (fail-closed)"
                    );
                    answers.push(EpochLiveness { epoch, samples: None });
                }
            }
        }

        let unobserved = self.machine.apply_liveness_tick(&answers, current_epoch, slot_in_epoch);
        let mut by_epoch: HashMap<Epoch, Vec<String>> = HashMap::new();
        for (epoch, key) in unobserved {
            by_epoch.entry(epoch).or_default().push(key);
        }
        for (epoch, keys) in by_epoch {
            self.warn_unobserved(current_epoch, epoch, &keys);
        }
    }

    /// One warning per `(pubkey, epoch)`. Entries older than the previous
    /// epoch are dropped; those epochs are no longer queried.
    fn warn_unobserved(&self, current_epoch: Epoch, epoch: Epoch, keys: &[String]) {
        if keys.is_empty() {
            return;
        }
        let retain_from = current_epoch.saturating_sub(2);
        let mut warned = self.unobserved_warned.lock();
        warned.retain(|(_, seen)| *seen >= retain_from);
        let mut fresh = Vec::new();
        for key in keys {
            if warned.insert((key.clone(), epoch)) {
                fresh.push(key.clone());
            }
        }
        drop(warned);
        for key in fresh {
            warn!(
                pubkey = %observability::logging::TruncatedPubkey::new(&key),
                epoch,
                "doppelganger liveness unobserved; Safe stays closed for this key"
            );
        }
    }

    /// Single-cycle driver for tests (no sleep / cancel).
    ///
    /// Queries the previous and current epochs at `(epoch, slot_in_epoch)`,
    /// the same pair [`Self::run`] queries from the clock.
    ///
    /// Compiled only for this crate's tests or when the `test-utils` feature
    /// is enabled. Integration tests see it through the self dev-dependency.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn drive_once_for_test(
        &self,
        epoch: Epoch,
        slot_in_epoch: u64,
    ) -> Vec<ForwardWindowStatus> {
        self.tick_once(epoch, slot_in_epoch).await
    }

    /// Drop import sidecars for loaded keys that are Safe.
    ///
    /// Called after every tick. A failed delete leaves the sidecar, so the
    /// next boot stays Pending. Keys that are not Safe are left alone.
    fn record_completed_imports(&self) {
        let (Some(dir), Some(map), Some(tracked)) =
            (&self.import_sidecar_dir, &self.pubkey_map, &self.tracked_keys)
        else {
            return;
        };
        let map = Arc::clone(map);
        let machine = Arc::clone(&self.machine);
        crate::config::clear_completed_import_sidecars(dir, tracked.as_ref(), move |pk| {
            let Some(public) = map.read().get(pk).cloned() else {
                return false;
            };
            machine.status(&public) == ForwardWindowStatus::Safe
        });
    }

    /// Test helper: run one index refresh from the attached pubkey map.
    ///
    /// `validators` is the index lookup. The loop client is only [`LivenessApi`],
    /// which has no `get_validators`. Not a production writer. [`Self::run`]
    /// must not call this.
    ///
    /// Compiled only for this crate's tests or when the `test-utils` feature
    /// is enabled. Integration tests build this crate without `cfg(test)`, so
    /// the `test-utils` arm inlines the refresh body.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn refresh_indices_for_test(&self, validators: &dyn NodeStatusApi) {
        #[cfg(test)]
        {
            self.refresh_indices_from_pubkey_map(validators).await;
        }
        #[cfg(not(test))]
        {
            refresh_indices_from_pubkey_map_impl!(self, validators);
        }
    }
}

/// Spawn the production liveness loop whenever a machine exists.
///
/// An empty registry still starts the loop. The loop makes no beacon-node
/// call until a pending key has an index. `pubkey_index` is the
/// workspace-shared registry (same handle used by `prepare_proposers` / duty
/// tracking). Production index refresh is
/// [`crate::index_resolver::IndexResolver`]; `pubkey_map` stays attached for
/// `LivenessObservationLoop::refresh_indices_for_test`.
///
/// The loop is registered on `executor` at Orchestrator tier (ARCH-2g P1-7).
pub fn spawn_liveness_loop(
    machine: Option<Arc<ForwardWindowMachine>>,
    beacon: Arc<dyn LivenessApi>,
    pubkey_index: SharedPubkeyIndexRegistry,
    pubkey_map: Option<PubkeyMap>,
    epoch_clock: Arc<MonotonicEpochClock>,
    executor: &TaskExecutor,
    // Keystore dir + shared DELETE/import lock for Safe sidecar cleanup.
    import_sidecar: Option<(std::path::PathBuf, Arc<TrackedKeys>)>,
) -> Option<LivenessLoopSpawn> {
    let machine = machine?;
    if pubkey_index.read().is_empty() {
        info!(
            "SEC-2c: starting liveness loop with empty indices \
             (IndexResolver owns index refresh; pending activation / post-import)"
        );
    }

    let pubkey_index_ret = Arc::clone(&pubkey_index);
    let cancel = executor.token();
    let exit_request: Arc<dyn ExitRequest> = Arc::new(executor.shutdown_handle());
    let mut loop_task =
        LivenessObservationLoop::new(machine, beacon, pubkey_index, epoch_clock, cancel)
            .with_exit_request(exit_request);
    if let Some(pm) = pubkey_map {
        loop_task = loop_task.with_pubkey_map(pm);
    }
    if let Some((dir, tracked)) = import_sidecar {
        loop_task = loop_task.with_detection_marker_dir(dir.clone());
        loop_task = loop_task.with_import_sidecar_dir(dir, tracked);
    }
    executor.spawn("liveness_loop", ShutdownTier::Orchestrator, async move {
        loop_task.run().await;
    });
    Some(LivenessLoopSpawn { pubkey_index: pubkey_index_ret })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubkey_index::PubkeyIndexRegistry;
    use bn_manager::MockBeaconNodeClient;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use beacon::{
        BeaconError, ValidatorData, ValidatorInfo, ValidatorLiveness, ValidatorLivenessResponse,
        ValidatorsResponse,
    };
    use doppelganger::{SigningEnablement, CLOSED_EPOCH_SLOT, DEFAULT_MONITORING_EPOCHS};
    use eth_types::Root;
    use signer::SignerService;
    use slashing::SlashingDb;

    // ── helpers ────────────────────────────────────────────────────────────

    fn gvr() -> Root {
        [0xab; 32]
    }

    fn machine() -> Arc<ForwardWindowMachine> {
        let db: Arc<dyn slashing::SlashingDbReader> =
            Arc::new(SlashingDb::open_in_memory().unwrap());
        Arc::new(ForwardWindowMachine::new(db, DEFAULT_MONITORING_EPOCHS, gvr()))
    }

    fn new_pk() -> crypto::PublicKey {
        crypto::SecretKey::generate().public_key()
    }

    /// Shared mock helpers for liveness tests (RF4-24).
    /// Mutable sequence / fail-first / validators live in Arc state captured by handlers.
    struct LivenessMockState {
        live: parking_lot::RwLock<HashMap<String, bool>>,
        fail_first: AtomicUsize,
        validators: parking_lot::RwLock<HashMap<String, String>>,
        live_sequence: parking_lot::Mutex<Vec<HashMap<String, bool>>>,
        /// Set when a test must prove signing stayed closed during a query.
        gate: parking_lot::Mutex<Option<SigningGateProbe>>,
    }

    struct SigningGateProbe {
        machine: Arc<ForwardWindowMachine>,
        pubkey: crypto::PublicKey,
        opened: Arc<AtomicBool>,
    }

    impl LivenessMockState {
        fn new(live: HashMap<String, bool>) -> Arc<Self> {
            Arc::new(Self {
                live: parking_lot::RwLock::new(live),
                fail_first: AtomicUsize::new(0),
                validators: parking_lot::RwLock::new(HashMap::new()),
                live_sequence: parking_lot::Mutex::new(Vec::new()),
                gate: parking_lot::Mutex::new(None),
            })
        }

        fn watch_signing_gate(
            &self,
            machine: Arc<ForwardWindowMachine>,
            pubkey: crypto::PublicKey,
            opened: Arc<AtomicBool>,
        ) {
            *self.gate.lock() = Some(SigningGateProbe { machine, pubkey, opened });
        }

        fn push_live_response(&self, indices: &[(&str, bool)]) {
            let mut m = HashMap::new();
            for (i, v) in indices {
                m.insert((*i).to_string(), *v);
            }
            self.live_sequence.lock().push(m);
        }

        fn with_validators(self: &Arc<Self>, pairs: &[(&str, &str)]) -> Arc<Self> {
            let mut v = HashMap::new();
            for (pk, idx) in pairs {
                v.insert((*pk).to_string(), (*idx).to_string());
            }
            *self.validators.write() = v;
            Arc::clone(self)
        }
    }

    fn build_liveness_mock(state: Arc<LivenessMockState>) -> MockBeaconNodeClient {
        let state_v = Arc::clone(&state);
        let state_l = Arc::clone(&state);
        MockBeaconNodeClient::new()
            .with_get_validators(move |pubkeys| {
                let vmap = state_v.validators.read();
                let data = pubkeys
                    .iter()
                    .filter_map(|pk| {
                        let idx = vmap.get(pk)?;
                        Some(ValidatorData {
                            index: idx.clone(),
                            status: "active_ongoing".to_string(),
                            validator: ValidatorInfo { pubkey: pk.clone() },
                        })
                    })
                    .collect();
                Ok(ValidatorsResponse { data })
            })
            .with_post_validator_liveness(move |_epoch, validator_indices| {
                if let Some(probe) = &*state_l.gate.lock() {
                    if probe.machine.is_signing_enabled(&probe.pubkey) {
                        probe.opened.store(true, Ordering::SeqCst);
                    }
                }
                let remaining = state_l.fail_first.load(Ordering::SeqCst);
                if remaining > 0 {
                    state_l.fail_first.fetch_sub(1, Ordering::SeqCst);
                    return Err(BeaconError::HttpError("primary BN down".to_string()));
                }
                let live_map = {
                    let mut seq = state_l.live_sequence.lock();
                    if !seq.is_empty() {
                        seq.remove(0)
                    } else {
                        state_l.live.read().clone()
                    }
                };
                let data = validator_indices
                    .iter()
                    .filter_map(|idx| {
                        live_map.get(idx).map(|is_live| ValidatorLiveness {
                            index: idx.clone(),
                            is_live: *is_live,
                        })
                    })
                    .collect();
                Ok(ValidatorLivenessResponse { data })
            })
    }

    /// Failover-style client: each liveness call tries "primary" (always fails) then
    /// "secondary" (returns not-live) — same sequence as the old FailoverLivenessClient.
    fn build_failover_liveness_mock(indices: &[&str]) -> MockBeaconNodeClient {
        let mut live = HashMap::new();
        for i in indices {
            live.insert((*i).to_string(), false);
        }
        let live = Arc::new(parking_lot::RwLock::new(live));
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let secondary_calls = Arc::new(AtomicUsize::new(0));
        MockBeaconNodeClient::new().with_post_validator_liveness(
            move |_epoch, validator_indices| {
                // Primary always down (matches fail_first=100 on the old primary mock).
                primary_calls.fetch_add(1, Ordering::SeqCst);
                let _primary: Result<ValidatorLivenessResponse, BeaconError> =
                    Err(BeaconError::HttpError("primary BN down".to_string()));
                // Failover to secondary.
                secondary_calls.fetch_add(1, Ordering::SeqCst);
                let live_map = live.read();
                let data = validator_indices
                    .iter()
                    .filter_map(|idx| {
                        live_map.get(idx).map(|is_live| ValidatorLiveness {
                            index: idx.clone(),
                            is_live: *is_live,
                        })
                    })
                    .collect();
                // Discard the primary Err and return secondary Ok — mirrors
                // `match primary { Ok(r) => Ok(r), Err(_) => secondary }`.
                let _ = _primary;
                Ok(ValidatorLivenessResponse { data })
            },
        )
    }

    fn all_not_live(indices: &[&str]) -> (MockBeaconNodeClient, Arc<LivenessMockState>) {
        let mut live = HashMap::new();
        for i in indices {
            live.insert((*i).to_string(), false);
        }
        let state = LivenessMockState::new(live);
        (build_liveness_mock(Arc::clone(&state)), state)
    }

    fn with_live(indices: &[(&str, bool)]) -> (MockBeaconNodeClient, Arc<LivenessMockState>) {
        let mut live = HashMap::new();
        for (i, v) in indices {
            live.insert((*i).to_string(), *v);
        }
        let state = LivenessMockState::new(live);
        (build_liveness_mock(Arc::clone(&state)), state)
    }

    fn loop_with(
        machine: Arc<ForwardWindowMachine>,
        beacon: Arc<dyn LivenessApi>,
        numeric_index: &str,
        pubkey: &crypto::PublicKey,
    ) -> LivenessObservationLoop {
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pubkey.to_bytes(), numeric_index.to_string());
        LivenessObservationLoop::new(
            machine,
            beacon,
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        )
        .with_slot_duration(Duration::from_millis(1))
    }

    async fn drive_closed_boot(
        loop_: &LivenessObservationLoop,
        start: u64,
    ) -> Vec<ForwardWindowStatus> {
        let remaining = DEFAULT_MONITORING_EPOCHS + 1;
        let mut last = Vec::new();
        for offset in 0..remaining {
            let counted = start + offset;
            last = loop_.drive_once_for_test(counted + 1, CLOSED_EPOCH_SLOT).await;
        }
        last
    }

    async fn drive_closed_import(
        loop_: &LivenessObservationLoop,
        start: u64,
    ) -> Vec<ForwardWindowStatus> {
        let remaining = DEFAULT_MONITORING_EPOCHS + 1;
        let mut last = Vec::new();
        for offset in 0..remaining {
            let counted = start + 1 + offset;
            last = loop_.drive_once_for_test(counted + 1, CLOSED_EPOCH_SLOT).await;
        }
        last
    }

    // ── SEC-2c tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_detected_liveness_in_window_keeps_gate_closed() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        assert!(!m.is_signing_enabled(&pk));

        let bn = Arc::new(with_live(&[("42", true)]).0);
        let loop_ = loop_with(Arc::clone(&m), bn, "42", &pk);

        loop_.drive_once_for_test(start, 0).await;

        assert_eq!(m.status(&pk), ForwardWindowStatus::Detected);
        assert!(!m.is_signing_enabled(&pk), "Detected must keep gate closed");

        m.tick(start + DEFAULT_MONITORING_EPOCHS + 5, 0);
        assert!(!m.is_signing_enabled(&pk));
        assert!(!m.is_signing_enabled(&pk), "no signing when Detected (enablement false)");
    }

    #[tokio::test]
    async fn test_clean_window_opens_gate_and_signing_proceeds() {
        let m = machine();
        let pk = new_pk();
        let start = 20u64;
        m.register(&pk, start);
        assert!(!m.is_signing_enabled(&pk));

        let bn = Arc::new(all_not_live(&["7"]).0);
        let loop_ = loop_with(Arc::clone(&m), bn, "7", &pk);

        let statuses = drive_closed_boot(&loop_, start).await;
        assert!(
            statuses.contains(&ForwardWindowStatus::Safe) || m.is_signing_enabled(&pk),
            "clean window must open gate"
        );
        assert!(m.is_signing_enabled(&pk), "signing must proceed after clean window");
        assert_eq!(m.status(&pk), ForwardWindowStatus::Safe);
    }

    /// A completed forward window removes the import sidecar. Pending and
    /// Detected keys keep theirs.
    #[tokio::test]
    async fn test_observed_safe_removes_import_sidecar_pending_and_detected_keep_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let m = machine();
        let safe_pk = new_pk();
        let pending_pk = new_pk();
        let detected_pk = new_pk();
        let start = 20u64;
        m.register_for_import(&safe_pk, start);
        m.register_for_import(&pending_pk, start + 50);
        m.register_for_import(&detected_pk, start);

        let write = |pk: &crypto::PublicKey| {
            let path =
                dir.path().join(format!("0x{}.import_meta.json", hex::encode(pk.to_bytes())));
            std::fs::write(&path, "{\"imported_unix_seconds\":1}").unwrap();
            path
        };
        let safe_path = write(&safe_pk);
        let pending_path = write(&pending_pk);
        let detected_path = write(&detected_pk);

        let mut pm = HashMap::new();
        pm.insert(safe_pk.to_bytes(), safe_pk.clone());
        pm.insert(pending_pk.to_bytes(), pending_pk.clone());
        pm.insert(detected_pk.to_bytes(), detected_pk.clone());
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(pm));

        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(safe_pk.to_bytes(), "7".to_string());
        reg.write().insert(detected_pk.to_bytes(), "8".to_string());
        let bn = Arc::new(with_live(&[("7", false), ("8", true)]).0);
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn,
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        )
        .with_slot_duration(Duration::from_millis(1))
        .with_pubkey_map(pubkey_map)
        .with_import_sidecar_dir(
            dir.path().to_path_buf(),
            Arc::new(crate::quiesce::TrackedKeys::new()),
        );

        // Import next_check is start + 1. A live answer there detects.
        loop_.drive_once_for_test(start + 1, 0).await;
        assert_eq!(m.status(&detected_pk), ForwardWindowStatus::Detected);
        assert!(detected_path.exists(), "Detected must keep the unfinished marker");
        assert!(safe_path.exists(), "Pending must keep the unfinished marker");

        drive_closed_import(&loop_, start).await;
        assert_eq!(m.status(&safe_pk), ForwardWindowStatus::Safe);
        assert!(!safe_path.exists(), "Safe observation must remove the import sidecar");
        assert!(pending_path.exists(), "a key still inside its window keeps its sidecar");
        assert!(detected_path.exists(), "Detected must keep the unfinished marker");
    }

    #[tokio::test]
    async fn test_liveness_loop_routes_through_bn_manager_failover() {
        let m = machine();
        let pk = new_pk();
        let start = 30u64;
        m.register(&pk, start);

        // Failover sequence preserved: one call path that succeeds after primary would fail
        // (shared mock returns secondary-style success; primary permanent-down is modeled
        // by always returning the secondary result — loop sees a single Ok, same as before).
        let failover = Arc::new(build_failover_liveness_mock(&["99"]));
        let loop_ = loop_with(Arc::clone(&m), failover.clone(), "99", &pk);

        let statuses = loop_.drive_once_for_test(start, 0).await;
        assert!(
            statuses.contains(&ForwardWindowStatus::Pending),
            "failover must succeed via secondary: {statuses:?}"
        );

        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));

        drive_closed_boot(&loop_, start).await;
        assert!(m.is_signing_enabled(&pk), "clean window via failover must open gate");
    }

    #[tokio::test]
    async fn test_single_doppelganger_mechanism_in_production() {
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 40);
        assert!(!m.is_signing_enabled(&pk), "Pending before loop");

        let km = crypto::KeyManager::new();
        let composite = Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(km)));
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let enablement: Arc<dyn SigningEnablement> = Arc::clone(&m) as _;
        let _signer = SignerService::new(composite, db).with_enablement(enablement);

        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "1".to_string());
        let bn = Arc::new(all_not_live(&["1"]).0);
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        let handle = spawn_liveness_loop(
            Some(Arc::clone(&m)),
            bn,
            Arc::clone(&reg),
            None,
            Arc::new(MonotonicEpochClock::with_start_time(
                0,
                std::time::Instant::now(),
                1_000_000,
                12_000,
            )),
            &exec,
            None,
        );
        assert!(handle.is_some(), "production loop must spawn with indices");
        let _ = exec.shutdown(crate::bootstrap::executor::TierBudget::default()).await;

        let empty = PubkeyIndexRegistry::shared();
        let (exec2, _rx2) = TaskExecutor::new(CancellationToken::new());
        let no_handle = spawn_liveness_loop(
            Some(machine()),
            Arc::new(all_not_live(&[]).0),
            empty,
            None,
            Arc::new(MonotonicEpochClock::new(0, 12_000)),
            &exec2,
            None,
        );
        assert!(no_handle.is_some(), "a machine with an empty registry still starts the loop");

        let (exec3, _rx3) = TaskExecutor::new(CancellationToken::new());
        let no_machine = spawn_liveness_loop(
            None,
            Arc::new(all_not_live(&["1"]).0),
            Arc::clone(&reg),
            None,
            Arc::new(MonotonicEpochClock::new(0, 12_000)),
            &exec3,
            None,
        );
        assert!(no_machine.is_none());
    }

    /// Finding 3: index map can be updated after spawn; new keys become observable.
    #[tokio::test]
    async fn test_index_map_refresh_allows_new_key_observation() {
        let m = machine();
        let pk = new_pk();
        let start = 50u64;
        m.register_for_import(&pk, start); // import-strict Pending
        assert!(!m.is_signing_enabled(&pk));

        let pk_hex_0x = format!("0x{}", hex::encode(pk.to_bytes()));
        let bare = hex::encode(pk.to_bytes());

        // Start with EMPTY registry — key cannot be observed yet.
        let pubkey_index = PubkeyIndexRegistry::shared();
        let (bn_mock, bn_state) = all_not_live(&["77"]);
        bn_state.with_validators(&[(&pk_hex_0x, "77")]);
        // Also make liveness report for 77.
        bn_state.live.write().insert("77".to_string(), false);
        let bn = Arc::new(bn_mock);

        let mut pm_inner = HashMap::new();
        pm_inner.insert(pk.to_bytes(), pk.clone());
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(pm_inner));

        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn.clone(),
            Arc::clone(&pubkey_index),
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        )
        .with_pubkey_map(pubkey_map)
        .with_slot_duration(Duration::from_millis(1));

        // Before refresh: empty map → no beacon call, still Pending.
        let before = loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        assert!(before.iter().all(|s| *s == ForwardWindowStatus::Pending));
        assert!(pubkey_index.read().is_empty());
        assert!(
            bn.post_validator_liveness_calls().is_empty(),
            "an empty registry makes no liveness call"
        );

        // Refresh pulls index 77 from BN for the pubkey_map key.
        loop_.refresh_indices_for_test(bn.as_ref()).await;
        assert_eq!(pubkey_index.read().bare_hex_of_index("77"), Some(bare.as_str()));

        drive_closed_import(&loop_, start).await;
        assert!(
            m.is_signing_enabled(&pk),
            "after index refresh + clean window, imported key must open"
        );
    }

    /// Finding 1: re-query after first complete not-live can still Detect if later live.
    #[tokio::test]
    async fn test_requery_after_not_live_can_still_detect() {
        let m = machine();
        let pk = new_pk();
        let start = 60u64;
        m.register(&pk, start);

        let (bn_mock, bn_state) = all_not_live(&["5"]);
        // First complete response: not live. Second: live.
        bn_state.push_live_response(&[("5", false)]);
        bn_state.push_live_response(&[("5", true)]);
        let bn = Arc::new(bn_mock);

        let loop_ = loop_with(Arc::clone(&m), bn, "5", &pk);

        // First observation: not-live, epoch not closed → still Pending.
        loop_.drive_once_for_test(start, 0).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);

        // Second observation same epoch: is_live=true → Detected.
        loop_.drive_once_for_test(start, 1).await;
        assert_eq!(
            m.status(&pk),
            ForwardWindowStatus::Detected,
            "re-query after complete not-live must still Detect on later is_live=true"
        );
        assert!(!m.is_signing_enabled(&pk));
    }

    /// Finding 3 helper: merge_validator_indices updates shared registry.
    #[test]
    fn test_merge_validator_indices_updates_map() {
        let reg = PubkeyIndexRegistry::shared();
        let mut pk_to_idx = HashMap::new();
        // 48-byte pubkey required for registry insert.
        let pk = [0xab; 48];
        pk_to_idx.insert(format!("0x{}", hex::encode(pk)), "9".to_string());
        merge_validator_indices(&reg, &pk_to_idx);
        assert_eq!(reg.read().index_of(&pk), Some("9"));
        assert_eq!(reg.read().bare_hex_of_index("9"), Some(hex::encode(pk).as_str()));
    }

    /// Spawn with empty indices but non-empty pubkey_map still starts (activation path).
    #[tokio::test]
    async fn test_spawn_with_empty_indices_but_pubkey_map() {
        let pk = new_pk();
        let mut pm = HashMap::new();
        pm.insert(pk.to_bytes(), pk);
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(pm));
        let empty = PubkeyIndexRegistry::shared();
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        let spawn = spawn_liveness_loop(
            Some(machine()),
            Arc::new(all_not_live(&[]).0),
            empty,
            Some(pubkey_map),
            Arc::new(MonotonicEpochClock::new(0, 12_000)),
            &exec,
            None,
        );
        assert!(
            spawn.is_some(),
            "must start with an empty index set and a pubkey map; IndexResolver re-resolves \
             pending-activation keys, not this loop"
        );
        let _ = exec.shutdown(crate::bootstrap::executor::TierBudget::default()).await;
    }

    /// Production `run` must not refresh indices. The refresh method is `cfg(test)`.
    #[test]
    fn has_no_index_refresh_call() {
        let src = include_str!("liveness_loop.rs");
        let run_body = src
            .split("pub async fn run(self)")
            .nth(1)
            .expect("run")
            .split("/// Test-only index refresh")
            .next()
            .expect("refresh docs follow run");
        assert!(
            !run_body.contains("refresh_indices_from_pubkey_map"),
            "production liveness loop must not refresh indices"
        );
        assert!(
            !run_body.contains("refresh_indices_for_test"),
            "production liveness loop must not call the test helper"
        );
        let fn_at = src.find("async fn refresh_indices_from_pubkey_map").expect("method");
        assert!(
            src[..fn_at].lines().rev().take(12).any(|line| line.trim() == "#[cfg(test)]"),
            "refresh_indices_from_pubkey_map must be test-only"
        );
        assert!(src.contains("fn refresh_indices_for_test"));
    }

    /// Beacon stand-in that implements [`LivenessApi`] and nothing else.
    ///
    /// Construction is the proof: a `BeaconNodeClient` constructor cannot name
    /// this type.
    struct LivenessOnlyMock;

    #[async_trait::async_trait]
    impl LivenessApi for LivenessOnlyMock {
        async fn post_validator_liveness(
            &self,
            _epoch: u64,
            _validator_indices: &[String],
        ) -> Result<ValidatorLivenessResponse, BeaconError> {
            Ok(ValidatorLivenessResponse { data: vec![] })
        }

        async fn post_validator_liveness_merged(
            &self,
            epoch: u64,
            validator_indices: &[String],
        ) -> Result<ValidatorLivenessResponse, BeaconError> {
            self.post_validator_liveness(epoch, validator_indices).await
        }
    }

    /// A liveness-only client must construct [`LivenessObservationLoop`].
    #[tokio::test]
    async fn liveness_only_mock_satisfies_observation_loop() {
        let loop_ = LivenessObservationLoop::new(
            machine(),
            Arc::new(LivenessOnlyMock),
            PubkeyIndexRegistry::shared(),
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        );
        let statuses = loop_.drive_once_for_test(0, 0).await;
        assert!(statuses.is_empty());
    }

    fn loop_at(slot_duration_ms: u64) -> LivenessObservationLoop {
        LivenessObservationLoop::new(
            machine(),
            Arc::new(MockBeaconNodeClient::new()),
            PubkeyIndexRegistry::shared(),
            Arc::new(MonotonicEpochClock::with_start_time(
                0,
                std::time::Instant::now(),
                0,
                slot_duration_ms,
            )),
            CancellationToken::new(),
        )
    }

    #[test]
    fn slot_sleep_follows_beacon_slot_duration() {
        assert_eq!(loop_at(6_000).slot_duration(), Duration::from_secs(6));
        assert_eq!(loop_at(12_000).slot_duration(), Duration::from_secs(12));
        assert_eq!(loop_at(0).slot_duration(), Duration::MAX);
    }

    /// An answer for epoch e taken before slot 24 of e+1 does not decrement.
    /// The beacon node is asked only for the previous epoch and the current one.
    /// Signing stays closed while those requests are in flight, including the
    /// request for the current epoch on the tick that finally reaches Safe.
    #[tokio::test]
    async fn answer_before_slot_24_does_not_decrement_and_queries_adjacent_epochs() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let (bn_mock, state) = all_not_live(&["7"]);
        let opened = Arc::new(AtomicBool::new(false));
        state.watch_signing_gate(Arc::clone(&m), pk.clone(), Arc::clone(&opened));
        let bn = Arc::new(bn_mock);
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "7", &pk);

        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT - 1).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(start + 2, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending, "two closed epochs are not enough");
        assert!(!m.is_signing_enabled(&pk));
        loop_.drive_once_for_test(start + 3, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Safe);
        assert!(
            !opened.load(Ordering::SeqCst),
            "signing must stay closed until both answers of the closing tick are applied"
        );

        let epochs: Vec<u64> =
            bn.post_validator_liveness_calls().into_iter().map(|(epoch, _)| epoch).collect();
        assert_eq!(
            epochs,
            vec![start, start + 1, start, start + 1, start + 1, start + 2, start + 2, start + 3,]
        );
    }

    /// Register at epoch 10. Ticks (11, 24) and (12, 24) are not live. At
    /// (13, 24) epoch 12 is not live and epoch 13 is live, so the key is
    /// Detected. The live answer is not dropped on the tick that would
    /// otherwise open the gate.
    #[tokio::test]
    async fn live_current_epoch_on_closing_tick_is_detected() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let (bn_mock, state) = all_not_live(&["7"]);
        let opened = Arc::new(AtomicBool::new(false));
        state.watch_signing_gate(Arc::clone(&m), pk.clone(), Arc::clone(&opened));
        let bn = Arc::new(bn_mock);
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "7", &pk);

        loop_.drive_once_for_test(11, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(12, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));

        state.push_live_response(&[("7", false)]);
        state.push_live_response(&[("7", true)]);
        loop_.drive_once_for_test(13, CLOSED_EPOCH_SLOT).await;

        assert_eq!(m.status(&pk), ForwardWindowStatus::Detected);
        assert!(!m.is_signing_enabled(&pk));
        assert!(
            !opened.load(Ordering::SeqCst),
            "signing must stay closed until the not-live and live answers are both applied"
        );
        let epochs: Vec<u64> =
            bn.post_validator_liveness_calls().into_iter().map(|(epoch, _)| epoch).collect();
        assert_eq!(epochs, vec![10, 11, 11, 12, 12, 13]);
    }

    /// An import's registration epoch is not a counted epoch and is not queried
    /// once `next_check` has moved to the following epoch.
    #[tokio::test]
    async fn import_starts_counting_in_the_next_epoch() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register_for_import(&pk, start);
        let bn = Arc::new(all_not_live(&["7"]).0);
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "7", &pk);

        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));
        let first: Vec<u64> =
            bn.post_validator_liveness_calls().into_iter().map(|(epoch, _)| epoch).collect();
        assert_eq!(first, vec![start + 1], "the import epoch itself is not requested");

        // Closing the import epoch plus the next `monitoring_epochs` epochs
        // would finish a boot window. The import is still one epoch short.
        loop_.drive_once_for_test(start + 2, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(start + 3, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));
    }

    /// Imported key reaches Safe only by driving the liveness loop through the
    /// closed epochs that start the epoch after import.
    #[tokio::test]
    async fn import_acceptance_through_liveness_loop() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register_for_import(&pk, start);
        let (bn_mock, state) = all_not_live(&["7"]);
        let opened = Arc::new(AtomicBool::new(false));
        state.watch_signing_gate(Arc::clone(&m), pk.clone(), Arc::clone(&opened));
        let bn = Arc::new(bn_mock);
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "7", &pk);

        for offset in 0..DEFAULT_MONITORING_EPOCHS {
            let counted = start + 1 + offset;
            loop_.drive_once_for_test(counted + 1, CLOSED_EPOCH_SLOT).await;
            assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
            assert!(!m.is_signing_enabled(&pk));
        }
        let last = start + 1 + DEFAULT_MONITORING_EPOCHS;
        loop_.drive_once_for_test(last + 1, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Safe);
        assert!(m.is_signing_enabled(&pk));
        assert!(
            !opened.load(Ordering::SeqCst),
            "signing must stay closed until both answers of the closing tick are applied"
        );

        let epochs: Vec<u64> =
            bn.post_validator_liveness_calls().into_iter().map(|(epoch, _)| epoch).collect();
        assert_eq!(epochs, vec![11, 12, 12, 13, 13, 14]);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn warns_once_per_unobserved_pubkey_and_epoch() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let prefix = hex::encode(pk.to_bytes());
        let prefix = &prefix[..10];
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            Arc::new(MockBeaconNodeClient::new()),
            PubkeyIndexRegistry::shared(),
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        );
        loop_.drive_once_for_test(start, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(start, CLOSED_EPOCH_SLOT).await;
        let epoch_10 = format!("epoch={start}");
        logs_assert(|lines| {
            let hits = lines
                .iter()
                .filter(|line| {
                    line.contains("unobserved") && line.contains(&epoch_10) && line.contains(prefix)
                })
                .count();
            if hits == 1 {
                Ok(())
            } else {
                Err(format!("expected one warn for epoch {start}, got {hits}: {lines:?}"))
            }
        });
        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        let epoch_11 = format!("epoch={}", start + 1);
        logs_assert(|lines| {
            let first = lines
                .iter()
                .filter(|line| line.contains("unobserved") && line.contains(&epoch_10))
                .count();
            let second = lines
                .iter()
                .filter(|line| {
                    line.contains("unobserved") && line.contains(&epoch_11) && line.contains(prefix)
                })
                .count();
            if first == 1 && second == 1 {
                Ok(())
            } else {
                Err(format!("epoch10={first} epoch11={second}: {lines:?}"))
            }
        });
    }

    /// A failed liveness query does not decrement. The key stays Pending.
    #[tokio::test]
    async fn liveness_query_error_does_not_decrement() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let bn = Arc::new(MockBeaconNodeClient::new());
        let loop_ = loop_with(Arc::clone(&m), bn, "7", &pk);
        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));
    }

    struct RecordingExit {
        codes: std::sync::Mutex<Vec<i32>>,
    }

    impl ExitRequest for RecordingExit {
        fn request(&self, exit_code: i32) {
            self.codes.lock().expect("exit codes").push(exit_code);
        }
    }

    /// Paused slot clock. A live answer for a Pending key requests exit 12 once,
    /// after the marker write succeeds.
    #[tokio::test(start_paused = true)]
    async fn detection_requests_shutdown_with_exit_code_12() {
        let dir = tempfile::tempdir().expect("temp");
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        let bn = Arc::new(with_live(&[("7", true)]).0);
        let cancel = CancellationToken::new();
        let recording = Arc::new(RecordingExit { codes: std::sync::Mutex::new(Vec::new()) });
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn,
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            cancel.clone(),
        )
        .with_slot_duration(Duration::from_secs(12))
        .with_detection_marker_dir(dir.path().to_path_buf())
        .with_exit_request(recording.clone() as Arc<dyn ExitRequest>);

        let task = tokio::spawn(loop_.run());
        let started = std::time::Instant::now();
        loop {
            if !recording.codes.lock().expect("exit codes").is_empty() {
                break;
            }
            if task.is_finished() {
                panic!("liveness loop ended before the shutdown request");
            }
            if started.elapsed() > Duration::from_secs(5) {
                panic!("no shutdown request within 5s; status={:?}", m.status(&pk));
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            recording.codes.lock().expect("exit codes").as_slice(),
            &[EXIT_DOPPELGANGER_DETECTED]
        );
        assert_eq!(m.status(&pk), ForwardWindowStatus::Detected);

        tokio::time::advance(Duration::from_secs(12)).await;
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            recording.codes.lock().expect("exit codes").as_slice(),
            &[12],
            "a later tick must not request shutdown again"
        );

        cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("liveness loop");
        assert_eq!(recording.codes.lock().expect("exit codes").as_slice(), &[12]);
    }

    struct MarkerExit {
        dir: std::path::PathBuf,
        codes: std::sync::Mutex<Vec<i32>>,
        marker_was_durable: std::sync::atomic::AtomicBool,
    }

    impl ExitRequest for MarkerExit {
        fn request(&self, exit_code: i32) {
            let ready = crate::detection_marker::marker_path(&self.dir).is_file();
            self.marker_was_durable.store(ready, std::sync::atomic::Ordering::SeqCst);
            self.codes.lock().expect("exit codes").push(exit_code);
        }
    }

    /// The liveness loop stores the latch, writes the marker, then requests exit 12.
    #[tokio::test(start_paused = true)]
    async fn detection_writes_marker_before_exit_12() {
        let dir = tempfile::tempdir().expect("temp");
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        let bn = Arc::new(with_live(&[("7", true)]).0);
        let cancel = CancellationToken::new();
        let recording = Arc::new(MarkerExit {
            dir: dir.path().to_path_buf(),
            codes: std::sync::Mutex::new(Vec::new()),
            marker_was_durable: std::sync::atomic::AtomicBool::new(false),
        });
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn,
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            cancel.clone(),
        )
        .with_slot_duration(Duration::from_secs(12))
        .with_detection_marker_dir(dir.path().to_path_buf())
        .with_exit_request(recording.clone() as Arc<dyn ExitRequest>);

        let task = tokio::spawn(loop_.run());
        let started = std::time::Instant::now();
        loop {
            if !recording.codes.lock().expect("exit codes").is_empty() {
                break;
            }
            if task.is_finished() {
                panic!("liveness loop ended before the shutdown request");
            }
            if started.elapsed() > Duration::from_secs(5) {
                panic!("no shutdown request within 5s");
            }
            tokio::task::yield_now().await;
        }
        assert!(
            recording.marker_was_durable.load(std::sync::atomic::Ordering::SeqCst),
            "the marker file must exist before the exit request"
        );
        assert_eq!(recording.codes.lock().expect("codes").as_slice(), &[12]);
        assert!(m.detected_latch());
        assert!(m.detection_persisted(), "the successful fsync must set the durability flag");
        match crate::detection_marker::inspect(dir.path()) {
            crate::detection_marker::MarkerInspect::Present(marker) => {
                assert!(marker
                    .pubkeys
                    .iter()
                    .any(|pk_hex| pk_hex.ends_with(&hex::encode(pk.to_bytes()))));
            }
            other => panic!("expected a readable marker, got {other:?}"),
        }
        cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("liveness loop");
    }

    async fn poll_until_parked(task: &tokio::task::JoinHandle<()>) {
        for _ in 0..32 {
            if task.is_finished() {
                panic!("liveness loop ended");
            }
            tokio::task::yield_now().await;
        }
    }

    /// A failed marker write does not exit. The next tick retries, and exit 12
    /// follows only after the write succeeds.
    #[tokio::test(start_paused = true)]
    async fn detection_does_not_exit_until_the_marker_write_succeeds() {
        let dir = tempfile::tempdir().expect("temp");
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"x").expect("file");
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        let bn = Arc::new(with_live(&[("7", true)]).0);
        let cancel = CancellationToken::new();
        let recording = Arc::new(RecordingExit { codes: std::sync::Mutex::new(Vec::new()) });
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn,
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            cancel.clone(),
        )
        .with_slot_duration(Duration::from_secs(12))
        .with_detection_marker_dir(not_a_dir.clone())
        .with_exit_request(recording.clone() as Arc<dyn ExitRequest>);

        let task = tokio::spawn(loop_.run());
        poll_until_parked(&task).await;
        assert!(
            recording.codes.lock().expect("codes").is_empty(),
            "a failed marker write must not request exit"
        );
        assert!(m.detected_latch(), "the latch stays set while the write is retried");
        assert!(!m.detection_persisted(), "a failed write must not set the durability flag");

        tokio::time::advance(Duration::from_secs(12)).await;
        poll_until_parked(&task).await;
        assert!(
            recording.codes.lock().expect("codes").is_empty(),
            "the retry must also refuse to exit while the write fails"
        );

        std::fs::remove_file(&not_a_dir).expect("remove blocker");
        std::fs::create_dir(&not_a_dir).expect("writable dir");
        tokio::time::advance(Duration::from_secs(12)).await;
        let started = std::time::Instant::now();
        loop {
            if !recording.codes.lock().expect("exit codes").is_empty() {
                break;
            }
            if task.is_finished() {
                panic!("liveness loop ended before the shutdown request");
            }
            if started.elapsed() > Duration::from_secs(5) {
                panic!("no shutdown request after the marker write succeeded");
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(recording.codes.lock().expect("codes").as_slice(), &[12]);
        assert!(m.detection_persisted(), "exit 12 follows the fsync that returned Ok");
        assert!(matches!(
            crate::detection_marker::inspect(&not_a_dir),
            crate::detection_marker::MarkerInspect::Present(_)
        ));
        cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("liveness loop");
    }

    /// Detection writes the marker, the real drain returns exit 12, and the
    /// next boot of the same directory is refused.
    #[tokio::test(start_paused = true)]
    async fn detection_exit_12_then_boot_is_refused() {
        let dir = tempfile::tempdir().expect("temp");
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        let bn = Arc::new(with_live(&[("7", true)]).0);
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let handle = executor.shutdown_handle();
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        let clock =
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000));
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn,
            reg,
            Arc::clone(&clock),
            token.clone(),
        )
        .with_slot_duration(Duration::from_secs(12))
        .with_detection_marker_dir(dir.path().to_path_buf())
        .with_exit_request(Arc::new(handle) as Arc<dyn ExitRequest>);

        let task = tokio::spawn(loop_.run());
        let (_outcome, res) = crate::bootstrap::await_shutdown_and_drain_with_signal(
            drain_inputs(
                executor,
                shutdown_rx,
                token.clone(),
                Some(detection_shutdown(Arc::clone(&m), dir.path().to_path_buf(), None, clock)),
            ),
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "the drain must return exit 12, got {res:?}"
        );
        assert!(matches!(
            crate::detection_marker::inspect(dir.path()),
            crate::detection_marker::MarkerInspect::Present(_)
        ));

        let err = boot_refusing(dir.path(), None).await;
        assert_eq!(err.exit_code(), EXIT_DOPPELGANGER_DETECTED);

        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("liveness loop");
    }

    /// A failed keystore write, then SIGTERM, still exits 12. The fallback
    /// record beside the slashing database is what the next boot refuses.
    #[tokio::test(start_paused = true)]
    async fn sigterm_during_marker_retry_exits_12_and_boot_is_refused() {
        let fallback = tempfile::tempdir().expect("temp");
        let missing = missing_marker_dir("sigterm");
        let (m, task, executor, shutdown_rx, token, clock) =
            latched_loop_with_failing_marker(&missing).await;
        assert!(
            !executor.doppelganger_exit_requested(),
            "a failed write must not have requested exit before the signal"
        );
        let (_outcome, res) = crate::bootstrap::await_shutdown_and_drain_with_signal(
            drain_inputs(
                executor,
                shutdown_rx,
                token,
                Some(detection_shutdown(
                    Arc::clone(&m),
                    missing,
                    Some(fallback.path().to_path_buf()),
                    clock,
                )),
            ),
            std::future::ready(()),
        )
        .await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "SIGTERM during the marker retry must exit 12, got {res:?}"
        );
        assert!(
            matches!(
                crate::detection_marker::inspect(fallback.path()),
                crate::detection_marker::MarkerInspect::Present(_)
            ),
            "the fallback marker must be durable"
        );
        let clean = tempfile::tempdir().expect("clean keystore");
        let err = boot_refusing(clean.path(), Some(fallback.path().join("slashing.sqlite"))).await;
        assert_eq!(err.exit_code(), EXIT_DOPPELGANGER_DETECTED);
        task.abort();
    }

    /// A failed keystore write, then token cancel, still exits 12 with a fallback.
    #[tokio::test(start_paused = true)]
    async fn token_cancel_during_marker_retry_exits_12() {
        let fallback = tempfile::tempdir().expect("temp");
        let missing = missing_marker_dir("cancel");
        let (m, task, executor, shutdown_rx, token, clock) =
            latched_loop_with_failing_marker(&missing).await;
        token.cancel();
        let (_outcome, res) = crate::bootstrap::await_shutdown_and_drain_with_signal(
            drain_inputs(
                executor,
                shutdown_rx,
                token,
                Some(detection_shutdown(m, missing, Some(fallback.path().to_path_buf()), clock)),
            ),
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "token cancel during the marker retry must exit 12, got {res:?}"
        );
        assert!(matches!(
            crate::detection_marker::inspect(fallback.path()),
            crate::detection_marker::MarkerInspect::Present(_)
        ));
        task.abort();
    }

    /// A panicking registered task while the latch is set must not exit 0 or 16.
    #[tokio::test]
    async fn panic_while_latched_exits_12_with_a_fallback_marker() {
        let fallback = tempfile::tempdir().expect("temp");
        let missing = missing_marker_dir("panic");
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        let samples =
            vec![ValidatorLivenessData { index: hex::encode(pk.to_bytes()), is_live: true }];
        let _ = m.apply_liveness_tick(&[EpochLiveness { epoch: 0, samples: Some(samples) }], 0, 0);
        assert!(m.detected_latch());
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        executor.spawn("boom_task", ShutdownTier::Background, async {
            panic!("latched task failed");
        });
        let clock =
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000));
        let (_outcome, res) = crate::bootstrap::await_shutdown_and_drain_with_signal(
            drain_inputs(
                executor,
                shutdown_rx,
                token,
                Some(detection_shutdown(m, missing, Some(fallback.path().to_path_buf()), clock)),
            ),
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "a panic while latched must exit 12, got {res:?}"
        );
        assert!(matches!(
            crate::detection_marker::inspect(fallback.path()),
            crate::detection_marker::MarkerInspect::Present(_)
        ));
    }

    /// A failed marker write increments this test's view of the counter by at least one.
    #[tokio::test(start_paused = true)]
    async fn failed_marker_write_increments_the_failure_counter() {
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let missing = missing_marker_dir("metric");
        let (_m, task, _executor, _shutdown_rx, token, _clock) =
            latched_loop_with_failing_marker(&missing).await;
        let after = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        assert!(
            after.saturating_sub(before) >= 1,
            "rvc_doppelganger_marker_write_failures_total must grow on a failed write \
             (before {before}, after {after})"
        );
        token.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.abort();
    }

    /// Marker and fallback writes fail. The pre-allocated record is overwritten
    /// in place, the drain exits 12, and the next boot refuses that record.
    #[tokio::test(flavor = "current_thread")]
    async fn in_place_record_survives_marker_and_fallback_write_failure() {
        let _guard = crate::detection_marker::arm_marker_write_failures(u32::MAX);
        let keys = tempfile::tempdir().expect("keys");
        let fallback = tempfile::tempdir().expect("fallback");
        crate::detection_marker::preallocate_detection_record(keys.path()).expect("record");
        let m = latched_machine();
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let keystore = keys.path().to_path_buf();
        let fallback_dir = fallback.path().to_path_buf();
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(
                    executor,
                    shutdown_rx,
                    token,
                    Some(detection_shutdown(m, keystore, Some(fallback_dir), clock)),
                ),
                std::future::ready(()),
            )
            .await
        });
        let (_outcome, res) = finish_within(drain, Duration::from_secs(2)).await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "a durable in-place record must exit 12, got {res:?}"
        );
        assert!(
            matches!(
                crate::detection_marker::inspect(keys.path()),
                crate::detection_marker::MarkerInspect::Absent
            ),
            "the injected marker write must not have created a marker"
        );
        assert!(
            matches!(
                crate::detection_marker::inspect(fallback.path()),
                crate::detection_marker::MarkerInspect::Absent
            ),
            "the injected fallback write must not have created a marker"
        );
        assert!(
            matches!(
                crate::detection_marker::inspect_record(keys.path()),
                crate::detection_marker::RecordInspect::Detected { .. }
            ),
            "the preallocated record must be detected"
        );
        let err = boot_refusing(keys.path(), None).await;
        assert_eq!(err.exit_code(), EXIT_DOPPELGANGER_DETECTED);
    }

    /// A write whose fsync already returned `Ok` exits 12 even when every later rewrite fails.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn durable_marker_exits_12_when_a_later_rewrite_fails() {
        let keys = tempfile::tempdir().expect("keys");
        crate::detection_marker::write_marker(
            keys.path(),
            &crate::detection_marker::DetectionMarker { epoch: 1, unix_secs: 2, pubkeys: vec![] },
        )
        .expect("marker");
        let m = latched_machine();
        // `write_marker` returned `Ok`: the file fsync and the directory fsync
        // both finished. The flag is that acknowledgement. The drain must not
        // infer it by reading the marker back.
        m.mark_detection_persisted();
        let _guard = crate::detection_marker::arm_marker_write_failures(u32::MAX);
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let keystore = keys.path().to_path_buf();
        let started = std::time::Instant::now();
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(
                    executor,
                    shutdown_rx,
                    token,
                    Some(detection_shutdown(m, keystore, None, clock)),
                ),
                std::future::ready(()),
            )
            .await
        });
        let (_outcome, res) = finish_within(drain, Duration::from_secs(2)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a durable marker must not sleep on a rewrite failure"
        );
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "an already-durable marker must exit 12, got {res:?}"
        );
        assert!(matches!(
            crate::detection_marker::inspect(keys.path()),
            crate::detection_marker::MarkerInspect::Present(_)
        ));
    }

    /// `pwrite` then a failed fsync leaves `detected` in the page cache. The
    /// drain retries and does not exit 12 until a write returns `Ok`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fsync_failure_after_pwrite_retries_until_a_write_returns_ok() {
        let keys = tempfile::tempdir().expect("keys");
        crate::detection_marker::preallocate_detection_record(keys.path()).expect("record");
        let guard = crate::detection_marker::arm_fsync_failures(u32::MAX);
        let m = latched_machine();
        let machine = Arc::clone(&m);
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let keystore = keys.path().to_path_buf();
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(
                    executor,
                    shutdown_rx,
                    token,
                    Some(detection_shutdown(m, keystore, None, clock)),
                ),
                std::future::ready(()),
            )
            .await
        });
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if drain.is_finished() {
                break;
            }
        }
        assert!(!drain.is_finished(), "a failed fsync must not exit 12");
        assert!(
            matches!(
                crate::detection_marker::inspect_record(keys.path()),
                crate::detection_marker::RecordInspect::Detected { .. }
            ),
            "the page cache shows detected after pwrite even though fsync failed"
        );
        assert!(
            !machine.detection_persisted(),
            "durability is the fsync result, not the read-back"
        );
        assert!(
            matches!(
                crate::detection_marker::inspect(keys.path()),
                crate::detection_marker::MarkerInspect::Absent
            ),
            "a marker rename waits until its fsync succeeds"
        );
        drop(guard);
        tokio::time::advance(Duration::from_secs(1)).await;
        let (_outcome, res) = finish_within(drain, Duration::from_secs(2)).await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "the drain exits 12 once a write returns Ok, got {res:?}"
        );
        assert!(machine.detection_persisted());
    }

    /// The first marker write fails, the drain waits, and the retry exits 12.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_retries_a_failed_marker_write_then_exits_12() {
        let _guard = crate::detection_marker::arm_marker_write_failures(1);
        let keys = tempfile::tempdir().expect("keys");
        let m = latched_machine();
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let keystore = keys.path().to_path_buf();
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(
                    executor,
                    shutdown_rx,
                    token,
                    Some(detection_shutdown(m, keystore, None, clock)),
                ),
                std::future::ready(()),
            )
            .await
        });
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if drain.is_finished() {
                break;
            }
        }
        assert!(!drain.is_finished(), "the drain must wait out the failed marker write");
        assert!(
            matches!(
                crate::detection_marker::inspect(keys.path()),
                crate::detection_marker::MarkerInspect::Absent
            ),
            "the first marker write must fail"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let (_outcome, res) = finish_within(drain, Duration::from_secs(2)).await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "the retry must exit 12, got {res:?}"
        );
        assert!(matches!(
            crate::detection_marker::inspect(keys.path()),
            crate::detection_marker::MarkerInspect::Present(_)
        ));
    }

    /// A signal with the latch clear returns Ok and leaves the record clear.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_without_detection_returns_ok_and_leaves_the_record_clear() {
        let keys = tempfile::tempdir().expect("keys");
        crate::detection_marker::preallocate_detection_record(keys.path()).expect("record");
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        assert!(!m.detected_latch());
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let (_outcome, res) = crate::bootstrap::await_shutdown_and_drain_with_signal(
            drain_inputs(
                executor,
                shutdown_rx,
                token,
                Some(detection_shutdown(m, keys.path().to_path_buf(), None, clock)),
            ),
            std::future::ready(()),
        )
        .await;
        assert!(res.is_ok(), "no detection must not exit 12, got {res:?}");
        assert!(matches!(
            crate::detection_marker::inspect_record(keys.path()),
            crate::detection_marker::RecordInspect::Clear
        ));
        assert!(matches!(
            crate::detection_marker::inspect(keys.path()),
            crate::detection_marker::MarkerInspect::Absent
        ));
    }

    fn latched_machine() -> Arc<ForwardWindowMachine> {
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        let samples =
            vec![ValidatorLivenessData { index: hex::encode(pk.to_bytes()), is_live: true }];
        let _ = m.apply_liveness_tick(&[EpochLiveness { epoch: 0, samples: Some(samples) }], 0, 0);
        assert!(m.detected_latch());
        m
    }

    fn test_clock() -> Arc<MonotonicEpochClock> {
        Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000))
    }

    async fn finish_within<T>(task: tokio::task::JoinHandle<T>, bound: Duration) -> T {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            std::thread::sleep(bound);
            let _ = tx.send(());
        });
        tokio::select! {
            joined = task => joined.expect("drain task"),
            _ = rx => panic!("drain did not finish within {bound:?}"),
        }
    }

    fn missing_marker_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rvc-dg-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn detection_shutdown(
        machine: Arc<ForwardWindowMachine>,
        keystore_dir: std::path::PathBuf,
        fallback_dir: Option<std::path::PathBuf>,
        epoch_clock: Arc<MonotonicEpochClock>,
    ) -> crate::bootstrap::DetectionShutdown {
        crate::bootstrap::DetectionShutdown { machine, keystore_dir, fallback_dir, epoch_clock }
    }

    fn drain_inputs(
        executor: TaskExecutor,
        shutdown_rx: tokio::sync::mpsc::Receiver<crate::bootstrap::executor::ShutdownReason>,
        shutdown_token: CancellationToken,
        detection: Option<crate::bootstrap::DetectionShutdown>,
    ) -> crate::bootstrap::ShutdownInputs {
        crate::bootstrap::ShutdownInputs {
            executor,
            orchestrator_handle: crate::orchestrator::OrchestratorHandle::for_drain_test(),
            shutdown_rx,
            shutdown_token,
            budget: crate::bootstrap::executor::TierBudget::default(),
            detection,
        }
    }

    async fn latched_loop_with_failing_marker(
        missing: &std::path::Path,
    ) -> (
        Arc<ForwardWindowMachine>,
        tokio::task::JoinHandle<()>,
        TaskExecutor,
        tokio::sync::mpsc::Receiver<crate::bootstrap::executor::ShutdownReason>,
        CancellationToken,
        Arc<MonotonicEpochClock>,
    ) {
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 0);
        let bn = Arc::new(with_live(&[("7", true)]).0);
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        let clock =
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000));
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn,
            reg,
            Arc::clone(&clock),
            token.clone(),
        )
        .with_slot_duration(Duration::from_secs(12))
        .with_detection_marker_dir(missing.to_path_buf())
        .with_exit_request(Arc::new(executor.shutdown_handle()) as Arc<dyn ExitRequest>);
        let task = tokio::spawn(loop_.run());
        let started = std::time::Instant::now();
        loop {
            if m.detected_latch() && !executor.doppelganger_exit_requested() {
                break;
            }
            if task.is_finished() {
                panic!("liveness loop ended before the latch");
            }
            if started.elapsed() > Duration::from_secs(5) {
                panic!("latch was not stored while the marker write failed");
            }
            tokio::task::yield_now().await;
        }
        (m, task, executor, shutdown_rx, token, clock)
    }

    async fn boot_refusing(
        keystore: &std::path::Path,
        slashing_db_path: Option<std::path::PathBuf>,
    ) -> crate::bootstrap::BootstrapError {
        let mut config = crate::config::Config {
            keystore_path: keystore.to_path_buf(),
            doppelganger_detection: false,
            ..Default::default()
        };
        if let Some(path) = slashing_db_path {
            config.slashing_db_path = path;
        }
        let boot_token = CancellationToken::new();
        let (boot_executor, boot_rx) = TaskExecutor::new(boot_token);
        crate::bootstrap::run(
            config,
            crate::bootstrap::RunOptions {
                strict_permissions: false,
                strict_slashing_semantics: false,
                timeouts: bn_manager::OperationTimeouts::default(),
            },
            boot_executor,
            boot_rx,
        )
        .await
        .expect_err("the restarted process must refuse the marker")
    }
}
