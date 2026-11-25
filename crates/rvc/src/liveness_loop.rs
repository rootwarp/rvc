//! SEC-2c: per-slot forward-window liveness observation loop.
//!
//! Drives [`ForwardWindowMachine`] with real network liveness via the bn-manager
//! (`LivenessApi::post_validator_liveness_merged`, multi-BN OR-merge).
//!
//! Each cycle (once per slot):
//! 1. Fetch liveness for the previous epoch and the current epoch
//! 2. Translate numeric validator indices → bare pubkey-hex (SEC-001)
//! 3. Apply both answers in one step, then read [`ForwardWindowMachine::statuses`]
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
//! `is_live` is OR-merged — any admitted BN reporting live wins (fail-safe: a
//! lagging primary that answers all-not-live cannot suppress a secondary that
//! saw activity). A not-live answer counts only when a synced witness reported
//! it. Errors and non-responses contribute nothing (they are not treated as
//! "not live"). If every BN fails the call returns `Err` and this loop still
//! fail-closes on errors/incomplete samples. The epoch is read again under the
//! machine lock; if it moved since the queries, live answers still detect and
//! the decrement is skipped.
//! A closed epoch older than the previous one is not queried again.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(test, feature = "test-utils"))]
use bn_manager::NodeStatusApi;
use bn_manager::{LivenessApi, RevocationCommit};
use doppelganger::{
    EpochLiveness, ForwardWindowMachine, ForwardWindowStatus, MonotonicEpochClock,
    ValidatorLivenessData,
};
use eth_types::Epoch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Instrument};

use crate::bootstrap::executor::{ShutdownHandle, ShutdownTier, TaskExecutor};
use crate::orchestrator::PubkeyMap;
#[cfg(any(test, feature = "test-utils"))]
use crate::pubkey_index::{parse_pubkey_bytes, pubkey_bytes_to_0x};
use crate::pubkey_index::{RegistryFreshness, SharedPubkeyIndexRegistry};
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

/// A liveness loop that [`prepare_liveness_loop`] built and that does not run
/// yet. [`spawn_liveness_loop`] registers it on the process [`TaskExecutor`]
/// (ARCH-2g).
pub struct LivenessLoopSpawn {
    /// Shared pubkey↔index registry (import/refresh may call [`merge_validator_indices`]).
    pub pubkey_index: SharedPubkeyIndexRegistry,
    /// The built loop. It runs only after [`spawn_liveness_loop`].
    loop_task: LivenessObservationLoop,
}

impl LivenessLoopSpawn {
    /// The detection persister of the loop. The shutdown drain writes through
    /// it, so the loop and the drain share the in-flight state of each path.
    pub fn persister(&self) -> Option<Arc<crate::detection_marker::DetectionPersister>> {
        self.loop_task.detection_persister.clone()
    }
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
    /// Pubkeys already logged once because they have no validator index.
    no_index_noted: parking_lot::Mutex<HashSet<String>>,
    /// Tick epoch of the last failed query. Only the first failure in a
    /// tick epoch logs at warn.
    last_query_failure_warned: parking_lot::Mutex<Option<Epoch>>,
    /// Drain request. Production [`prepare_liveness_loop`] always sets this.
    exit_request: Option<Arc<dyn ExitRequest>>,
    /// The writer of the detection paths: the keystore directory for the
    /// record and the marker, and the owned fallback marker beside the
    /// slashing database. The fallback marker records the keystore directory
    /// as its owner. The loop gets the fallback only in these paths, with that
    /// keystore directory. Production always sets the keystore directory. It
    /// sets the fallback when the slashing database is in a different
    /// directory. The shutdown drain uses the same persister.
    detection_persister: Option<Arc<crate::detection_marker::DetectionPersister>>,
    /// Replaces the monotonic clock in tests. Production leaves this unset.
    #[cfg(any(test, feature = "test-utils"))]
    clock_seam: Option<Arc<ClockSeam>>,
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
            no_index_noted: parking_lot::Mutex::new(HashSet::new()),
            last_query_failure_warned: parking_lot::Mutex::new(None),
            exit_request: None,
            detection_persister: None,
            #[cfg(any(test, feature = "test-utils"))]
            clock_seam: None,
        }
    }

    /// Read epochs from `seam` instead of the monotonic clock.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_clock_seam(mut self, seam: Arc<ClockSeam>) -> Self {
        self.clock_seam = Some(seam);
        self
    }

    fn clock_epoch(&self) -> Epoch {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(seam) = &self.clock_seam {
            return seam.read_epoch();
        }
        self.epoch_clock.current_epoch()
    }

    fn clock_slot(&self) -> u64 {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(seam) = &self.clock_seam {
            return seam.slot_in_epoch.load(std::sync::atomic::Ordering::SeqCst);
        }
        self.epoch_clock.slot_in_epoch()
    }

    /// Install the process-exit request used on the first detection.
    pub fn with_exit_request(mut self, exit_request: Arc<dyn ExitRequest>) -> Self {
        self.exit_request = Some(exit_request);
        self
    }

    /// Directory that receives `.rvc.doppelganger_detected` before exit 12,
    /// with no fallback marker. This call replaces the paths of a previous
    /// call, and it removes their fallback.
    pub fn with_detection_marker_dir(self, dir: std::path::PathBuf) -> Self {
        self.with_detection_paths(crate::detection_marker::DetectionPaths {
            keystore_dir: dir,
            fallback: None,
        })
    }

    /// Set the paths that the loop writes before exit 12. The loop writes the
    /// record and the marker in the keystore directory. It also writes the
    /// owned fallback marker when `paths` has a fallback. A caller can give
    /// the fallback only with its keystore directory. This call replaces the
    /// paths of a previous call.
    pub fn with_detection_paths(self, paths: crate::detection_marker::DetectionPaths) -> Self {
        self.with_detection_persister(crate::detection_marker::DetectionPersister::new(paths))
    }

    /// Write the detection through `persister` before exit 12. The shutdown
    /// drain gives the same persister, so it starts no second write on a path
    /// whose write of this loop is still running. This call replaces the
    /// paths of a previous call.
    pub fn with_detection_persister(
        mut self,
        persister: Arc<crate::detection_marker::DetectionPersister>,
    ) -> Self {
        self.detection_persister = Some(persister);
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
                let epoch_at_query = self.clock_epoch();
                let slot_at_query = self.clock_slot();
                // Network observation may store the latch. The marker write is
                // the only disk step before the exit request, and that request
                // waits until the write succeeds. Sidecar file I/O stays after it.
                let TickOutcome { statuses, current_epoch, slot_in_epoch } = self
                    .tick(epoch_at_query, slot_at_query, &|| self.clock_epoch() == epoch_at_query)
                    .await;
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
                if latched && !self.machine.detection_persisted() {
                    let detected_pubkeys = self.machine.detected_hexes();
                    self.persist_detection_marker(current_epoch, &detected_pubkeys).await;
                }
                // The durable flag of the machine is the only durability flag.
                // Only a durable report of this loop or of the drain sets it.
                let durable = self.machine.detection_persisted();
                if durable && !shutdown_requested {
                    shutdown_requested = true;
                    match &self.exit_request {
                        Some(request) => request.request(EXIT_DOPPELGANGER_DETECTED),
                        None => {
                            error!("doppelganger detected but no shutdown handle is installed")
                        }
                    }
                } else if durable {
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

                // A latched process exits 12 and the next boot refuses, so the
                // sidecars stay. A cleanup that blocks on a hung keystore
                // directory or on `TrackedKeys` could hold the exit.
                if !self.machine.detected_latch() {
                    self.record_completed_imports();
                }

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

    /// Write the detection to each configured path with
    /// [`crate::detection_marker::DetectionPersister::persist`]: the record
    /// and the marker in the keystore directory, and the owned fallback
    /// marker when one is set. Each path is written on its own blocking
    /// thread, so a hung keystore mount does not block the runtime or the
    /// fallback.
    ///
    /// [`crate::detection_marker::log_persist_report`] logs and counts each
    /// failed path. A loop with no detection paths has no keystore directory
    /// and no fallback. It logs one error and counts one failure. The machine
    /// gets the durable flag only from a durable report: a write and its fsync
    /// returned `Ok` on at least one path. Otherwise the loop stays up and
    /// latched, and the next tick writes again. Exit 12 waits for the flag. A
    /// later read is not durability.
    async fn persist_detection_marker(&self, epoch: Epoch, pubkeys: &[String]) {
        let Some(persister) = &self.detection_persister else {
            crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.inc();
            error!(
                "doppelganger detected but no data directory is configured for the marker; \
                 staying up and refusing signatures until a marker can be written"
            );
            return;
        };
        let marker = crate::detection_marker::DetectionMarker {
            epoch,
            unix_secs: crate::detection_marker::unix_secs_now(),
            pubkeys: pubkeys.to_vec(),
        };
        let report = persister.persist(&marker).await;
        crate::detection_marker::log_persist_report(&report, "liveness loop");
        if report.durable() {
            self.machine.mark_detection_persisted();
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

    /// Query the previous epoch and the current epoch, apply the answers, then
    /// report status. [`Self::run`] and the test driver both call this.
    ///
    /// An empty index registry makes no beacon-node call. A not-live answer
    /// decrements only for the previous epoch at slot >= [`doppelganger::CLOSED_EPOCH_SLOT`],
    /// and only if `epoch_unchanged` returns `true`. That closure runs under
    /// the machine lock, so it must be a clock read that does not block.
    /// After the queries the clock is read again for the logs and the marker
    /// epoch. Sidecar cleanup is the caller's step.
    async fn tick(
        &self,
        epoch_at_query: Epoch,
        slot_at_query: u64,
        epoch_unchanged: &(dyn Fn() -> bool + Sync),
    ) -> TickOutcome {
        let observation = self.observe_adjacent(epoch_at_query).await;
        let current_epoch = self.clock_epoch();
        let slot_in_epoch = self.clock_slot();
        self.record_liveness(&observation, epoch_at_query, slot_at_query, epoch_unchanged);
        let statuses = self.machine.statuses(current_epoch, slot_in_epoch);
        TickOutcome { statuses, current_epoch, slot_in_epoch }
    }

    /// Fetch epochs `current - 1` and `current`.
    ///
    /// A closed epoch older than `current - 1` is not queried again. A missed
    /// closed window is not queried again, and the remaining decrements are
    /// still required, so a miss never closes the window early.
    ///
    /// The caller applies the answers with an epoch check under the machine
    /// lock. A live answer at or after `next_check_epoch` is `Detected` before any
    /// decrement, so signing stays closed until both answers of this tick are
    /// applied. A failed or partial current-epoch query does not let the
    /// previous epoch's decrement open the gate.
    ///
    /// The indices are read under one registry freshness token, which is
    /// returned with the answers, and a stale registry asks about no index.
    /// The token is read again before each query. Once it has moved (a
    /// revocation or a revalidation), the rest of the tick asks about no index.
    /// [`Self::record_liveness`] applies the answers only under that token.
    ///
    /// A failed query gives `samples: None`. The first failure in a tick epoch
    /// logs at warn. The other failures in that epoch log at debug.
    async fn observe_adjacent(&self, current_epoch: Epoch) -> Observation {
        let pending = self.machine.pending_keys();
        if pending.is_empty() {
            let freshness = self.pubkey_index.read().freshness();
            return Observation { answers: Vec::new(), freshness };
        }
        let (freshness, index_to_bare) = {
            let registry = self.pubkey_index.read();
            let freshness = registry.freshness();
            // A stale index may name another validator: ask about none until revalidated.
            let index_to_bare = if freshness == RegistryFreshness::Stale {
                HashMap::new()
            } else {
                registry.index_to_bare_hex().clone()
            };
            (freshness, index_to_bare)
        };
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
            if numeric.is_empty() || !self.indices_unchanged_since(freshness) {
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
                    if self.first_query_failure_in(current_epoch) {
                        warn!(
                            epoch,
                            error = %e,
                            "liveness query failed; will retry next slot (fail-closed)"
                        );
                    } else {
                        debug!(
                            epoch,
                            error = %e,
                            "liveness query failed; will retry next slot (fail-closed)"
                        );
                    }
                    answers.push(EpochLiveness { epoch, samples: None });
                }
            }
        }

        Observation { answers, freshness }
    }

    /// Record a failed query in the tick epoch `current_epoch`. Return `true`
    /// for the first failure in that epoch.
    ///
    /// Only a failure moves the marker. A failure after a recovery in the
    /// same epoch returns `false`.
    fn first_query_failure_in(&self, current_epoch: Epoch) -> bool {
        self.last_query_failure_warned.lock().replace(current_epoch) != Some(current_epoch)
    }

    /// Whether the index registry still has the freshness token `snapshot`.
    fn indices_unchanged_since(&self, snapshot: RegistryFreshness) -> bool {
        self.pubkey_index.read().freshness() == snapshot
    }

    /// Apply one tick's answers if the index registry still has the freshness
    /// token they were read under.
    ///
    /// The token check and the state change run under the registry's
    /// [`RevocationCommit`], which every revocation-generation bump and every
    /// registry revalidation also holds. Lock order: the commit lock, then the
    /// forward-window state mutex (inside `apply_liveness_if`), then the
    /// registry read in the check. A revocation or revalidation that finished
    /// before the commit lock was taken moves the token, and the whole tick is
    /// dropped: nothing from it counts, opens the gate or detects. One that
    /// arrives while the lock is held waits until the state is written.
    ///
    /// After the token check, `epoch_unchanged` runs under the same state
    /// mutex. `false` skips every not-live decrement of the tick.
    ///
    /// A key with no validator index is logged once at info. An omitted or
    /// failed answer for a key that has an index is warned once per
    /// `(pubkey, epoch)`.
    fn record_liveness(
        &self,
        observation: &Observation,
        current_epoch: Epoch,
        slot_in_epoch: u64,
        epoch_unchanged: &dyn Fn() -> bool,
    ) {
        #[cfg(test)]
        tests::before_admission();
        let commit = self.pubkey_index.read().revocation_commit();
        #[cfg(test)]
        tests::before_commit();
        let held = commit.as_deref().map(RevocationCommit::hold);
        let admitted = self.machine.apply_liveness_if(
            &observation.answers,
            current_epoch,
            slot_in_epoch,
            epoch_unchanged,
            || {
                let fresh = self.indices_unchanged_since(observation.freshness);
                #[cfg(test)]
                tests::inside_commit();
                fresh
            },
        );
        #[cfg(test)]
        tests::after_commit();
        drop(held);
        let Some(unobserved) = admitted else {
            debug!(
                current_epoch,
                "index registry changed before the liveness answers were applied; tick dropped"
            );
            return;
        };
        let indexed = self.indexed_bare_hexes();
        let mut by_epoch: HashMap<Epoch, Vec<String>> = HashMap::new();
        let mut no_index = Vec::new();
        for (epoch, key) in unobserved {
            if indexed.contains(&key) {
                by_epoch.entry(epoch).or_default().push(key);
            } else {
                no_index.push(key);
            }
        }
        self.note_no_index(&no_index);
        for (epoch, keys) in by_epoch {
            self.warn_unobserved(current_epoch, epoch, &keys);
        }
    }

    fn indexed_bare_hexes(&self) -> HashSet<String> {
        self.pubkey_index.read().index_to_bare_hex().values().cloned().collect()
    }

    /// Log once per pubkey that has no beacon index yet.
    ///
    /// An omitted or failed answer for a key that already has an index still
    /// goes through [`Self::warn_unobserved`].
    fn note_no_index(&self, keys: &[String]) {
        if keys.is_empty() {
            return;
        }
        let mut noted = self.no_index_noted.lock();
        let mut fresh = Vec::new();
        for key in keys {
            if noted.insert(key.clone()) {
                fresh.push(key.clone());
            }
        }
        drop(noted);
        for key in fresh {
            info!(
                pubkey = %observability::logging::TruncatedPubkey::new(&key),
                "doppelganger liveness: no index yet; Safe stays closed until an index is known"
            );
        }
    }

    /// One warning per `(pubkey, epoch)` when a queried key is omitted or the
    /// query fails.
    ///
    /// Pairs with `epoch < current_epoch.saturating_sub(2)` are dropped
    /// (`retain_from`). A key with no validator index is not warned here.
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
    /// The driver queries the previous and current epochs at `(epoch, slot_in_epoch)`.
    /// It uses the same tick as [`Self::run`]. It then removes sidecars for Safe keys.
    ///
    /// With a [`ClockSeam`], the check compares the current seam epoch with its
    /// value at the start of the tick. The driven epoch does not affect this
    /// comparison. A seam that moves during the queries skips the not-live
    /// decrement. A still seam does not. With no seam, the check passes.
    ///
    /// Compiled only for this crate's tests or when the `test-utils` feature
    /// is enabled. Integration tests see it through the self dev-dependency.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn drive_once_for_test(
        &self,
        epoch: Epoch,
        slot_in_epoch: u64,
    ) -> Vec<ForwardWindowStatus> {
        let outcome = if self.clock_seam.is_some() {
            let seam_at_start = self.clock_epoch();
            self.tick(epoch, slot_in_epoch, &|| self.clock_epoch() == seam_at_start).await
        } else {
            self.tick(epoch, slot_in_epoch, &|| true).await
        };
        self.record_completed_imports();
        outcome.statuses
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

/// Test clock. Production reads [`MonotonicEpochClock`].
///
/// The epoch script is `#[cfg(test)]`. Builds without `cfg(test)` do not
/// include it, also when the `test-utils` feature is on. In those builds, a
/// loop epoch read is one atomic load of the stored epoch.
#[cfg(any(test, feature = "test-utils"))]
pub struct ClockSeam {
    epoch: std::sync::atomic::AtomicU64,
    slot_in_epoch: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    script: parking_lot::Mutex<std::collections::VecDeque<Epoch>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl ClockSeam {
    /// Epoch and slot the liveness loop reads while this seam is installed.
    pub fn new(epoch: u64, slot_in_epoch: u64) -> Arc<Self> {
        Arc::new(Self {
            epoch: std::sync::atomic::AtomicU64::new(epoch),
            slot_in_epoch: std::sync::atomic::AtomicU64::new(slot_in_epoch),
            #[cfg(test)]
            script: parking_lot::Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// Replace the script. Each loop epoch read takes the next scripted epoch.
    ///
    /// When the script is empty, a read returns the stored epoch.
    #[cfg(test)]
    pub fn script_epochs(&self, epochs: &[Epoch]) {
        *self.script.lock() = epochs.iter().copied().collect();
    }

    /// Return the number of scripted epochs that the loop has not read.
    #[cfg(test)]
    pub fn script_remaining(&self) -> usize {
        self.script.lock().len()
    }

    fn read_epoch(&self) -> Epoch {
        #[cfg(test)]
        if let Some(epoch) = self.script.lock().pop_front() {
            return epoch;
        }
        self.epoch()
    }

    /// Move the stored epoch. Loop reads return it when the script is empty.
    pub fn set_epoch(&self, epoch: u64) {
        self.epoch.store(epoch, std::sync::atomic::Ordering::SeqCst);
    }

    /// Epoch stored by [`Self::set_epoch`].
    pub fn epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Build the production liveness loop whenever a machine exists. The loop
/// does not run until [`spawn_liveness_loop`] registers it.
///
/// An empty registry still builds the loop. The loop makes no beacon-node
/// call until a pending key has an index. `pubkey_index` is the
/// workspace-shared registry (same handle used by `prepare_proposers` / duty
/// tracking). Production index refresh is
/// [`crate::index_resolver::IndexResolver`]; `pubkey_map` stays attached for
/// `LivenessObservationLoop::refresh_indices_for_test`.
///
/// The loop takes its cancel token and its exit request from `executor`.
/// `keystore` gives the detection paths and the lock that the keymanager
/// DELETE and import hold. The loop writes these paths before it requests
/// exit 12. It removes the Safe import sidecars from their keystore
/// directory. The loop gets the owned fallback marker only in these paths,
/// with its keystore directory.
pub fn prepare_liveness_loop(
    machine: Option<Arc<ForwardWindowMachine>>,
    beacon: Arc<dyn LivenessApi>,
    pubkey_index: SharedPubkeyIndexRegistry,
    pubkey_map: Option<PubkeyMap>,
    epoch_clock: Arc<MonotonicEpochClock>,
    executor: &TaskExecutor,
    // Detection paths + shared DELETE/import lock for Safe sidecar cleanup.
    keystore: Option<(crate::detection_marker::DetectionPaths, Arc<TrackedKeys>)>,
) -> Option<LivenessLoopSpawn> {
    let machine = machine?;
    let pubkey_index_ret = Arc::clone(&pubkey_index);
    let cancel = executor.token();
    let exit_request: Arc<dyn ExitRequest> = Arc::new(executor.shutdown_handle());
    let mut loop_task =
        LivenessObservationLoop::new(machine, beacon, pubkey_index, epoch_clock, cancel)
            .with_exit_request(exit_request);
    if let Some(pm) = pubkey_map {
        loop_task = loop_task.with_pubkey_map(pm);
    }
    if let Some((paths, tracked)) = keystore {
        loop_task = loop_task.with_import_sidecar_dir(paths.keystore_dir.clone(), tracked);
        loop_task = loop_task.with_detection_paths(paths);
    }
    Some(LivenessLoopSpawn { pubkey_index: pubkey_index_ret, loop_task })
}

/// Register the `prepared` loop on `executor` at Orchestrator tier
/// (ARCH-2g P1-7). From here the loop can latch a detection.
///
/// Boot calls this after its last fallible step, so a latch that the loop
/// sets always reaches the drain.
pub fn spawn_liveness_loop(prepared: LivenessLoopSpawn, executor: &TaskExecutor) {
    let LivenessLoopSpawn { pubkey_index, loop_task } = prepared;
    if pubkey_index.read().is_empty() {
        info!(
            "SEC-2c: starting liveness loop with empty indices \
             (IndexResolver owns index refresh; pending activation / post-import)"
        );
    }
    executor.spawn("liveness_loop", ShutdownTier::Orchestrator, async move {
        loop_task.run().await;
    });
}

/// One tick's liveness answers, with the index registry freshness token their
/// indices were read under.
struct Observation {
    answers: Vec<EpochLiveness>,
    freshness: RegistryFreshness,
}

/// What one liveness tick gives back to `run` or the test driver.
struct TickOutcome {
    statuses: Vec<ForwardWindowStatus>,
    /// Epoch read after the queries. `run` logs it and writes it to the marker.
    current_epoch: Epoch,
    /// Slot in the epoch read after the queries, for the logs.
    slot_in_epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // Test-only rendezvous points in `record_liveness`. They live in this
    // module because the spawn census needs the test module last.
    type Hook = Box<dyn FnMut()>;
    type Slot = std::thread::LocalKey<RefCell<Option<Hook>>>;

    thread_local! {
        static BEFORE_ADMISSION: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static BEFORE_COMMIT: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static INSIDE_COMMIT: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static AFTER_COMMIT: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    fn fire(slot: &'static Slot) {
        slot.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
    }

    /// After the last answer, before admission starts.
    pub(super) fn before_admission() {
        fire(&BEFORE_ADMISSION);
    }

    /// The last point before the state commit at which a writer can finish.
    pub(super) fn before_commit() {
        fire(&BEFORE_COMMIT);
    }

    /// After the token check, with the commit lock held, before the state write.
    pub(super) fn inside_commit() {
        fire(&INSIDE_COMMIT);
    }

    /// After the state write has returned, with the commit lock still held.
    pub(super) fn after_commit() {
        fire(&AFTER_COMMIT);
    }

    /// Clears its slot when dropped, also on a failed assert.
    struct Armed(&'static Slot);

    impl Drop for Armed {
        fn drop(&mut self) {
            self.0.with(|hook| *hook.borrow_mut() = None);
        }
    }

    fn arm(slot: &'static Slot, hook: impl FnMut() + 'static) -> Armed {
        slot.with(|armed| *armed.borrow_mut() = Some(Box::new(hook)));
        Armed(slot)
    }

    fn arm_before_admission(hook: impl FnMut() + 'static) -> Armed {
        arm(&BEFORE_ADMISSION, hook)
    }

    /// Runs `writer` on another thread and waits for it, so the order is fixed.
    fn on_another_thread<T: Send + 'static>(writer: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(writer).join().expect("writer thread")
    }
    use crate::pubkey_index::PubkeyIndexRegistry;
    use bn_manager::MockBeaconNodeClient;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tracing_subscriber::layer::SubscriberExt;

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

        m.statuses(start + DEFAULT_MONITORING_EPOCHS + 5, 0);
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

    struct LoopLog(Arc<std::sync::Mutex<String>>);

    struct LoopLogVisitor<'a>(&'a mut String);

    impl tracing::field::Visit for LoopLogVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={:?}", field.name(), value);
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={}", field.name(), value);
        }
    }

    impl<S> tracing_subscriber::Layer<S> for LoopLog
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut line = String::new();
            event.record(&mut LoopLogVisitor(&mut line));
            let mut buf = self.0.lock().expect("logs");
            buf.push_str(&line);
            buf.push('\n');
        }
    }

    /// A key with no beacon index logs once at info across epochs.
    ///
    /// The same loop then warns when that key has an index and the answer
    /// omits it. The info line does not repeat.
    #[tokio::test(flavor = "current_thread")]
    async fn no_index_key_logs_once_not_per_epoch() {
        let logs = Arc::new(std::sync::Mutex::new(String::new()));
        let subscriber = tracing_subscriber::registry().with(LoopLog(Arc::clone(&logs)));
        let _guard = tracing::subscriber::set_default(subscriber);

        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let reg = PubkeyIndexRegistry::shared();
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            Arc::new(all_not_live(&[]).0),
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        )
        .with_slot_duration(Duration::from_millis(1));
        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(start + 2, CLOSED_EPOCH_SLOT).await;
        let text = logs.lock().expect("logs").clone();
        assert_eq!(text.matches("no index yet").count(), 1, "{text}");
        assert_eq!(text.matches("doppelganger liveness unobserved").count(), 0, "{text}");
        assert!(!m.is_signing_enabled(&pk));

        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            Arc::new(all_not_live(&[]).0),
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        )
        .with_slot_duration(Duration::from_millis(1));
        loop_.drive_once_for_test(start + 3, CLOSED_EPOCH_SLOT).await;
        let text = logs.lock().expect("logs").clone();
        assert_eq!(text.matches("no index yet").count(), 1, "{text}");
        assert!(text.matches("doppelganger liveness unobserved").count() >= 1, "{text}");
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
        let handle = prepare_liveness_loop(
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
        spawn_liveness_loop(
            handle.expect("A machine and a registry with an index must give a built loop."),
            &exec,
        );
        let _ = exec.shutdown(crate::bootstrap::executor::TierBudget::default()).await;

        let empty = PubkeyIndexRegistry::shared();
        let (exec2, _rx2) = TaskExecutor::new(CancellationToken::new());
        let no_handle = prepare_liveness_loop(
            Some(machine()),
            Arc::new(all_not_live(&[]).0),
            empty,
            None,
            Arc::new(MonotonicEpochClock::new(0, 12_000)),
            &exec2,
            None,
        );
        spawn_liveness_loop(
            no_handle.expect("A machine with an empty registry must give a built loop."),
            &exec2,
        );

        let (exec3, _rx3) = TaskExecutor::new(CancellationToken::new());
        let no_machine = prepare_liveness_loop(
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
        let spawn = prepare_liveness_loop(
            Some(machine()),
            Arc::new(all_not_live(&[]).0),
            empty,
            Some(pubkey_map),
            Arc::new(MonotonicEpochClock::new(0, 12_000)),
            &exec,
            None,
        );
        spawn_liveness_loop(
            spawn.expect(
                "`prepare_liveness_loop` must build the loop when the index registry is empty \
                 and a public-key map is available. IndexResolver resolves the indices of \
                 pending keys, not this loop.",
            ),
            &exec,
        );
        let _ = exec.shutdown(crate::bootstrap::executor::TierBudget::default()).await;
    }

    /// Return a beacon node in the test process and a count of its liveness
    /// requests. Each answer gives `is_live` for each requested index.
    fn counted_liveness(
        is_live: bool,
    ) -> (Arc<dyn LivenessApi>, tokio::sync::watch::Receiver<usize>) {
        let (count, requests) = tokio::sync::watch::channel(0usize);
        let beacon =
            MockBeaconNodeClient::new().with_post_validator_liveness(move |_epoch, indices| {
                count.send_modify(|requests| *requests += 1);
                let data =
                    indices.into_iter().map(|index| ValidatorLiveness { index, is_live }).collect();
                Ok(ValidatorLivenessResponse { data })
            });
        (Arc::new(beacon), requests)
    }

    /// Register one pending key with the index "1" on `machine`. Build the
    /// production loop with `prepare_liveness_loop`, with `dir` as the keystore
    /// directory. Then start it with `spawn_liveness_loop` on `executor`.
    /// Return the detection persister of the loop.
    fn spawn_production_loop(
        machine: &Arc<ForwardWindowMachine>,
        beacon: Arc<dyn LivenessApi>,
        dir: &std::path::Path,
        executor: &TaskExecutor,
    ) -> Arc<crate::detection_marker::DetectionPersister> {
        let pk = new_pk();
        machine.register(&pk, 0);
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "1".to_string());
        let clock =
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000));
        let prepared = prepare_liveness_loop(
            Some(Arc::clone(machine)),
            beacon,
            reg,
            None,
            clock,
            executor,
            Some((
                crate::detection_marker::DetectionPaths {
                    keystore_dir: dir.to_path_buf(),
                    fallback: None,
                },
                Arc::new(TrackedKeys::new()),
            )),
        )
        .expect("`prepare_liveness_loop` must build the loop when a machine is available.");
        let persister = prepared.persister().expect("The built loop must have a persister.");
        spawn_liveness_loop(prepared, executor);
        persister
    }

    /// W4-D2c fix1: the task that `spawn_liveness_loop` registers must run the
    /// loop. The loop must send a liveness request for the indexed key before
    /// its task ends. Then the drain must join the task. The test does not use
    /// a timeout: the request count or the end of the task stops the wait.
    #[tokio::test]
    async fn spawned_production_loop_sends_a_liveness_request_before_the_drain() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let (beacon, mut requests) = counted_liveness(false);
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        spawn_production_loop(&machine(), beacon, dir.path(), &executor);

        tokio::select! {
            biased;
            _ = requests.wait_for(|count| *count > 0) => {}
            () = executor.wait_until_work_finished("liveness_loop") => {}
        }
        assert!(
            *requests.borrow() > 0,
            "The liveness loop must send a liveness request before its task ends."
        );
        assert!(
            !executor.work_finished("liveness_loop"),
            "The liveness loop must continue to run after its first liveness request."
        );
        let outcome = executor.shutdown(crate::bootstrap::executor::TierBudget::default()).await;
        assert!(
            outcome.joined.contains(&"liveness_loop"),
            "The drain must join the liveness loop. The drain joined {:?} and aborted {:?}.",
            outcome.joined,
            outcome.aborted
        );
    }

    /// W4-D2c fix1: the production loop sees a live key. In the tick of its
    /// first liveness request, the loop must:
    ///
    /// 1. Latch the detection.
    /// 2. Write the detection marker in the keystore directory.
    /// 3. Request exit 12 through the executor.
    ///
    /// The runtime has one thread. The test waits until the first round of
    /// the persister of the loop has its result. The tick has then made its
    /// exit request. A latched key is not pending, so the loop sends no
    /// second request.
    #[tokio::test]
    async fn spawned_production_loop_writes_the_marker_and_requests_the_exit() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let m = machine();
        let (beacon, mut requests) = counted_liveness(true);
        let (executor, mut shutdown_rx) = TaskExecutor::new(CancellationToken::new());
        let persister = spawn_production_loop(&m, beacon, dir.path(), &executor);

        tokio::select! {
            biased;
            _ = requests.wait_for(|count| *count > 0) => {}
            () = executor.wait_until_work_finished("liveness_loop") => {}
        }
        wait_for_rounds(&persister, 1).await;
        let reason = shutdown_rx.try_recv();
        assert!(m.detected_latch(), "The liveness loop must latch the detection of a live key.");
        assert!(
            matches!(
                crate::detection_marker::inspect(dir.path()),
                crate::detection_marker::MarkerInspect::Present(_)
            ),
            "The liveness loop must write the detection marker in the keystore directory."
        );
        assert!(
            matches!(reason, Ok(crate::bootstrap::executor::ShutdownReason::DoppelgangerDetected))
                && executor.doppelganger_exit_requested(),
            "The liveness loop must request exit 12 through the executor in the same tick. The \
             shutdown reason is {reason:?}."
        );
        let outcome = executor.shutdown(crate::bootstrap::executor::TierBudget::default()).await;
        assert!(
            outcome.joined.contains(&"liveness_loop"),
            "The drain must join the liveness loop. The drain joined {:?} and aborted {:?}.",
            outcome.joined,
            outcome.aborted
        );
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

    /// A revocation makes index 4 stale: the pass asks the BN nothing about it,
    /// and the pending key gets no sample (fail-closed, not decremented).
    #[tokio::test]
    async fn liveness_never_queries_an_index_from_before_a_revocation() {
        use std::sync::atomic::AtomicU64;

        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let bn = Arc::new(all_not_live(&["4"]).0);
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "4", &pk);
        let generation = Arc::new(AtomicU64::new(0));
        loop_.pubkey_index().write().attach_revocation(Arc::clone(&generation), 0);
        let pending = m.pending_keys();
        generation.fetch_add(1, Ordering::Release);

        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;

        assert_eq!(bn.post_validator_liveness_calls(), Vec::<(u64, Vec<String>)>::new());
        assert_eq!(m.pending_keys(), pending, "no sample: the closed epoch is not counted");
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
    }

    /// A key registered at epoch 10 with index 4, validated under revocation
    /// generation 0 and observed at `(11, CLOSED_EPOCH_SLOT)`. The mock bumps
    /// the generation while it answers liveness call `bump_on_call` (0 asks
    /// epoch 10, 1 asks epoch 11) and answers call `n` with `live[n]`.
    struct RevokedMidTick {
        machine: Arc<ForwardWindowMachine>,
        pk: crypto::PublicKey,
        bn: Arc<MockBeaconNodeClient>,
        loop_: LivenessObservationLoop,
        generation: Arc<std::sync::atomic::AtomicU64>,
    }

    impl RevokedMidTick {
        fn new(bump_on_call: usize, live: [bool; 2]) -> Self {
            use std::sync::atomic::AtomicU64;

            let machine = machine();
            let pk = new_pk();
            machine.register(&pk, 10);
            let generation = Arc::new(AtomicU64::new(0));
            let bump = Arc::clone(&generation);
            let calls = AtomicUsize::new(0);
            let bn = Arc::new(MockBeaconNodeClient::new().with_post_validator_liveness(
                move |_epoch, indices| {
                    let call = calls.fetch_add(1, Ordering::SeqCst);
                    if call == bump_on_call {
                        bump.fetch_add(1, Ordering::Release);
                    }
                    let is_live = live[call];
                    let data = indices
                        .into_iter()
                        .map(|index| ValidatorLiveness { index, is_live })
                        .collect();
                    Ok(ValidatorLivenessResponse { data })
                },
            ));
            let loop_ =
                loop_with(Arc::clone(&machine), Arc::clone(&bn) as Arc<dyn LivenessApi>, "4", &pk);
            loop_.pubkey_index().write().attach_revocation(Arc::clone(&generation), 0);
            Self { machine, pk, bn, loop_, generation }
        }

        /// Revoke on another thread at the last point before the state commit.
        fn revoke_before_commit(&self) -> Armed {
            let generation = Arc::clone(&self.generation);
            arm(&BEFORE_COMMIT, move || {
                let generation = Arc::clone(&generation);
                on_another_thread(move || generation.fetch_add(1, Ordering::Release));
            })
        }

        /// Revoke after the last answer, at the admission rendezvous.
        fn revoke_before_admission(&self) -> Armed {
            let generation = Arc::clone(&self.generation);
            arm_before_admission(move || {
                generation.fetch_add(1, Ordering::Release);
            })
        }

        async fn tick(&self) {
            self.loop_.drive_once_for_test(11, CLOSED_EPOCH_SLOT).await;
        }

        fn next_checks(&self) -> Vec<u64> {
            self.machine.pending_keys().iter().map(|key| key.next_check_epoch).collect()
        }

        fn is_fresh(&self) -> bool {
            self.loop_.pubkey_index().read().is_fresh()
        }
    }

    fn ask(epoch: u64) -> (u64, Vec<String>) {
        (epoch, vec!["4".to_string()])
    }

    #[tokio::test]
    async fn a_revocation_during_the_first_liveness_query_stops_the_tick() {
        let probe = RevokedMidTick::new(0, [false, false]);
        assert_eq!(probe.next_checks(), vec![10]);

        probe.tick().await;

        assert!(!probe.is_fresh(), "precondition: the first query straddled the bump");
        assert_eq!(
            probe.bn.post_validator_liveness_calls(),
            vec![ask(10)],
            "no liveness query is sent with an index from before the revocation"
        );
        assert_eq!(probe.next_checks(), vec![10], "the straddled not-live answer is not counted");
        assert_eq!(probe.machine.status(&probe.pk), ForwardWindowStatus::Pending);
    }

    #[tokio::test]
    async fn a_live_answer_after_a_revocation_does_not_detect() {
        let probe = RevokedMidTick::new(0, [false, true]);

        probe.tick().await;

        assert!(!probe.is_fresh(), "precondition: the first query straddled the bump");
        assert_eq!(
            probe.machine.status(&probe.pk),
            ForwardWindowStatus::Pending,
            "a stale index's live answer must not detect: Detected is sticky"
        );
        assert_eq!(probe.bn.post_validator_liveness_calls(), vec![ask(10)]);
        assert_eq!(probe.next_checks(), vec![10]);
    }

    /// The epoch-11 answer straddled the bump, so the tick is refused at
    /// admission, with the epoch-10 answer from before the bump.
    #[tokio::test]
    async fn a_live_answer_to_a_query_that_straddled_a_revocation_is_dropped() {
        let probe = RevokedMidTick::new(1, [false, true]);

        probe.tick().await;

        assert!(!probe.is_fresh(), "precondition: the second query straddled the bump");
        assert_eq!(probe.bn.post_validator_liveness_calls(), vec![ask(10), ask(11)]);
        assert_eq!(probe.machine.status(&probe.pk), ForwardWindowStatus::Pending);
        assert_eq!(probe.next_checks(), vec![10], "nothing from the tick is counted");
    }

    /// No query straddles the revocation: it lands after the last answer and
    /// before the answers are applied. The live answer is not counted.
    #[tokio::test]
    async fn a_live_answer_is_not_counted_once_a_revocation_lands_before_admission() {
        const NO_BUMP: usize = usize::MAX;
        let probe = RevokedMidTick::new(NO_BUMP, [false, true]);
        let _armed = probe.revoke_before_admission();

        probe.tick().await;

        assert!(!probe.is_fresh(), "precondition: the revocation ran before admission");
        assert_eq!(probe.bn.post_validator_liveness_calls(), vec![ask(10), ask(11)]);
        assert_eq!(
            probe.machine.status(&probe.pk),
            ForwardWindowStatus::Pending,
            "a live answer through a pre-revocation index must not detect"
        );
        assert_eq!(probe.next_checks(), vec![10], "nothing from the tick is counted");
    }

    /// What a writer reported first.
    #[derive(Debug, PartialEq, Eq)]
    enum Writer {
        /// It has to wait for the commit lock.
        Waiting,
        /// It finished.
        Done,
    }

    /// Bound for a signal that arrives at once; only a missing lock waits it out.
    const WATCHDOG: Duration = Duration::from_secs(10);

    /// A real beacon-node revocation that starts after the closing tick's token
    /// check, while the commit lock is held, waits until the state is written.
    /// The key goes Safe on answers that were fresh at the check, and the
    /// revocation lands after that write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_during_the_commit_waits_until_the_state_is_written() {
        use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};

        let manager = Arc::new(
            BnManager::new(BnManagerConfig::new(vec!["http://127.0.0.1:9".to_string()]))
                .expect("one-node pool"),
        );
        let generation = manager.revocation_watch().generation().expect("a tracked generation");
        let commit = manager.revocation_commit().expect("a commit lock");
        let counted = counted_to_the_closing_epoch(
            MidQuery::Nothing,
            Arc::clone(&generation),
            Some(Arc::clone(&commit)),
        )
        .await;
        let (events_tx, events) = std::sync::mpsc::channel();
        let contended = events_tx.clone();
        commit.on_contended(Some(Arc::new(move || {
            let _ = contended.send(Writer::Waiting);
        })));
        let seen = Arc::new(parking_lot::Mutex::new(None));
        let revoker = Arc::new(parking_lot::Mutex::new(None));
        let _armed = {
            let (manager, generation) = (Arc::clone(&manager), Arc::clone(&generation));
            let (seen, revoker) = (Arc::clone(&seen), Arc::clone(&revoker));
            arm(&INSIDE_COMMIT, move || {
                let (manager, done) = (Arc::clone(&manager), events_tx.clone());
                *revoker.lock() = Some(std::thread::spawn(move || {
                    manager.testing_revoke_admission(0);
                    let _ = done.send(Writer::Done);
                }));
                let first = events.recv_timeout(WATCHDOG).ok();
                *seen.lock() = Some((first, generation.load(Ordering::Acquire)));
            })
        };

        counted.loop_.drive_once_for_test(counted.closing, CLOSED_EPOCH_SLOT).await;

        let revoker = revoker.lock().take().expect("the rendezvous ran");
        revoker.join().expect("revoker");
        commit.on_contended(None);
        let (first, generation_then) = seen.lock().take().expect("the rendezvous ran");
        assert_eq!(first, Some(Writer::Waiting), "the revocation waited for the commit lock");
        assert_eq!(generation_then, 0, "and had not bumped the generation");
        assert_eq!(
            counted.machine.status(&counted.pk),
            ForwardWindowStatus::Safe,
            "the state was written first, on answers fresh at the check"
        );
        assert!(counted.machine.is_signing_enabled(&counted.pk));
        assert_eq!(generation.load(Ordering::Acquire), 1, "the revocation landed after the write");
        assert!(!counted.registry.read().is_fresh());
        let requests = counted.bn.post_validator_liveness_calls().split_off(counted.before);
        assert_eq!(requests, vec![ask(12), ask(13)]);
    }

    /// A production writer raced against the closing tick's state commit.
    #[derive(Debug, Clone, Copy)]
    enum CommitRacer {
        /// A real beacon-node revocation.
        Revoker,
        /// A real index-resolver revalidation of the same registry.
        Revalidator,
    }

    /// When the racer starts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RacerStart {
        /// In the admission check, before the state write.
        BeforeTheWrite,
        /// After the state write has returned, before the commit lock is released.
        AfterTheWrite,
    }

    /// One step of a commit race, in the order the steps happened.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Step {
        /// The state write returned; the key's status right then.
        Committed(ForwardWindowStatus),
        /// The racer had to wait for the commit lock.
        RacerWaiting,
        /// The racer finished; the key's status it then saw.
        RacerDone(ForwardWindowStatus),
    }

    struct CommitRace {
        counted: Counted,
        steps: Vec<Step>,
    }

    /// Close the window on a real `BnManager`'s generation and commit lock,
    /// with `racer` started at `start`, and record the steps in order.
    ///
    /// A racer started after the write is the latest point at which a racer
    /// could get in before the commit lock is released: it must still have to
    /// wait. The rendezvous waits only for the racer's first step (it waited,
    /// or it finished), so a racer that does not wait shows up at once.
    async fn race_the_commit(racer: Option<(CommitRacer, RacerStart)>) -> CommitRace {
        use crate::index_resolver::{IndexResolver, IndexResolverDeps};
        use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};

        let manager = Arc::new(
            BnManager::new(BnManagerConfig::new(vec!["http://127.0.0.1:9".to_string()]))
                .expect("one-node pool"),
        );
        let generation = manager.revocation_watch().generation().expect("a tracked generation");
        let commit = manager.revocation_commit().expect("a commit lock");
        let counted = counted_to_the_closing_epoch(
            MidQuery::Nothing,
            Arc::clone(&generation),
            Some(Arc::clone(&commit)),
        )
        .await;
        let steps = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (first_tx, first) = std::sync::mpsc::channel();
        {
            let (steps, first_tx) = (Arc::clone(&steps), first_tx.clone());
            commit.on_contended(Some(Arc::new(move || {
                steps.lock().push(Step::RacerWaiting);
                let _ = first_tx.send(());
            })));
        }
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::from([(
            counted.bytes,
            counted.pk.clone(),
        )])));
        let hex = pubkey_bytes_to_0x(&counted.bytes);
        let resolver_bn = Arc::new(MockBeaconNodeClient::new().with_get_validators(move |pks| {
            let data = pks
                .iter()
                .filter(|pk| *pk == &hex)
                .map(|pk| ValidatorData {
                    index: "9".to_string(),
                    status: "active_ongoing".to_string(),
                    validator: ValidatorInfo { pubkey: pk.clone() },
                })
                .collect();
            Ok(ValidatorsResponse { data })
        }));
        let (key_gen_tx, key_gen_rx) = tokio::sync::watch::channel(0u64);
        let resolver = IndexResolver::new(
            IndexResolverDeps {
                registry: Arc::clone(&counted.registry),
                pubkey_map,
                beacon: resolver_bn,
                key_gen_tx,
                key_gen_rx,
                epoch_clock: Arc::new(MonotonicEpochClock::with_start_time(
                    0,
                    std::time::Instant::now(),
                    0,
                    12_000,
                )),
            },
            CancellationToken::new(),
        );
        let mut resolver = Some(resolver);
        let handle = Arc::new(parking_lot::Mutex::new(None));
        // Starts the racer on another thread and waits for its first step.
        let start_racer = {
            let (machine, pk) = (Arc::clone(&counted.machine), counted.pk.clone());
            let (steps, handle) = (Arc::clone(&steps), Arc::clone(&handle));
            let (manager, generation) = (Arc::clone(&manager), Arc::clone(&generation));
            move |kind: CommitRacer| {
                let (machine, pk, steps, done) =
                    (Arc::clone(&machine), pk.clone(), Arc::clone(&steps), first_tx.clone());
                let finish = move || {
                    steps.lock().push(Step::RacerDone(machine.status(&pk)));
                    let _ = done.send(());
                };
                let thread = match kind {
                    CommitRacer::Revoker => {
                        let manager = Arc::clone(&manager);
                        std::thread::spawn(move || {
                            manager.testing_revoke_admission(0);
                            finish();
                        })
                    }
                    CommitRacer::Revalidator => {
                        // Only to put the resolver into revalidation: production
                        // bumps go through `revoke_at`, under the commit lock.
                        generation.fetch_add(1, Ordering::Release);
                        let mut resolver = resolver.take().expect("one revalidator");
                        std::thread::spawn(move || {
                            let runtime = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("revalidator runtime");
                            runtime.block_on(resolver.drive_once_for_test(0));
                            finish();
                        })
                    }
                };
                *handle.lock() = Some(thread);
                first.recv_timeout(WATCHDOG).expect("the racer's first step");
            }
        };
        let (racer_in_check, racer_after_write) = match racer {
            Some((kind, RacerStart::BeforeTheWrite)) => (Some(kind), None),
            Some((kind, RacerStart::AfterTheWrite)) => (None, Some(kind)),
            None => (None, None),
        };
        // The rendezvous run on this thread, so the racer's starter needs no `Send`.
        type Start = std::rc::Rc<RefCell<Option<Box<dyn FnOnce()>>>>;
        let start_in_check = Start::default();
        let _in_check = {
            let start_in_check = Start::clone(&start_in_check);
            arm(&INSIDE_COMMIT, move || {
                let start = start_in_check.borrow_mut().take();
                if let Some(start) = start {
                    start();
                }
            })
        };
        let start_after_write = Start::default();
        let _after_write = {
            let (machine, pk) = (Arc::clone(&counted.machine), counted.pk.clone());
            let (steps, start_after_write) = (Arc::clone(&steps), Start::clone(&start_after_write));
            arm(&AFTER_COMMIT, move || {
                steps.lock().push(Step::Committed(machine.status(&pk)));
                let start = start_after_write.borrow_mut().take();
                if let Some(start) = start {
                    start();
                }
            })
        };
        // Exactly one of the two rendezvous gets the racer.
        let start_racer: Box<dyn FnOnce(CommitRacer)> = Box::new(start_racer);
        if let Some(kind) = racer_in_check {
            *start_in_check.borrow_mut() = Some(Box::new(move || start_racer(kind)));
        } else if let Some(kind) = racer_after_write {
            *start_after_write.borrow_mut() = Some(Box::new(move || start_racer(kind)));
        }

        counted.loop_.drive_once_for_test(counted.closing, CLOSED_EPOCH_SLOT).await;

        let racer_thread = handle.lock().take();
        if let Some(thread) = racer_thread {
            thread.join().expect("racer thread");
        }
        commit.on_contended(None);
        let steps = steps.lock().clone();
        CommitRace { counted, steps }
    }

    /// RSA M3 boundary: a revocation that starts after the state write has
    /// returned still waits for the commit lock, and finishes after the commit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_after_the_state_write_waits_until_the_commit_is_released() {
        let race = race_the_commit(Some((CommitRacer::Revoker, RacerStart::AfterTheWrite))).await;

        assert_eq!(
            race.steps,
            vec![
                Step::Committed(ForwardWindowStatus::Safe),
                Step::RacerWaiting,
                Step::RacerDone(ForwardWindowStatus::Safe),
            ],
            "the revocation is excluded until the commit is released, then sees the commit"
        );
        assert_eq!(race.counted.generation.load(Ordering::Acquire), 1);
        assert!(race.counted.machine.is_signing_enabled(&race.counted.pk));
    }

    /// RSA M3 boundary, revalidation side: a revalidation that starts after the
    /// state write has returned still waits for the commit lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revalidation_after_the_state_write_waits_until_the_commit_is_released() {
        let race =
            race_the_commit(Some((CommitRacer::Revalidator, RacerStart::AfterTheWrite))).await;

        assert_eq!(
            race.steps,
            vec![
                Step::Committed(ForwardWindowStatus::Safe),
                Step::RacerWaiting,
                Step::RacerDone(ForwardWindowStatus::Safe),
            ],
            "the revalidation is excluded until the commit is released, then sees the commit"
        );
        let registry = race.counted.registry.read();
        assert_eq!(registry.freshness(), crate::pubkey_index::RegistryFreshness::Fresh(1));
        assert_eq!(registry.index_of(&race.counted.bytes), Some("9"), "it ran after the commit");
    }

    /// A revocation that starts in the admission check, before the state write,
    /// is still waiting when the write has returned, and finishes after it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_started_before_the_state_write_finishes_after_the_commit() {
        let race = race_the_commit(Some((CommitRacer::Revoker, RacerStart::BeforeTheWrite))).await;

        assert_eq!(
            race.steps,
            vec![
                Step::RacerWaiting,
                Step::Committed(ForwardWindowStatus::Safe),
                Step::RacerDone(ForwardWindowStatus::Safe),
            ],
            "the revocation waits through the state write and finishes after the commit"
        );
        assert_eq!(race.counted.generation.load(Ordering::Acquire), 1);
    }

    /// Healthy control: the same rendezvous with no racer commits Safe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_commit_rendezvous_with_no_racer_reaches_safe() {
        let race = race_the_commit(None).await;

        assert_eq!(race.steps, vec![Step::Committed(ForwardWindowStatus::Safe)]);
        assert_eq!(race.counted.generation.load(Ordering::Acquire), 0);
        assert!(race.counted.machine.is_signing_enabled(&race.counted.pk));
        assert!(race.counted.registry.read().is_fresh());
    }

    /// What happens to the index registry during the closing tick.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MidQuery {
        Nothing,
        Revoke,
        /// Revoke, then revalidate the key to index 9 before the old answer is used.
        RevokeAndRevalidateTo9,
        /// Revoke, revalidate the key to index 9, then revoke again.
        TwoRevokers,
    }

    /// When the closing tick's change happens.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ChangeAt {
        /// While the first query is in flight.
        FirstQuery,
        /// After the last answer, at the admission rendezvous.
        BeforeAdmission,
        /// At the last point before the state commit at which a writer can finish.
        BeforeCommit,
    }

    struct ClosingTick {
        machine: Arc<ForwardWindowMachine>,
        pk: crypto::PublicKey,
        registry: SharedPubkeyIndexRegistry,
        /// The closing tick's liveness requests.
        requests: Vec<(u64, Vec<String>)>,
        /// Whether the armed rendezvous ran during the closing tick.
        reached_rendezvous: bool,
    }

    /// Applies `change` with each writer on its own joined thread, so the order is fixed.
    fn change_registry(
        change: MidQuery,
        generation: &Arc<std::sync::atomic::AtomicU64>,
        registry: &SharedPubkeyIndexRegistry,
        key: [u8; 48],
    ) {
        let revoke = || {
            let generation = Arc::clone(generation);
            on_another_thread(move || generation.fetch_add(1, Ordering::Release) + 1)
        };
        let revalidate_to_9 = |seen: u64| {
            let registry = Arc::clone(registry);
            on_another_thread(move || {
                let answer = HashMap::from([(key, "9".to_string())]);
                assert!(registry.write().revalidate(seen, &answer));
            });
        };
        match change {
            MidQuery::Nothing => {}
            MidQuery::Revoke => {
                revoke();
            }
            MidQuery::RevokeAndRevalidateTo9 => revalidate_to_9(revoke()),
            MidQuery::TwoRevokers => {
                revalidate_to_9(revoke());
                revoke();
            }
        }
    }

    /// A key registered at epoch 10 with index 4 under `generation` (at 0),
    /// with every epoch but the closing one counted with no change.
    struct Counted {
        machine: Arc<ForwardWindowMachine>,
        pk: crypto::PublicKey,
        bytes: [u8; 48],
        registry: SharedPubkeyIndexRegistry,
        generation: Arc<std::sync::atomic::AtomicU64>,
        /// Applies the fixture's change inside the next liveness query.
        armed: Arc<AtomicBool>,
        bn: Arc<MockBeaconNodeClient>,
        loop_: LivenessObservationLoop,
        closing: u64,
        /// Liveness requests made before the closing tick.
        before: usize,
    }

    async fn counted_to_the_closing_epoch(
        change: MidQuery,
        generation: Arc<std::sync::atomic::AtomicU64>,
        commit: Option<Arc<RevocationCommit>>,
    ) -> Counted {
        let machine = machine();
        let pk = new_pk();
        let bytes = pk.to_bytes();
        let start = 10u64;
        machine.register(&pk, start);
        let registry = PubkeyIndexRegistry::shared();
        registry.write().insert(bytes, "4".to_string());
        registry.write().attach_revocation(Arc::clone(&generation), 0);
        if let Some(commit) = commit {
            registry.write().attach_commit(commit);
        }
        let armed = Arc::new(AtomicBool::new(false));
        let bn = {
            let (armed, generation, registry) =
                (Arc::clone(&armed), Arc::clone(&generation), Arc::clone(&registry));
            Arc::new(MockBeaconNodeClient::new().with_post_validator_liveness(
                move |_epoch, indices| {
                    if armed.swap(false, Ordering::SeqCst) {
                        change_registry(change, &generation, &registry, bytes);
                    }
                    let data = indices
                        .into_iter()
                        .map(|index| ValidatorLiveness { index, is_live: false })
                        .collect();
                    Ok(ValidatorLivenessResponse { data })
                },
            ))
        };
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&machine),
            Arc::clone(&bn) as Arc<dyn LivenessApi>,
            Arc::clone(&registry),
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        );
        let closing = start + DEFAULT_MONITORING_EPOCHS + 1;
        for epoch in start + 1..closing {
            loop_.drive_once_for_test(epoch, CLOSED_EPOCH_SLOT).await;
        }
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Pending);
        assert_eq!(
            machine.pending_keys().iter().map(|key| key.next_check_epoch).collect::<Vec<_>>(),
            vec![closing - 1],
            "precondition: one count left"
        );
        let before = bn.post_validator_liveness_calls().len();
        Counted { machine, pk, bytes, registry, generation, armed, bn, loop_, closing, before }
    }

    /// Run the closing tick at epoch 13 of [`counted_to_the_closing_epoch`] and
    /// apply `change` `at` the given point.
    async fn closing_tick(change: MidQuery, at: ChangeAt) -> ClosingTick {
        use std::sync::atomic::AtomicU64;

        let generation = Arc::new(AtomicU64::new(0));
        let Counted { machine, pk, bytes, registry, generation, armed, bn, loop_, closing, before } =
            counted_to_the_closing_epoch(change, generation, None).await;
        let reached = Arc::new(AtomicBool::new(false));

        armed.store(at == ChangeAt::FirstQuery, Ordering::SeqCst);
        let slot: Option<&'static Slot> = match at {
            ChangeAt::FirstQuery => None,
            ChangeAt::BeforeAdmission => Some(&BEFORE_ADMISSION),
            ChangeAt::BeforeCommit => Some(&BEFORE_COMMIT),
        };
        let _armed = slot.map(|slot| {
            let (reached, generation, registry) =
                (Arc::clone(&reached), Arc::clone(&generation), Arc::clone(&registry));
            arm(slot, move || {
                reached.store(true, Ordering::SeqCst);
                change_registry(change, &generation, &registry, bytes);
            })
        });
        loop_.drive_once_for_test(closing, CLOSED_EPOCH_SLOT).await;

        let requests = bn.post_validator_liveness_calls().split_off(before);
        let reached_rendezvous = reached.load(Ordering::SeqCst);
        ClosingTick { machine, pk, registry, requests, reached_rendezvous }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_closing_tick_opens_signing_when_the_registry_holds_still() {
        let tick = closing_tick(MidQuery::Nothing, ChangeAt::FirstQuery).await;

        assert_eq!(tick.requests, vec![ask(12), ask(13)]);
        assert_eq!(tick.machine.status(&tick.pk), ForwardWindowStatus::Safe);
        assert!(tick.machine.is_signing_enabled(&tick.pk));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_during_the_closing_tick_keeps_signing_closed() {
        let tick = closing_tick(MidQuery::Revoke, ChangeAt::FirstQuery).await;

        assert!(!tick.registry.read().is_fresh(), "precondition: the first query straddled it");
        assert_eq!(
            tick.machine.status(&tick.pk),
            ForwardWindowStatus::Pending,
            "observations through a pre-revocation index must not open the gate"
        );
        assert!(!tick.machine.is_signing_enabled(&tick.pk));
        assert_eq!(tick.requests, vec![ask(12)], "no query after the revocation");
    }

    /// The registry is fresh again by the time the old answer returns, so a
    /// `bool` freshness check would pass. The token check does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revalidation_to_another_index_during_the_closing_tick_keeps_signing_closed() {
        let tick = closing_tick(MidQuery::RevokeAndRevalidateTo9, ChangeAt::FirstQuery).await;

        let registry = tick.registry.read();
        assert_eq!(registry.freshness(), crate::pubkey_index::RegistryFreshness::Fresh(1));
        assert_eq!(registry.index_of(&tick.pk.to_bytes()), Some("9"), "precondition");
        drop(registry);
        assert_eq!(
            tick.machine.status(&tick.pk),
            ForwardWindowStatus::Pending,
            "an answer about index 4 must not count once the key is index 9"
        );
        assert!(!tick.machine.is_signing_enabled(&tick.pk));
        assert_eq!(tick.requests, vec![ask(12)], "index 4 is not asked again");
    }

    /// Both answers are checked before the revocation; it lands after the last
    /// answer and before the final decrement is applied.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_after_the_last_answer_keeps_signing_closed() {
        let tick = closing_tick(MidQuery::Revoke, ChangeAt::BeforeAdmission).await;

        assert!(tick.reached_rendezvous, "precondition: the rendezvous ran");
        assert!(!tick.registry.read().is_fresh(), "precondition: revoked before admission");
        assert_eq!(tick.requests, vec![ask(12), ask(13)], "both queries ran before it");
        assert_eq!(
            tick.machine.status(&tick.pk),
            ForwardWindowStatus::Pending,
            "answers admitted after a revocation must not open the gate"
        );
        assert!(!tick.machine.is_signing_enabled(&tick.pk));
    }

    /// The registry is fresh again at admission, so a `bool` freshness check
    /// would pass. The token check does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revalidation_to_another_index_after_the_last_answer_keeps_signing_closed() {
        let tick = closing_tick(MidQuery::RevokeAndRevalidateTo9, ChangeAt::BeforeAdmission).await;

        assert!(tick.reached_rendezvous, "precondition: the rendezvous ran");
        let registry = tick.registry.read();
        assert_eq!(registry.freshness(), crate::pubkey_index::RegistryFreshness::Fresh(1));
        assert_eq!(registry.index_of(&tick.pk.to_bytes()), Some("9"), "precondition");
        drop(registry);
        assert_eq!(tick.requests, vec![ask(12), ask(13)]);
        assert_eq!(
            tick.machine.status(&tick.pk),
            ForwardWindowStatus::Pending,
            "answers about index 4 must not count once the key is index 9"
        );
        assert!(!tick.machine.is_signing_enabled(&tick.pk));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_closing_tick_opens_signing_through_the_admission_rendezvous() {
        let tick = closing_tick(MidQuery::Nothing, ChangeAt::BeforeAdmission).await;

        assert!(tick.reached_rendezvous, "the rendezvous ran with no change");
        assert_eq!(tick.requests, vec![ask(12), ask(13)]);
        assert_eq!(tick.machine.status(&tick.pk), ForwardWindowStatus::Safe);
        assert!(tick.machine.is_signing_enabled(&tick.pk));
    }

    /// A revocation finishes at the last point a writer can finish before the
    /// closing tick's state commit. A finished revocation is never followed by
    /// that commit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_finished_just_before_the_commit_keeps_signing_closed() {
        let tick = closing_tick(MidQuery::Revoke, ChangeAt::BeforeCommit).await;

        assert!(tick.reached_rendezvous, "precondition: the rendezvous ran");
        assert!(!tick.registry.read().is_fresh(), "precondition: revoked");
        assert_eq!(tick.requests, vec![ask(12), ask(13)], "both queries ran before it");
        assert_eq!(
            tick.machine.status(&tick.pk),
            ForwardWindowStatus::Pending,
            "a finished revocation must keep the key Pending"
        );
        assert!(!tick.machine.is_signing_enabled(&tick.pk));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revalidation_to_another_index_finished_just_before_the_commit_keeps_signing_closed()
    {
        let tick = closing_tick(MidQuery::RevokeAndRevalidateTo9, ChangeAt::BeforeCommit).await;

        assert!(tick.reached_rendezvous, "precondition: the rendezvous ran");
        let registry = tick.registry.read();
        assert_eq!(registry.freshness(), crate::pubkey_index::RegistryFreshness::Fresh(1));
        assert_eq!(registry.index_of(&tick.pk.to_bytes()), Some("9"), "precondition");
        drop(registry);
        assert_eq!(
            tick.machine.status(&tick.pk),
            ForwardWindowStatus::Pending,
            "answers about index 4 must not count once the key is index 9"
        );
        assert!(!tick.machine.is_signing_enabled(&tick.pk));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_revocations_around_a_revalidation_finished_just_before_the_commit_keep_signing_closed(
    ) {
        let tick = closing_tick(MidQuery::TwoRevokers, ChangeAt::BeforeCommit).await;

        assert!(tick.reached_rendezvous, "precondition: the rendezvous ran");
        let registry = tick.registry.read();
        assert_eq!(registry.generation(), Some(2), "precondition: two revocations");
        assert!(!registry.is_fresh(), "precondition: revalidated under 1, now 2");
        assert_eq!(registry.index_of(&tick.pk.to_bytes()), Some("9"), "precondition");
        drop(registry);
        assert_eq!(tick.machine.status(&tick.pk), ForwardWindowStatus::Pending);
        assert!(!tick.machine.is_signing_enabled(&tick.pk));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_closing_tick_opens_signing_through_the_commit_rendezvous() {
        let tick = closing_tick(MidQuery::Nothing, ChangeAt::BeforeCommit).await;

        assert!(tick.reached_rendezvous, "the rendezvous ran with no change");
        assert_eq!(tick.requests, vec![ask(12), ask(13)]);
        assert_eq!(tick.machine.status(&tick.pk), ForwardWindowStatus::Safe);
        assert!(tick.machine.is_signing_enabled(&tick.pk));
    }

    /// No detection is counted from an answer whose index was revoked before
    /// the state commit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_answer_is_not_counted_once_a_revocation_finishes_just_before_the_commit() {
        const NO_BUMP: usize = usize::MAX;
        let probe = RevokedMidTick::new(NO_BUMP, [false, true]);
        let _armed = probe.revoke_before_commit();

        probe.tick().await;

        assert!(!probe.is_fresh(), "precondition: revoked");
        assert_eq!(probe.bn.post_validator_liveness_calls(), vec![ask(10), ask(11)]);
        assert_eq!(
            probe.machine.status(&probe.pk),
            ForwardWindowStatus::Pending,
            "a live answer through a revoked index must not detect"
        );
        assert_eq!(probe.next_checks(), vec![10], "nothing from the tick is counted");
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
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        // Index 7 is known and the answer omits it, so this is the per-epoch warn.
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            Arc::new(all_not_live(&[]).0),
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            CancellationToken::new(),
        );
        loop_.drive_once_for_test(start, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(start, CLOSED_EPOCH_SLOT).await;
        let epoch_10 = format!("epoch={start}");
        let warn = "doppelganger liveness unobserved";
        logs_assert(|lines| {
            let hits = lines
                .iter()
                .filter(|line| {
                    line.contains(warn) && line.contains(&epoch_10) && line.contains(prefix)
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
                .filter(|line| {
                    line.contains(warn) && line.contains(&epoch_10) && line.contains(prefix)
                })
                .count();
            let second = lines
                .iter()
                .filter(|line| {
                    line.contains(warn) && line.contains(&epoch_11) && line.contains(prefix)
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

    /// When the pool admits no beacon node:
    /// - Each tick makes two queries that fail.
    /// - Three ticks in epoch 11 produce one warning and five debug messages.
    /// - One tick in epoch 12 adds one warning and one debug message.
    /// - Each failure event has its level, its queried epoch and the error.
    /// - The key stays Pending.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn liveness_query_failure_warns_once_per_epoch_while_halted() {
        const FAILED: &str = "liveness query failed";
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let bn = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_validator_liveness(|_, _| Err(BeaconError::NoAdmittedNode)),
        );
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "7", &pk);
        let count = |level: &str| {
            let hits = std::cell::Cell::new(0);
            logs_assert(|lines| {
                hits.set(lines.iter().filter(|l| l.contains(level) && l.contains(FAILED)).count());
                Ok(())
            });
            hits.get()
        };

        for _ in 0..3 {
            loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        }
        let queries = bn.post_validator_liveness_calls().len();
        assert_eq!(queries, 6, "The three ticks in epoch 11 must send six queries.");
        assert_eq!(count(" WARN "), 1, "The six failures in epoch 11 must log one warning.");
        assert_eq!(count("DEBUG "), 5, "The other five failures in epoch 11 must log at debug.");

        loop_.drive_once_for_test(start + 2, CLOSED_EPOCH_SLOT).await;
        let queries = bn.post_validator_liveness_calls().len();
        assert_eq!(queries, 8, "The tick in epoch 12 must send two queries.");
        assert_eq!(count(" WARN "), 2, "The first failure in epoch 12 must log a second warning.");
        assert_eq!(count("DEBUG "), 6, "The second failure in epoch 12 must log at debug.");

        let events = failure_events_in(|f| logs_assert(f));
        // One row for each tick: the previous-epoch query, then the current-epoch query.
        let expected = [
            (halted_event("WARN", 10), halted_event("DEBUG", 11)),
            (halted_event("DEBUG", 10), halted_event("DEBUG", 11)),
            (halted_event("DEBUG", 10), halted_event("DEBUG", 11)),
            (halted_event("WARN", 11), halted_event("DEBUG", 12)),
        ];
        assert_eq!(events.len(), 2 * expected.len(), "Each tick must log two failure events.");
        for (tick, (previous, current)) in expected.iter().enumerate() {
            assert_eq!(
                &events[2 * tick],
                previous,
                "The previous-epoch failure in tick {} must have this level, epoch and error.",
                tick + 1
            );
            assert_eq!(
                &events[2 * tick + 1],
                current,
                "The current-epoch failure in tick {} must have this level, epoch and error.",
                tick + 1
            );
        }
        assert_eq!(
            m.status(&pk),
            ForwardWindowStatus::Pending,
            "A failed query must not decrement."
        );
    }

    /// The message of each failed liveness query event.
    const QUERY_FAILED: &str = "liveness query failed; will retry next slot (fail-closed)";

    /// The message of each per-key unobserved warning.
    const UNOBSERVED: &str = "doppelganger liveness unobserved";

    /// Return one entry for each failed-query line, in log order.
    ///
    /// An entry is the level and then the fields, for example
    /// "WARN epoch=10 error=no admitted beacon node; duties halted".
    fn query_failure_events(lines: &[&str]) -> Vec<String> {
        lines
            .iter()
            .filter_map(|line| {
                let (head, fields) = line.split_once(QUERY_FAILED)?;
                let level = head
                    .split_whitespace()
                    .find(|word| ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].contains(word))
                    .unwrap_or("NO-LEVEL");
                Some(format!("{level}{fields}"))
            })
            .collect()
    }

    /// Read the failed-query entries of a `traced_test`.
    ///
    /// `logs_assert` must give its argument to the `logs_assert` of that test.
    fn failure_events_in(
        logs_assert: impl Fn(&dyn Fn(&[&str]) -> Result<(), String>),
    ) -> Vec<String> {
        let found = RefCell::new(Vec::new());
        logs_assert(&|lines| {
            *found.borrow_mut() = query_failure_events(lines);
            Ok(())
        });
        found.into_inner()
    }

    /// The entry of [`query_failure_events`] for a query of `epoch` that fails
    /// with `NoAdmittedNode` and logs at `level`.
    fn halted_event(level: &str, epoch: Epoch) -> String {
        format!("{level} epoch={epoch} error={}", BeaconError::NoAdmittedNode)
    }

    /// One reply of [`scripted_liveness`].
    #[derive(Clone, Copy)]
    enum Reply {
        /// The query fails with `NoAdmittedNode`.
        Halted,
        /// The query answers not live for each index.
        NotLive,
    }

    /// A liveness mock that uses the next reply in `replies` for each query.
    ///
    /// After the last reply in the script, each query answers not live.
    fn scripted_liveness(replies: &[Reply]) -> Arc<MockBeaconNodeClient> {
        let replies: std::collections::VecDeque<Reply> = replies.iter().copied().collect();
        let replies = parking_lot::Mutex::new(replies);
        Arc::new(MockBeaconNodeClient::new().with_post_validator_liveness(move |_, indices| {
            match replies.lock().pop_front() {
                Some(Reply::Halted) => Err(BeaconError::NoAdmittedNode),
                Some(Reply::NotLive) | None => Ok(ValidatorLivenessResponse {
                    data: indices
                        .into_iter()
                        .map(|index| ValidatorLiveness { index, is_live: false })
                        .collect(),
                }),
            }
        }))
    }

    /// When the pool admits no beacon node, each failed query still gives an answer:
    /// - Three calls of `observe_adjacent` in epoch 11 each give two answers with `samples: None`.
    /// - Five of these six failures log at debug, after the first warning.
    /// - A tick in epoch 11 after these calls logs its two failures at debug.
    /// - That tick gives the indexed key one unobserved warning for epoch 10 and one for epoch 11.
    /// - After the failures, the key is Safe only after three closed epochs that are not live.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn liveness_query_failures_keep_none_answers_and_the_full_window() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        let prefix = hex::encode(pk.to_bytes());
        let prefix = &prefix[..10];
        let bn = scripted_liveness(&[Reply::Halted; 8]);
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "7", &pk);
        let unobserved = |epoch: Epoch| {
            let field = format!(" epoch={epoch}");
            let hits = std::cell::Cell::new(0);
            logs_assert(|lines| {
                hits.set(
                    lines
                        .iter()
                        .filter(|l| l.contains(UNOBSERVED) && l.contains(prefix))
                        .filter(|l| l.ends_with(&field))
                        .count(),
                );
                Ok(())
            });
            hits.get()
        };

        for call in 1..=3 {
            let observation = loop_.observe_adjacent(start + 1).await;
            let answers: Vec<(Epoch, Option<usize>)> = observation
                .answers
                .iter()
                .map(|answer| (answer.epoch, answer.samples.as_ref().map(Vec::len)))
                .collect();
            assert_eq!(
                answers,
                vec![(start, None), (start + 1, None)],
                "Call {call} in epoch 11 must give an answer with no samples for each failed query."
            );
        }
        let mut expected = vec![
            halted_event("WARN", start),
            halted_event("DEBUG", start + 1),
            halted_event("DEBUG", start),
            halted_event("DEBUG", start + 1),
            halted_event("DEBUG", start),
            halted_event("DEBUG", start + 1),
        ];
        assert_eq!(
            failure_events_in(|f| logs_assert(f)),
            expected,
            "Five of the six failures in epoch 11 must log at debug after the first warning."
        );

        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        assert_eq!(
            bn.post_validator_liveness_calls().len(),
            8,
            "The three calls and the tick in epoch 11 must send eight queries."
        );
        expected.extend([halted_event("DEBUG", start), halted_event("DEBUG", start + 1)]);
        assert_eq!(
            failure_events_in(|f| logs_assert(f)),
            expected,
            "The tick in epoch 11 must log its two failures at debug."
        );
        assert_eq!(
            unobserved(start),
            1,
            "A debug failure in epoch 11 must give one unobserved warning for epoch 10."
        );
        assert_eq!(
            unobserved(start + 1),
            1,
            "A debug failure in epoch 11 must give one unobserved warning for epoch 11."
        );
        assert_eq!(
            m.status(&pk),
            ForwardWindowStatus::Pending,
            "The failed queries must not decrement."
        );

        let closed = DEFAULT_MONITORING_EPOCHS + 1;
        for counted in 1..closed {
            loop_.drive_once_for_test(start + 1 + counted, CLOSED_EPOCH_SLOT).await;
            assert_eq!(
                m.status(&pk),
                ForwardWindowStatus::Pending,
                "The key must stay Pending after {counted} closed epochs that are not live."
            );
        }
        loop_.drive_once_for_test(start + 1 + closed, CLOSED_EPOCH_SLOT).await;
        assert_eq!(
            m.status(&pk),
            ForwardWindowStatus::Safe,
            "The key must be Safe after three closed epochs that are not live."
        );
    }

    /// A query that succeeds does not move the warning marker.
    ///
    /// Each tick uses slot 0, so a not-live answer does not decrement:
    /// - Tick 1 in epoch 11 has a success and then the first failure. That failure logs at warn.
    /// - Tick 2 in epoch 11 has a success and then a failure. That failure logs at debug.
    /// - Tick 3 in epoch 12 has two failures. The first logs at warn. The second logs at debug.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn liveness_success_does_not_move_the_warning_marker() {
        use Reply::{Halted, NotLive};
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 10);
        let bn = scripted_liveness(&[NotLive, Halted, NotLive, Halted, Halted, Halted]);
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&bn) as Arc<dyn LivenessApi>, "7", &pk);
        let counts = || {
            let events = failure_events_in(|f| logs_assert(f));
            let warns = events.iter().filter(|e| e.starts_with("WARN ")).count();
            let debugs = events.iter().filter(|e| e.starts_with("DEBUG ")).count();
            (warns, debugs)
        };

        loop_.drive_once_for_test(11, 0).await;
        assert_eq!(
            counts(),
            (1, 0),
            "A success before the first failure in epoch 11 must not stop its warning."
        );
        loop_.drive_once_for_test(11, 0).await;
        assert_eq!(
            counts(),
            (1, 1),
            "A failure after a success in epoch 11 must log at debug, not at warn."
        );
        loop_.drive_once_for_test(12, 0).await;
        assert_eq!(counts(), (2, 2), "Epoch 12 must add one warning and one debug message.");
        assert_eq!(
            failure_events_in(|f| logs_assert(f)),
            vec![
                halted_event("WARN", 11),
                halted_event("DEBUG", 11),
                halted_event("WARN", 11),
                halted_event("DEBUG", 12),
            ],
            "Only the first failure in each tick epoch must log at warn."
        );
        assert_eq!(
            bn.post_validator_liveness_calls().len(),
            6,
            "The three ticks must send six queries."
        );
        assert_eq!(
            m.status(&pk),
            ForwardWindowStatus::Pending,
            "A not-live answer at slot 0 must not decrement."
        );
    }

    #[derive(Default)]
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

    /// The epoch moves while the two liveness queries are in flight. The final
    /// not-live decrement is skipped. A live answer on the same tick still detects.
    #[tokio::test(start_paused = true)]
    async fn epoch_change_during_queries_skips_final_decrement() {
        let m = machine();
        let pending_pk = new_pk();
        let live_pk = new_pk();
        let start = 10u64;
        m.register(&pending_pk, start);

        let seam = ClockSeam::new(13, CLOSED_EPOCH_SLOT);
        let advance = Arc::new(AtomicBool::new(false));
        let advance_flag = Arc::clone(&advance);
        let seam_for_mock = Arc::clone(&seam);
        let beacon = Arc::new(MockBeaconNodeClient::new().with_post_validator_liveness(
            move |_epoch, indices| {
                if advance_flag.swap(false, Ordering::SeqCst) {
                    seam_for_mock.set_epoch(seam_for_mock.epoch().saturating_add(1));
                }
                let data = indices
                    .iter()
                    .map(|idx| ValidatorLiveness { index: idx.clone(), is_live: idx == "2" })
                    .collect();
                Ok(ValidatorLivenessResponse { data })
            },
        ));
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pending_pk.to_bytes(), "1".to_string());
        reg.write().insert(live_pk.to_bytes(), "2".to_string());
        let cancel = CancellationToken::new();
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            beacon,
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            cancel.clone(),
        )
        .with_slot_duration(Duration::from_secs(12))
        .with_clock_seam(Arc::clone(&seam));

        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(start + 2, CLOSED_EPOCH_SLOT).await;
        assert_eq!(m.status(&pending_pk), ForwardWindowStatus::Pending);
        m.register(&live_pk, 13);
        advance.store(true, Ordering::SeqCst);

        let task = tokio::spawn(loop_.run());
        for _ in 0..256 {
            if m.status(&live_pk) == ForwardWindowStatus::Detected {
                break;
            }
            if task.is_finished() {
                panic!("liveness loop ended before the live answer was applied");
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(seam.epoch(), 14, "the clock seam must move between the two queries");
        assert_eq!(
            m.status(&pending_pk),
            ForwardWindowStatus::Pending,
            "an epoch change must skip the final not-live decrement"
        );
        assert_eq!(m.status(&live_pk), ForwardWindowStatus::Detected);
        assert!(m.detected_latch());
        assert!(!m.is_signing_enabled(&pending_pk));
        assert!(!m.is_signing_enabled(&live_pk));

        cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("liveness loop");
    }

    /// The epoch stays put, and the slot crosses the closed boundary while the
    /// queries are in flight. The decrement uses the slot from before the
    /// queries. Passing the post-query slot would open the gate.
    #[tokio::test(start_paused = true)]
    async fn same_epoch_uses_the_pre_query_slot_for_the_closed_check() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);

        let seam = ClockSeam::new(13, CLOSED_EPOCH_SLOT - 1);
        let calls = Arc::new(AtomicUsize::new(0));
        let arm = Arc::new(AtomicBool::new(false));
        let calls_for_mock = Arc::clone(&calls);
        let arm_for_mock = Arc::clone(&arm);
        let seam_for_mock = Arc::clone(&seam);
        let beacon = Arc::new(MockBeaconNodeClient::new().with_post_validator_liveness(
            move |_epoch, indices| {
                calls_for_mock.fetch_add(1, Ordering::SeqCst);
                if arm_for_mock.load(Ordering::SeqCst) {
                    seam_for_mock.slot_in_epoch.store(CLOSED_EPOCH_SLOT, Ordering::SeqCst);
                }
                let data = indices
                    .iter()
                    .map(|idx| ValidatorLiveness { index: idx.clone(), is_live: false })
                    .collect();
                Ok(ValidatorLivenessResponse { data })
            },
        ));
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "1".to_string());
        let cancel = CancellationToken::new();
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            beacon,
            reg,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0, 12_000)),
            cancel.clone(),
        )
        .with_slot_duration(Duration::from_secs(12))
        .with_clock_seam(Arc::clone(&seam));

        loop_.drive_once_for_test(start + 1, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(start + 2, CLOSED_EPOCH_SLOT).await;
        assert_eq!(calls.load(Ordering::SeqCst), 4, "the two closed epochs are applied before run");
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));
        arm.store(true, Ordering::SeqCst);

        let task = tokio::spawn(loop_.run());
        for _ in 0..256 {
            if calls.load(Ordering::SeqCst) >= 6 {
                break;
            }
            if task.is_finished() {
                panic!("liveness loop ended before both queries of the open slot");
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            6,
            "run queries the previous epoch and the current one"
        );
        for _ in 0..32 {
            if task.is_finished() {
                panic!("liveness loop ended before the pre-query slot was applied");
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(seam.epoch(), 13, "the epoch must stay on the value read before the queries");
        assert_eq!(
            seam.slot_in_epoch.load(Ordering::SeqCst),
            CLOSED_EPOCH_SLOT,
            "the slot must close during the queries"
        );
        assert_eq!(
            m.status(&pk),
            ForwardWindowStatus::Pending,
            "a same-epoch slot that closes during the queries must not decrement"
        );
        assert!(!m.is_signing_enabled(&pk));

        cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("liveness loop");
    }

    /// This structure stores the result of one `run` tick with a scripted seam.
    struct ScriptedTick {
        status: ForwardWindowStatus,
        latched: bool,
        script_left: usize,
        /// This field records the number of scripted epochs left at admission
        /// under the machine lock.
        left_at_admission: Option<usize>,
        /// This field records the number of scripted epochs left after the state write.
        left_after_write: Option<usize>,
    }

    /// The helper runs one tick of `run` with these conditions:
    /// - The key has one not-live decrement left.
    /// - The seam stores epoch 13 and slot `CLOSED_EPOCH_SLOT`.
    /// - The epoch reads of the tick take the epochs in `script`, in order.
    /// - The beacon answers `is_live` for the key in epochs 12 and 13.
    ///
    /// `INSIDE_COMMIT` fires in the admission check, under the machine lock.
    /// `AFTER_COMMIT` fires after the state write. The cancel token stops the
    /// loop after that write.
    async fn run_one_scripted_tick(script: &[Epoch], is_live: bool) -> ScriptedTick {
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 10);
        let (bn, state) = all_not_live(&["1"]);
        let seam = ClockSeam::new(13, CLOSED_EPOCH_SLOT);
        let loop_ = loop_with(Arc::clone(&m), Arc::new(bn), "1", &pk)
            .with_slot_duration(Duration::from_secs(12))
            .with_clock_seam(Arc::clone(&seam));
        loop_.drive_once_for_test(11, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(12, CLOSED_EPOCH_SLOT).await;
        assert_eq!(
            m.pending_keys().iter().map(|key| key.next_check_epoch).collect::<Vec<_>>(),
            vec![12],
            "The two driven ticks must count epochs 10 and 11 before run starts."
        );
        state.live.write().insert("1".to_string(), is_live);
        seam.script_epochs(script);

        type Left = std::rc::Rc<std::cell::Cell<Option<usize>>>;
        let left_at_admission = Left::default();
        let left_after_write = Left::default();
        let record = |left: &Left| {
            let (seam, left) = (Arc::clone(&seam), std::rc::Rc::clone(left));
            move || left.set(Some(seam.script_remaining()))
        };
        let _inside = arm(&INSIDE_COMMIT, record(&left_at_admission));
        let _after = arm(&AFTER_COMMIT, record(&left_after_write));
        let cancel = loop_.cancel.clone();
        let task = tokio::spawn(loop_.run());
        for _ in 0..256 {
            if left_after_write.get().is_some() {
                break;
            }
            assert!(!task.is_finished(), "The loop must not stop before the first state write.");
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("The liveness loop must stop without a panic.");
        ScriptedTick {
            status: m.status(&pk),
            latched: m.detected_latch(),
            script_left: seam.script_remaining(),
            left_at_admission: left_at_admission.get(),
            left_after_write: left_after_write.get(),
        }
    }

    /// The test uses these conditions:
    /// - The two reads before the machine lock return epoch 13.
    /// - The read under the lock returns epoch 14.
    /// - The key has one not-live decrement left.
    ///
    /// The key must stay Pending. The tick must consume the script.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn rollover_between_reread_and_apply_skips_the_decrement() {
        let tick = run_one_scripted_tick(&[13, 13, 14], false).await;
        assert_eq!(
            tick.status,
            ForwardWindowStatus::Pending,
            "An epoch change under the machine lock must skip the last decrement."
        );
        assert!(!tick.latched, "A not-live answer must not set the detection latch.");
        assert_eq!(tick.script_left, 0, "The tick must take the three scripted epochs.");
        assert_eq!(
            tick.left_at_admission,
            Some(1),
            "The tick must read the epoch for the third time after the admission check starts."
        );
        assert_eq!(
            tick.left_after_write,
            Some(0),
            "The tick must read the epoch for the third time before the state write ends."
        );
    }

    /// The helper drives a key registered at epoch 10 through epochs 11, 12
    /// and 13. These conditions apply:
    /// - Each driven tick uses slot `CLOSED_EPOCH_SLOT`.
    /// - The beacon answers not live to each query.
    /// - The seam stores epoch 13.
    /// - If `move_on_last` is true, each query of the last tick sets the seam to epoch 14.
    ///
    /// The helper returns the key status and the stored seam epoch.
    async fn drive_three_closed_epochs(move_on_last: bool) -> (ForwardWindowStatus, Epoch) {
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 10);
        let seam = ClockSeam::new(13, CLOSED_EPOCH_SLOT);
        let armed = Arc::new(AtomicBool::new(false));
        let (armed_for_mock, seam_for_mock) = (Arc::clone(&armed), Arc::clone(&seam));
        let beacon =
            MockBeaconNodeClient::new().with_post_validator_liveness(move |_epoch, indices| {
                if armed_for_mock.load(Ordering::SeqCst) {
                    seam_for_mock.set_epoch(14);
                }
                let data = indices
                    .iter()
                    .map(|idx| ValidatorLiveness { index: idx.clone(), is_live: false })
                    .collect();
                Ok(ValidatorLivenessResponse { data })
            });
        let loop_ = loop_with(Arc::clone(&m), Arc::new(beacon), "1", &pk)
            .with_clock_seam(Arc::clone(&seam));
        loop_.drive_once_for_test(11, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(12, CLOSED_EPOCH_SLOT).await;
        armed.store(move_on_last, Ordering::SeqCst);
        loop_.drive_once_for_test(13, CLOSED_EPOCH_SLOT).await;
        (m.status(&pk), seam.epoch())
    }

    /// The beacon moves the seam from epoch 13 to epoch 14 during the driven
    /// queries for epoch 13. The last not-live decrement must not run.
    #[tokio::test]
    async fn drive_once_for_test_skips_the_decrement_when_the_epoch_changes() {
        let (status, seam_epoch) = drive_three_closed_epochs(true).await;
        assert_eq!(seam_epoch, 14, "The beacon must move the seam during the last driven tick.");
        assert_eq!(
            status,
            ForwardWindowStatus::Pending,
            "A seam that moves during the driven queries must skip the last decrement."
        );
    }

    /// The seam stays at epoch 13 while the driver drives epochs 11, 12 and 13.
    /// The driver compares the seam with itself, so each decrement runs.
    #[tokio::test]
    async fn drive_once_for_test_with_a_still_seam_still_decrements() {
        let (status, seam_epoch) = drive_three_closed_epochs(false).await;
        assert_eq!(seam_epoch, 13, "The seam must not move.");
        assert_eq!(
            status,
            ForwardWindowStatus::Safe,
            "A still seam must let the driven not-live answers finish the window."
        );
    }

    /// The script changes the epoch under the machine lock, and the key is
    /// live. The live answer must still detect.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn rollover_keeps_a_live_answer() {
        let tick = run_one_scripted_tick(&[13, 13, 14], true).await;
        assert_eq!(
            tick.status,
            ForwardWindowStatus::Detected,
            "An epoch change under the machine lock must not drop a live answer."
        );
        assert!(tick.latched, "The live answer must set the detection latch.");
    }

    /// The script keeps epoch 13 for the three reads of the tick. The last
    /// not-live decrement must run through `run`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_with_a_still_epoch_applies_the_last_decrement() {
        let tick = run_one_scripted_tick(&[13, 13, 13], false).await;
        assert_eq!(
            tick.status,
            ForwardWindowStatus::Safe,
            "An unchanged epoch under the machine lock must apply the last decrement."
        );
        assert_eq!(tick.script_left, 0, "The tick must take the three scripted epochs.");
    }

    /// The recorder keeps one value for each exit request. The value is true
    /// if the sidecar exists at that time.
    struct SidecarAtExit {
        sidecar: std::path::PathBuf,
        present: std::sync::Mutex<Vec<bool>>,
    }

    impl ExitRequest for SidecarAtExit {
        fn request(&self, _exit_code: i32) {
            let mut present = self.present.lock().expect("The record lock must not be poisoned.");
            present.push(self.sidecar.exists());
        }
    }

    /// W4-D3d2 (fix round 1): the first run tick makes the not-live key Safe
    /// and removes its sidecar. Then the test writes the sidecar again and
    /// registers a live key. The second tick has these results:
    ///
    /// - The live key becomes Detected, and the loop requests the exit one
    ///   time.
    /// - The latched loop keeps the sidecar of the Safe key: a cleanup that
    ///   blocks on the keystore directory or on `TrackedKeys` cannot hold
    ///   exit 12.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_keeps_a_safe_sidecar_once_the_detection_latches() {
        let dir = tempfile::tempdir().expect("The test must create a directory.");
        let m = machine();
        let (safe_pk, live_pk) = (new_pk(), new_pk());
        m.register(&safe_pk, 10);
        let name = format!("0x{}.import_meta.json", hex::encode(safe_pk.to_bytes()));
        let sidecar = dir.path().join(name);
        std::fs::write(&sidecar, "{\"imported_unix_seconds\":1}")
            .expect("The test must write the sidecar.");
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(safe_pk.to_bytes(), "1".to_string());
        reg.write().insert(live_pk.to_bytes(), "2".to_string());
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::from([(
            safe_pk.to_bytes(),
            safe_pk.clone(),
        )])));
        let exit =
            Arc::new(SidecarAtExit { sidecar: sidecar.clone(), present: Default::default() });
        let cancel = CancellationToken::new();
        let bn = Arc::new(with_live(&[("1", false), ("2", true)]).0);
        let loop_ =
            LivenessObservationLoop::new(Arc::clone(&m), bn, reg, test_clock(), cancel.clone())
                .with_slot_duration(Duration::from_secs(12))
                .with_clock_seam(ClockSeam::new(13, CLOSED_EPOCH_SLOT))
                .with_pubkey_map(pubkey_map)
                .with_import_sidecar_dir(
                    dir.path().to_path_buf(),
                    Arc::new(crate::quiesce::TrackedKeys::new()),
                )
                .with_detection_marker_dir(dir.path().to_path_buf())
                .with_exit_request(exit.clone() as Arc<dyn ExitRequest>);
        loop_.drive_once_for_test(11, CLOSED_EPOCH_SLOT).await;
        loop_.drive_once_for_test(12, CLOSED_EPOCH_SLOT).await;
        assert!(sidecar.exists(), "A Pending key must keep its sidecar.");

        let task = tokio::spawn(loop_.run());
        poll_until_parked(&task).await;
        assert!(!sidecar.exists(), "The run tick must remove the sidecar of the Safe key.");
        std::fs::write(&sidecar, "{\"imported_unix_seconds\":1}")
            .expect("The test must write the sidecar again.");
        m.register(&live_pk, 13);
        tokio::time::advance(Duration::from_secs(12)).await;
        poll_until_parked(&task).await;
        cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        task.await.expect("The liveness loop must stop without a panic.");
        assert_eq!(
            m.status(&safe_pk),
            ForwardWindowStatus::Safe,
            "The tick must finish the window of the safe key."
        );
        assert_eq!(
            m.status(&live_pk),
            ForwardWindowStatus::Detected,
            "The tick must detect the live key."
        );
        assert_eq!(
            *exit.present.lock().expect("The record lock must not be poisoned."),
            vec![true],
            "The loop must request the exit one time, with the sidecar present."
        );
        assert!(sidecar.exists(), "The latched loop must keep the sidecar of the Safe key.");
    }

    /// Wait until the loop task waits in its slot sleep. Use this only with
    /// paused time: paused time moves only when no task can run and no
    /// blocking write runs, so the 1 ms sleep ends after each write of the
    /// tick has returned and the loop has parked.
    async fn poll_until_parked(task: &tokio::task::JoinHandle<()>) {
        tokio::time::sleep(Duration::from_millis(1)).await;
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
                    Some(fallback_in(fallback.path())),
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
                crate::detection_marker::inspect_fallback(&fallback_in(fallback.path())).owned,
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
                Some(detection_shutdown(m, missing, Some(fallback_in(fallback.path())), clock)),
            ),
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "token cancel during the marker retry must exit 12, got {res:?}"
        );
        assert!(matches!(
            crate::detection_marker::inspect_fallback(&fallback_in(fallback.path())).owned,
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
                Some(detection_shutdown(m, missing, Some(fallback_in(fallback.path())), clock)),
            ),
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "a panic while latched must exit 12, got {res:?}"
        );
        assert!(matches!(
            crate::detection_marker::inspect_fallback(&fallback_in(fallback.path())).owned,
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
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn in_place_record_survives_marker_and_fallback_write_failure() {
        let keys = tempfile::tempdir().expect("keys");
        let fallback = tempfile::tempdir().expect("fallback");
        let _keys_faults = marker_writes_fail(keys.path());
        let _fallback_faults = marker_writes_fail(fallback.path());
        crate::detection_marker::preallocate_detection_record(keys.path()).expect("record");
        let m = latched_machine();
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let keystore = keys.path().to_path_buf();
        let fallback_path = fallback_in(fallback.path());
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(
                    executor,
                    shutdown_rx,
                    token,
                    Some(detection_shutdown(m, keystore, Some(fallback_path), clock)),
                ),
                std::future::ready(()),
            )
            .await
        });
        let (_outcome, res) = join_in_paused_time(drain).await;
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
                crate::detection_marker::inspect_fallback(&fallback_in(fallback.path())).owned,
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

    /// Instances A and B use one directory for their databases. The keystore
    /// directory of instance A is absent. The drain of instance A writes only
    /// the fallback marker for `a.sqlite`. The test requires these results:
    ///
    /// - The drain of instance A must return the doppelganger detection error.
    /// - Boot for instance B must proceed past the marker check.
    /// - Boot for instance A must return exit code 12.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fallback_marker_of_one_instance_does_not_refuse_another_sharing_the_db_dir() {
        let shared = tempfile::tempdir().expect("The test must create the database directory.");
        let root_a = tempfile::tempdir().expect("The test must create the parent of keystore A.");
        let keys_a = root_a.path().join("keys");
        let db_a = shared.path().join("a.sqlite");
        let fallback = crate::detection_marker::FallbackMarkerPath::for_config(&keys_a, &db_a)
            .expect("The test must find a fallback path beside the database.");
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let keystore = keys_a.clone();
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(
                    executor,
                    shutdown_rx,
                    token,
                    Some(detection_shutdown(
                        latched_machine(),
                        keystore,
                        Some(fallback),
                        test_clock(),
                    )),
                ),
                std::future::ready(()),
            )
            .await
        });

        let (_outcome, res) = join_in_paused_time(drain).await;

        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain of instance A must return the doppelganger detection error. The result \
             is {res:?}."
        );
        let keys_b = tempfile::tempdir().expect("The test must create the keystore of instance B.");
        let err = boot_refusing(keys_b.path(), Some(shared.path().join("b.sqlite"))).await;
        assert_ne!(
            err.exit_code(),
            EXIT_DOPPELGANGER_DETECTED,
            "Instance B must not exit with code 12 when only instance A has a fallback marker. \
             The error is {err}."
        );
        std::fs::create_dir(&keys_a).expect("The test must create the keystore of instance A.");
        let err = boot_refusing(&keys_a, Some(db_a)).await;
        assert_eq!(
            err.exit_code(),
            EXIT_DOPPELGANGER_DETECTED,
            "Boot for instance A must return exit code 12. The error is {err}."
        );
    }

    /// The keystore directory does not exist, so the record write and the
    /// keystore marker write fail. An injected failure stops the fallback
    /// write. The test requires these results:
    ///
    /// - While the three writes fail, the drain stays active and the durable
    ///   flag stays clear.
    /// - After the injection stops, the fallback write succeeds on the next
    ///   attempt, and the drain returns exit 12.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn drain_retries_while_three_writes_fail_and_exits_12_after_one_succeeds() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let fallback = tempfile::tempdir().expect("The test must create the database directory.");
        let guard = marker_writes_fail(fallback.path());
        let m = latched_machine();
        let machine = Arc::clone(&m);
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection = detection_shutdown(
            m,
            root.path().join("keys"),
            Some(fallback_in(fallback.path())),
            test_clock(),
        );
        let persister = Arc::clone(&detection.persister);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_for_rounds(&persister, 1).await;

        assert!(!drain.is_finished(), "The drain must stay active while the three writes fail.");
        assert!(
            !machine.detection_persisted(),
            "The durable flag must stay clear while the three writes fail."
        );
        drop(guard);
        tokio::time::advance(Duration::from_secs(1)).await;
        let (_outcome, res) = join_in_paused_time(drain).await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain must return exit 12 after the fallback write succeeds. The result is \
             {res:?}."
        );
        assert!(
            matches!(
                crate::detection_marker::inspect_fallback(&fallback_in(fallback.path())).owned,
                crate::detection_marker::MarkerInspect::Present(_)
            ),
            "The fallback marker must be present after the drain."
        );
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
        let _guard = marker_writes_fail(keys.path());
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection = detection_shutdown(m, keys.path().to_path_buf(), None, clock);
        let persister = Arc::clone(&detection.persister);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_until(|| drain.is_finished() || persister.rounds() > 0).await;
        assert_eq!(
            persister.rounds(),
            0,
            "a durable marker must not start a rewrite round or sleep on a rewrite failure"
        );
        let (_outcome, res) = finish_within(drain, Duration::from_secs(2)).await;
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
        let guard = fsyncs_fail(keys.path());
        let m = latched_machine();
        let machine = Arc::clone(&m);
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection = detection_shutdown(m, keys.path().to_path_buf(), None, clock);
        let persister = Arc::clone(&detection.persister);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_for_rounds(&persister, 1).await;
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
        let latched: Vec<String> =
            machine.detected_hexes().iter().map(|key| format!("0x{key}")).collect();
        let marker = crate::detection_marker::inspect(keys.path());
        assert!(
            persister.finished(crate::detection_marker::PersistPath::KeystoreMarker) == 2
                && matches!(
                    &marker,
                    crate::detection_marker::MarkerInspect::Present(found)
                        if found.pubkeys == latched
                ),
            "After the fault ends, a new keystore marker write must end and publish the marker \
             with the latched key. The marker is {marker:?}."
        );
    }

    /// The first marker write fails, the drain waits, and the retry exits 12.
    /// W4-D3a (747-9): the failure counter grows by at least 1 across the
    /// drain.
    /// W4-D3b: the record is missing in each round. The drain counts each
    /// failed path one time, so the counter increases by exactly 3.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_retries_a_failed_marker_write_then_exits_12() {
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let keys = tempfile::tempdir().expect("keys");
        let guard = marker_writes_fail(keys.path());
        let m = latched_machine();
        let clock = test_clock();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection = detection_shutdown(m, keys.path().to_path_buf(), None, clock);
        let persister = Arc::clone(&detection.persister);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_for_rounds(&persister, 1).await;
        drop(guard);
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
        let after = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        assert!(
            after.saturating_sub(before) >= 1,
            "The failed marker write of the drain must increment \
             rvc_doppelganger_marker_write_failures_total. The value before the drain is \
             {before}, and the value after the drain is {after}."
        );
        assert_eq!(
            after.saturating_sub(before),
            3,
            "The drain must count each failed path one time. The first round has two failed \
             paths: the missing record and the keystore marker. The second round has one failed \
             path: the missing record."
        );
    }

    /// W4-D3a (747-5): each fsync fails while the running loop sets the latch.
    /// The page cache then shows a detected record. The test requires these
    /// results:
    ///
    /// - The loop must not request exit 12.
    /// - At 5 s, the drain must still run. The durable flag must stay clear.
    /// - After the fsync failures stop, the drain must return exit 12.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn loop_fsync_failure_then_shutdown_keeps_retrying() {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        crate::detection_marker::preallocate_detection_record(keys.path())
            .expect("The test must preallocate the record.");
        let guard = fsyncs_fail(keys.path());
        let (m, task, executor, shutdown_rx, token, clock) = spawn_live_loop(keys.path());
        poll_until_parked(&task).await;
        assert!(m.detected_latch(), "The loop must set the latch while each fsync fails.");
        assert!(
            !executor.doppelganger_exit_requested(),
            "The loop must not request exit 12 while each fsync fails."
        );
        let machine = Arc::clone(&m);
        let detection = detection_shutdown(m, keys.path().to_path_buf(), None, clock);
        let persister = Arc::clone(&detection.persister);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        advance_rounds(&persister, 5).await;
        wait_for_rounds(&persister, 6).await;

        assert!(!drain.is_finished(), "The drain must not finish while each fsync fails.");
        assert!(
            matches!(
                crate::detection_marker::inspect_record(keys.path()),
                crate::detection_marker::RecordInspect::Detected { .. }
            ),
            "The page cache must show a detected record after the failed fsync."
        );
        assert!(
            !machine.detection_persisted(),
            "The durable flag must stay clear while each fsync fails."
        );
        drop(guard);
        tokio::time::advance(Duration::from_secs(1)).await;
        let (_outcome, res) = finish_within(drain, Duration::from_secs(2)).await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain must return exit 12 after a write and its fsync return Ok. The result is \
             {res:?}."
        );
        task.abort();
    }

    /// W4-D3a (747-8): the keystore directory and the fallback directory do
    /// not exist, so each write of the drain fails. Both writes fail for one
    /// hour of paused time. A limit on the number of failed rounds must not
    /// stop the drain in that hour. The test requires these results:
    ///
    /// - After one hour, the drain must still run.
    /// - The failure counter must increase by at least 120 during the hour.
    /// - After the test creates the fallback directory, the drain must return
    ///   exit 12, and the owned fallback marker must be present.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn drain_waits_while_both_writes_fail_then_exits_12_once_the_fallback_exists() {
        const FAILING_SECS: u64 = 3_600;
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let db_dir = root.path().join("db");
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection = detection_shutdown(
            latched_machine(),
            root.path().join("keys"),
            Some(fallback_in(&db_dir)),
            test_clock(),
        );
        let persister = Arc::clone(&detection.persister);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        advance_rounds(&persister, FAILING_SECS as usize).await;
        wait_for_rounds(&persister, FAILING_SECS as usize + 1).await;

        assert!(!drain.is_finished(), "The drain must not finish while both writes fail.");
        let failures = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL
            .get()
            .saturating_sub(before);
        assert!(
            failures >= FAILING_SECS / 30,
            "The failure counter must increase by at least 120 during the hour. In \
             {FAILING_SECS} s, the failure counter increased by {failures}."
        );
        std::fs::create_dir(&db_dir).expect("The test must create the fallback directory.");
        tokio::time::advance(Duration::from_secs(1)).await;
        let (_outcome, res) = finish_within(drain, Duration::from_secs(2)).await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain must return exit 12 after the fallback write succeeds. The result is \
             {res:?}."
        );
        assert!(
            matches!(
                crate::detection_marker::inspect_fallback(&fallback_in(&db_dir)).owned,
                crate::detection_marker::MarkerInspect::Present(_)
            ),
            "The owned fallback marker must be present after the drain."
        );
    }

    /// Let the drain of `persister` run `rounds` failed rounds: wait for the
    /// result of each round, then move paused time by the retry wait of 1 s.
    async fn advance_rounds(
        persister: &crate::detection_marker::DetectionPersister,
        rounds: usize,
    ) {
        for round in 1..=rounds {
            wait_for_rounds(persister, round).await;
            tokio::time::advance(Duration::from_secs(1)).await;
        }
    }

    /// Return the `error` value of each `ERROR` line in `logged` that has the
    /// `path` value `path`. In a line, the `path` value is all the text
    /// between ` path=` and ` error=`. The `error` value is all the text after
    /// ` error=`. Thus a space in a path does not stop the match.
    fn path_errors(logged: &[String], path: &std::path::Path) -> Vec<String> {
        let path = path.display().to_string();
        logged
            .iter()
            .filter(|line| line.contains(" ERROR "))
            .filter_map(|line| {
                let (_, fields) = line.split_once(" path=")?;
                let (value, error) = fields.split_once(" error=")?;
                (value == path).then(|| error.to_string())
            })
            .collect()
    }

    /// W4-D3b: a directory is at the record path, so the record write of the
    /// drain fails. The keystore marker write succeeds. The test requires
    /// these results:
    ///
    /// - The drain returns exit 12.
    /// - The log has one error line with the record path. The `error` value
    ///   of that line is the error that the record write gives. The test
    ///   gets that error from `commit_detection_record` before the drain.
    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn drain_logs_the_record_error_with_its_path() {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        let record = crate::detection_marker::record_path(keys.path());
        std::fs::create_dir(&record).expect("The test must create a directory at the record path.");
        let record_error = crate::detection_marker::commit_detection_record(keys.path(), 0, 0)
            .expect_err("The record write must fail while a directory is at the record path.")
            .to_string();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        // The drain needs an epoch clock. `test_clock` reads
        // `std::time::Instant::now()` one time to make it. No assertion uses
        // that clock, and the test does not wait on the wall clock.
        let detection =
            detection_shutdown(latched_machine(), keys.path().to_path_buf(), None, test_clock());

        let (_outcome, res) = crate::bootstrap::await_shutdown_and_drain_with_signal(
            drain_inputs(executor, shutdown_rx, token, Some(detection)),
            std::future::ready(()),
        )
        .await;

        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain must return exit 12 after the keystore marker write succeeds. The result \
             is {res:?}."
        );
        let logged = RefCell::new(Vec::new());
        logs_assert(|lines| {
            logged.replace(lines.iter().map(ToString::to_string).collect());
            Ok(())
        });
        let logged = logged.into_inner();
        assert_eq!(
            path_errors(&logged, &record),
            [record_error],
            "The log must have one error line with the record path and the error of the record \
             write. The log is {logged:#?}."
        );
    }

    /// W4-D3b: each path of the drain fails in the first round. Each path
    /// has a different error:
    ///
    /// - The record is missing.
    /// - A directory is at the keystore marker path.
    /// - A regular file is at the path of the fallback directory.
    ///
    /// Before the drain, the test gets the error of each writer for these
    /// paths. The test requires these results:
    ///
    /// - The first round logs one error line for each path. The `error`
    ///   value of each line is the error of the writer of that path.
    /// - The first round increases the failure counter by exactly 3, one
    ///   for each failed path.
    /// - The drain continues after the first round.
    /// - The test replaces the file with a directory and moves paused time by
    ///   1 s. Then the drain returns exit 12, and the owned fallback marker
    ///   is present.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[tracing_test::traced_test]
    async fn drain_logs_each_failed_path_with_its_error() {
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let keys = root.path().join("keys");
        std::fs::create_dir(&keys).expect("The test must create the keystore directory.");
        std::fs::create_dir(crate::detection_marker::marker_path(&keys))
            .expect("The test must create a directory at the keystore marker path.");
        let db_dir = root.path().join("db");
        std::fs::write(&db_dir, b"")
            .expect("The test must put a regular file at the fallback directory path.");
        let fallback = fallback_in(&db_dir);
        let paths = [
            crate::detection_marker::record_path(&keys),
            crate::detection_marker::marker_path(&keys),
            fallback.owned_path(),
        ];
        let marker = crate::detection_marker::DetectionMarker {
            epoch: 0,
            unix_secs: 0,
            pubkeys: Vec::new(),
        };
        let errors = [
            crate::detection_marker::commit_detection_record(&keys, 0, 0).err(),
            crate::detection_marker::write_marker(&keys, &marker).err(),
            crate::detection_marker::write_fallback_marker(&fallback, &keys, &marker).err(),
        ]
        .map(|error| error.expect("Each write must fail before the drain starts.").to_string());
        assert_eq!(
            errors.iter().collect::<std::collections::BTreeSet<_>>().len(),
            3,
            "The test must give a different error to each path. The errors are {errors:?}."
        );
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        // The drain needs an epoch clock. `test_clock` reads
        // `std::time::Instant::now()` one time to make it. No assertion uses
        // that clock. The test moves only paused Tokio time, and the counter
        // check uses the increase from the value before the drain.
        let detection =
            detection_shutdown(latched_machine(), keys, Some(fallback.clone()), test_clock());
        let persister = Arc::clone(&detection.persister);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_for_rounds(&persister, 1).await;

        let failures = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL
            .get()
            .saturating_sub(before);
        let logged = RefCell::new(Vec::new());
        logs_assert(|lines| {
            logged.replace(lines.iter().map(ToString::to_string).collect());
            Ok(())
        });
        let logged = logged.into_inner();
        assert_eq!(
            paths.each_ref().map(|path| path_errors(&logged, path)),
            errors.map(|error| vec![error]),
            "The first round must log one error line for each path. The error value of each line \
             must be the error of the writer of that path. The paths are {paths:?}. The log is \
             {logged:#?}."
        );
        assert_eq!(
            failures, 3,
            "The first round must increase the failure counter by exactly 3, one for each failed \
             path. The counter increased by {failures}."
        );
        assert!(
            !drain.is_finished(),
            "The drain must continue after the first round, because each path failed."
        );
        std::fs::remove_file(&db_dir).expect("The test must remove the regular file.");
        std::fs::create_dir(&db_dir).expect("The test must create the fallback directory.");
        tokio::time::advance(Duration::from_secs(1)).await;
        let (_outcome, res) = join_in_paused_time(drain).await;
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain must return exit 12 after the fallback write succeeds. The result is \
             {res:?}."
        );
        assert!(
            matches!(
                crate::detection_marker::inspect_fallback(&fallback).owned,
                crate::detection_marker::MarkerInspect::Present(_)
            ),
            "The owned fallback marker must be present after the drain."
        );
    }

    /// The epoch that the W4-D3c loop tests give to the loop through a clock
    /// seam.
    const LOOP_EPOCH: Epoch = 9;

    /// The Unix time that the W4-D3c loop tests give to the writers.
    const LOOP_UNIX_SECS: u64 = 1_700_000_000;

    /// The message of each error line of `log_persist_report`.
    const REPORT_MESSAGE: &str = "failed to persist the doppelganger detection on this path";

    /// The level, the target and the fields of each event on the test
    /// thread, one line for each event. The current-thread runtime runs the
    /// loop on the test thread. As a result, the log gets the lines of the
    /// loop and the lines in its detached tick span. It gets no line of a
    /// different test.
    #[derive(Clone, Default)]
    struct ThreadLog(Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ThreadLog {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let metadata = event.metadata();
            let mut line = format!("{} {}", metadata.level(), metadata.target());
            event.record(&mut LoopLogVisitor(&mut line));
            self.0.lock().expect("The test must store the log line.").push(line);
        }
    }

    impl ThreadLog {
        /// Send each event of the test thread to this log until the guard
        /// drops.
        fn capture(&self) -> tracing::subscriber::DefaultGuard {
            tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()))
        }

        /// Return each line, in the log order.
        fn lines(&self) -> Vec<String> {
            self.0.lock().expect("The test must read the log.").clone()
        }

        /// Return each `ERROR` line with a `path` field, in the log order.
        fn path_lines(&self) -> Vec<String> {
            let lines = self.lines().into_iter();
            lines.filter(|line| line.starts_with("ERROR ") && line.contains(" path=")).collect()
        }
    }

    /// Return the line of [`ThreadLog`] that `log_persist_report` must give
    /// for a failed path of the liveness loop.
    fn loop_report_line(
        kind: crate::detection_marker::PersistPath,
        path: &std::path::Path,
        error: &std::io::Error,
    ) -> String {
        format!(
            "ERROR rvc::detection_marker message={REPORT_MESSAGE} context=liveness loop \
             kind={kind:?} path={} error={error}",
            path.display()
        )
    }

    /// The paths of a loop test in which the two marker writes fail.
    /// `lines` has the line that the loop must log for each failed path, in
    /// the write order.
    struct FailingMarkers {
        paths: crate::detection_marker::DetectionPaths,
        lines: Vec<String>,
    }

    /// Make a keystore directory in `root` with a directory at the keystore
    /// marker path. Put a regular file at the path of the fallback
    /// directory. Because of these entries, the two marker writes fail. If
    /// `record` is `true`, pre-allocate the record. Then the record write
    /// succeeds. If `record` is `false`, the record is missing, and its write
    /// also fails. Before the loop starts, get the error of the writer of
    /// each failed path for its line. Each write must fail with the error
    /// kind of its cause. The record write must give `NotFound`, the keystore
    /// marker write `IsADirectory`, and the fallback marker write
    /// `NotADirectory`.
    fn failing_markers(root: &std::path::Path, record: bool) -> FailingMarkers {
        use crate::detection_marker::PersistPath;
        let keys = root.join("keys");
        std::fs::create_dir(&keys).expect("The test must create the keystore directory.");
        let marker_path = crate::detection_marker::marker_path(&keys);
        std::fs::create_dir(&marker_path)
            .expect("The test must create a directory at the keystore marker path.");
        let db_dir = root.join("db");
        std::fs::write(&db_dir, b"")
            .expect("The test must put a regular file at the fallback directory path.");
        let fallback = fallback_in(&db_dir);
        let marker = crate::detection_marker::DetectionMarker {
            epoch: 0,
            unix_secs: 0,
            pubkeys: Vec::new(),
        };
        let mut lines = Vec::new();
        if record {
            crate::detection_marker::preallocate_detection_record(&keys)
                .expect("The test must pre-allocate the record.");
        } else {
            let path = crate::detection_marker::record_path(&keys);
            let result = crate::detection_marker::commit_detection_record(&keys, 0, 0);
            let cause = (std::io::ErrorKind::NotFound, "the record is missing");
            lines.push(failed_line(PersistPath::Record, &path, result, cause));
        }
        let result = crate::detection_marker::write_marker(&keys, &marker);
        let cause = (std::io::ErrorKind::IsADirectory, "a directory is at its path");
        lines.push(failed_line(PersistPath::KeystoreMarker, &marker_path, result, cause));
        let result = crate::detection_marker::write_fallback_marker(&fallback, &keys, &marker);
        let cause =
            (std::io::ErrorKind::NotADirectory, "a regular file is at the path of its directory");
        lines.push(failed_line(PersistPath::FallbackMarker, &fallback.owned_path(), result, cause));
        let paths = crate::detection_marker::DetectionPaths {
            keystore_dir: keys,
            fallback: Some(fallback),
        };
        FailingMarkers { paths, lines }
    }

    /// Return the line of [`loop_report_line`] for the failed write `result`
    /// of the path `kind`. The write must fail with the error kind of
    /// `cause`. The text of `cause` gives the reason.
    fn failed_line(
        kind: crate::detection_marker::PersistPath,
        path: &std::path::Path,
        result: std::io::Result<()>,
        (cause, reason): (std::io::ErrorKind, &str),
    ) -> String {
        let error = result.err();
        assert_eq!(
            error.as_ref().map(std::io::Error::kind),
            Some(cause),
            "The {kind:?} write must fail with {cause:?}, because {reason}. The error is \
             {error:?}."
        );
        error.map(|error| loop_report_line(kind, path, &error)).unwrap_or_default()
    }

    /// A liveness loop from [`spawn_detecting_loop`].
    struct DetectingLoop<E> {
        machine: Arc<ForwardWindowMachine>,
        /// The one key of the loop, as a marker stores it: `0x` and the
        /// lowercase hex.
        marker_key: String,
        exits: Arc<E>,
        cancel: CancellationToken,
        task: tokio::task::JoinHandle<()>,
    }

    /// Spawn a liveness loop that gets a live answer for its one key. The
    /// loop reads epoch [`LOOP_EPOCH`] from a clock seam. It writes the
    /// detection to `paths` when `paths` is set. `exit` gets the machine and
    /// makes the exit request of the loop. `RecordingExit` stores each exit
    /// code.
    fn spawn_detecting_loop<E: ExitRequest + 'static>(
        paths: Option<crate::detection_marker::DetectionPaths>,
        exit: impl FnOnce(&Arc<ForwardWindowMachine>) -> E,
    ) -> DetectingLoop<E> {
        spawn_configured_loop(
            |loop_| match paths {
                Some(paths) => loop_.with_detection_paths(paths),
                None => loop_,
            },
            exit,
        )
    }

    /// Spawn the loop of [`spawn_detecting_loop`]. `configure` sets the
    /// detection paths of the loop before the spawn.
    fn spawn_configured_loop<E: ExitRequest + 'static>(
        configure: impl FnOnce(LivenessObservationLoop) -> LivenessObservationLoop,
        exit: impl FnOnce(&Arc<ForwardWindowMachine>) -> E,
    ) -> DetectingLoop<E> {
        let machine = machine();
        let pk = new_pk();
        machine.register(&pk, 0);
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "7".to_string());
        let exits = Arc::new(exit(&machine));
        let cancel = CancellationToken::new();
        // The constructor needs an epoch clock. `test_clock` reads
        // `std::time::Instant::now()` one time to make it. The loop reads its
        // epoch from the seam, so no assertion uses that clock.
        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&machine),
            Arc::new(with_live(&[("7", true)]).0),
            reg,
            test_clock(),
            cancel.clone(),
        )
        .with_clock_seam(ClockSeam::new(LOOP_EPOCH, 0))
        .with_slot_duration(Duration::from_secs(12))
        .with_exit_request(Arc::clone(&exits) as Arc<dyn ExitRequest>);
        let task = tokio::spawn(configure(loop_).run());
        let marker_key = format!("0x{}", hex::encode(pk.to_bytes()));
        DetectingLoop { machine, marker_key, exits, cancel, task }
    }

    /// Return the marker in `inspected`. Return `None` when `inspected` is
    /// not a valid marker.
    fn present_marker(
        inspected: crate::detection_marker::MarkerInspect,
    ) -> Option<crate::detection_marker::DetectionMarker> {
        match inspected {
            crate::detection_marker::MarkerInspect::Present(marker) => Some(marker),
            _ => None,
        }
    }

    /// An exit request that stores each exit code with two values that it
    /// reads at the request: the owned fallback marker and the durable flag.
    struct FallbackAtExit {
        machine: Arc<ForwardWindowMachine>,
        fallback: crate::detection_marker::FallbackMarkerPath,
        requests:
            std::sync::Mutex<Vec<(i32, Option<crate::detection_marker::DetectionMarker>, bool)>>,
    }

    impl ExitRequest for FallbackAtExit {
        fn request(&self, exit_code: i32) {
            let marker = crate::detection_marker::inspect_fallback(&self.fallback).owned;
            let durable = self.machine.detection_persisted();
            let mut requests = self.requests.lock().expect("The test must store the request.");
            requests.push((exit_code, present_marker(marker), durable));
        }
    }

    /// W4-D3c (746-10): the keystore directory is missing. The fallback
    /// directory exists. The loop detects the key on its first tick. The test
    /// sends no signal and starts no drain. The loop must request exit 12 one
    /// time. At that request, these conditions must be true:
    ///
    /// - The owned fallback marker contains the key, the epoch and the Unix
    ///   time that the loop got.
    /// - The machine has the durable flag.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn running_loop_writes_the_fallback_when_the_keystore_dir_fails() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let keys = root.path().join("keys");
        let db_dir = root.path().join("db");
        std::fs::create_dir(&db_dir).expect("The test must create the fallback directory.");
        let fallback = fallback_in(&db_dir);
        let _unix = crate::detection_marker::arm_unix_secs(LOOP_UNIX_SECS);
        let paths = crate::detection_marker::DetectionPaths {
            keystore_dir: keys,
            fallback: Some(fallback.clone()),
        };
        let live = spawn_detecting_loop(Some(paths), |machine| FallbackAtExit {
            machine: Arc::clone(machine),
            fallback: fallback.clone(),
            requests: std::sync::Mutex::default(),
        });
        poll_until_parked(&live.task).await;

        let marker = crate::detection_marker::DetectionMarker {
            epoch: LOOP_EPOCH,
            unix_secs: LOOP_UNIX_SECS,
            pubkeys: vec![live.marker_key.clone()],
        };
        assert_eq!(
            live.exits.requests.lock().expect("The test must read the requests.").as_slice(),
            [(EXIT_DOPPELGANGER_DETECTED, Some(marker), true)],
            "The loop must request exit 12 one time without a signal or a drain. At the request, \
             the owned fallback marker must contain the key, the epoch and the Unix time that \
             the loop got. The machine must have the durable flag at the request."
        );
        live.cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        live.task.await.expect("The loop task must not panic.");
    }

    /// W4-D3c (746-5): the test pre-allocates the record and sets no
    /// fallback path. Each keystore marker write returns an error. The test
    /// reads the error from the marker writer before the first tick. The
    /// test checks these conditions:
    ///
    /// - The log has one error line with the keystore marker path. The
    ///   `error` value of that line is the error of the writer, and the
    ///   `context` value is `liveness loop`. The line has the message
    ///   "failed to persist the doppelganger detection on this path".
    /// - The failure counter increases by exactly 1.
    /// - The record contains the epoch and the Unix time that the loop got.
    /// - The keystore marker is absent on the disk.
    /// - The loop requests exit 12 one time, because the record is durable.
    ///
    /// Then the test moves paused time by one slot. The next tick must not
    /// write again, and it must not request exit 12 again.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[tracing_test::traced_test]
    async fn loop_logs_and_counts_a_marker_failure_when_the_record_is_durable() {
        let keys = tempfile::tempdir().expect("The test must create the keystore directory.");
        crate::detection_marker::preallocate_detection_record(keys.path())
            .expect("The test must pre-allocate the record.");
        let _failures = marker_writes_fail(keys.path());
        let marker_path = crate::detection_marker::marker_path(keys.path());
        let marker_error = crate::detection_marker::write_marker(
            keys.path(),
            &crate::detection_marker::DetectionMarker {
                epoch: 0,
                unix_secs: 0,
                pubkeys: Vec::new(),
            },
        )
        .expect_err("The marker write must return the test error.")
        .to_string();
        let _unix = crate::detection_marker::arm_unix_secs(LOOP_UNIX_SECS);
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let paths = crate::detection_marker::DetectionPaths {
            keystore_dir: keys.path().to_path_buf(),
            fallback: None,
        };
        let live = spawn_detecting_loop(Some(paths), |_| RecordingExit::default());
        poll_until_parked(&live.task).await;

        let failures = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL
            .get()
            .saturating_sub(before);
        // `logs_assert` keeps only the lines with the scope of this test. The
        // loop logs in its detached `liveness_loop.tick` span, so the test
        // reads all of the captured log. The marker path is in a new
        // temporary directory, thus a line of a different test cannot match.
        let captured = tracing_test::internal::global_buf()
            .lock()
            .expect("The test must lock the captured log.")
            .clone();
        let logged: Vec<String> = String::from_utf8(captured)
            .expect("The captured log must be UTF-8.")
            .lines()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            path_errors(&logged, &marker_path),
            [marker_error],
            "The log must have one error line with the keystore marker path and the error of the \
             marker write. The log is {logged:#?}."
        );
        let marker_field = format!(" path={} error=", marker_path.display());
        assert_eq!(
            logged
                .iter()
                .filter(|line| line.contains(" ERROR ") && line.contains(&marker_field))
                .map(|line| line.contains("context=\"liveness loop\""))
                .collect::<Vec<_>>(),
            [true],
            "The error line of the keystore marker path must have the context of the liveness \
             loop. The log is {logged:#?}."
        );
        assert_eq!(
            logged
                .iter()
                .filter(|line| line.contains(" ERROR ") && line.contains(&marker_field))
                .map(|line| line.contains(&format!(": {REPORT_MESSAGE} ")))
                .collect::<Vec<_>>(),
            [true],
            "The error line of the keystore marker path must have the message \
             \"{REPORT_MESSAGE}\". The log is {logged:#?}."
        );
        assert_eq!(
            failures, 1,
            "The loop must increase the failure counter by exactly 1, for the failed keystore \
             marker. The counter increased by {failures}."
        );
        assert_eq!(
            crate::detection_marker::inspect_record(keys.path()),
            crate::detection_marker::RecordInspect::Detected {
                epoch: LOOP_EPOCH,
                unix_secs: LOOP_UNIX_SECS,
            },
            "The record must contain the epoch and the Unix time that the loop got."
        );
        let marker = crate::detection_marker::inspect(keys.path());
        assert!(
            matches!(marker, crate::detection_marker::MarkerInspect::Absent),
            "The keystore marker must be absent, because each marker write failed. The marker is \
             {marker:?}."
        );
        assert!(live.machine.detection_persisted(), "The record write must set the durable flag.");
        assert_eq!(
            live.exits.codes.lock().expect("The test must read the exit codes.").as_slice(),
            &[EXIT_DOPPELGANGER_DETECTED],
            "The loop must request exit 12 one time, because the record is durable."
        );

        tokio::time::advance(Duration::from_secs(12)).await;
        poll_until_parked(&live.task).await;
        let failures = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL
            .get()
            .saturating_sub(before);
        assert_eq!(
            failures, 1,
            "After a durable report, the next tick must not write again. The counter increased \
             by {failures}."
        );
        assert_eq!(
            live.exits.codes.lock().expect("The test must read the exit codes.").as_slice(),
            &[EXIT_DOPPELGANGER_DETECTED],
            "The next tick must not request exit 12 again."
        );
        live.cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        live.task.await.expect("The loop task must not panic.");
    }

    /// W4-D3c: the keystore directory is missing, and the test sets no
    /// fallback path. Because of this, the record write and the keystore
    /// marker write fail. The test checks these conditions:
    ///
    /// - The failure counter increases by exactly 2, one time for each
    ///   failed path. The loop adds no other count.
    /// - The durable flag stays clear, and the loop does not request exit 12.
    /// - The record and the keystore marker are missing on the disk.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn loop_counts_each_failed_path_once_when_no_path_is_durable() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let keys = root.path().join("keys");
        let paths =
            crate::detection_marker::DetectionPaths { keystore_dir: keys.clone(), fallback: None };
        let failures = failures_of_a_tick_with_no_durable_path(Some(paths)).await;
        assert_eq!(
            failures, 2,
            "The loop must increase the failure counter by exactly 2, one time for the record \
             and one time for the keystore marker. The counter increased by {failures}."
        );
        assert_eq!(
            crate::detection_marker::inspect_record(&keys),
            crate::detection_marker::RecordInspect::Absent,
            "The record must be absent, because the keystore directory does not exist."
        );
        let marker = crate::detection_marker::inspect(&keys);
        assert!(
            matches!(marker, crate::detection_marker::MarkerInspect::Absent),
            "The keystore marker must be absent, because the keystore directory does not exist. \
             The marker is {marker:?}."
        );
    }

    /// Spawn a loop from [`spawn_detecting_loop`] with `paths`, and let it
    /// run its first tick. No path can be durable. The loop must not set the
    /// durable flag and must not request exit 12. Return the increase of the
    /// failure counter.
    async fn failures_of_a_tick_with_no_durable_path(
        paths: Option<crate::detection_marker::DetectionPaths>,
    ) -> u64 {
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let live = spawn_detecting_loop(paths, |_| RecordingExit::default());
        poll_until_parked(&live.task).await;
        let failures = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL
            .get()
            .saturating_sub(before);
        assert!(
            !live.machine.detection_persisted(),
            "The loop must not set the durable flag, because no path is durable."
        );
        assert!(
            live.exits.codes.lock().expect("The test must read the exit codes.").is_empty(),
            "The loop must not request exit 12, because no path is durable."
        );
        live.cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        live.task.await.expect("The loop task must not panic.");
        failures
    }

    /// W4-D3c: the test gives no detection paths. As a result, the loop has
    /// no keystore directory and no fallback path. The test checks these
    /// conditions:
    ///
    /// - One tick increases the failure counter by exactly 1.
    /// - The log has one error line with the configuration reason.
    /// - The log has no line of `log_persist_report`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn loop_counts_one_failure_when_no_keystore_dir_is_configured() {
        let log = ThreadLog::default();
        let _log = log.capture();
        let failures = failures_of_a_tick_with_no_durable_path(None).await;
        assert_eq!(
            failures, 1,
            "The loop must increase the failure counter by exactly 1, because no keystore \
             directory is configured. The counter increased by {failures}."
        );
        let logged = log.lines();
        let errors: Vec<&String> = logged
            .iter()
            .filter(|line| {
                ["ERROR rvc::liveness_loop ", "ERROR rvc::detection_marker "]
                    .iter()
                    .any(|start| line.starts_with(start))
                    && !line.contains(DETECTED_MESSAGE)
            })
            .collect();
        assert_eq!(
            errors,
            [&format!("ERROR rvc::liveness_loop message={NO_PATHS_MESSAGE}")],
            "The loop must log one error line with the configuration reason. The log must have \
             no line of the report. The log is {logged:#?}."
        );
    }

    /// The message of the error line that the loop logs for each key when it
    /// sets the latch.
    const DETECTED_MESSAGE: &str =
        "message=doppelganger detected; refusing new signatures and requesting shutdown";

    /// The message of the error line of a loop with no detection paths.
    const NO_PATHS_MESSAGE: &str = "doppelganger detected but no data directory is configured \
                                    for the marker; staying up and refusing signatures until a \
                                    marker can be written";

    /// W4-D3c fix1: the loop has a fallback, and each of its three writes
    /// fails:
    ///
    /// - The record is missing.
    /// - A directory is at the keystore marker path.
    /// - A regular file is at the path of the fallback directory.
    ///
    /// The test checks these conditions:
    ///
    /// - The log has one error line for each path, in the write order. Each
    ///   line has the message of the report, the context `liveness loop`,
    ///   the path, and the error that the writer of that path gives.
    /// - The failure counter increases by exactly 3.
    /// - The durable flag stays clear, and the loop does not request exit 12.
    /// - Each path on the disk stays as the test made it. The record stays
    ///   absent. See [`assert_failed_paths_stay`].
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn loop_logs_and_counts_each_failed_path_when_the_fallback_fails() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let failing = failing_markers(root.path(), false);
        let paths = failing.paths.clone();
        let log = ThreadLog::default();
        let _log = log.capture();
        let failures = failures_of_a_tick_with_no_durable_path(Some(failing.paths)).await;
        assert_eq!(
            log.path_lines(),
            failing.lines,
            "The loop must log one error line for each failed path. Each line must have the \
             message of the report, the context of the liveness loop, the path and the error of \
             the writer. The log is {:#?}.",
            log.lines()
        );
        assert_eq!(
            failures, 3,
            "The loop must increase the failure counter by exactly 3, one time for each failed \
             path. The counter increased by {failures}."
        );
        assert_failed_paths_stay(&paths, false);
    }

    /// Check the disk after a tick with the paths of [`failing_markers`].
    /// Each failed write must keep its path as the test made it:
    ///
    /// - The keystore directory holds only the marker directory, and the
    ///   record when `record` is `true`. It holds no temporary file.
    /// - The directory at the keystore marker path is empty. The marker read
    ///   gives `Unreadable` with `InvalidData` for that path.
    /// - When `record` is `false`, the record read gives `Absent`.
    /// - The regular file at the path of the fallback directory is empty. The
    ///   read of the owned fallback marker gives `Unreadable` with
    ///   `NotADirectory`.
    fn assert_failed_paths_stay(paths: &crate::detection_marker::DetectionPaths, record: bool) {
        use crate::detection_marker::MarkerInspect;
        let keys = &paths.keystore_dir;
        let marker_path = crate::detection_marker::marker_path(keys);
        let mut made = vec![marker_path.clone()];
        if record {
            made.push(crate::detection_marker::record_path(keys));
        }
        made.sort();
        let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(keys)
            .expect("The test must read the keystore directory.")
            .map(|entry| entry.expect("The test must read each entry.").path())
            .collect();
        entries.sort();
        assert_eq!(
            entries, made,
            "The keystore directory must hold only the entries that the test made. It must hold \
             no temporary file of a failed write."
        );
        let in_marker_dir = std::fs::read_dir(&marker_path)
            .expect("The test must read the directory at the keystore marker path.")
            .count();
        assert_eq!(in_marker_dir, 0, "The directory at the keystore marker path must stay empty.");
        let marker = crate::detection_marker::inspect(keys);
        assert!(
            matches!(
                &marker,
                MarkerInspect::Unreadable { path, source }
                    if *path == marker_path && source.kind() == std::io::ErrorKind::InvalidData
            ),
            "The keystore marker read must give Unreadable with InvalidData, because a directory \
             is at the marker path. The result is {marker:?}."
        );
        if !record {
            assert_eq!(
                crate::detection_marker::inspect_record(keys),
                crate::detection_marker::RecordInspect::Absent,
                "The record must stay absent, because its write failed."
            );
        }
        let fallback = paths.fallback.as_ref().expect("The paths must have a fallback.");
        assert_eq!(
            std::fs::read(&fallback.dir).map_err(|err| err.kind()),
            Ok(Vec::new()),
            "The regular file at the path of the fallback directory must stay empty."
        );
        let owned = crate::detection_marker::inspect_fallback(fallback).owned;
        assert!(
            matches!(
                &owned,
                MarkerInspect::Unreadable { path, source }
                    if *path == fallback.owned_path()
                        && source.kind() == std::io::ErrorKind::NotADirectory
            ),
            "The owned fallback marker read must give Unreadable with NotADirectory, because a \
             regular file is at the path of its directory. The result is {owned:?}."
        );
    }

    /// W4-D3c fix1: the test pre-allocates the record and gives the loop a
    /// fallback. The two marker writes fail:
    ///
    /// - A directory is at the keystore marker path.
    /// - A regular file is at the path of the fallback directory.
    ///
    /// The test checks these conditions:
    ///
    /// - The log has one error line for each marker path, in the write
    ///   order. Each line has the message of the report, the context
    ///   `liveness loop`, the path, and the error that the writer of that
    ///   path gives.
    /// - The failure counter increases by exactly 2.
    /// - The record contains the epoch and the Unix time that the loop got.
    /// - The machine has the durable flag, and the loop requests exit 12 one
    ///   time.
    /// - Each marker path on the disk stays as the test made it. See
    ///   [`assert_failed_paths_stay`].
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn loop_logs_and_counts_both_marker_failures_when_the_record_is_durable() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let failing = failing_markers(root.path(), true);
        let paths = failing.paths.clone();
        let keys = paths.keystore_dir.clone();
        let _unix = crate::detection_marker::arm_unix_secs(LOOP_UNIX_SECS);
        let log = ThreadLog::default();
        let _log = log.capture();
        let before = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL.get();
        let live = spawn_detecting_loop(Some(failing.paths), |_| RecordingExit::default());
        poll_until_parked(&live.task).await;

        let failures = crate::metrics::RVC_DOPPELGANGER_MARKER_WRITE_FAILURES_TOTAL
            .get()
            .saturating_sub(before);
        assert_eq!(
            log.path_lines(),
            failing.lines,
            "The loop must log one error line for each failed marker path. Each line must have \
             the message of the report, the context of the liveness loop, the path and the error \
             of the writer. The log is {:#?}.",
            log.lines()
        );
        assert_eq!(
            failures, 2,
            "The loop must increase the failure counter by exactly 2, one time for each failed \
             marker. The counter increased by {failures}."
        );
        assert_eq!(
            crate::detection_marker::inspect_record(&keys),
            crate::detection_marker::RecordInspect::Detected {
                epoch: LOOP_EPOCH,
                unix_secs: LOOP_UNIX_SECS,
            },
            "The record must contain the epoch and the Unix time that the loop got."
        );
        assert_failed_paths_stay(&paths, true);
        assert!(live.machine.detection_persisted(), "The record write must set the durable flag.");
        assert_eq!(
            live.exits.codes.lock().expect("The test must read the exit codes.").as_slice(),
            &[EXIT_DOPPELGANGER_DETECTED],
            "The loop must request exit 12 one time, because the record is durable."
        );
        live.cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        live.task.await.expect("The loop task must not panic.");
    }

    /// W4-D3c fix1: `with_detection_marker_dir` replaces the paths of a
    /// previous call, and it removes the fallback of these paths. The test
    /// gives the loop paths with a fallback and a different keystore
    /// directory. Then it calls `with_detection_marker_dir` with the
    /// keystore directory `keys`. The fallback directory and `keys` exist.
    /// The test checks these conditions after the first tick:
    ///
    /// - The keystore marker in `keys` contains the key, the epoch and the
    ///   Unix time that the loop got.
    /// - The owned fallback marker is absent.
    /// - The loop requests exit 12 one time, because the keystore marker is
    ///   durable.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn with_detection_marker_dir_removes_the_fallback_of_a_previous_call() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let keys = root.path().join("keys");
        std::fs::create_dir(&keys).expect("The test must create the keystore directory.");
        let db_dir = root.path().join("db");
        std::fs::create_dir(&db_dir).expect("The test must create the fallback directory.");
        let fallback = fallback_in(&db_dir);
        let previous = crate::detection_marker::DetectionPaths {
            keystore_dir: root.path().join("previous-keys"),
            fallback: Some(fallback.clone()),
        };
        let _unix = crate::detection_marker::arm_unix_secs(LOOP_UNIX_SECS);
        let marker_dir = keys.clone();
        let live = spawn_configured_loop(
            |loop_| loop_.with_detection_paths(previous).with_detection_marker_dir(marker_dir),
            |_| RecordingExit::default(),
        );
        poll_until_parked(&live.task).await;

        let marker = crate::detection_marker::DetectionMarker {
            epoch: LOOP_EPOCH,
            unix_secs: LOOP_UNIX_SECS,
            pubkeys: vec![live.marker_key.clone()],
        };
        assert_eq!(
            present_marker(crate::detection_marker::inspect(&keys)),
            Some(marker),
            "The keystore marker in the directory of `with_detection_marker_dir` must contain the \
             key, the epoch and the Unix time that the loop got."
        );
        let owned = crate::detection_marker::inspect_fallback(&fallback).owned;
        assert!(
            matches!(owned, crate::detection_marker::MarkerInspect::Absent),
            "The owned fallback marker must be absent, because `with_detection_marker_dir` \
             removes the fallback of the previous call. The marker is {owned:?}."
        );
        assert_eq!(
            live.exits.codes.lock().expect("The test must read the exit codes.").as_slice(),
            &[EXIT_DOPPELGANGER_DETECTED],
            "The loop must request exit 12 one time, because the keystore marker is durable."
        );
        live.cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        live.task.await.expect("The loop task must not panic.");
    }

    /// Return each item of the Rust source `src` that can hold a fallback
    /// without its keystore directory. The scan reads each item of the
    /// file. It also reads the items in inner modules, in `impl` blocks, in
    /// traits and in function bodies. It skips each item with
    /// `#[cfg(test)]` and the items in it. It returns these items when
    /// their type names `FallbackMarkerPath`:
    ///
    /// - A parameter of a `fn`, of an `impl` method or of a trait method.
    /// - A field of a struct or of an enum variant.
    /// - A type alias or a `static`.
    fn fallback_holders(src: &str) -> Vec<String> {
        let file = syn::parse_file(src).expect("The source must be valid Rust.");
        let mut scan = FallbackHolders::default();
        syn::visit::Visit::visit_file(&mut scan, &file);
        scan.0
    }

    /// The items that [`fallback_holders`] finds, in the order of the source.
    #[derive(Default)]
    struct FallbackHolders(Vec<String>);

    impl FallbackHolders {
        /// Return `true` when `attrs` has `#[cfg(test)]`.
        fn in_tests(attrs: &[syn::Attribute]) -> bool {
            attrs.iter().any(|attr| {
                attr.path().is_ident("cfg")
                    && attr.parse_args::<syn::Ident>().is_ok_and(|arg| arg == "test")
            })
        }

        /// Return `true` when `ty` names `FallbackMarkerPath`.
        fn names_fallback(ty: &syn::Type) -> bool {
            struct Names(bool);
            impl<'ast> syn::visit::Visit<'ast> for Names {
                fn visit_ident(&mut self, ident: &'ast syn::Ident) {
                    self.0 |= ident == "FallbackMarkerPath";
                }
            }
            let mut names = Names(false);
            syn::visit::Visit::visit_type(&mut names, ty);
            names.0
        }

        /// Add each parameter of `sig` that names `FallbackMarkerPath`.
        fn params(&mut self, sig: &syn::Signature) {
            let names = sig.inputs.iter().filter_map(|input| match input {
                syn::FnArg::Typed(arg) if Self::names_fallback(&arg.ty) => Some(match &*arg.pat {
                    syn::Pat::Ident(pat) => pat.ident.to_string(),
                    _ => String::from("_"),
                }),
                _ => None,
            });
            self.0.extend(names.map(|name| format!("fn {} parameter {name}", sig.ident)));
        }

        /// Add each field of `owner` that names `FallbackMarkerPath`. A
        /// field with no name gets its index.
        fn fields(&mut self, owner: &str, fields: &syn::Fields) {
            for (index, field) in fields.iter().enumerate() {
                if Self::names_fallback(&field.ty) {
                    let name =
                        field.ident.as_ref().map_or_else(|| index.to_string(), ToString::to_string);
                    self.0.push(format!("{owner} field {name}"));
                }
            }
        }

        /// Add the item `label` when it is outside the tests and `ty` names
        /// `FallbackMarkerPath`.
        fn typed(&mut self, attrs: &[syn::Attribute], label: String, ty: &syn::Type) {
            if !Self::in_tests(attrs) && Self::names_fallback(ty) {
                self.0.push(label);
            }
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for FallbackHolders {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if !Self::in_tests(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            if !Self::in_tests(&item.attrs) {
                syn::visit::visit_item_impl(self, item);
            }
        }

        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            if !Self::in_tests(&item.attrs) {
                syn::visit::visit_item_trait(self, item);
            }
        }

        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if !Self::in_tests(&item.attrs) {
                self.params(&item.sig);
                syn::visit::visit_item_fn(self, item);
            }
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if !Self::in_tests(&item.attrs) {
                self.params(&item.sig);
                syn::visit::visit_impl_item_fn(self, item);
            }
        }

        fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
            if !Self::in_tests(&item.attrs) {
                self.params(&item.sig);
                syn::visit::visit_trait_item_fn(self, item);
            }
        }

        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            if !Self::in_tests(&item.attrs) {
                self.fields(&format!("struct {}", item.ident), &item.fields);
            }
        }

        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            if !Self::in_tests(&item.attrs) {
                for variant in &item.variants {
                    let owner = format!("enum {} variant {}", item.ident, variant.ident);
                    self.fields(&owner, &variant.fields);
                }
            }
        }

        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            self.typed(&item.attrs, format!("type {}", item.ident), &item.ty);
        }

        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            self.typed(&item.attrs, format!("static {}", item.ident), &item.ty);
        }
    }

    /// W4-D3c fix1: the owned fallback marker records its keystore directory
    /// as its owner. The loop must get the fallback only in `DetectionPaths`,
    /// with that keystore directory. The test reads the source of this file
    /// with [`fallback_holders`]. Outside the tests, no item can hold a
    /// fallback without its keystore directory. As a result, no caller can
    /// make a loop with a fallback and with no keystore directory.
    #[test]
    fn the_loop_gets_the_fallback_only_with_its_keystore_dir() {
        let holders = fallback_holders(include_str!("liveness_loop.rs"));
        assert_eq!(
            holders,
            Vec::<String>::new(),
            "The loop must get the fallback only in `DetectionPaths`, with its keystore \
             directory. These items can hold a fallback without its keystore directory: \
             {holders:?}."
        );
    }

    impl LivenessLoopSpawn {
        /// Latch the machine of the built loop with a live answer for its one
        /// pending key. Then run the loop with a clock seam at `epoch`, until
        /// the loop waits after its first tick. The enablement tests use it.
        pub(crate) async fn run_first_detecting_tick(self, epoch: Epoch) {
            let key = self.loop_task.machine.pending_keys().pop().expect("A key must be pending.");
            let live = ValidatorLivenessData { index: key.pubkey_hex, is_live: true };
            let answer = EpochLiveness { epoch: key.next_check_epoch, samples: Some(vec![live]) };
            let _ = self.loop_task.machine.apply_live_answers_only(&[answer]);
            let persister = self.persister().expect("The built loop must have a persister.");
            let task = tokio::spawn(self.loop_task.with_clock_seam(ClockSeam::new(epoch, 0)).run());
            wait_for_rounds(&persister, 1).await;
            assert!(!task.is_finished(), "The loop must not stop after its first tick.");
        }
    }

    /// The real-time limit of a wait for a blocking write. It is hang
    /// protection only: each caller asserts its condition after the wait.
    const WAIT_LIMIT: Duration = Duration::from_secs(10);

    /// Yield until `done` returns `true`, for at most [`WAIT_LIMIT`] of real
    /// time. Paused time does not move: a yield is not an idle runtime.
    async fn wait_until(mut done: impl FnMut() -> bool) {
        let started = std::time::Instant::now();
        while !done() && started.elapsed() < WAIT_LIMIT {
            tokio::task::yield_now().await;
        }
    }

    /// Wait until each configured path of `persister` has the result of
    /// `rounds` rounds, then assert it. On a current-thread runtime, the task
    /// of the last round has then reached its next await: the retry sleep of
    /// the drain or the slot sleep of the loop.
    async fn wait_for_rounds(
        persister: &crate::detection_marker::DetectionPersister,
        rounds: usize,
    ) {
        use crate::detection_marker::PersistPath;
        let fallback = persister.paths().fallback.is_some();
        let done = || {
            [PersistPath::Record, PersistPath::KeystoreMarker]
                .into_iter()
                .chain(fallback.then_some(PersistPath::FallbackMarker))
                .all(|path| persister.finished(path) >= rounds)
        };
        wait_until(done).await;
        assert!(
            done(),
            "Each path must have the result of {rounds} rounds. The persister started {} rounds.",
            persister.rounds()
        );
    }

    /// Arm the directory faults `faults` for `dir`. They reach the threads of
    /// the blocking pool.
    fn dir_faults(
        dir: &std::path::Path,
        faults: crate::detection_marker::DirFaults,
    ) -> crate::detection_marker::DirFaultGuard {
        crate::detection_marker::arm_dir_faults(dir, faults)
    }

    /// Each marker write in `dir` fails until the guard drops.
    fn marker_writes_fail(dir: &std::path::Path) -> crate::detection_marker::DirFaultGuard {
        let faults =
            crate::detection_marker::DirFaults { marker_write_fails: true, ..Default::default() };
        dir_faults(dir, faults)
    }

    /// Each fsync in `dir` fails until the guard drops.
    fn fsyncs_fail(dir: &std::path::Path) -> crate::detection_marker::DirFaultGuard {
        dir_faults(
            dir,
            crate::detection_marker::DirFaults { fsync_fails: true, ..Default::default() },
        )
    }

    /// A latched machine and a persister whose keystore directory hangs in
    /// each fsync. The record is pre-allocated in `keystore`. The owned
    /// fallback marker is in its own directory and has no fault.
    struct HungKeystore {
        machine: Arc<ForwardWindowMachine>,
        persister: Arc<crate::detection_marker::DetectionPersister>,
        keystore: std::path::PathBuf,
        fallback: crate::detection_marker::FallbackMarkerPath,
        _faults: crate::detection_marker::DirFaultGuard,
    }

    /// Make the directories `keystore` and `fallback` in `root`, latch a
    /// machine for `detected`, and hold each fsync in `keystore` in `gate`.
    fn hung_keystore_fixture(
        root: &std::path::Path,
        detected: &crypto::PublicKey,
        gate: Arc<crate::detection_marker::FsyncGate>,
    ) -> HungKeystore {
        let keystore = root.join("keystore");
        let db_dir = root.join("fallback");
        for dir in [&keystore, &db_dir] {
            std::fs::create_dir(dir).expect("The test must create the directory.");
        }
        crate::detection_marker::preallocate_detection_record(&keystore)
            .expect("The test must pre-allocate the record.");
        let fallback = fallback_in(&db_dir);
        let paths = crate::detection_marker::DetectionPaths {
            keystore_dir: keystore.clone(),
            fallback: Some(fallback.clone()),
        };
        let faults =
            crate::detection_marker::DirFaults { fsync_gate: Some(gate), ..Default::default() };
        HungKeystore {
            machine: latched_machine_for(detected),
            persister: crate::detection_marker::DetectionPersister::new(paths),
            _faults: dir_faults(&keystore, faults),
            keystore,
            fallback,
        }
    }

    /// Wait until the fallback write of `persister` has its result, then move
    /// paused time by the persist timeout. Paused time cannot move before:
    /// the parked keystore writes stop the auto-advance.
    async fn advance_after_fallback(persister: &crate::detection_marker::DetectionPersister) {
        use crate::detection_marker::PersistPath;
        wait_until(|| persister.finished(PersistPath::FallbackMarker) == 1).await;
        tokio::time::advance(crate::detection_marker::DETECTION_PERSIST_TIMEOUT).await;
    }

    /// Open `gate` and wait until the keystore writes of `persister` end.
    /// Return `true` when both ended.
    async fn release_keystore_writes(
        gate: &crate::detection_marker::FsyncGate,
        persister: &crate::detection_marker::DetectionPersister,
    ) -> bool {
        use crate::detection_marker::PersistPath;
        gate.open();
        let ended = || {
            !persister.in_flight(PersistPath::Record)
                && !persister.in_flight(PersistPath::KeystoreMarker)
        };
        wait_until(ended).await;
        ended()
    }

    /// The line of [`ThreadLog`] for a timed-out path of the drain.
    fn drain_timed_out_line(
        kind: crate::detection_marker::PersistPath,
        path: &std::path::Path,
    ) -> String {
        format!(
            "ERROR rvc::detection_marker message={REPORT_MESSAGE} context=shutdown drain \
             kind={kind:?} path={} error={}",
            path.display(),
            crate::detection_marker::PersistError::TimedOut
        )
    }

    /// W4-D3d2 (746-10): each fsync in the keystore directory hangs. The
    /// drain writes the three paths off the runtime. The test requires these
    /// results:
    ///
    /// - The fallback write returns before paused time moves.
    /// - 1 ns before the persist timeout, the drain still waits. At the
    ///   timeout, it returns exit 12.
    /// - The owned fallback marker holds the latched key.
    /// - The drain logs `TimedOut` for the record and the keystore marker.
    /// - The two keystore writes still wait in the gate, and the watchdog of
    ///   the gate did not fire.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn hung_keystore_path_still_reaches_the_fallback() {
        use crate::detection_marker::PersistPath;
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let gate = crate::detection_marker::FsyncGate::with_watchdog(WAIT_LIMIT);
        let hung = hung_keystore_fixture(root.path(), &new_pk(), Arc::clone(&gate));
        let log = ThreadLog::default();
        let _log = log.capture();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection = crate::bootstrap::DetectionShutdown {
            machine: Arc::clone(&hung.machine),
            persister: Arc::clone(&hung.persister),
            epoch_clock: test_clock(),
        };
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_until(|| hung.persister.finished(PersistPath::FallbackMarker) == 1).await;
        let deadline = Duration::from_secs(5);
        tokio::time::advance(deadline - Duration::from_nanos(1)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let pending = !drain.is_finished();
        tokio::time::advance(Duration::from_nanos(1)).await;
        let (_outcome, res) = join_in_paused_time(drain).await;
        let parked = (gate.blocked(), gate.watchdog_fired());
        let released = release_keystore_writes(&gate, &hung.persister).await;

        assert!(
            pending,
            "The drain must still wait 1 ns before the persist timeout, after the fallback write \
             returned."
        );
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain must return exit 12 after the fallback write. The result is {res:?}."
        );
        assert_eq!(
            parked,
            (2, false),
            "The two keystore writes must still wait in the gate when the drain returns, and the \
             watchdog must not have opened the gate."
        );
        assert!(released, "The two keystore writes must end after the gate opens.");
        let fallback =
            present_marker(crate::detection_marker::inspect_fallback(&hung.fallback).owned);
        assert_eq!(
            fallback.map(|marker| marker.pubkeys),
            Some(hung.machine.detected_hexes().iter().map(|key| format!("0x{key}")).collect()),
            "The owned fallback marker must hold the latched key."
        );
        assert_eq!(
            log.path_lines(),
            [
                drain_timed_out_line(
                    PersistPath::Record,
                    &crate::detection_marker::record_path(&hung.keystore)
                ),
                drain_timed_out_line(
                    PersistPath::KeystoreMarker,
                    &crate::detection_marker::marker_path(&hung.keystore)
                ),
            ],
            "The drain must log TimedOut for the record and the keystore marker. The log is {:#?}.",
            log.lines()
        );
    }

    /// W4-D3d2: each fsync in the keystore directory hangs while the running
    /// loop writes the detection. The loop must write the fallback off the
    /// runtime and request exit 12 one time, with the fallback marker present
    /// and the durable flag set at the request. The keystore writes must still
    /// wait in the gate, and the watchdog must not fire.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn running_loop_reaches_the_fallback_while_the_keystore_hangs() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let gate = crate::detection_marker::FsyncGate::with_watchdog(WAIT_LIMIT);
        let hung = hung_keystore_fixture(root.path(), &new_pk(), Arc::clone(&gate));
        let persister = Arc::clone(&hung.persister);
        let fallback = hung.fallback.clone();
        let live = spawn_configured_loop(
            |loop_| loop_.with_detection_persister(persister),
            |machine| FallbackAtExit {
                machine: Arc::clone(machine),
                fallback,
                requests: std::sync::Mutex::default(),
            },
        );
        advance_after_fallback(&hung.persister).await;
        let requests =
            || live.exits.requests.lock().expect("The test must read the requests.").len();
        wait_until(|| requests() == 1).await;
        let parked = (gate.blocked(), gate.watchdog_fired());
        let released = release_keystore_writes(&gate, &hung.persister).await;

        let requests =
            live.exits.requests.lock().expect("The test must read the requests.").clone();
        assert_eq!(
            requests
                .into_iter()
                .map(|(code, marker, durable)| (code, marker.is_some(), durable))
                .collect::<Vec<_>>(),
            [(EXIT_DOPPELGANGER_DETECTED, true, true)],
            "The loop must request exit 12 one time, with the fallback marker present and the \
             durable flag set."
        );
        assert_eq!(
            parked,
            (2, false),
            "The two keystore writes must still wait in the gate at the request, and the watchdog \
             must not have opened the gate."
        );
        assert!(released, "The two keystore writes must end after the gate opens.");
        live.cancel.cancel();
        tokio::time::advance(Duration::from_secs(12)).await;
        live.task.await.expect("The loop task must not panic.");
    }

    /// Register one live key with the index "1" on `machine`. Build the loop
    /// with `prepare_liveness_loop` for `keys`, `fallback` and `tracked`, take
    /// the detection state of the drain with `drain_detection`, and spawn the
    /// loop with `spawn_liveness_loop`, as `run_with_clock` does. Return that
    /// detection state.
    fn boot_wired_loop(
        machine: &Arc<ForwardWindowMachine>,
        keys: &std::path::Path,
        fallback: Option<crate::detection_marker::FallbackMarkerPath>,
        tracked: Arc<TrackedKeys>,
        executor: &TaskExecutor,
    ) -> crate::bootstrap::DetectionShutdown {
        let pk = new_pk();
        machine.register(&pk, 0);
        let reg = PubkeyIndexRegistry::shared();
        reg.write().insert(pk.to_bytes(), "1".to_string());
        let pubkey_map: PubkeyMap =
            Arc::new(parking_lot::RwLock::new(HashMap::from([(pk.to_bytes(), pk)])));
        let paths =
            crate::detection_marker::DetectionPaths { keystore_dir: keys.to_path_buf(), fallback };
        let prepared = prepare_liveness_loop(
            Some(Arc::clone(machine)),
            counted_liveness(true).0,
            reg,
            Some(pubkey_map),
            test_clock(),
            executor,
            Some((paths, tracked)),
        );
        let config = crate::config::Config {
            keystore_path: keys.to_path_buf(),
            slashing_db_path: keys.join("slashing.sqlite"),
            ..Default::default()
        };
        let detection = crate::bootstrap::drain_detection(
            prepared.as_ref(),
            Some(Arc::clone(machine)),
            &config,
            &test_clock(),
        );
        if let Some(prepared) = prepared {
            spawn_liveness_loop(prepared, executor);
        }
        detection.expect("A machine must give the drain its detection state.")
    }

    /// W4-D3d2 (fix round 1, F4): the boot-wired loop leaves both keystore
    /// writes parked, and the executor drain aborts it after the Orchestrator
    /// budget. The test requires these results:
    ///
    /// - The executor drain aborts the loop task.
    /// - The first drain round gives `TimedOut` at once for both parked paths
    ///   and starts no second write: two writes still wait in the gate.
    /// - After the gate opens, the late successes of the loop writes make the
    ///   next round durable with no new write, and the drain returns exit 12.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn boot_wired_drain_starts_no_second_write_on_a_parked_loop_path() {
        use crate::detection_marker::PersistPath;
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let keys = root.path().join("keystore");
        std::fs::create_dir(&keys).expect("The test must create the keystore directory.");
        crate::detection_marker::preallocate_detection_record(&keys)
            .expect("The test must pre-allocate the record.");
        let gate = crate::detection_marker::FsyncGate::with_watchdog(WAIT_LIMIT);
        let faults = crate::detection_marker::DirFaults {
            fsync_gate: Some(Arc::clone(&gate)),
            ..Default::default()
        };
        let _faults = dir_faults(&keys, faults);
        let machine = machine();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection =
            boot_wired_loop(&machine, &keys, None, Arc::new(TrackedKeys::new()), &executor);
        let persister = Arc::clone(&detection.persister);
        wait_until(|| gate.blocked() == 2).await;
        let cancelled = token.clone();
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_until(|| cancelled.is_cancelled()).await;
        tokio::time::advance(Duration::from_secs(3)).await;
        wait_until(|| persister.rounds() == 2 || gate.blocked() > 2).await;
        let spawned = || {
            (persister.spawned(PersistPath::Record), persister.spawned(PersistPath::KeystoreMarker))
        };
        assert_eq!(
            (persister.rounds(), gate.blocked(), spawned(), machine.detection_persisted()),
            (2, 2, (1, 1), false),
            "The first drain round must time out at once on the two paths that the loop left \
             parked, start no second write, and not be durable."
        );
        let released = release_keystore_writes(&gate, &persister).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let (outcome, res) = join_in_paused_time(drain).await;
        assert!(
            released && outcome.aborted.contains(&"liveness_loop"),
            "The executor drain must abort the loop task, and the parked writes must end after \
             the gate opens. The drain aborted {:?}.",
            outcome.aborted
        );
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The late successes must make the drain return exit 12. The result is {res:?}."
        );
        assert_eq!(
            (spawned(), gate.watchdog_fired()),
            ((1, 1), false),
            "The drain must not write a path again after its late success."
        );
    }

    /// W4-D3d2 (fix round 1, F1): a sidecar is in the keystore directory, and
    /// a thread holds `TrackedKeys` until a gate opens. A sidecar cleanup
    /// would wait for that lock on the runtime thread. The boot-wired loop
    /// detects its key, and the fallback marker is writable. The drain must
    /// return exit 12 while the lock is still held, with the sidecar kept.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn boot_wired_loop_exits_12_while_tracked_keys_is_held() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let keys = root.path().join("keystore");
        let db_dir = root.path().join("fallback");
        for dir in [&keys, &db_dir] {
            std::fs::create_dir(dir).expect("The test must create the directory.");
        }
        let sidecar = keys.join(format!("0x{}.import_meta.json", hex::encode([0x44; 48])));
        std::fs::write(&sidecar, "{\"imported_unix_seconds\":1}")
            .expect("The test must write the sidecar.");
        let tracked = Arc::new(TrackedKeys::new());
        let gate = crate::detection_marker::FsyncGate::with_watchdog(WAIT_LIMIT);
        let holder = {
            let (tracked, gate) = (Arc::clone(&tracked), Arc::clone(&gate));
            std::thread::spawn(move || {
                let _held = tracked.lock();
                gate.wait_open(|| {});
            })
        };
        wait_until(|| gate.blocked() == 1).await;
        let machine = machine();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection =
            boot_wired_loop(&machine, &keys, Some(fallback_in(&db_dir)), tracked, &executor);
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::pending(),
            )
            .await
        });
        let (_outcome, res) = join_in_paused_time(drain).await;
        let held = (gate.blocked(), gate.watchdog_fired());
        gate.open();
        holder.join().expect("The lock holder must not panic.");

        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "The drain must return exit 12. The result is {res:?}."
        );
        assert_eq!(
            held,
            (1, false),
            "The drain must return while the thread still holds TrackedKeys, before the watchdog \
             opens the gate."
        );
        assert!(sidecar.exists(), "The latched loop must keep the sidecar.");
    }

    /// W4-D3d2 (fix round 1, F2): a result that is not exit 12 drops the
    /// keystore lock guard, so a second lock attempt succeeds. The production
    /// boot test checks that exit 12 keeps the lock.
    #[test]
    fn a_result_that_is_not_exit_12_releases_the_keystore_lock() {
        let dir = tempfile::tempdir().expect("The test must create a temporary directory.");
        let guard = crate::startup::acquire_keystore_lock(dir.path())
            .expect("The test must take the keystore lock.");
        crate::bootstrap::keep_keystore_lock_on_detection(&Ok(()), Some(guard));
        assert!(
            crate::startup::acquire_keystore_lock(dir.path()).is_ok(),
            "A result that is not exit 12 must drop the keystore lock guard."
        );
    }

    /// W4-D3d2 (fix round 1, F3): all three writes of drain round 1 park and
    /// time out. Then the fallback write ends with `Ok`, and each later
    /// fallback write fails. The late success must make the next round
    /// durable with no new fallback write, so the drain returns exit 12 while
    /// the keystore writes still wait.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn late_fallback_success_after_a_timeout_makes_the_drain_exit_12() {
        use crate::detection_marker::PersistPath;
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let gate = crate::detection_marker::FsyncGate::with_watchdog(WAIT_LIMIT);
        let hung = hung_keystore_fixture(root.path(), &new_pk(), Arc::clone(&gate));
        let fallback_gate = crate::detection_marker::FsyncGate::with_watchdog(WAIT_LIMIT);
        let faults = crate::detection_marker::DirFaults {
            fsync_gate: Some(Arc::clone(&fallback_gate)),
            ..Default::default()
        };
        let fallback_faults = dir_faults(&hung.fallback.dir, faults);
        let log = ThreadLog::default();
        let _log = log.capture();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let detection = crate::bootstrap::DetectionShutdown {
            machine: Arc::clone(&hung.machine),
            persister: Arc::clone(&hung.persister),
            epoch_clock: test_clock(),
        };
        let drain = tokio::spawn(async move {
            crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            )
            .await
        });
        wait_until(|| gate.blocked() == 2 && fallback_gate.blocked() == 1).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        wait_until(|| log.path_lines().len() == 3).await;
        drop(fallback_faults);
        wait_until(|| !hung.persister.in_flight(PersistPath::FallbackMarker)).await;
        let _later_writes_fail = marker_writes_fail(&hung.fallback.dir);
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_until(|| drain.is_finished()).await;
        let finished = (drain.is_finished(), gate.blocked());
        let released = release_keystore_writes(&gate, &hung.persister).await;

        assert_eq!(
            finished,
            (true, 2),
            "The drain must return while the keystore writes still wait. The first round logged \
             {:#?}.",
            log.path_lines()
        );
        let (_outcome, res) = drain.await.expect("The drain task must not panic.");
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)) && released,
            "The late fallback success must make the drain return exit 12. The result is {res:?}."
        );
        let fallback =
            present_marker(crate::detection_marker::inspect_fallback(&hung.fallback).owned);
        assert_eq!(
            (hung.persister.spawned(PersistPath::FallbackMarker), fallback.is_some()),
            (1, true),
            "The first fallback write must be on the disk, and the drain must not write the \
             fallback again."
        );
    }

    /// The fixed secret key, the validator index and the password of the
    /// production boot test.
    const BOOT_KEY: [u8; 32] = [0x2d; 32];
    const BOOT_INDEX: &str = "9";
    const BOOT_PASSWORD: &str = "w4d3d2-boot";

    /// Mount a beacon node on `server` that serves `pubkey` with
    /// [`BOOT_INDEX`] at the genesis `genesis_time`, and that answers each
    /// liveness request with "live".
    async fn mount_live_beacon_node(server: &wiremock::MockServer, pubkey: &str, genesis: u64) {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let far = "18446744073709551615";
        let spec = serde_json::json!({
            "GENESIS_FORK_VERSION": "0x00000000", "ALTAIR_FORK_EPOCH": "0",
            "ALTAIR_FORK_VERSION": "0x01000000", "BELLATRIX_FORK_EPOCH": "0",
            "BELLATRIX_FORK_VERSION": "0x02000000", "CAPELLA_FORK_EPOCH": "0",
            "CAPELLA_FORK_VERSION": "0x03000000", "DENEB_FORK_EPOCH": "0",
            "DENEB_FORK_VERSION": "0x04000000", "ELECTRA_FORK_EPOCH": "0",
            "ELECTRA_FORK_VERSION": "0x05000000", "FULU_FORK_EPOCH": far,
            "FULU_FORK_VERSION": "0x06000000", "GLOAS_FORK_EPOCH": far,
            "GLOAS_FORK_VERSION": "0x07000000", "SECONDS_PER_SLOT": "12", "SLOTS_PER_EPOCH": "32"
        });
        let validator = serde_json::json!({ "data": [{
            "index": BOOT_INDEX, "status": "active_ongoing", "validator": { "pubkey": pubkey }
        }] });
        let gets = [
            ("/eth/v1/config/spec", serde_json::json!({ "data": spec })),
            (
                "/eth/v1/beacon/genesis",
                serde_json::json!({ "data": { "genesis_time": genesis.to_string(),
                    "genesis_validators_root": format!("0x{}", "11".repeat(32)),
                    "genesis_fork_version": "0x00000000" } }),
            ),
            (
                "/eth/v1/beacon/states/head/fork",
                serde_json::json!({ "execution_optimistic": false, "finalized": false,
                    "data": { "previous_version": "0x04000000",
                    "current_version": "0x05000000", "epoch": "0" } }),
            ),
            (
                "/eth/v1/node/syncing",
                serde_json::json!({ "data": { "head_slot": "100000", "sync_distance": "0",
                    "is_syncing": false, "is_optimistic": false, "el_offline": false } }),
            ),
            (
                "/eth/v2/node/version",
                serde_json::json!({ "data": { "beacon_node": { "code": "MK", "name": "mock-bn",
                    "version": "w4d3d2", "commit": "00" } } }),
            ),
            ("/eth/v1/beacon/states/head/validators", validator.clone()),
        ];
        for (route, body) in gets {
            let reply = ResponseTemplate::new(200).set_body_json(body);
            Mock::given(method("GET")).and(path(route)).respond_with(reply).mount(server).await;
        }
        let posts = [
            (r"^/eth/v1/beacon/states/head/validators$", validator),
            (
                r"^/eth/v1/validator/liveness/\d+$",
                serde_json::json!({ "data": [{ "index": BOOT_INDEX, "is_live": true }] }),
            ),
            (
                r"^/eth/v1/validator/duties/(attester|sync)/\d+$",
                serde_json::json!({ "dependent_root": format!("0x{}", "22".repeat(32)),
                    "execution_optimistic": false, "data": [] }),
            ),
        ];
        for (route, body) in posts {
            let reply = ResponseTemplate::new(200).set_body_json(body);
            Mock::given(method("POST"))
                .and(path_regex(route))
                .respond_with(reply)
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path_regex(r"^/eth/v1/validator/duties/proposer/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": format!("0x{}", "22".repeat(32)),
                "execution_optimistic": false, "data": []
            })))
            .mount(server)
            .await;
    }

    /// W4-D3d2 fix round 2 (F2, F3): the production `bootstrap::run` with
    /// detection and keystore locking on. The beacon node answers "live" for
    /// the one key. The record write and the keystore marker write of each
    /// round wait in a gate (before the marker rename), and each fallback
    /// write fails until the test removes that fault. The test cancels the
    /// process token while the writes of the loop wait. It requires these
    /// results:
    ///
    /// - The first drain round starts no second keystore write: two writes
    ///   still wait in the gate after it logged its three failed paths.
    /// - After the fallback fault ends, `run` returns exit 12.
    /// - After `run` returns, a second keystore lock attempt (as
    ///   `clear-detection` makes it) fails while the marker write still waits.
    #[tokio::test(flavor = "current_thread")]
    async fn production_boot_keeps_the_lock_and_starts_no_second_write_on_exit_12() {
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let (keys, db_dir) = (root.path().join("keys"), root.path().join("db"));
        for dir in [&keys, &db_dir] {
            std::fs::create_dir(dir).expect("The test must create the directory.");
        }
        let secret = crypto::SecretKey::from_bytes(&BOOT_KEY).expect("The key must be valid.");
        let pubkey = format!("0x{}", hex::encode(secret.public_key().to_bytes()));
        let keystore = crypto::Keystore::encrypt(
            &secret,
            BOOT_PASSWORD.as_bytes(),
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .and_then(|keystore| keystore.to_json())
        .expect("The test must encrypt the keystore.");
        std::fs::write(keys.join(format!("keystore-{pubkey}.json")), keystore)
            .expect("The test must write the keystore.");
        let password_file = root.path().join("password.txt");
        std::fs::write(&password_file, format!("*={BOOT_PASSWORD}\n"))
            .expect("The test must write the password file.");
        let validators = root.path().join("validators.toml");
        std::fs::write(
            &validators,
            format!(
                "[defaults]\nfee_recipient = \"0x{}\"\n\n[[validators]]\npubkey = \"{pubkey}\"\n",
                "11".repeat(20)
            ),
        )
        .expect("The test must write the validator file.");
        let genesis = crate::detection_marker::unix_secs_now() - 3_600;
        let server = wiremock::MockServer::start().await;
        mount_live_beacon_node(&server, &pubkey, genesis).await;
        let gate = crate::detection_marker::FsyncGate::with_watchdog(Duration::from_secs(60));
        let faults = crate::detection_marker::DirFaults {
            keystore_writes_gate: Some(Arc::clone(&gate)),
            ..Default::default()
        };
        let _keystore_faults = dir_faults(&keys, faults);
        let fallback_faults = marker_writes_fail(&db_dir);
        let config = crate::config::Config {
            beacon_url: server.uri(),
            beacon_nodes: vec![server.uri()],
            network: crate::config::Network::Custom,
            genesis_time: Some(genesis),
            genesis_validators_root: Some(format!("0x{}", "11".repeat(32))),
            keystore_path: keys.clone(),
            password_file: Some(password_file),
            slashing_db_path: db_dir.join("slashing.sqlite"),
            allow_fresh_db: true,
            doppelganger_detection: true,
            metrics_port: 0,
            validators_config: Some(validators),
            ..Default::default()
        };
        let options = crate::bootstrap::RunOptions {
            strict_permissions: false,
            strict_slashing_semantics: false,
            timeouts: bn_manager::OperationTimeouts::default(),
        };
        let log = ThreadLog::default();
        let _log = log.capture();
        let token = CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let run = tokio::spawn(crate::bootstrap::run(config, options, executor, shutdown_rx));
        let drain_lines = || {
            log.path_lines().iter().filter(|line| line.contains("context=shutdown drain")).count()
        };
        let boot_limit = std::time::Instant::now();
        while gate.blocked() < 2 && !run.is_finished() && boot_limit.elapsed() < CHILD_WATCHDOG {
            tokio::task::yield_now().await;
        }
        if run.is_finished() {
            panic!("run must not stop before the drain. The result is {:?}.", run.await);
        }
        assert_eq!(gate.blocked(), 2, "The loop must park its two keystore writes after boot.");
        token.cancel();
        wait_until(|| drain_lines() >= 3).await;
        let first_round = (drain_lines(), gate.blocked());
        drop(fallback_faults);
        wait_until(|| run.is_finished()).await;
        let finished = run.is_finished();
        let second = crate::startup::acquire_keystore_lock(&keys).map(drop);
        let parked = gate.blocked();
        gate.open();

        assert_eq!(
            first_round,
            (3, 2),
            "The first drain round must log its three failed paths and start no second write on \
             the two keystore paths that the loop left parked."
        );
        assert!(finished, "run must return after the fallback fault ends.");
        let res = run.await.expect("The run task must not panic.");
        assert!(
            matches!(res, Err(crate::bootstrap::BootstrapError::DoppelgangerDetected)),
            "run must return exit 12. The result is {res:?}."
        );
        assert!(
            second.is_err() && parked == 2 && !gate.watchdog_fired(),
            "After run returns, a second keystore lock attempt must fail while the marker write \
             still waits. The attempt gave {second:?}, and {parked} writes waited."
        );
    }

    /// The name of the environment variable that gives the child process of
    /// [`hung_keystore_write_still_exits_12_in_a_child_process`] its root
    /// directory. The parent owns that directory.
    const DETECTION_EXIT_CHILD_ROOT: &str = "RVC_TEST_DETECTION_EXIT_CHILD_ROOT";

    /// The real-time limit of the parent for the child process. It is hang
    /// protection only.
    const CHILD_WATCHDOG: Duration = Duration::from_secs(30);

    /// The secret key bytes of the latched key, the signer key and the
    /// imported key of the child process.
    const CHILD_KEYS: [u8; 3] = [0x11, 0x22, 0x33];

    /// The slot and the signing root of the block that the child process
    /// signs.
    const CHILD_SIGN: (u64, Root) = (21, [0x5a; 32]);

    /// The stdout line of a child process whose parked work still waits after
    /// the runtime shut down: the two keystore fsyncs, the sign and the
    /// import.
    const CHILD_LINE: &str = "detection-exit-child: blocked_fsyncs=2 blocked_holds=2";

    fn child_key(index: usize) -> crypto::SecretKey {
        crypto::SecretKey::from_bytes(&[CHILD_KEYS[index]; 32])
            .expect("The child key bytes must be a valid secret key.")
    }

    /// A signing backend that waits in `0` until it opens.
    struct ParkedSigner(Arc<crate::detection_marker::FsyncGate>);

    #[async_trait::async_trait]
    impl crypto::Signer for ParkedSigner {
        async fn sign(
            &self,
            _signing_root: &Root,
            _pubkey: &[u8; 48],
        ) -> Result<crypto::Signature, crypto::SigningError> {
            self.0.wait_open(|| {});
            Err(crypto::SigningError::RemoteSignerError("the test gate opened".to_string()))
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            Vec::new()
        }
    }

    /// Start a slashable block sign of [`CHILD_SIGN`] with the signer key
    /// and the slashing database `db_path`. The sign commits its reservation,
    /// then its backend waits in `gate`.
    fn park_slashable_sign(
        db_path: &std::path::Path,
        gate: &Arc<crate::detection_marker::FsyncGate>,
    ) -> tokio::task::JoinHandle<Result<Vec<u8>, signer::SigningGateError>> {
        let db = Arc::new(SlashingDb::open(db_path).expect("The test must open the database."));
        db.set_genesis_validators_root(&gvr()).expect("The test must pin the root.");
        let backend: Arc<dyn crypto::Signer> = Arc::new(ParkedSigner(Arc::clone(gate)));
        let pubkey = child_key(1).public_key();
        tokio::spawn(async move {
            let locks = signer::ValidatorLockMap::new();
            signer::sign_slashable(signer::SignSlashableRequest {
                locks: &locks,
                pubkey: &pubkey,
                enablement: signer::always_enabled(),
                signer: backend,
                signing_root: CHILD_SIGN.1,
                sign_timeout: CHILD_WATCHDOG,
                policy: signer::TimeoutPolicySource::Fixed(signer::TimeoutPolicy::DiscardStagedRow),
                hooks: Arc::new(signer::NoopSignHooks),
                op_name: "hung_keystore_exit_child",
                slashing_db: db,
                client_cn: "local-vc".to_string(),
                gvr: gvr(),
                kind: signer::SlashableKind::Block { slot: CHILD_SIGN.0 },
                fork_name: None,
                pre_reserve_barrier: None,
            })
            .await
        })
    }

    /// Start a windowed keystore import of the imported key into `keys`, with
    /// the validator file `validators`. The import persists the disabled hold,
    /// then waits in `gate` before it publishes the keystore.
    fn park_windowed_import(
        keys: &std::path::Path,
        validators: &std::path::Path,
        gate: &Arc<crate::detection_marker::FsyncGate>,
    ) -> tokio::task::JoinHandle<Result<[u8; 48], keymanager_api::traits::ImportKeystoreError>>
    {
        use keymanager_api::traits::KeystoreManager;
        let sk = child_key(2);
        let pk_hex = format!("0x{}", hex::encode(sk.public_key().to_bytes()));
        std::fs::create_dir(keys).expect("The test must create the import directory.");
        std::fs::write(
            validators,
            format!(
                "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\n\
                 gas_limit = 30000000\n\n[[validators]]\npubkey = \"{pk_hex}\"\nenabled = true\n"
            ),
        )
        .expect("The test must write the validator file.");
        let store = Arc::new(
            validator_store::ValidatorStore::load_from_config(validators)
                .expect("The test must load the validator file."),
        );
        let composite = Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(
            crypto::KeyManager::new(),
        )));
        let pubkey_map: PubkeyMap = Arc::default();
        let (key_gen, _key_gen_rx) = tokio::sync::watch::channel(0u64);
        let denylist = Arc::new(crate::deletion_denylist::DeletionDenylist::empty_at(
            keys.join(".rvc.deleted_keys"),
        ));
        let admissions = Arc::new(crate::key_admission::KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen.clone(),
            Arc::clone(&composite),
            store,
            denylist,
            None,
            test_clock(),
        ));
        let adapter = crate::keymanager_adapters::KeystoreManagerAdapter::new(
            keys.to_path_buf(),
            composite,
            pubkey_map,
            key_gen,
        )
        .with_admission_service(admissions);
        adapter.set_doppelganger_window(CHILD_WATCHDOG);
        let parked = Arc::clone(gate);
        adapter.set_before_admit_hook(Arc::new(move || parked.wait_open(|| {})));
        let json = crypto::Keystore::encrypt(
            &sk,
            b"testpass",
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .and_then(|keystore| keystore.to_json())
        .expect("The test must encrypt the keystore.");
        tokio::spawn(async move { adapter.import_keystore(&json, "testpass").await })
    }

    /// The child process of
    /// [`hung_keystore_write_still_exits_12_in_a_child_process`]. Without
    /// [`DETECTION_EXIT_CHILD_ROOT`] it returns at once.
    ///
    /// The child parks a slashable sign after its reservation and a windowed
    /// import after its disabled hold. Then it runs the real drain while each
    /// fsync in the keystore directory waits in a gate that never opens. It
    /// shuts its runtime down with the helper of `main`, prints the parked
    /// counts, and exits with the status that `main` maps from the result.
    #[test]
    #[ignore = "child of hung_keystore_write_still_exits_12_in_a_child_process"]
    fn hung_keystore_exit_child() {
        let Some(root) = std::env::var_os(DETECTION_EXIT_CHILD_ROOT) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("The child must build its runtime.");
        let fsyncs = crate::detection_marker::FsyncGate::without_watchdog();
        let holds = crate::detection_marker::FsyncGate::without_watchdog();
        let hung = hung_keystore_fixture(&root, &child_key(0).public_key(), Arc::clone(&fsyncs));
        let res = crate::startup::block_on_then_shutdown(runtime, async {
            let _sign = park_slashable_sign(&hung.fallback.slashing_db_path, &holds);
            let _import =
                park_windowed_import(&root.join("import"), &root.join("validators.toml"), &holds);
            wait_until(|| holds.blocked() == 2).await;
            let token = CancellationToken::new();
            let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
            let detection = crate::bootstrap::DetectionShutdown {
                machine: Arc::clone(&hung.machine),
                persister: Arc::clone(&hung.persister),
                epoch_clock: test_clock(),
            };
            let drain = crate::bootstrap::await_shutdown_and_drain_with_signal(
                drain_inputs(executor, shutdown_rx, token, Some(detection)),
                std::future::ready(()),
            );
            tokio::join!(drain, advance_after_fallback(&hung.persister)).0 .1
        });
        println!(
            "detection-exit-child: blocked_fsyncs={} blocked_holds={}",
            fsyncs.blocked(),
            holds.blocked()
        );
        std::io::Write::flush(&mut std::io::stdout()).expect("The child must flush stdout.");
        std::process::exit(res.err().map_or(0, |err| err.named_exit_code().unwrap_or(1)));
    }

    /// Kills and reaps the child process on drop, also when an assertion
    /// fails.
    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// W4-D3d2 (746-10): the child process runs the real drain with each
    /// fsync in its keystore directory blocked by a gate that never opens,
    /// and a sign and an import parked. It exits through
    /// `startup::block_on_then_shutdown` and the exit mapping of `main`. The
    /// parent requires these results:
    ///
    /// - The exit status is exactly 12.
    /// - Stdout has [`CHILD_LINE`]: the parked work still waited after the
    ///   runtime shut down.
    /// - The owned fallback marker holds the latched key. The keystore marker
    ///   is absent, and its temporary file is left.
    /// - After the exit, the slashing database still has the reservation of
    ///   the parked sign, and the validator file still has the disabled hold
    ///   of the parked import. The keystore of the import is not published.
    #[test]
    fn hung_keystore_write_still_exits_12_in_a_child_process() {
        use std::io::Read;
        let root = tempfile::tempdir().expect("The test must create a temporary directory.");
        let name = module_path!().split_once("::").map_or(module_path!(), |(_, path)| path);
        let mut child = ChildGuard(
            std::process::Command::new(std::env::current_exe().expect("The test binary path."))
                .args([&format!("{name}::hung_keystore_exit_child"), "--exact", "--ignored"])
                .arg("--nocapture")
                .env(DETECTION_EXIT_CHILD_ROOT, root.path())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("The test must start the child process."),
        );
        let mut stdout = child.0.stdout.take().expect("The child must have a stdout pipe.");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            let read = stdout.read_to_string(&mut text);
            let _ = sender.send(read.map(|_| text));
        });
        let finished = receiver.recv_timeout(CHILD_WATCHDOG);
        if finished.is_err() {
            let _ = child.0.kill();
        }
        let status = child.0.wait().ok().and_then(|status| status.code());
        let stdout = finished.or_else(|_| receiver.recv_timeout(CHILD_WATCHDOG));
        let stdout = stdout.ok().and_then(Result::ok).unwrap_or_default();

        assert_eq!(
            status,
            Some(EXIT_DOPPELGANGER_DETECTED),
            "The child must exit with status 12 within {CHILD_WATCHDOG:?}. Its stdout is \
             {stdout:?}."
        );
        assert!(
            stdout.lines().any(|line| line == CHILD_LINE),
            "The child must print {CHILD_LINE:?}. Its stdout is {stdout:?}."
        );
        let fallback = fallback_in(&root.path().join("fallback"));
        let marker = present_marker(crate::detection_marker::inspect_fallback(&fallback).owned);
        let latched = format!("0x{}", hex::encode(child_key(0).public_key().to_bytes()));
        assert_eq!(
            marker.map(|marker| marker.pubkeys),
            Some(vec![latched]),
            "The owned fallback marker must hold the latched key."
        );
        let keystore = root.path().join("keystore");
        let temps: Vec<String> = std::fs::read_dir(&keystore)
            .expect("The test must read the keystore directory.")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.starts_with(".rvc.doppelganger_tmp.") && name.ends_with(".tmp"))
            .collect();
        let inspected = crate::detection_marker::inspect(&keystore);
        assert!(
            matches!(inspected, crate::detection_marker::MarkerInspect::Absent) && temps.len() == 1,
            "The keystore marker write must not reach its rename: the marker must be absent and \
             one temporary file must be left. The marker is {inspected:?}, and the temporary \
             files are {temps:?}."
        );

        let db = SlashingDb::open(&fallback.slashing_db_path)
            .expect("The restart must open the slashing database.");
        let signer_key = hex::encode(child_key(1).public_key().to_bytes());
        let blocks = db.get_blocks(&signer_key).expect("The restart must read the blocks.");
        assert_eq!(
            blocks
                .iter()
                .map(|block| (block.slot, block.signing_root.is_some()))
                .collect::<Vec<_>>(),
            [(CHILD_SIGN.0, true)],
            "After the restart, the slashing database must still have the reservation that the \
             sign committed before its backend call. The blocks are {blocks:?}."
        );
        let store =
            validator_store::ValidatorStore::load_from_config(&root.path().join("validators.toml"))
                .expect("The restart must load the validator file.");
        let imported = child_key(2).public_key().to_bytes();
        let hold = store.get_config(&imported).and_then(|config| config.doppelganger_hold_until);
        let mut staged: Vec<String> = std::fs::read_dir(root.path().join("import"))
            .expect("The test must read the import directory.")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.ends_with(".json") || name.ends_with(".json.partial"))
            .collect();
        staged.sort();
        let key = format!("0x{}", hex::encode(imported));
        let partials = [format!("{key}.import_meta.json.partial"), format!("{key}.json.partial")];
        assert!(
            !store.is_signing_enabled(&imported) && hold.is_some() && staged == partials,
            "After the restart, the imported key must stay disabled with its hold, and its \
             keystore must stay staged as `.partial`. The hold is {hold:?}, and the keystore \
             files are {staged:?}."
        );
        let clean = tempfile::tempdir().expect("The test must create a clean keystore.");
        let restart = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("The test must build a runtime.");
        let err = restart.block_on(boot_refusing(clean.path(), Some(fallback.slashing_db_path)));
        assert_eq!(
            err.exit_code(),
            EXIT_DOPPELGANGER_DETECTED,
            "A restart with this slashing database must refuse with exit 12, because of its \
             fallback marker. The error is {err}."
        );
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
        latched_machine_for(&new_pk())
    }

    /// A machine whose latch is set for `pk`.
    fn latched_machine_for(pk: &crypto::PublicKey) -> Arc<ForwardWindowMachine> {
        let m = machine();
        m.register(pk, 0);
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

    /// The limit for a drain task in paused Tokio time. It does not use the
    /// wall clock.
    const PAUSED_DRAIN_LIMIT: Duration = Duration::from_secs(30);

    /// Wait until `task` finishes. Use this only in a test with paused time.
    /// The join handle is the completion signal. The limit is
    /// [`PAUSED_DRAIN_LIMIT`] of paused time, which goes forward only while
    /// the runtime has no task that can run.
    async fn join_in_paused_time<T>(task: tokio::task::JoinHandle<T>) -> T {
        let joined = tokio::time::timeout(PAUSED_DRAIN_LIMIT, task).await;
        assert!(
            joined.is_ok(),
            "The drain task must finish within {PAUSED_DRAIN_LIMIT:?} of paused time."
        );
        joined.ok().and_then(Result::ok).expect("The drain task must not panic.")
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
        fallback: Option<crate::detection_marker::FallbackMarkerPath>,
        epoch_clock: Arc<MonotonicEpochClock>,
    ) -> crate::bootstrap::DetectionShutdown {
        let paths = crate::detection_marker::DetectionPaths { keystore_dir, fallback };
        let persister = crate::detection_marker::DetectionPersister::new(paths);
        crate::bootstrap::DetectionShutdown { machine, persister, epoch_clock }
    }

    /// Return the fallback path for `slashing.sqlite` in `dir`.
    fn fallback_in(dir: &std::path::Path) -> crate::detection_marker::FallbackMarkerPath {
        crate::detection_marker::FallbackMarkerPath {
            dir: dir.to_path_buf(),
            slashing_db_path: dir.join("slashing.sqlite"),
        }
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

    /// The machine, the loop task, the executor, its shutdown receiver, the
    /// process token and the clock of [`spawn_live_loop`].
    type LiveLoop = (
        Arc<ForwardWindowMachine>,
        tokio::task::JoinHandle<()>,
        TaskExecutor,
        tokio::sync::mpsc::Receiver<crate::bootstrap::executor::ShutdownReason>,
        CancellationToken,
        Arc<MonotonicEpochClock>,
    );

    /// Spawn a liveness loop that gets a live answer for its key. The loop
    /// writes the record and the marker in `marker_dir`.
    fn spawn_live_loop(marker_dir: &std::path::Path) -> LiveLoop {
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
        .with_detection_marker_dir(marker_dir.to_path_buf())
        .with_exit_request(Arc::new(executor.shutdown_handle()) as Arc<dyn ExitRequest>);
        let task = tokio::spawn(loop_.run());
        (m, task, executor, shutdown_rx, token, clock)
    }

    async fn latched_loop_with_failing_marker(missing: &std::path::Path) -> LiveLoop {
        let (m, task, executor, shutdown_rx, token, clock) = spawn_live_loop(missing);
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
        poll_until_parked(&task).await;
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
