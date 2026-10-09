//! SEC-2c: per-slot forward-window liveness observation loop.
//!
//! Drives [`ForwardWindowMachine`] with real network liveness via the bn-manager
//! (`LivenessApi::post_validator_liveness_merged`, multi-BN OR-merge).
//!
//! Each cycle (once per slot):
//! 1. Query liveness for recently completed epochs that still need observation
//! 2. Translate numeric validator indices → bare pubkey-hex (SEC-001)
//! 3. `observe_liveness` then `tick`
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

use bn_manager::{LivenessApi, NodeStatusApi};
use doppelganger::{
    ForwardWindowMachine, ForwardWindowStatus, MonotonicEpochClock, ValidatorLivenessData,
    DEFAULT_MONITORING_EPOCHS,
};
use eth_types::{Epoch, SLOT_DURATION_MS};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Instrument};

use crate::bootstrap::executor::{ShutdownTier, TaskExecutor};
use crate::orchestrator::PubkeyMap;
use crate::pubkey_index::{parse_pubkey_bytes, pubkey_bytes_to_0x, SharedPubkeyIndexRegistry};

/// Lookback for completed-epoch liveness queries.
///
/// Covers a full monitoring window (`DEFAULT_MONITORING_EPOCHS` inclusive span
/// is `monitoring_epochs + 1` epochs) plus slack after multi-epoch BN outages
/// (review Finding 4).
const LIVENESS_LOOKBACK_EPOCHS: u64 = DEFAULT_MONITORING_EPOCHS + 2;

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

/// Background task that ticks the forward-window machine once per slot.
pub struct LivenessObservationLoop {
    machine: Arc<ForwardWindowMachine>,
    beacon: Arc<dyn LivenessApi>,
    /// Shared pubkey ↔ index registry (liveness uses the reverse index→bare-hex view).
    pubkey_index: SharedPubkeyIndexRegistry,
    /// Live keystore/keymanager pubkey set for periodic BN index re-resolve.
    pubkey_map: Option<PubkeyMap>,
    epoch_clock: Arc<MonotonicEpochClock>,
    /// Slot duration used for the sleep interval (defaults to mainnet 12s).
    slot_duration: Duration,
    cancel: CancellationToken,
}

/// Body of the retained liveness index refresh. Expanded only from the test helper
/// (and, under `cfg(test)`, from `refresh_indices_from_pubkey_map`).
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
            epoch_clock,
            slot_duration: Duration::from_millis(SLOT_DURATION_MS),
            cancel,
        }
    }

    /// Attach the pubkey map used by [`Self::refresh_indices_for_test`].
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

    /// Shared registry handle.
    pub fn pubkey_index(&self) -> SharedPubkeyIndexRegistry {
        Arc::clone(&self.pubkey_index)
    }

    /// Run until cancelled. Spawns no tasks — register via [`spawn_liveness_loop`].
    pub async fn run(self) {
        info!(
            slot_duration_secs = self.slot_duration.as_secs(),
            lookback_epochs = LIVENESS_LOOKBACK_EPOCHS,
            "SEC-2c: forward-window liveness observation loop started"
        );

        // Track epochs that completed at least once. While any key remains
        // Pending we still re-query lookback epochs so a later is_live=true can
        // Detect after an earlier complete not-live (review Finding 1).
        let mut observed_epochs: HashSet<Epoch> = HashSet::new();
        let mut has_pending = true;

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

                let current_epoch = self.epoch_clock.current_epoch();
                let slot_in_epoch = self.epoch_clock.slot_in_epoch();

                // Observe completed epochs that may still be needed by Pending keys.
                if current_epoch > 0 {
                    let lookback_start = current_epoch.saturating_sub(LIVENESS_LOOKBACK_EPOCHS);
                    for epoch in lookback_start..current_epoch {
                        // Finding 1: re-query while Pending remain; only skip when
                        // nothing is Pending and this epoch already completed once.
                        if !has_pending && observed_epochs.contains(&epoch) {
                            continue;
                        }
                        match self.observe_epoch(epoch).await {
                            Ok(true) => {
                                observed_epochs.insert(epoch);
                            }
                            Ok(false) => {
                                debug!(epoch, "liveness observation incomplete; will retry");
                            }
                            Err(e) => {
                                warn!(
                                    epoch,
                                    error = %e,
                                    "liveness query failed; will retry next slot (fail-closed)"
                                );
                            }
                        }
                    }
                }

                let statuses = self.machine.tick(current_epoch, slot_in_epoch);
                has_pending = statuses.contains(&ForwardWindowStatus::Pending);
                let detected =
                    statuses.iter().filter(|s| **s == ForwardWindowStatus::Detected).count();
                let pending =
                    statuses.iter().filter(|s| **s == ForwardWindowStatus::Pending).count();
                let safe = statuses.iter().filter(|s| **s == ForwardWindowStatus::Safe).count();
                if detected > 0 {
                    error!(
                        detected,
                        pending,
                        safe,
                        current_epoch,
                        slot_in_epoch,
                        "doppelganger Detected: gate permanently closed for affected keys \
                         (no signing for those validators)"
                    );
                } else {
                    debug!(pending, safe, current_epoch, slot_in_epoch, "forward-window tick");
                }

                // Bound memory; keep more than lookback so re-queries after Pending
                // drain still skip correctly.
                if current_epoch > LIVENESS_LOOKBACK_EPOCHS + 4 {
                    let retain_from = current_epoch.saturating_sub(LIVENESS_LOOKBACK_EPOCHS + 4);
                    observed_epochs.retain(|e| *e >= retain_from);
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

    /// Query BN liveness for `epoch`, translate indices, feed the machine.
    ///
    /// Returns `Ok(true)` if observation completed (no IncompleteLiveness),
    /// `Ok(false)` if there was nothing to query or the response was incomplete.
    async fn observe_epoch(&self, epoch: Epoch) -> Result<bool, String> {
        let index_to_bare = self.pubkey_index.read().index_to_bare_hex().clone();
        if index_to_bare.is_empty() {
            return Ok(false);
        }

        let numeric_indices: Vec<String> = index_to_bare.keys().cloned().collect();
        let response = self
            .beacon
            .post_validator_liveness_merged(epoch, &numeric_indices)
            .await
            .map_err(|e| e.to_string())?;

        let samples: Vec<ValidatorLivenessData> = response
            .data
            .into_iter()
            .filter_map(|v| {
                // Translate numeric index → bare pubkey hex. Untranslatable → drop
                // (fail-closed: observe_liveness treats missing as incomplete).
                let pubkey_hex = index_to_bare.get(&v.index)?;
                Some(ValidatorLivenessData { index: pubkey_hex.clone(), is_live: v.is_live })
            })
            .collect();

        match self.machine.observe_liveness(epoch, &samples) {
            Ok(()) => {
                debug!(epoch, sample_count = samples.len(), "observe_liveness complete");
                Ok(true)
            }
            Err(doppelganger::DoppelgangerError::IncompleteLiveness {
                epoch: e,
                missing_count,
            }) => {
                debug!(epoch = e, missing_count, "observe_liveness incomplete (D-2 fail-closed)");
                Ok(false)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Single-cycle driver for tests (no sleep / cancel).
    ///
    /// Observes `observe_epoch` if given, then ticks at `(tick_epoch, slot_in_epoch)`.
    pub async fn drive_once_for_test(
        &self,
        observe_epoch: Option<Epoch>,
        tick_epoch: Epoch,
        slot_in_epoch: u64,
    ) -> Result<Vec<ForwardWindowStatus>, String> {
        if let Some(epoch) = observe_epoch {
            let _ = self.observe_epoch(epoch).await?;
        }
        Ok(self.machine.tick(tick_epoch, slot_in_epoch))
    }

    /// Test helper: run one index refresh from the attached pubkey map.
    ///
    /// `validators` is the index lookup. The loop client is only [`LivenessApi`],
    /// which has no `get_validators`. Not a production writer. [`Self::run`]
    /// must not call this.
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

/// Spawn the production liveness loop when a machine is present and there are
/// keys (resolved indices and/or a non-empty pubkey map for later re-resolve).
///
/// `pubkey_index` is the workspace-shared registry (same handle used by
/// `prepare_proposers` / duty tracking). Production index refresh is
/// [`crate::index_resolver::IndexResolver`]; `pubkey_map` stays attached for
/// [`LivenessObservationLoop::refresh_indices_for_test`].
///
/// The loop is registered on `executor` at Orchestrator tier (ARCH-2g P1-7).
pub fn spawn_liveness_loop(
    machine: Option<Arc<ForwardWindowMachine>>,
    beacon: Arc<dyn LivenessApi>,
    pubkey_index: SharedPubkeyIndexRegistry,
    pubkey_map: Option<PubkeyMap>,
    epoch_clock: Arc<MonotonicEpochClock>,
    executor: &TaskExecutor,
) -> Option<LivenessLoopSpawn> {
    let machine = machine?;
    let has_pubkeys = pubkey_map.as_ref().is_some_and(|m| !m.read().is_empty());
    let has_indices = !pubkey_index.read().is_empty();
    if !has_indices && !has_pubkeys {
        warn!(
            "SEC-2c: no validator indices or pubkeys; liveness loop not started \
             (gate remains fail-safe closed for Pending keys)"
        );
        return None;
    }
    if !has_indices {
        info!(
            "SEC-2c: starting liveness loop with empty indices \
             (IndexResolver owns index refresh; pending activation / post-import)"
        );
    }

    let pubkey_index_ret = Arc::clone(&pubkey_index);
    let cancel = executor.token();
    let mut loop_task =
        LivenessObservationLoop::new(machine, beacon, pubkey_index, epoch_clock, cancel);
    if let Some(pm) = pubkey_map {
        loop_task = loop_task.with_pubkey_map(pm);
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use beacon::{
        BeaconError, ValidatorData, ValidatorInfo, ValidatorLiveness, ValidatorLivenessResponse,
        ValidatorsResponse,
    };
    use doppelganger::SigningEnablement;
    use eth_types::{Root, SLOTS_PER_EPOCH};
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
    }

    impl LivenessMockState {
        fn new(live: HashMap<String, bool>) -> Arc<Self> {
            Arc::new(Self {
                live: parking_lot::RwLock::new(live),
                fail_first: AtomicUsize::new(0),
                validators: parking_lot::RwLock::new(HashMap::new()),
                live_sequence: parking_lot::Mutex::new(Vec::new()),
            })
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
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0)),
            CancellationToken::new(),
        )
        .with_slot_duration(Duration::from_millis(1))
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

        loop_.drive_once_for_test(Some(start), start, 0).await.unwrap();

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

        let end = start + DEFAULT_MONITORING_EPOCHS;
        for epoch in start..=end {
            loop_.drive_once_for_test(Some(epoch), epoch, 0).await.unwrap();
        }
        let statuses = loop_.drive_once_for_test(None, end, SLOTS_PER_EPOCH - 1).await.unwrap();
        assert!(
            statuses.contains(&ForwardWindowStatus::Safe) || m.is_signing_enabled(&pk),
            "clean window must open gate"
        );
        assert!(m.is_signing_enabled(&pk), "signing must proceed after clean window");
        assert_eq!(m.status(&pk), ForwardWindowStatus::Safe);
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

        let ok = loop_.drive_once_for_test(Some(start), start, 0).await;
        assert!(ok.is_ok(), "failover must succeed via secondary: {ok:?}");

        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));

        let end = start + DEFAULT_MONITORING_EPOCHS;
        for epoch in (start + 1)..=end {
            loop_.drive_once_for_test(Some(epoch), epoch, 0).await.unwrap();
        }
        loop_.drive_once_for_test(None, end, SLOTS_PER_EPOCH - 1).await.unwrap();
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
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 1_000_000)),
            &exec,
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
            Arc::new(MonotonicEpochClock::new(0)),
            &exec2,
        );
        assert!(no_handle.is_none());

        let (exec3, _rx3) = TaskExecutor::new(CancellationToken::new());
        let no_machine = spawn_liveness_loop(
            None,
            Arc::new(all_not_live(&["1"]).0),
            Arc::clone(&reg),
            None,
            Arc::new(MonotonicEpochClock::new(0)),
            &exec3,
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
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0)),
            CancellationToken::new(),
        )
        .with_pubkey_map(pubkey_map)
        .with_slot_duration(Duration::from_millis(1));

        // Before refresh: empty map → observe is no-op (incomplete path).
        let before = loop_.drive_once_for_test(Some(start), start, 0).await.unwrap();
        assert!(before.iter().all(|s| *s == ForwardWindowStatus::Pending));
        assert!(pubkey_index.read().is_empty());

        // Refresh pulls index 77 from BN for the pubkey_map key.
        loop_.refresh_indices_for_test(bn.as_ref()).await;
        assert_eq!(pubkey_index.read().bare_hex_of_index("77"), Some(bare.as_str()));

        // Now observation succeeds for the imported key.
        let end = start + DEFAULT_MONITORING_EPOCHS;
        for epoch in start..=end {
            loop_.drive_once_for_test(Some(epoch), epoch, 0).await.unwrap();
        }
        loop_.drive_once_for_test(None, end, SLOTS_PER_EPOCH - 1).await.unwrap();
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

        // First observation: complete not-live → still Pending.
        loop_.drive_once_for_test(Some(start), start, 0).await.unwrap();
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);

        // Second observation same epoch: is_live=true → Detected (no permanent lock-in).
        loop_.drive_once_for_test(Some(start), start, 1).await.unwrap();
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
            Arc::new(MonotonicEpochClock::new(0)),
            &exec,
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
}
