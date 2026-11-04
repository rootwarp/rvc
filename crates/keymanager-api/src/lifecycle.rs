//! Doppelganger import/delete lifecycle owning the KM-2 concurrency invariant.
//!
//! # KM-2 / SF-3
//!
//! A concurrent delete + re-import must never leave a stale background enable
//! task alive that later flips `enabled = true` (or clears monitoring) on a key
//! that is inside a fresh doppelganger window.  That invariant is enforced only
//! inside this type — handlers call [`DoppelgangerLifecycle::on_import`] /
//! [`DoppelgangerLifecycle::on_delete`] and do not touch cancel tokens or the
//! state lock directly.
//!
//! # Lock-ordering invariant
//!
//! `state_lock` is the OUTERMOST doppelganger-state lock.  The paths below
//! follow: acquire `state_lock` first, then (if needed) `cancel_tokens` — never
//! the reverse — to avoid deadlock.
//!
//! - `cancel_tokens` is ALWAYS taken while holding `state_lock` on any path that
//!   mutates doppelganger state.
//! - `state_lock` is NEVER held across an `.await`; every guarded section is
//!   synchronous (the spawned enable task acquires it AFTER its `sleep_until`
//!   future resolves).
//!
//! The protected paths take the locks in that order:
//! - **import** ([`Self::on_import`]): holds the lock across `add_validator`
//!   (Local only) + `start_monitoring` + cancel-token insert (PRD §KM-2 (a)+(b)).
//! - **arming**: `spawn_enable_task` is the only place that inserts a cancel
//!   token and spawns the enable task. Import, the boot re-arm
//!   ([`DoppelgangerLifecycle::rearm_persisted_hold`]) and an early wake call it
//!   under the lock.
//! - **disable** ([`Self::disable_for_delete`]): holds `state_lock` across
//!   cancel-token remove/cancel, then `set_validator_enabled(false)`. The token
//!   is cancelled even when the write fails. No `.await`.
//! - **delete** ([`Self::on_delete`]): holds the lock across the caller's remove
//!   operation + unconditional cancel-token remove/cancel, and on success across
//!   `remove_validator` (Local) + `cancel_monitoring` (PRD §KM-2 (b)+(Finding 3)).
//! - **spawned enable task** (timer branch): acquires the lock after
//!   `sleep_until` resolves, re-checks `is_cancelled()` under the lock before
//!   enabling, then holds it across `set_validator_enabled` (Local) +
//!   `stop_monitoring` + cancel-token self-prune (PRD §KM-2 (c)+(Finding 1+2)).

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use observability::logging::TruncatedPubkey;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::traits::{DoppelgangerMonitor, Pubkey, QuiesceError, SigningQuiesce, ValidatorManager};

/// Whether [`DoppelgangerLifecycle::on_delete`] should update the validators file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigTouch {
    /// Keystore delete succeeded, or the keystore was already gone. Drop the row.
    Apply { keystore_present: bool },
    /// Keystore delete failed. Leave the validators row alone.
    Skip,
}

/// Result of the validators-file half of a delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigRemoval {
    /// [`ConfigTouch::Skip`], or a remote delete that does not own the row.
    NotAttempted,
    /// The row was removed.
    Removed,
    /// No row was present.
    Absent,
    /// The write failed. The live row is unchanged.
    Failed(String),
}

/// How long DELETE waits for the slashable per-pubkey lock.
///
/// Longer than the signer's default sign timeout so a signature that already
/// passed the under-lock enablement check can reserve and finish. A timeout
/// is [`QuiesceError::DrainTimedOut`] and fails the DELETE.
pub const DEFAULT_DELETE_QUIESCE_TIMEOUT: Duration = Duration::from_secs(8);

/// Drain used when no VC [`SigningQuiesce`] is installed.
///
/// Handler tests that build [`DoppelgangerLifecycle`] directly keep the old
/// export-then-delete behaviour. Production replaces this before serving.
struct NoopSigningQuiesce;

#[async_trait::async_trait]
impl SigningQuiesce for NoopSigningQuiesce {
    async fn quiesce(&self, _pubkey: &Pubkey, _timeout: Duration) -> Result<(), QuiesceError> {
        Ok(())
    }
}

/// Whether an import registers with [`ValidatorManager`].
///
/// Local keystore imports add the validator as disabled and flip it enabled
/// when the window elapses.  Remote (Web3Signer) imports only join the
/// enablement / monitoring gate — the remote key manager owns registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    Local,
    Remote,
}

thread_local! {
    /// This thread already holds [`DoppelgangerLifecycle::state_lock`].
    /// A disable hook invoked from under that lock must not lock it again.
    static STATE_LOCK_HELD: Cell<bool> = const { Cell::new(false) };
}

struct StateLockGuard<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl Drop for StateLockGuard<'_> {
    fn drop(&mut self) {
        STATE_LOCK_HELD.with(|held| held.set(false));
    }
}

/// Owns the per-key doppelganger window, cancel-token map, and KM-2 state lock.
pub struct DoppelgangerLifecycle {
    window: Duration,
    cancel_tokens: Mutex<HashMap<Pubkey, CancellationToken>>,
    /// See module-level lock-ordering docs.
    state_lock: Mutex<()>,
    monitor: Arc<dyn DoppelgangerMonitor>,
    validator_manager: Arc<dyn ValidatorManager>,
    signing_quiesce: Arc<dyn SigningQuiesce>,
    quiesce_timeout: Duration,
    /// Runs after the hold check and before the enable write. Must not take
    /// `state_lock`. Test builds only.
    #[cfg(test)]
    before_enable_write: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl DoppelgangerLifecycle {
    /// Create a lifecycle bound to `monitor` and `validator_manager`.
    ///
    /// `window` must match the window configured in `monitor`.
    /// `Duration::ZERO` disables the hold (keys enable immediately).
    pub fn new(
        window: Duration,
        monitor: Arc<dyn DoppelgangerMonitor>,
        validator_manager: Arc<dyn ValidatorManager>,
    ) -> Self {
        Self {
            window,
            cancel_tokens: Mutex::new(HashMap::new()),
            state_lock: Mutex::new(()),
            monitor,
            validator_manager,
            signing_quiesce: Arc::new(NoopSigningQuiesce),
            quiesce_timeout: DEFAULT_DELETE_QUIESCE_TIMEOUT,
            #[cfg(test)]
            before_enable_write: Mutex::new(None),
        }
    }

    /// Park between the enable task's hold check and its store write.
    ///
    /// The hook must not acquire `state_lock`. `None` clears it.
    #[cfg(test)]
    pub fn set_before_enable_write_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.before_enable_write.lock().expect("before_enable_write poisoned") = hook;
    }

    #[cfg(test)]
    fn fire_before_enable_write(&self) {
        let hook = self.before_enable_write.lock().expect("before_enable_write poisoned").clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Replace the no-op drain. `timeout` bounds [`Self::quiesce_for_delete`].
    #[must_use]
    pub fn with_signing_quiesce(
        mut self,
        quiesce: Arc<dyn SigningQuiesce>,
        timeout: Duration,
    ) -> Self {
        self.signing_quiesce = quiesce;
        self.quiesce_timeout = timeout;
        self
    }

    /// Disable `pubkey` and cancel a pending doppelganger enable task.
    ///
    /// The enable task is the path that would set `enabled` back to true.
    /// Cancelling it here, before the drain, means a failed delete is not
    /// undone by a window that elapses during export. Does not remove the
    /// validator; [`Self::on_delete`] still owns removal.
    fn lock_state(&self) -> StateLockGuard<'_> {
        let guard = self.state_lock.lock().expect("doppelganger state_lock poisoned");
        STATE_LOCK_HELD.with(|held| held.set(true));
        StateLockGuard { _guard: guard }
    }

    fn cancel_enable_token(&self, pubkey: &Pubkey) {
        if let Some(token) =
            self.cancel_tokens.lock().expect("cancel_tokens poisoned").remove(pubkey)
        {
            token.cancel();
        }
    }

    pub fn disable_for_delete(&self, pubkey: &Pubkey) -> Result<(), String> {
        let _guard = self.lock_state();
        // Cancel first. A failed write must not leave the enable task able to
        // publish `enabled = true` when the window elapses.
        self.cancel_enable_token(pubkey);
        // Publish-first: the key stays disabled in memory even when the write fails.
        self.validator_manager.set_validator_enabled(pubkey, false)?;
        Ok(())
    }

    /// Quiesce `pubkey` and wait up to the configured drain timeout.
    ///
    /// `Ok` means the slashable lock was free and the under-lock gate is
    /// closed. It does not mean non-slashable duties are idle. `Err` is only
    /// [`QuiesceError::DrainTimedOut`]; the key stays quiesced either way.
    pub async fn quiesce_for_delete(&self, pubkey: &Pubkey) -> Result<(), QuiesceError> {
        self.signing_quiesce.quiesce(pubkey, self.quiesce_timeout).await
    }

    /// Duration of the post-import enablement hold.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Sleep until `stored_unix`, and no longer than the configured window.
    fn clamped_hold_wait(&self, stored_unix: u64) -> Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Duration::from_secs(stored_unix.saturating_sub(now)).min(self.window)
    }

    /// Shared monitor handle (list handlers, tests).
    pub fn monitor(&self) -> &Arc<dyn DoppelgangerMonitor> {
        &self.monitor
    }

    /// Whether `pubkey` has cleared the doppelganger window.
    pub fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
        self.monitor.is_doppelganger_safe(pubkey)
    }

    /// Register a freshly imported key and spawn the enable task.
    ///
    /// Acquires the KM-2 state lock.  Local imports call
    /// [`ValidatorManager::add_validator`]`(pubkey, false)`; remote imports skip
    /// that and only join the monitor + cancel-token path.
    pub fn on_import(self: &Arc<Self>, pubkey: Pubkey, kind: ImportKind) -> Result<(), String> {
        #[cfg(test)]
        if FAIL_NEXT_IMPORT.with(|cell| cell.replace(false)) {
            return Err("injected import failure".into());
        }
        let _guard = self.lock_state();

        if kind == ImportKind::Local {
            let until = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(self.window.as_secs());
            let armed =
                self.validator_manager.begin_doppelganger_hold(pubkey, until).map_err(|e| {
                    format!("{e}; the key stays disabled and a retry is reported as a duplicate")
                })?;
            // A pre-existing slashing or operator disable must not start a timer.
            if !armed {
                return Ok(());
            }
        }
        self.monitor.start_monitoring(pubkey);
        let residual = self.hold_residual(&pubkey, kind);
        self.spawn_enable_task(pubkey, kind, residual);
        Ok(())
    }

    /// Run `remove_op` under the KM-2 state lock, then cancel any enable task.
    ///
    /// `remove_op` must return `(removed, value)` where `removed` is true when
    /// the key was actually deleted (so monitoring / validator registration can
    /// be torn down).  Token cancel is **unconditional** (Finding 3) so a
    /// NotFound / error path cannot leave a stale enable task alive.
    ///
    /// On `removed == true`:
    /// - Local: [`ValidatorManager::remove_validator`]
    /// - both kinds: [`DoppelgangerMonitor::cancel_monitoring`]. The monitor may
    ///   skip it while another key backend holds the key, such as a re-import
    ///   that landed after `remove_op` released the key-set lock.
    pub fn on_delete<T>(
        &self,
        pubkey: &Pubkey,
        kind: ImportKind,
        remove_op: impl FnOnce() -> (ConfigTouch, T),
    ) -> (ConfigRemoval, T) {
        let _guard = self.lock_state();
        let (touch, value) = remove_op();

        // KM-2 Finding 3: cancel any live token unconditionally.
        self.cancel_enable_token(pubkey);

        let config = match touch {
            ConfigTouch::Skip => ConfigRemoval::NotAttempted,
            ConfigTouch::Apply { .. } => {
                let removal = if kind == ImportKind::Local {
                    match self.validator_manager.remove_validator(pubkey) {
                        Ok(true) => ConfigRemoval::Removed,
                        Ok(false) => ConfigRemoval::Absent,
                        Err(e) => ConfigRemoval::Failed(e),
                    }
                } else {
                    ConfigRemoval::NotAttempted
                };
                // A failed config write leaves the row. Keep monitoring so a
                // retry can still tear the key down.
                if !matches!(removal, ConfigRemoval::Failed(_)) {
                    self.monitor.cancel_monitoring(pubkey);
                }
                removal
            }
        };

        (config, value)
    }

    async fn run_enable_task(
        self: Arc<Self>,
        pubkey: Pubkey,
        kind: ImportKind,
        token: CancellationToken,
        deadline: tokio::time::Instant,
        pubkey_hex: String,
    ) {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                self.finish_enable(pubkey, kind, token, pubkey_hex).await;
            }
            _ = token.cancelled() => {
                // Key was deleted (or re-imported) before the window elapsed.
                // Do not enable: a fresh window is already running or the key has
                // been removed entirely. The displacer/deleter owns the map slot,
                // so we do not touch cancel_tokens here.
                info!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    "Doppelganger background task cancelled (key deleted or re-imported)"
                );
            }
        }
    }

    /// Enable after the window, retrying a failed local persist until it lands
    /// or the token is cancelled. `state_lock` is never held across `.await`.
    async fn finish_enable(
        self: Arc<Self>,
        pubkey: Pubkey,
        kind: ImportKind,
        token: CancellationToken,
        pubkey_hex: String,
    ) {
        loop {
            {
                // KM-2 (Finding 1+2): re-check cancellation under `state_lock`.
                let _g = self.lock_state();
                if token.is_cancelled() {
                    return;
                }
                if kind == ImportKind::Local {
                    // Re-check the hold under `state_lock` before any enable write.
                    // `release_doppelganger_hold` checks again under the store lock.
                    if !self.validator_manager.is_doppelganger_hold(&pubkey) {
                        if self.monitor.signing_closed_by_detection(&pubkey) {
                            if self.rollback_if_detection_closed(&pubkey, &pubkey_hex) {
                                // Rollback drops the token only for a Detected
                                // key. This task is finished either way.
                                self.cancel_enable_token(&pubkey);
                                return;
                            }
                        } else {
                            self.cancel_enable_token(&pubkey);
                            return;
                        }
                    } else {
                        #[cfg(test)]
                        self.fire_before_enable_write();
                        match self.validator_manager.release_doppelganger_hold(&pubkey) {
                            Ok(true) => {
                                if self.complete_enable(&pubkey, &pubkey_hex) {
                                    return;
                                }
                            }
                            Ok(false) => {
                                if self.validator_manager.is_doppelganger_hold(&pubkey) {
                                    let residual = self.hold_residual(&pubkey, kind);
                                    // Spawn from a sync helper. Building that future
                                    // inside this async fn, while `state_lock` is
                                    // held, makes the enable task `!Send`.
                                    self.spawn_enable_task(pubkey, kind, residual);
                                    return;
                                }
                                if self.monitor.signing_closed_by_detection(&pubkey) {
                                    if self.rollback_if_detection_closed(&pubkey, &pubkey_hex) {
                                        self.cancel_enable_token(&pubkey);
                                        return;
                                    }
                                } else {
                                    self.cancel_enable_token(&pubkey);
                                    return;
                                }
                            }
                            Err(e) => {
                                error!(
                                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                                    error = %e,
                                    "doppelganger re-enable was not persisted; retrying"
                                );
                            }
                        }
                    }
                } else {
                    #[cfg(test)]
                    self.fire_before_enable_write();
                    if self.complete_enable(&pubkey, &pubkey_hex) {
                        return;
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                _ = token.cancelled() => {
                    info!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        "Doppelganger re-enable retry cancelled"
                    );
                    return;
                }
            }
        }
    }

    /// Stop monitoring and prune this task's cancel token. Caller holds `state_lock`.
    ///
    /// Returns `false` when a detection rollback could not be persisted, so the
    /// caller retries. The store write has already happened; this is the
    /// post-write re-check.
    fn complete_enable(&self, pubkey: &Pubkey, pubkey_hex: &str) -> bool {
        if !self.rollback_if_detection_closed(pubkey, pubkey_hex) {
            return false;
        }
        if self.monitor.signing_closed_by_detection(pubkey) {
            // Do not stop_monitoring: the forward window is not satisfied.
            // The task is done, so drop its cancel token. A non-detected key
            // keeps the enabled=true that release already wrote.
            self.cancel_enable_token(pubkey);
            return true;
        }
        // SF-4 / SEC-2b: prune wall-clock pending only.
        // Must NOT cancel ForwardWindowMachine state —
        // M-12 elapsed ≠ forward-window satisfied.
        self.monitor.stop_monitoring(pubkey);
        // KM-2 (c): prune our OWN cancel-token entry now that the window
        // has elapsed.  We hold `state_lock` here, consistent with the
        // lock-ordering invariant (outer lock, then cancel_tokens).
        self.cancel_tokens.lock().expect("cancel_tokens poisoned").remove(pubkey);
        info!(
            pubkey = %TruncatedPubkey::new(pubkey_hex),
            "Doppelganger window elapsed; enabling validator for attestation"
        );
        true
    }

    /// Roll `enabled` back when detection closed signing.
    ///
    /// `Ok(true)` means the step is finished (nothing to roll back, or the
    /// rollback landed). `Ok` is not "the key is enabled". `false` means the
    /// rollback write failed and the caller must retry.
    ///
    /// `is_doppelganger_safe` is the monitor's `is_signing_enabled`. It is
    /// consulted only after this key is itself `Detected`. A `Pending` key,
    /// and a key that is only closed by the process latch, keeps the
    /// wall-clock enable (M-12). No machine lock is held across the store
    /// write: the monitor takes that lock only for the comparison.
    fn rollback_if_detection_closed(&self, pubkey: &Pubkey, pubkey_hex: &str) -> bool {
        // The latch closes signing for every key. Only a key that is itself
        // Detected gets `enabled = false` written back.
        if !self.monitor.is_detected_key(pubkey) {
            return true;
        }
        let signing_enabled = self.monitor.is_doppelganger_safe(pubkey);
        if signing_enabled {
            error!(
                pubkey = %TruncatedPubkey::new(pubkey_hex),
                "detection closed signing but is_signing_enabled was true; rolling back anyway"
            );
        }
        match self.validator_manager.set_validator_enabled(pubkey, false) {
            Ok(()) => {
                self.cancel_tokens.lock().expect("cancel_tokens poisoned").remove(pubkey);
                error!(
                    pubkey = %TruncatedPubkey::new(pubkey_hex),
                    "doppelganger detection rolled back enabled=true"
                );
                true
            }
            Err(e) => {
                error!(
                    pubkey = %TruncatedPubkey::new(pubkey_hex),
                    error = %e,
                    "doppelganger detection rollback was not persisted; retrying"
                );
                false
            }
        }
    }

    /// How long a new enable task sleeps. A `Local` hold waits until its
    /// stored deadline, and no longer than the window. Without a stored
    /// deadline, and for a `Remote` import, it waits the window.
    fn hold_residual(&self, pubkey: &Pubkey, kind: ImportKind) -> Duration {
        if kind == ImportKind::Local {
            match self.validator_manager.armed_hold_unix(pubkey) {
                Some(stored) => self.clamped_hold_wait(stored),
                None => self.window,
            }
        } else {
            self.window
        }
    }

    /// Arm the enable task for `pubkey`: the only cancel-token insert and the
    /// only spawn of [`Self::run_enable_task`].
    ///
    /// Caller holds `state_lock`. The spawned task is built in this sync fn.
    fn spawn_enable_task(self: &Arc<Self>, pubkey: Pubkey, kind: ImportKind, residual: Duration) {
        let cancel_token = CancellationToken::new();
        // SF-3 / KM-2 (a): if a token was already present for this pubkey
        // (e.g. a stale task from a prior import that a racing delete had not
        // yet cancelled), cancel the DISPLACED token so it can never enable a
        // key that is now inside a fresh window. No token is ever dropped from
        // the map without being cancelled.
        //
        // The `.cancel()` runs WHILE the `cancel_tokens` guard is held so that
        // "insert new + cancel old" is atomic against a concurrent task's
        // self-prune (KM-2 (c)): a displaced task observes its token cancelled
        // before it can prune the fresh entry.
        {
            let mut tokens = self.cancel_tokens.lock().expect("cancel_tokens poisoned");
            if let Some(displaced) = tokens.insert(pubkey, cancel_token.clone()) {
                displaced.cancel();
            }
        }
        let this = Arc::clone(self);
        let token = cancel_token;
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        // Capture the `Instant` before spawn so a paused test clock still
        // sees a fixed deadline.
        let deadline = tokio::time::Instant::now() + residual;
        tokio::spawn(async move {
            this.run_enable_task(pubkey, kind, token, deadline, pubkey_hex).await;
        });
    }

    /// Re-arm a hold that was already persisted. Does not write the validators file.
    pub fn rearm_persisted_hold(self: &Arc<Self>, pubkey: Pubkey, residual: Duration) {
        let _guard = self.lock_state();
        self.monitor.start_monitoring(pubkey);
        self.spawn_enable_task(pubkey, ImportKind::Local, residual);
    }

    /// Cancel a pending enable task because the key was disabled outside the
    /// doppelganger timer. Does not write the validators file.
    ///
    /// Safe to call from a store disable hook that runs on this thread while
    /// `state_lock` is already held (`disable_for_delete`).
    pub fn cancel_enable_on_disable(&self, pubkey: &Pubkey) {
        if STATE_LOCK_HELD.with(|held| held.get()) {
            self.cancel_enable_token(pubkey);
            return;
        }
        let _guard = self.lock_state();
        self.cancel_enable_token(pubkey);
    }

    /// Snapshot the cancel-token currently registered for `pubkey` (tests).
    pub fn current_cancel_token(&self, pubkey: &Pubkey) -> Option<CancellationToken> {
        self.cancel_tokens.lock().expect("cancel_tokens poisoned").get(pubkey).cloned()
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_IMPORT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Next [`DoppelgangerLifecycle::on_import`] returns an error (tests).
#[cfg(test)]
pub fn arm_import_failure() {
    FAIL_NEXT_IMPORT.with(|cell| cell.set(true));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as StdMutex;

    /// Test double: unsafe while `start_monitoring` is outstanding.
    /// `cancel_monitoring` inherits the prune-pending default.
    struct PendingSetMonitor {
        pending: StdMutex<std::collections::HashSet<Pubkey>>,
    }

    impl PendingSetMonitor {
        fn new() -> Self {
            Self { pending: StdMutex::new(std::collections::HashSet::new()) }
        }
    }

    impl DoppelgangerMonitor for PendingSetMonitor {
        fn start_monitoring(&self, pubkey: Pubkey) {
            self.pending.lock().unwrap().insert(pubkey);
        }

        fn stop_monitoring(&self, pubkey: &Pubkey) {
            self.pending.lock().unwrap().remove(pubkey);
        }

        fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
            !self.pending.lock().unwrap().contains(pubkey)
        }
    }

    struct SpyValidatorManager {
        state: StdMutex<StdHashMap<Pubkey, bool>>,
    }

    impl SpyValidatorManager {
        fn new() -> Self {
            Self { state: StdMutex::new(StdHashMap::new()) }
        }

        fn is_enabled(&self, pubkey: &Pubkey) -> bool {
            self.state.lock().unwrap().get(pubkey).copied().unwrap_or(false)
        }

        fn is_tracked(&self, pubkey: &Pubkey) -> bool {
            self.state.lock().unwrap().contains_key(pubkey)
        }
    }

    impl ValidatorManager for SpyValidatorManager {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
            self.state.lock().unwrap().insert(pubkey, enabled);
            Ok(())
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
            Ok(self.state.lock().unwrap().remove(pubkey).is_some())
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
            if let Some(v) = self.state.lock().unwrap().get_mut(pubkey) {
                *v = enabled;
            }
            Ok(())
        }
    }

    fn test_pubkey(seed: u8) -> Pubkey {
        let mut pk = [0u8; 48];
        pk[0] = seed;
        pk
    }

    fn lifecycle(
        window: Duration,
        vm: Arc<SpyValidatorManager>,
    ) -> (Arc<DoppelgangerLifecycle>, Arc<PendingSetMonitor>) {
        let monitor = Arc::new(PendingSetMonitor::new());
        let life = Arc::new(DoppelgangerLifecycle::new(
            window,
            monitor.clone() as Arc<dyn DoppelgangerMonitor>,
            vm as Arc<dyn ValidatorManager>,
        ));
        (life, monitor)
    }

    #[tokio::test]
    async fn test_remote_import_registers_with_lifecycle_like_local() {
        let vm = Arc::new(SpyValidatorManager::new());
        let window = Duration::from_secs(60);
        let (life, gate) = lifecycle(window, vm.clone());
        let pk = test_pubkey(1);

        life.on_import(pk, ImportKind::Remote).expect("remote import");

        assert!(!vm.is_tracked(&pk), "remote import must not register with ValidatorManager");
        assert!(!gate.is_doppelganger_safe(&pk), "remote import starts monitoring");
        assert!(
            life.current_cancel_token(&pk).is_some(),
            "remote import must register a cancel token like local"
        );
    }

    #[tokio::test]
    async fn test_second_import_displaces_first_cancel_token_under_lock() {
        let vm = Arc::new(SpyValidatorManager::new());
        let (life, _) = lifecycle(Duration::from_secs(3600), vm);
        let pk = test_pubkey(2);

        life.on_import(pk, ImportKind::Local).expect("import");
        let t1 = life.current_cancel_token(&pk).expect("T1 after first import");
        assert!(!t1.is_cancelled());

        life.on_import(pk, ImportKind::Local).expect("import");
        let t2 = life.current_cancel_token(&pk).expect("T2 after second import");
        assert!(!t2.is_cancelled());
        assert!(
            t1.is_cancelled(),
            "second import must cancel the displaced token under the state lock"
        );
    }

    #[tokio::test]
    async fn test_delete_during_window_cancels_enable_task() {
        let vm = Arc::new(SpyValidatorManager::new());
        let (life, gate) = lifecycle(Duration::from_secs(3600), vm.clone());
        let pk = test_pubkey(3);

        life.on_import(pk, ImportKind::Local).expect("import");
        let t1 = life.current_cancel_token(&pk).expect("token after import");
        assert!(vm.is_tracked(&pk));
        assert!(!gate.is_doppelganger_safe(&pk));

        let (config, removed) = life.on_delete(&pk, ImportKind::Local, || {
            (ConfigTouch::Apply { keystore_present: true }, true)
        });
        assert!(removed);
        assert!(matches!(config, ConfigRemoval::Removed));
        assert!(t1.is_cancelled(), "delete during window cancels the enable task");
        assert!(life.current_cancel_token(&pk).is_none());
        assert!(!vm.is_tracked(&pk), "local delete removes validator");
        // cancel_monitoring on PendingSetMonitor defaults to stop_monitoring → safe
        assert!(gate.is_doppelganger_safe(&pk));
    }

    #[tokio::test(start_paused = true)]
    async fn test_enable_task_rechecks_cancellation_under_state_lock() {
        let vm = Arc::new(SpyValidatorManager::new());
        let window = Duration::from_secs(60);
        let (life, gate) = lifecycle(window, vm.clone());
        let pk = test_pubkey(4);

        life.on_import(pk, ImportKind::Local).expect("import");
        // Advance past the original deadline so the enable task's sleep is ready,
        // then displace before the task is polled (Finding 1+2).
        tokio::time::advance(window + Duration::from_secs(1)).await;

        let _ = life.on_delete(&pk, ImportKind::Local, || {
            (ConfigTouch::Apply { keystore_present: true }, ())
        });
        life.on_import(pk, ImportKind::Local).expect("import");

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            !vm.is_enabled(&pk),
            "stale enable task must re-check cancellation under the state lock"
        );
        assert!(
            !gate.is_doppelganger_safe(&pk),
            "stale task must not stop_monitoring a fresh window"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_lifecycle_window_zero_enables_immediately() {
        let vm = Arc::new(SpyValidatorManager::new());
        let (life, gate) = lifecycle(Duration::ZERO, vm.clone());
        let pk = test_pubkey(5);

        life.on_import(pk, ImportKind::Local).expect("import");
        // Zero window: sleep_until(now) is immediately ready.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(vm.is_enabled(&pk), "zero window enables immediately");
        assert!(gate.is_doppelganger_safe(&pk));
        assert!(
            life.current_cancel_token(&pk).is_none(),
            "enable task prunes its own cancel-token entry"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_local_import_enables_after_window() {
        let vm = Arc::new(SpyValidatorManager::new());
        let window = Duration::from_secs(60);
        let (life, _) = lifecycle(window, vm.clone());
        let pk = test_pubkey(6);

        life.on_import(pk, ImportKind::Local).expect("import");
        assert!(!vm.is_enabled(&pk));
        assert!(life.current_cancel_token(&pk).is_some());

        tokio::time::advance(window + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(vm.is_enabled(&pk));
        assert!(life.current_cancel_token(&pk).is_none());
    }

    /// A later delete whose keystore is already gone must still drop the config row.
    #[tokio::test]
    async fn test_keystore_absent_retry_still_removes_the_validator() {
        let vm = Arc::new(SpyValidatorManager::new());
        let (life, _) = lifecycle(Duration::from_secs(3600), vm.clone());
        let pk = test_pubkey(7);
        life.on_import(pk, ImportKind::Local).expect("import");
        assert!(vm.is_tracked(&pk));
        // Keystore delete returned not-found. The handler still asks to drop the row.
        let (config, ()) = life.on_delete(&pk, ImportKind::Local, || {
            (ConfigTouch::Apply { keystore_present: false }, ())
        });
        assert!(matches!(config, ConfigRemoval::Removed));
        assert!(
            !vm.is_tracked(&pk),
            "a not-found keystore retry must still drop the leftover config row"
        );
    }

    /// A failed DELETE disable must already have cancelled the enable task.
    #[tokio::test]
    async fn test_disable_for_delete_cancels_token_when_persist_fails() {
        let vm = Arc::new(DisablePersistFails::new());
        let monitor = Arc::new(PendingSetMonitor::new());
        let life = Arc::new(DoppelgangerLifecycle::new(
            Duration::from_secs(3600),
            monitor,
            vm as Arc<dyn ValidatorManager>,
        ));
        let pk = test_pubkey(8);
        life.on_import(pk, ImportKind::Local).expect("import");
        let token = life.current_cancel_token(&pk).expect("enable task is armed");
        let err = life.disable_for_delete(&pk).expect_err("persist failure");
        assert!(err.contains("validators file"));
        assert!(
            token.is_cancelled(),
            "disable_for_delete must cancel the re-enable token before returning the error"
        );
        assert!(life.current_cancel_token(&pk).is_none());
    }

    /// A failed re-enable persist is retried instead of leaving the key disabled.
    #[tokio::test(start_paused = true)]
    async fn test_reenable_persist_failure_is_retried() {
        let vm = Arc::new(FlakyReenable::new(1));
        let monitor = Arc::new(PendingSetMonitor::new());
        let window = Duration::from_secs(30);
        let life = Arc::new(DoppelgangerLifecycle::new(
            window,
            monitor,
            Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        ));
        let pk = test_pubkey(9);
        life.on_import(pk, ImportKind::Local).expect("import");
        tokio::time::advance(window + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(vm.is_enabled(&pk), "a failed re-enable must be retried");
    }

    /// A restart inside the window starts the wall-clock task again for the residual only.
    #[tokio::test(start_paused = true)]
    async fn test_rearm_persisted_hold_enables_after_the_residual_window() {
        let vm = Arc::new(SpyValidatorManager::new());
        let (life, gate) = lifecycle(Duration::from_secs(3600), vm.clone());
        let pk = test_pubkey(11);
        vm.add_validator(pk, false).expect("row survived the restart");

        life.rearm_persisted_hold(pk, Duration::from_secs(30));
        tokio::task::yield_now().await;
        assert!(
            !vm.is_enabled(&pk),
            "re-arming inside the window must not enable the key immediately"
        );
        assert!(life.current_cancel_token(&pk).is_some(), "the enable task must be armed");
        assert!(!gate.is_doppelganger_safe(&pk));

        tokio::time::advance(Duration::from_secs(29)).await;
        tokio::task::yield_now().await;
        assert!(!vm.is_enabled(&pk), "the key stays disabled until the residual elapses");

        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(
            vm.is_enabled(&pk),
            "a re-armed hold must enable the key when the residual window elapses"
        );
        assert!(life.current_cancel_token(&pk).is_none());
        assert!(gate.is_doppelganger_safe(&pk));
    }

    /// A slashing or operator disable during the window must not be undone
    /// when the enable task wakes. The task re-checks under `state_lock`.
    #[tokio::test(start_paused = true)]
    async fn test_enable_task_does_not_reenable_a_cleared_hold() {
        let vm = Arc::new(HoldTrackingManager::new());
        let window = Duration::from_secs(30);
        let life = Arc::new(DoppelgangerLifecycle::new(
            window,
            Arc::new(PendingSetMonitor::new()),
            Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        ));
        let pk = test_pubkey(12);
        life.on_import(pk, ImportKind::Local).expect("import");
        assert!(!vm.is_enabled(&pk));
        assert!(vm.is_hold(&pk), "import arms a hold");
        let token = life.current_cancel_token(&pk).expect("enable task is armed");

        vm.clear_hold(&pk);
        life.cancel_enable_on_disable(&pk);
        assert!(token.is_cancelled(), "any disable must cancel the doppelganger enable task");

        tokio::time::advance(window + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(
            !vm.is_enabled(&pk),
            "the enable task must not persist enabled=true after the hold was cleared"
        );
    }

    /// A wake before the stored deadline must not enable the key.
    #[tokio::test(start_paused = true)]
    async fn test_early_release_rearms_instead_of_enabling() {
        let vm = Arc::new(EarlyRelease::new(100));
        let window = Duration::from_secs(4);
        let life = Arc::new(DoppelgangerLifecycle::new(
            window,
            Arc::new(PendingSetMonitor::new()),
            Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        ));
        let pk = test_pubkey(14);
        life.on_import(pk, ImportKind::Local).expect("import");
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(vm.release_calls() >= 1, "the wait must be clamped to the window");
        assert!(!vm.is_enabled(&pk), "an early release must not enable the key");
        assert!(
            life.current_cancel_token(&pk).is_some(),
            "an early release must re-arm instead of enabling"
        );
    }

    /// The enable task sleeps until the stored unix deadline, not a fresh window.
    #[tokio::test(start_paused = true)]
    async fn test_enable_task_uses_the_persisted_hold_deadline() {
        let vm = Arc::new(ShortPersistedHold::new(10));
        let window = Duration::from_secs(30);
        let life = Arc::new(DoppelgangerLifecycle::new(
            window,
            Arc::new(PendingSetMonitor::new()),
            Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        ));
        let pk = test_pubkey(13);
        life.on_import(pk, ImportKind::Local).expect("import");
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert!(!vm.is_enabled(&pk), "the enable task must wait for the persisted hold deadline");
        tokio::time::advance(Duration::from_secs(8)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(vm.is_enabled(&pk), "the enable task must use the persisted hold deadline");
    }

    struct DisablePersistFails {
        inner: SpyValidatorManager,
    }

    impl DisablePersistFails {
        fn new() -> Self {
            Self { inner: SpyValidatorManager::new() }
        }
    }

    impl ValidatorManager for DisablePersistFails {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
            self.inner.add_validator(pubkey, enabled)
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
            self.inner.remove_validator(pubkey)
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
            if !enabled {
                return Err("validators file write failed".into());
            }
            self.inner.set_validator_enabled(pubkey, enabled)
        }
    }

    struct FlakyReenable {
        fails_left: StdMutex<u32>,
        enabled: StdMutex<StdHashMap<Pubkey, bool>>,
    }

    impl FlakyReenable {
        fn new(fails: u32) -> Self {
            Self { fails_left: StdMutex::new(fails), enabled: StdMutex::new(StdHashMap::new()) }
        }

        fn is_enabled(&self, pubkey: &Pubkey) -> bool {
            self.enabled.lock().unwrap().get(pubkey).copied().unwrap_or(false)
        }
    }

    impl ValidatorManager for FlakyReenable {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
            self.enabled.lock().unwrap().insert(pubkey, enabled);
            Ok(())
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
            Ok(self.enabled.lock().unwrap().remove(pubkey).is_some())
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
            if enabled {
                let mut left = self.fails_left.lock().unwrap();
                if *left > 0 {
                    *left -= 1;
                    return Err("re-enable persist failed".into());
                }
            }
            self.enabled.lock().unwrap().insert(*pubkey, enabled);
            Ok(())
        }
    }

    /// Tracks a doppelganger hold separately from `enabled`.
    struct HoldTrackingManager {
        enabled: StdMutex<StdHashMap<Pubkey, bool>>,
        hold: StdMutex<StdHashMap<Pubkey, bool>>,
    }

    impl HoldTrackingManager {
        fn new() -> Self {
            Self {
                enabled: StdMutex::new(StdHashMap::new()),
                hold: StdMutex::new(StdHashMap::new()),
            }
        }

        fn is_enabled(&self, pubkey: &Pubkey) -> bool {
            self.enabled.lock().unwrap().get(pubkey).copied().unwrap_or(false)
        }

        fn is_hold(&self, pubkey: &Pubkey) -> bool {
            self.hold.lock().unwrap().get(pubkey).copied().unwrap_or(false)
        }

        fn clear_hold(&self, pubkey: &Pubkey) {
            self.hold.lock().unwrap().insert(*pubkey, false);
            self.enabled.lock().unwrap().insert(*pubkey, false);
        }
    }

    impl ValidatorManager for HoldTrackingManager {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
            self.enabled.lock().unwrap().insert(pubkey, enabled);
            self.hold.lock().unwrap().insert(pubkey, !enabled);
            Ok(())
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
            self.hold.lock().unwrap().remove(pubkey);
            Ok(self.enabled.lock().unwrap().remove(pubkey).is_some())
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
            if enabled {
                self.hold.lock().unwrap().insert(*pubkey, false);
            }
            self.enabled.lock().unwrap().insert(*pubkey, enabled);
            Ok(())
        }

        fn is_doppelganger_hold(&self, pubkey: &Pubkey) -> bool {
            self.hold.lock().unwrap().get(pubkey).copied().unwrap_or(false)
        }
    }

    /// Reports a unix deadline shorter than the lifecycle window.
    struct ShortPersistedHold {
        until: u64,
        enabled: StdMutex<StdHashMap<Pubkey, bool>>,
    }

    impl ShortPersistedHold {
        fn new(offset_secs: u64) -> Self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Self {
                until: now.saturating_add(offset_secs),
                enabled: StdMutex::new(StdHashMap::new()),
            }
        }

        fn is_enabled(&self, pubkey: &Pubkey) -> bool {
            self.enabled.lock().unwrap().get(pubkey).copied().unwrap_or(false)
        }
    }

    impl ValidatorManager for ShortPersistedHold {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
            self.enabled.lock().unwrap().insert(pubkey, enabled);
            Ok(())
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
            Ok(self.enabled.lock().unwrap().remove(pubkey).is_some())
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
            self.enabled.lock().unwrap().insert(*pubkey, enabled);
            Ok(())
        }

        fn armed_hold_unix(&self, _pubkey: &Pubkey) -> Option<u64> {
            Some(self.until)
        }
    }

    /// Hold stays set. `release` reports that it is too early to enable.
    struct EarlyRelease {
        until: u64,
        releases: StdMutex<u32>,
        enabled: StdMutex<StdHashMap<Pubkey, bool>>,
    }

    impl EarlyRelease {
        fn new(offset_secs: u64) -> Self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Self {
                until: now.saturating_add(offset_secs),
                releases: StdMutex::new(0),
                enabled: StdMutex::new(StdHashMap::new()),
            }
        }

        fn is_enabled(&self, pubkey: &Pubkey) -> bool {
            self.enabled.lock().unwrap().get(pubkey).copied().unwrap_or(false)
        }

        fn release_calls(&self) -> u32 {
            *self.releases.lock().unwrap()
        }
    }

    impl ValidatorManager for EarlyRelease {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
            self.enabled.lock().unwrap().insert(pubkey, enabled);
            Ok(())
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
            Ok(self.enabled.lock().unwrap().remove(pubkey).is_some())
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
            self.enabled.lock().unwrap().insert(*pubkey, enabled);
            Ok(())
        }

        fn is_doppelganger_hold(&self, _pubkey: &Pubkey) -> bool {
            true
        }

        fn armed_hold_unix(&self, _pubkey: &Pubkey) -> Option<u64> {
            Some(self.until)
        }

        fn release_doppelganger_hold(&self, _pubkey: &Pubkey) -> Result<bool, String> {
            *self.releases.lock().unwrap() += 1;
            Ok(false)
        }
    }

    #[derive(Clone, Copy)]
    enum RaceEvent {
        Latch(u64),
        Admit { seq: u64, enabled: bool },
    }

    struct RaceMonitor {
        closed: std::sync::atomic::AtomicBool,
        next: std::sync::atomic::AtomicU64,
        events: StdMutex<Vec<RaceEvent>>,
        /// `None` treats every key as detected once `closed` is set.
        only: Option<Pubkey>,
    }

    impl DoppelgangerMonitor for RaceMonitor {
        fn start_monitoring(&self, _pubkey: Pubkey) {}

        fn stop_monitoring(&self, _pubkey: &Pubkey) {}

        fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool {
            let seq = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let enabled = !self.closed.load(std::sync::atomic::Ordering::SeqCst);
            self.events.lock().expect("events").push(RaceEvent::Admit { seq, enabled });
            enabled
        }

        fn signing_closed_by_detection(&self, _pubkey: &Pubkey) -> bool {
            self.closed.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn is_detected_key(&self, pubkey: &Pubkey) -> bool {
            if !self.closed.load(std::sync::atomic::Ordering::SeqCst) {
                return false;
            }
            self.only.is_none_or(|only| only == *pubkey)
        }
    }

    /// Detection between the enable task's check and its store write.
    ///
    /// The store must not finish with `enabled = true`, and an admission
    /// check sequenced after the latch must not return safe.
    #[tokio::test(start_paused = true)]
    async fn enable_task_racing_detection_never_leaves_a_detected_key_enabled() {
        let vm = Arc::new(SpyValidatorManager::new());
        let monitor = Arc::new(RaceMonitor {
            closed: std::sync::atomic::AtomicBool::new(false),
            next: std::sync::atomic::AtomicU64::new(0),
            events: StdMutex::new(Vec::new()),
            only: None,
        });
        let life = Arc::new(DoppelgangerLifecycle::new(
            Duration::ZERO,
            monitor.clone() as Arc<dyn DoppelgangerMonitor>,
            vm.clone() as Arc<dyn ValidatorManager>,
        ));
        let hooked = Arc::clone(&monitor);
        life.set_before_enable_write_hook(Some(Arc::new(move || {
            let seq = hooked.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            hooked.closed.store(true, std::sync::atomic::Ordering::SeqCst);
            hooked.events.lock().expect("events").push(RaceEvent::Latch(seq));
        })));
        let pk = test_pubkey(42);
        life.on_import(pk, ImportKind::Local).expect("import");

        let mut finished = false;
        for _ in 0..200 {
            let latched = monitor
                .events
                .lock()
                .expect("events")
                .iter()
                .any(|event| matches!(event, RaceEvent::Latch(_)));
            if latched && life.current_cancel_token(&pk).is_none() {
                finished = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(finished, "enable task must observe detection and finish");
        assert!(!vm.is_enabled(&pk), "store must not end enabled");

        let events = monitor.events.lock().expect("events").iter().copied().collect::<Vec<_>>();
        let latch = events.iter().find_map(|event| match event {
            RaceEvent::Latch(seq) => Some(*seq),
            RaceEvent::Admit { .. } => None,
        });
        let latch = latch.expect("latch sequence");
        for event in &events {
            if let RaceEvent::Admit { seq, enabled: true } = event {
                assert!(*seq < latch, "admission {seq} followed latch {latch}");
            }
        }
        assert!(!monitor.is_doppelganger_safe(&pk), "a check after the latch is refused");
    }

    /// The process-wide latch must not persist enabled=false for a key that
    /// was not itself Detected.
    #[tokio::test(start_paused = true)]
    async fn latch_rollback_persists_only_the_detected_key() {
        let vm = Arc::new(SpyValidatorManager::new());
        let detected = test_pubkey(7);
        let other = test_pubkey(8);
        let monitor = Arc::new(RaceMonitor {
            closed: std::sync::atomic::AtomicBool::new(false),
            next: std::sync::atomic::AtomicU64::new(0),
            events: StdMutex::new(Vec::new()),
            only: Some(detected),
        });
        let life = Arc::new(DoppelgangerLifecycle::new(
            Duration::ZERO,
            monitor.clone() as Arc<dyn DoppelgangerMonitor>,
            vm.clone() as Arc<dyn ValidatorManager>,
        ));
        let hooked = Arc::clone(&monitor);
        life.set_before_enable_write_hook(Some(Arc::new(move || {
            hooked.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        })));
        life.on_import(detected, ImportKind::Local).expect("detected import");
        life.on_import(other, ImportKind::Local).expect("other import");

        let mut finished = false;
        for _ in 0..200 {
            if life.current_cancel_token(&detected).is_none()
                && life.current_cancel_token(&other).is_none()
                && monitor.closed.load(std::sync::atomic::Ordering::SeqCst)
            {
                finished = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(finished, "both enable tasks must finish");
        assert!(!vm.is_enabled(&detected), "the detected key is rolled back");
        assert!(vm.is_enabled(&other), "a key that was not detected stays enabled");
    }

    struct FlakyRollback {
        inner: SpyValidatorManager,
        fails_left: StdMutex<u32>,
        attempts: StdMutex<u32>,
    }

    impl FlakyRollback {
        fn new(fails: u32) -> Self {
            Self {
                inner: SpyValidatorManager::new(),
                fails_left: StdMutex::new(fails),
                attempts: StdMutex::new(0),
            }
        }
    }

    impl ValidatorManager for FlakyRollback {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) -> Result<(), String> {
            self.inner.add_validator(pubkey, enabled)
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> Result<bool, String> {
            self.inner.remove_validator(pubkey)
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) -> Result<(), String> {
            if !enabled {
                *self.attempts.lock().unwrap() += 1;
                let mut left = self.fails_left.lock().unwrap();
                if *left > 0 {
                    *left -= 1;
                    return Err("rollback persist failed".into());
                }
            }
            self.inner.set_validator_enabled(pubkey, enabled)
        }
    }

    /// A failed detection rollback stays armed and retries until the write lands.
    #[tokio::test(start_paused = true)]
    async fn failed_rollback_write_is_retried_until_it_persists() {
        let vm = Arc::new(FlakyRollback::new(1));
        let pk = test_pubkey(14);
        let monitor = Arc::new(RaceMonitor {
            closed: std::sync::atomic::AtomicBool::new(false),
            next: std::sync::atomic::AtomicU64::new(0),
            events: StdMutex::new(Vec::new()),
            only: Some(pk),
        });
        let life = Arc::new(DoppelgangerLifecycle::new(
            Duration::ZERO,
            monitor.clone() as Arc<dyn DoppelgangerMonitor>,
            Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        ));
        let hooked = Arc::clone(&monitor);
        life.set_before_enable_write_hook(Some(Arc::new(move || {
            hooked.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        })));
        life.on_import(pk, ImportKind::Local).expect("import");

        let mut saw_failure = false;
        for _ in 0..50 {
            if *vm.attempts.lock().unwrap() >= 1 {
                saw_failure = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(saw_failure, "the first rollback write must run");
        assert!(
            life.current_cancel_token(&pk).is_some(),
            "a failed rollback must not cancel its own retry"
        );
        assert!(vm.inner.is_enabled(&pk), "enabled=true stays until a rollback write succeeds");

        tokio::time::advance(Duration::from_millis(200)).await;
        let mut persisted = false;
        for _ in 0..50 {
            if !vm.inner.is_enabled(&pk) && life.current_cancel_token(&pk).is_none() {
                persisted = true;
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(200)).await;
        }
        assert!(persisted, "the retry must persist enabled=false");
        assert!(*vm.attempts.lock().unwrap() >= 2, "the failed write must be attempted again");
    }

    /// INV2 (FU-A2a) on the boot re-arm path: detection between the re-armed
    /// task's hold check and its store write. The key must end disabled and
    /// the task must drop its cancel token.
    #[tokio::test(start_paused = true)]
    async fn rearmed_hold_racing_detection_never_leaves_a_detected_key_enabled() {
        let vm = Arc::new(SpyValidatorManager::new());
        let pk = test_pubkey(43);
        vm.add_validator(pk, false).expect("the held row survived the restart");
        let monitor = Arc::new(RaceMonitor {
            closed: std::sync::atomic::AtomicBool::new(false),
            next: std::sync::atomic::AtomicU64::new(0),
            events: StdMutex::new(Vec::new()),
            only: Some(pk),
        });
        let life = Arc::new(DoppelgangerLifecycle::new(
            Duration::from_secs(3600),
            monitor.clone() as Arc<dyn DoppelgangerMonitor>,
            vm.clone() as Arc<dyn ValidatorManager>,
        ));
        let hooked = Arc::clone(&monitor);
        life.set_before_enable_write_hook(Some(Arc::new(move || {
            hooked.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        })));

        life.rearm_persisted_hold(pk, Duration::from_secs(30));
        assert!(life.current_cancel_token(&pk).is_some(), "the re-armed task holds a token");
        tokio::time::advance(Duration::from_secs(31)).await;

        let mut finished = false;
        for _ in 0..200 {
            if monitor.closed.load(std::sync::atomic::Ordering::SeqCst)
                && life.current_cancel_token(&pk).is_none()
            {
                finished = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(finished, "the re-armed task must reach its write, see detection and finish");
        assert!(!vm.is_enabled(&pk), "a re-armed Detected key must not end enabled");
        assert!(vm.is_tracked(&pk), "the rollback keeps the row");
    }

    /// The hold stays set, and its stored deadline is `ahead` seconds past the
    /// wall clock whenever it is read, so every release is too early. Records
    /// the paused-clock instant of each release.
    struct RollingHold {
        ahead: u64,
        releases: StdMutex<Vec<tokio::time::Instant>>,
    }

    impl ValidatorManager for RollingHold {
        fn add_validator(&self, _pubkey: Pubkey, _enabled: bool) -> Result<(), String> {
            Ok(())
        }

        fn remove_validator(&self, _pubkey: &Pubkey) -> Result<bool, String> {
            Ok(false)
        }

        fn set_validator_enabled(&self, _pubkey: &Pubkey, _enabled: bool) -> Result<(), String> {
            Ok(())
        }

        fn armed_hold_unix(&self, _pubkey: &Pubkey) -> Option<u64> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Some(now + self.ahead)
        }

        fn release_doppelganger_hold(&self, _pubkey: &Pubkey) -> Result<bool, String> {
            self.releases.lock().unwrap().push(tokio::time::Instant::now());
            Ok(false)
        }
    }

    /// An early wake re-arms for the rest of the stored deadline: not a fresh
    /// window, and not a part of it. The deadline is always 10 s ahead, so
    /// each wait is 10 s, or 9 s if a wall-clock second ticks between the
    /// store's read and the lifecycle's.
    #[tokio::test(start_paused = true)]
    async fn early_release_rearms_for_the_rest_of_the_stored_deadline() {
        let vm = Arc::new(RollingHold { ahead: 10, releases: StdMutex::new(Vec::new()) });
        let life = Arc::new(DoppelgangerLifecycle::new(
            Duration::from_secs(30),
            Arc::new(PendingSetMonitor::new()),
            Arc::clone(&vm) as Arc<dyn ValidatorManager>,
        ));
        let pk = test_pubkey(15);
        let imported = tokio::time::Instant::now();
        life.on_import(pk, ImportKind::Local).expect("import");
        // Paused clock: every timer due before 25 s fires, in order, first.
        tokio::time::sleep(Duration::from_secs(25)).await;
        let releases = vm.releases.lock().unwrap().clone();
        let waits: Vec<Duration> = std::iter::once(&imported)
            .chain(&releases)
            .zip(&releases)
            .map(|(from, to)| *to - *from)
            .collect();
        let rest = Duration::from_secs(9)..=Duration::from_secs(10);
        assert!(
            waits.iter().all(|wait| rest.contains(wait)),
            "each wait must be the rest of the stored deadline: {waits:?}"
        );
        assert_eq!(waits.len(), 2, "two early wakes by 25 s: {waits:?}");
    }

    /// A validators double whose `remove_validator` returns the given result.
    struct RemoveOutcome(Result<bool, String>);

    impl ValidatorManager for RemoveOutcome {
        fn add_validator(&self, _pubkey: Pubkey, _enabled: bool) -> Result<(), String> {
            Ok(())
        }

        fn remove_validator(&self, _pubkey: &Pubkey) -> Result<bool, String> {
            self.0.clone()
        }

        fn set_validator_enabled(&self, _pubkey: &Pubkey, _enabled: bool) -> Result<(), String> {
            Ok(())
        }
    }

    /// KM-2 Finding 3: `on_delete` cancels and removes the enable token on
    /// every path: either touch, either kind, every validators-file result.
    #[tokio::test]
    async fn on_delete_cancels_the_enable_token_on_every_path() {
        let present = ConfigTouch::Apply { keystore_present: true };
        let gone = ConfigTouch::Apply { keystore_present: false };
        let write_failed = "validators file write failed".to_string();
        let cases = [
            (ImportKind::Local, ConfigTouch::Skip, Ok(true), ConfigRemoval::NotAttempted),
            (ImportKind::Remote, ConfigTouch::Skip, Ok(true), ConfigRemoval::NotAttempted),
            (ImportKind::Local, present, Ok(true), ConfigRemoval::Removed),
            (ImportKind::Local, gone, Ok(false), ConfigRemoval::Absent),
            (
                ImportKind::Local,
                present,
                Err(write_failed.clone()),
                ConfigRemoval::Failed(write_failed),
            ),
            (ImportKind::Remote, present, Ok(true), ConfigRemoval::NotAttempted),
        ];
        for (kind, touch, removal, expected) in cases {
            let life = Arc::new(DoppelgangerLifecycle::new(
                Duration::from_secs(3600),
                Arc::new(PendingSetMonitor::new()),
                Arc::new(RemoveOutcome(removal)),
            ));
            let pk = test_pubkey(16);
            life.on_import(pk, kind).expect("import");
            let token = life.current_cancel_token(&pk).expect("the enable task is armed");

            let (config, ()) = life.on_delete(&pk, kind, || (touch, ()));

            assert_eq!(config, expected, "{kind:?} {touch:?}");
            assert!(token.is_cancelled(), "{kind:?} {touch:?} {config:?}: token cancelled");
            assert!(life.current_cancel_token(&pk).is_none(), "{kind:?} {touch:?}: token removed");
        }
    }

    fn stored_hold(until: u64) -> Arc<dyn ValidatorManager> {
        Arc::new(ShortPersistedHold { until, enabled: StdMutex::new(StdHashMap::new()) })
    }

    fn residual_life(vm: Arc<dyn ValidatorManager>) -> DoppelgangerLifecycle {
        DoppelgangerLifecycle::new(Duration::from_secs(30), Arc::new(PendingSetMonitor::new()), vm)
    }

    /// A remote import has no hold of its own: it waits the window even when
    /// the manager reports a deadline that has passed.
    #[test]
    fn hold_residual_uses_the_window_for_remote_imports() {
        let life = residual_life(stored_hold(0));
        assert_eq!(
            life.hold_residual(&test_pubkey(1), ImportKind::Remote),
            Duration::from_secs(30)
        );
    }

    /// A local hold waits until its stored deadline and never past the window.
    /// Deadlines 0 and `u64::MAX` give the same answer at any wall-clock time.
    #[test]
    fn hold_residual_clamps_a_stored_deadline_to_the_window() {
        let pk = test_pubkey(1);
        assert_eq!(
            residual_life(stored_hold(u64::MAX)).hold_residual(&pk, ImportKind::Local),
            Duration::from_secs(30)
        );
        assert_eq!(
            residual_life(stored_hold(0)).hold_residual(&pk, ImportKind::Local),
            Duration::ZERO
        );
    }

    /// A local key whose manager stores no deadline waits the window.
    #[test]
    fn hold_residual_uses_the_window_without_a_stored_deadline() {
        let life = residual_life(Arc::new(SpyValidatorManager::new()));
        assert_eq!(life.hold_residual(&test_pubkey(1), ImportKind::Local), Duration::from_secs(30));
    }

    // 662-AC1: a source scan of the production part of this file.

    /// Identifiers that only one production `fn` may name, and how often it
    /// names them: the enable task, the task spawn and the token insert.
    const ARMING_OWNERS: [(&str, &str, usize); 3] = [
        ("run_enable_task", "spawn_enable_task", 1),
        ("spawn", "spawn_enable_task", 1),
        ("insert", "spawn_enable_task", 1),
    ];

    /// The stored-deadline read and its clamp: only `hold_residual` names them.
    const RESIDUAL_OWNERS: [(&str, &str, usize); 2] =
        [("armed_hold_unix", "hold_residual", 1), ("clamped_hold_wait", "hold_residual", 1)];

    /// `fn` items each scan reads, each defined once.
    const ARMING_FNS: [&str; 2] = ["spawn_enable_task", "run_enable_task"];
    const RESIDUAL_FNS: [&str; 2] = ["hold_residual", "clamped_hold_wait"];

    /// What `cancel_tokens` may be followed by outside `spawn_enable_task`
    /// (whitespace removed, literals blanked): a remove or a read through a
    /// temporary guard.
    const TOKEN_TAKES: [&str; 2] = [".lock().expect().remove(", ".lock().expect().get("];

    /// The field's type and its initialiser, the only other places that may
    /// name `cancel_tokens`. A pattern cannot take either shape.
    const TOKEN_FIELD: [&str; 2] =
        [":Mutex<HashMap<Pubkey,CancellationToken>>", ":Mutex::new(HashMap::new())"];

    /// Identifiers the production part may not name: a child module, an
    /// included file or `unsafe` code could reach the private items unseen,
    /// and these map writes and blocking runs are not counted as arming.
    /// Every `spawn*` name other than `spawn` and `spawn_enable_task` is
    /// reported too.
    const FORBIDDEN: [&str; 9] = [
        "mod",
        "include",
        "unsafe",
        "entry",
        "or_insert",
        "or_insert_with",
        "or_default",
        "get_mut",
        "block_on",
    ];

    /// The macros, attributes and derives the production part may use. Any
    /// other one, `macro_rules!` included, could expand to code the scan
    /// never reads.
    const MACROS: [&str; 6] = ["error", "format", "info", "matches", "select", "thread_local"];
    const ATTRIBUTES: [&str; 4] = ["async_trait", "cfg", "derive", "must_use"];
    const DERIVES: [&str; 5] = ["Clone", "Copy", "Debug", "Eq", "PartialEq"];

    /// Words in a block header or a statement that let the code after them
    /// run later than the statement: an async block or a nested `fn`. A
    /// closure is found by its `|`.
    const DEFERRED: [&str; 2] = ["async", "fn"];

    /// Length of the block comment that opens `rest`. Block comments nest.
    fn block_comment_len(rest: &[char]) -> Option<usize> {
        let mut depth = 0usize;
        let mut at = 0;
        while let Some(pair) = rest.get(at..at + 2) {
            if pair == ['/', '*'] {
                depth += 1;
                at += 2;
            } else if pair == ['*', '/'] {
                depth -= 1;
                at += 2;
                if depth == 0 {
                    return Some(at);
                }
            } else {
                at += 1;
            }
        }
        None
    }

    /// `src` with comments and string, raw-string and char literals blanked.
    /// Newlines are kept, so line numbers do not move.
    fn code_only(src: &str) -> String {
        let chars: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0;
        while i < chars.len() {
            let rest = &chars[i..];
            let until = |from: usize, close: &[char]| {
                (from..rest.len())
                    .find(|&at| rest[at..].starts_with(close))
                    .map(|at| at + close.len())
            };
            let blank = match rest {
                ['/', '/', ..] => Some(rest.iter().position(|&c| c == '\n').unwrap_or(rest.len())),
                ['/', '*', ..] => block_comment_len(rest),
                ['"', ..] => {
                    let mut at = 1;
                    while at < rest.len() && rest[at] != '"' {
                        at += if rest[at] == '\\' { 2 } else { 1 };
                    }
                    Some(at + 1)
                }
                ['r', '#' | '"', ..] => {
                    let hashes = rest[1..].iter().take_while(|&&c| c == '#').count();
                    let close: Vec<char> =
                        std::iter::once('"').chain(std::iter::repeat_n('#', hashes)).collect();
                    if rest.get(1 + hashes) == Some(&'"') {
                        until(2 + hashes, &close)
                    } else {
                        None
                    }
                }
                ['\'', '\\', ..] => until(3, &['\'']),
                ['\'', _, '\'', ..] => Some(3),
                _ => None,
            };
            if let Some(len) = blank {
                let len = len.min(rest.len());
                out.extend(rest[..len].iter().map(|&c| if c == '\n' { '\n' } else { ' ' }));
                i += len;
            } else {
                out.push(chars[i]);
                i += 1;
            }
        }
        out
    }

    fn ident_char(c: char) -> bool {
        c == '_' || c.is_alphanumeric()
    }

    /// Byte offsets of `ident` in `code` as a whole identifier.
    fn ident_offsets<'a>(code: &'a str, ident: &'a str) -> impl Iterator<Item = usize> + 'a {
        code.match_indices(ident).map(|(at, _)| at).filter(move |&at| {
            !code[..at].ends_with(ident_char) && !code[at + ident.len()..].starts_with(ident_char)
        })
    }

    /// Whether the identifier at `at` is the name in a `fn` definition.
    fn is_definition(code: &str, at: usize) -> bool {
        code[..at].trim_end().strip_suffix("fn").is_some_and(|before| !before.ends_with(ident_char))
    }

    fn line_of(code: &str, at: usize) -> usize {
        code[..at].matches('\n').count() + 1
    }

    /// Offset just past the `}` that closes the `{` at `open`.
    fn block_end(code: &str, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (offset, c) in code[open..].char_indices() {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + offset + 1);
                }
            }
        }
        None
    }

    /// The `{` of the innermost block around `at`.
    fn block_open(code: &str, at: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (offset, c) in code[..at].char_indices().rev() {
            if c == '}' {
                depth += 1;
            } else if c == '{' {
                if depth == 0 {
                    return Some(offset);
                }
                depth -= 1;
            }
        }
        None
    }

    /// Where the statement or block header around `at` starts.
    fn statement_start(code: &str, at: usize) -> usize {
        code[..at].rfind([';', '{', '}']).map_or(0, |end| end + 1)
    }

    fn collapsed(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The statement around `at` with its whitespace collapsed, and where it ends.
    fn statement_at(code: &str, at: usize) -> (String, usize) {
        let end = code[at..].find(';').map_or(code.len(), |len| at + len);
        (collapsed(&code[statement_start(code, at)..end]), end)
    }

    /// Each identifier (or number) in `code` and its offset.
    fn idents(code: &str) -> impl Iterator<Item = (usize, &str)> + '_ {
        code.char_indices()
            .filter(move |&(at, c)| ident_char(c) && !code[..at].ends_with(ident_char))
            .map(move |(at, _)| {
                let len = code[at..].find(|c: char| !ident_char(c)).unwrap_or(code.len() - at);
                (at, &code[at..at + len])
            })
    }

    /// Keywords a `!` negation may follow. Any other identifier before a `!`
    /// that is not `!=` names a macro.
    const NEGATING_KEYWORDS: [&str; 7] = ["break", "if", "in", "match", "return", "while", "yield"];

    /// Code the scan cannot read, and writes and runs the arming rules do
    /// not count: each `FORBIDDEN` identifier, each other `spawn*` name,
    /// and each macro, attribute or derive that is not on its list.
    fn scope_violations(code: &str) -> Vec<String> {
        let mut found = Vec::new();
        for (at, ident) in idents(code) {
            let line = line_of(code, at);
            let after = code[at + ident.len()..].trim_start();
            let spawn =
                ident.starts_with("spawn") && !["spawn", "spawn_enable_task"].contains(&ident);
            let keyword = NEGATING_KEYWORDS.contains(&ident) && !code[..at].ends_with('#');
            let macro_call = after.starts_with('!') && !after.starts_with("!=") && !keyword;
            if spawn || FORBIDDEN.contains(&ident) {
                found.push(format!("line {line}: {ident} is not allowed"));
            } else if macro_call && !MACROS.contains(&ident) {
                found.push(format!("line {line}: macro {ident}! is not on the list"));
            }
        }
        for (at, _) in code.match_indices('#') {
            let rest = code[at + 1..].trim_start();
            let rest = rest.strip_prefix('!').map_or(rest, str::trim_start);
            let Some(attribute) = rest.strip_prefix('[') else {
                continue;
            };
            let attribute = &attribute[..attribute.find(']').unwrap_or(attribute.len())];
            let mut names = attribute.split(|c: char| !ident_char(c)).filter(|n| !n.is_empty());
            let line = line_of(code, at);
            match names.next() {
                Some("derive") => found.extend(
                    names
                        .filter(|name| !DERIVES.contains(name))
                        .map(|name| format!("line {line}: derive {name} is not on the list")),
                ),
                Some(name) if ATTRIBUTES.contains(&name) => {}
                name => found.push(format!(
                    "line {line}: attribute {} is not on the list",
                    name.unwrap_or_default()
                )),
            }
        }
        found
    }

    /// Whether `text` holds a closure, an async block or a nested `fn`.
    fn defers(text: &str) -> bool {
        text.contains('|') || DEFERRED.iter().any(|word| ident_offsets(text, word).next().is_some())
    }

    /// Whether the code at `at` runs while the block opened at `open` runs:
    /// no block header between them, and no part of `at`'s own statement
    /// before it, starts a closure, an async block or a nested `fn`.
    fn runs_inline(code: &str, open: usize, at: usize) -> bool {
        let mut inner = at;
        loop {
            if defers(&code[statement_start(code, inner)..inner]) {
                return false;
            }
            match block_open(code, inner) {
                Some(block) if block == open => return true,
                Some(block) => inner = block,
                None => return false,
            }
        }
    }

    /// Every `fn` item with a body: its name, and the range from `fn` through
    /// the closing `}`.
    fn fn_items(code: &str) -> Vec<(&str, std::ops::Range<usize>)> {
        ident_offsets(code, "fn")
            .filter_map(|at| {
                let name_at = at + 2 + (code[at + 2..].len() - code[at + 2..].trim_start().len());
                let len = code[name_at..].find(|c: char| !ident_char(c))?;
                let open = name_at + code[name_at..].find(['{', ';'])?;
                let body_end = (len > 0 && code[open..].starts_with('{'))
                    .then(|| block_end(code, open))
                    .flatten()?;
                Some((&code[name_at..name_at + len], at..body_end))
            })
            .collect()
    }

    /// The innermost `fn` item around `at`.
    fn owner_of<'a>(items: &[(&'a str, std::ops::Range<usize>)], at: usize) -> Option<&'a str> {
        items
            .iter()
            .filter(|(_, item)| item.contains(&at))
            .min_by_key(|(_, item)| item.len())
            .map(|&(name, _)| name)
    }

    /// The production part of `src` with literals and comments blanked. The
    /// `#[cfg(test)] mod tests` it cuts off must be the last item.
    fn production_code(src: &str, found: &mut Vec<String>) -> String {
        let Some((production, tests)) = src.split_once("#[cfg(test)]\nmod tests {") else {
            found.push("no #[cfg(test)] mod tests".into());
            return code_only(src);
        };
        let tests = code_only(&format!("{{{tests}"));
        if block_end(&tests, 0).is_none_or(|end| !tests[end..].trim().is_empty()) {
            found.push("code after the test module".into());
        }
        code_only(production)
    }

    /// Each break of the single-owner rules in `code`: a `defined` item not
    /// defined exactly once, or an `owners` identifier named outside its owner
    /// (definitions aside) or named there other than the expected number of
    /// times.
    fn owner_violations(
        code: &str,
        defined: &[&str],
        owners: &[(&str, &str, usize)],
    ) -> Vec<String> {
        let items = fn_items(code);
        let mut found = Vec::new();
        for &name in defined {
            let count = items.iter().filter(|(item, _)| *item == name).count();
            if count != 1 {
                found.push(format!("{name}: {count} definitions"));
            }
        }
        for &(ident, owner, expected) in owners {
            let mut inside = 0;
            for at in ident_offsets(code, ident).filter(|&at| !is_definition(code, at)) {
                if owner_of(&items, at) == Some(owner) {
                    inside += 1;
                } else {
                    found.push(format!("line {}: {ident} outside {owner}", line_of(code, at)));
                }
            }
            if inside != expected {
                found.push(format!("{owner}: names {ident} {inside} times, not {expected}"));
            }
        }
        found
    }

    /// The token write in `spawn_enable_task`: one `cancel_tokens` guard,
    /// bound in a block and named once more, in
    /// `if let Some(<old>) = <guard>.insert(..) { <old>.cancel(); }`, which
    /// closes before that block does (KM-2 (a)/(c)).
    fn token_guard_violations(code: &str, owner: std::ops::Range<usize>) -> Vec<String> {
        let uses: Vec<usize> =
            ident_offsets(code, "cancel_tokens").filter(|at| owner.contains(at)).collect();
        let [at] = uses[..] else {
            return vec![format!("spawn_enable_task: names cancel_tokens {} times", uses.len())];
        };
        let (statement, bound) = statement_at(code, at);
        let guard = statement
            .strip_prefix("let mut ")
            .and_then(|rest| rest.strip_suffix(" = self.cancel_tokens.lock().expect( )"))
            .filter(|guard| guard.chars().all(ident_char));
        let (Some(guard), Some(end)) =
            (guard, block_open(code, at).and_then(|o| block_end(code, o)))
        else {
            return vec![format!(
                "spawn_enable_task: cancel_tokens guard is not bound: {statement}"
            )];
        };
        let named: Vec<usize> =
            ident_offsets(&code[bound..end], guard).map(|at| bound + at).collect();
        let inserted = match named[..] {
            [at] if code[at + guard.len()..].trim_start().starts_with(".insert(") => at,
            _ => {
                return vec![format!(
                    "spawn_enable_task: guard {guard} is named {} times after its binding, \
                     not once for the insert",
                    named.len()
                )]
            }
        };
        let binding = collapsed(&code[statement_start(code, inserted)..inserted]);
        let displaced =
            binding.strip_prefix("if let Some(").and_then(|rest| rest.strip_suffix(") ="));
        let then = code[inserted..end].find('{').map(|at| inserted + at);
        let cancelled = displaced.zip(then).is_some_and(|(old, then)| {
            block_end(code, then).is_some_and(|close| {
                collapsed(&code[then..close]) == format!("{{ {old}.cancel(); }}")
            })
        });
        if cancelled {
            Vec::new()
        } else {
            vec!["spawn_enable_task: the displaced token is not cancelled under the guard".into()]
        }
    }

    /// A `spawn_enable_task` call that is not `self.spawn_enable_task(`
    /// inside the block of an earlier `let <guard> = self.lock_state();`,
    /// with the guard never named again and no closure, async block or
    /// nested `fn` between that block and the call.
    fn unlocked_arming_calls(code: &str) -> Vec<String> {
        let held = |call: usize| {
            ident_offsets(code, "lock_state").filter(|&at| at < call).any(|at| {
                let (statement, bound) = statement_at(code, at);
                let guard = statement
                    .strip_prefix("let ")
                    .and_then(|rest| rest.strip_suffix(" = self.lock_state()"))
                    .filter(|guard| *guard != "_" && guard.chars().all(ident_char));
                let open = block_open(code, at);
                let end = open.and_then(|open| block_end(code, open));
                match (guard, open, end) {
                    (Some(guard), Some(open), Some(end)) => {
                        call < end
                            && ident_offsets(&code[bound..end], guard).next().is_none()
                            && runs_inline(code, open, call)
                    }
                    _ => false,
                }
            })
        };
        let on_self = |call: usize| {
            code[..call].strip_suffix("self.").is_some_and(|before| !before.ends_with(ident_char))
        };
        ident_offsets(code, "spawn_enable_task")
            .filter(|&at| !is_definition(code, at))
            .filter_map(|at| {
                let line = line_of(code, at);
                if !on_self(at) {
                    Some(format!(
                        "line {line}: spawn_enable_task is not called as self.spawn_enable_task("
                    ))
                } else if !held(at) {
                    Some(format!("line {line}: spawn_enable_task( without state_lock"))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Each break of the arming rules (662-AC1) in the production part of `src`.
    fn arming_violations(src: &str) -> Vec<String> {
        let mut found = Vec::new();
        let code = production_code(src, &mut found);
        let items = fn_items(&code);
        found.extend(owner_violations(&code, &ARMING_FNS, &ARMING_OWNERS));
        for at in ident_offsets(&code, "cancel_tokens") {
            if owner_of(&items, at) == Some("spawn_enable_task") {
                continue;
            }
            let next: String = code[at + "cancel_tokens".len()..]
                .chars()
                .filter(|c| !c.is_whitespace())
                .take(48)
                .collect();
            let take =
                code[..at].ends_with("self.") && TOKEN_TAKES.iter().any(|t| next.starts_with(t));
            let field = TOKEN_FIELD.iter().any(|shape| next.starts_with(shape));
            if !take && !field {
                found.push(format!(
                    "line {}: cancel_tokens is not a field, remove or get",
                    line_of(&code, at)
                ));
            }
        }
        match items.iter().find(|(item, _)| *item == "spawn_enable_task") {
            Some((_, owner)) => found.extend(token_guard_violations(&code, owner.clone())),
            None => found.push("spawn_enable_task: no body".into()),
        }
        found.extend(unlocked_arming_calls(&code));
        found.extend(scope_violations(&code));
        found
    }

    /// 662-AC1: only `spawn_enable_task` inserts an enable-task token and
    /// spawns `run_enable_task`. It holds one `cancel_tokens` guard across the
    /// insert and the displaced cancel, and every caller holds `state_lock`.
    #[test]
    fn enable_task_arming_has_one_owner() {
        let violations = arming_violations(include_str!("lifecycle.rs"));
        assert!(violations.is_empty(), "{violations:#?}");
    }

    /// Each break of the residual rule (662-AC1) in the production part of `src`.
    fn residual_violations(src: &str) -> Vec<String> {
        let mut found = Vec::new();
        let code = production_code(src, &mut found);
        found.extend(owner_violations(&code, &RESIDUAL_FNS, &RESIDUAL_OWNERS));
        found.extend(scope_violations(&code));
        found
    }

    /// 662-AC1: the residual rule has one owner. Only `hold_residual` reads
    /// the stored deadline and clamps it to the window, and no code the scan
    /// cannot read could hold a copy.
    #[test]
    fn hold_residual_has_one_owner() {
        let violations = residual_violations(include_str!("lifecycle.rs"));
        assert!(violations.is_empty(), "{violations:#?}");
    }

    const ARMING_FIXTURE: &str = r##"
impl Life {
    fn spawn_enable_task(self: &Arc<Self>, pk: Pubkey, residual: Duration) {
        let token = CancellationToken::new();
        {
            let mut map = self.cancel_tokens.lock().expect("map");
            if let Some(old) = map.insert(pk, token.clone()) {
                old.cancel();
            }
        }
        let this = Arc::clone(self);
        let label = ("}", r#"a"{"#, '}', '\'', "tokio::spawn(");
        tokio::spawn(async move { this.run_enable_task(pk, token, label).await });
    }

    async fn run_enable_task(self: Arc<Self>, pk: Pubkey, token: CancellationToken) {
        // self.run_enable_task( in a comment is not a call
        self.finish(pk, token).await;
    }

    fn on_import(self: &Arc<Self>, pk: Pubkey) -> Result<(), String> {
        let _held = self.lock_state();
        /* outer /* inner */ map.insert( } */
        self.spawn_enable_task(pk, self.hold_residual(&pk));
        Ok(())
    }

    fn rearm(self: &Arc<Self>, pk: Pubkey, residual: Duration) {
        self.spawn_enable_task(pk, residual);
    }

    fn on_delete(&self, pk: &Pubkey) {
        let _held = self.lock_state();
        if let Some(old) = self.cancel_tokens.lock().expect("map").remove(pk) {
            old.cancel();
        }
    }

    fn second_arm(&self, pk: Pubkey, token: CancellationToken) {
        self.cancel_tokens.lock().expect("map").entry(pk).or_insert(token);
        tokio::task::spawn(Self::run_enable_task);
    }

    fn hold_residual(&self, pk: &Pubkey) -> Duration {
        self.vm.armed_hold_unix(pk).map_or(self.window, |at| self.clamped_hold_wait(at))
    }

    fn clamped_hold_wait(&self, at: u64) -> Duration {
        Duration::from_secs(at).min(self.window)
    }
}

#[cfg(test)]
mod tests {
    fn decoy(life: Life) {
        life.cancel_tokens.lock().unwrap().insert(pk, token);
        tokio::spawn(life.run_enable_task(pk));
    }
}
"##;

    /// The arming violations of `ARMING_FIXTURE` with `from` replaced once.
    fn fixture(from: &str, to: &str) -> Vec<String> {
        assert!(ARMING_FIXTURE.contains(from), "{from}");
        arming_violations(&ARMING_FIXTURE.replacen(from, to, 1))
    }

    fn reported(violations: Vec<String>, violation: &str) {
        assert!(violations.iter().any(|v| v == violation), "{violation}: {violations:#?}");
    }

    /// The scan cannot pass vacuously: it sees every `fn` body, the lexer
    /// blanks each literal and comment kind (nested block comments too), the
    /// test module is cut off, and each rule reports its own violation.
    #[test]
    fn arming_scan_sees_every_fn_body_in_a_fixture() {
        let mut cut = Vec::new();
        let code = production_code(ARMING_FIXTURE, &mut cut);
        assert!(cut.is_empty(), "{cut:?}");
        let items = fn_items(&code);
        let names: Vec<&str> = items.iter().map(|&(name, _)| name).collect();
        assert_eq!(
            names,
            [
                "spawn_enable_task",
                "run_enable_task",
                "on_import",
                "rearm",
                "on_delete",
                "second_arm",
                "hold_residual",
                "clamped_hold_wait",
            ]
        );
        for (name, item) in &items {
            assert!(code[item.clone()].ends_with('}'), "{name}: {}", &code[item.clone()]);
        }
        let on_import = items.iter().find(|(name, _)| *name == "on_import").expect("on_import");
        assert!(
            code[on_import.1.clone()].contains("Ok(())"),
            "a nested comment ends at its own */"
        );
        assert_eq!(
            arming_violations(ARMING_FIXTURE),
            [
                "line 41: run_enable_task outside spawn_enable_task",
                "line 41: spawn outside spawn_enable_task",
                "line 40: cancel_tokens is not a field, remove or get",
                "line 29: spawn_enable_task( without state_lock",
                "line 40: entry is not allowed",
                "line 40: or_insert is not allowed",
            ]
        );
        let residual = owner_violations(&code, &RESIDUAL_FNS, &RESIDUAL_OWNERS);
        assert!(residual.is_empty(), "{residual:?}");

        let guard = "                old.cancel();\n            }\n";
        reported(
            fixture(guard, "            }\n"),
            "spawn_enable_task: the displaced token is not cancelled under the guard",
        );
        reported(
            fixture(
                "        {\n            let mut map = self.cancel_tokens.lock().expect(\"map\");\n            \
                 if let Some(old) = map.insert(pk, token.clone()) {\n                old.cancel();\n            \
                 }\n        }\n",
                "        let old = {\n            let mut map = self.cancel_tokens.lock().expect(\"map\");\n            \
                 map.insert(pk, token.clone())\n        };\n        if let Some(old) = old {\n            \
                 old.cancel();\n        }\n",
            ),
            "spawn_enable_task: the displaced token is not cancelled under the guard",
        );
        reported(
            fixture(
                "                old.cancel();\n",
                "                drop(map);\nold.cancel();\n",
            ),
            "spawn_enable_task: guard map is named 2 times after its binding, not once for the \
             insert",
        );
        reported(
            fixture(
                "            let mut map = self.cancel_tokens.lock().expect(\"map\");\n            if \
                 let Some(old) = map.insert(pk, token.clone()) {",
                "            if let Some(old) = \
                 self.cancel_tokens.lock().expect(\"map\").insert(pk, token.clone()) {",
            ),
            "spawn_enable_task: cancel_tokens guard is not bound: if let Some(old) = \
             self.cancel_tokens.lock().expect( ).insert(pk, token.clone()) { old.cancel()",
        );
        reported(
            fixture(
                "        let this =",
                "        self.cancel_tokens.lock().expect(\"\");\nlet this =",
            ),
            "spawn_enable_task: names cancel_tokens 2 times",
        );
        reported(
            fixture("        let _held = self.lock_state();\n        /*", "        /*"),
            "line 23: spawn_enable_task( without state_lock",
        );
        reported(
            fixture(
                "let _held = self.lock_state();\n        /*",
                "let _ = self.lock_state();\n        /*",
            ),
            "line 24: spawn_enable_task( without state_lock",
        );
        reported(
            fixture("        /* outer", "        drop(_held);\n        /* outer"),
            "line 25: spawn_enable_task( without state_lock",
        );
        reported(
            fixture("        tokio::spawn(async", "        (async"),
            "spawn_enable_task: names spawn 0 times, not 1",
        );
        reported(
            fixture("    fn rearm(", "    fn spawn_enable_task() {}\n    fn rearm("),
            "spawn_enable_task: 2 definitions",
        );
        reported(
            fixture("    async fn run_enable_task(", "    async fn run_enable_task_v2("),
            "run_enable_task: 0 definitions",
        );
        reported(
            fixture("    fn spawn_enable_task(", "    fn spawn_enable_task_v2("),
            "spawn_enable_task: no body",
        );
        reported(
            fixture(
                "            let mut map",
                "            map.insert(pk, token.clone());\nlet mut map",
            ),
            "spawn_enable_task: names insert 2 times, not 1",
        );
        reported(
            arming_violations(&format!("{ARMING_FIXTURE}fn after_tests() {{}}\n")),
            "code after the test module",
        );
        reported(arming_violations("fn spawn_enable_task() {}"), "no #[cfg(test)] mod tests");
        assert_eq!(
            owner_violations(
                &code,
                &["hold_residual", "rearm_v2"],
                &[("clamped_hold_wait", "hold_residual", 1), ("armed_hold_unix", "on_import", 1)]
            ),
            [
                "rearm_v2: 0 definitions",
                "line 45: armed_hold_unix outside on_import",
                "on_import: names armed_hold_unix 0 times, not 1",
            ]
        );
    }

    /// The shapes the PR #952 R1 reviews found the scan missing, one fixture
    /// each: code the scan cannot read (Z1-Z3, Z5, Z6), a destructured field
    /// (Z5), arming that runs after `state_lock` drops (Z7, P15), and a
    /// displaced cancel that runs after the guard drops or names another
    /// token (Z4, Z8).
    #[test]
    fn arming_scan_reports_each_known_bypass() {
        for (item, violation) in [
            ("mod rearm_path;", "line 2: mod is not allowed"),
            ("#[path = \"arm.rs\"] mod arm;", "line 2: attribute path is not on the list"),
            ("include!(\"lifecycle_arm.rs\");", "line 2: include is not allowed"),
            ("macro_rules! arm { () => {}; }", "line 2: macro macro_rules! is not on the list"),
            ("fn arm() { arm!(); }", "line 2: macro arm! is not on the list"),
            ("fn arm() { r#if!(); }", "line 2: macro if! is not on the list"),
            ("#[arm] fn arm() {}", "line 2: attribute arm is not on the list"),
            ("#![arm]", "line 2: attribute arm is not on the list"),
            ("#[derive(Debug, Arm)] struct Arm;", "line 2: derive Arm is not on the list"),
            ("unsafe fn arm() {}", "line 2: unsafe is not allowed"),
            ("fn arm(m: M) { m.entry(K); }", "line 2: entry is not allowed"),
            ("fn arm(e: E) { e.or_insert(V); }", "line 2: or_insert is not allowed"),
            ("fn arm(e: E) { e.or_insert_with(V); }", "line 2: or_insert_with is not allowed"),
            ("fn arm(e: E) { e.or_default(); }", "line 2: or_default is not allowed"),
            ("fn arm(m: M) { m.get_mut(K); }", "line 2: get_mut is not allowed"),
            ("fn arm(h: H) { h.block_on(F); }", "line 2: block_on is not allowed"),
            (
                "fn arm() { tokio::task::spawn_blocking(F); }",
                "line 2: spawn_blocking is not allowed",
            ),
            ("fn arm() { tokio::task::spawn_local(F); }", "line 2: spawn_local is not allowed"),
        ] {
            reported(fixture("impl Life {", &format!("{item}\nimpl Life {{")), violation);
        }
        reported(
            residual_violations(&ARMING_FIXTURE.replacen(
                "impl Life {",
                "mod copy;\nimpl Life {",
                1,
            )),
            "line 2: mod is not allowed",
        );

        assert_eq!(
            fixture(
                "#[cfg(test)]",
                "struct Life {\n    cancel_tokens: Mutex<HashMap<Pubkey, CancellationToken>>,\n}\n\
                 impl Life {\n    fn new() -> Self {\n        \
                 Self { cancel_tokens: Mutex::new(HashMap::new()) }\n    }\n}\n\
                 #[derive(Clone, Copy, Debug, Eq, PartialEq)]\nstruct Shape;\n\
                 #[must_use]\nfn negated(map: u8, b: bool) -> bool {\n    \
                 if !b && map != 0 {\n        return !b;\n    }\n    matches!(map, 1)\n}\n\
                 #[cfg(test)]",
            ),
            arming_violations(ARMING_FIXTURE),
            "the field, its initialiser, the listed derives, macros and attributes, a `!=`, \
             a negation, and the guard's name outside its block are allowed"
        );
        reported(
            fixture(
                "        if let Some(old) = self.cancel_tokens.lock().expect(\"map\").remove(pk) {",
                "        let Self { cancel_tokens: map, .. } = self;\n        \
                 if let Some(old) = map.lock().expect(\"map\").remove(pk) {",
            ),
            "line 34: cancel_tokens is not a field, remove or get",
        );

        let rearm = "        self.spawn_enable_task(pk, residual);\n    }\n\n    fn on_delete";
        let guarded = |arm: &str| {
            fixture(
                rearm,
                &format!(
                    "        let arm = {{\n            let _held = self.lock_state();\n            \
                     {arm}\n        }};\n        arm();\n    }}\n\n    fn on_delete"
                ),
            )
        };
        let inline = guarded("self.spawn_enable_task(pk, residual)");
        assert!(!inline.iter().any(|v| v.contains("without state_lock")), "{inline:#?}");
        for arm in [
            "move || self.spawn_enable_task(pk, residual)",
            "async move { self.spawn_enable_task(pk, residual) }",
            "impl Life { fn arm(self: &Arc<Self>) { self.spawn_enable_task(PK, R) } }",
        ] {
            reported(guarded(arm), "line 31: spawn_enable_task( without state_lock");
        }
        for receiver in ["this.", "myself.", "Self::"] {
            reported(
                fixture(
                    "        self.spawn_enable_task(pk, self.hold_residual(&pk));",
                    &format!("        {receiver}spawn_enable_task(pk, self.hold_residual(&pk));"),
                ),
                "line 24: spawn_enable_task is not called as self.spawn_enable_task(",
            );
        }

        let cancel =
            "            if let Some(old) = map.insert(pk, token.clone()) {\n                \
             old.cancel();\n            }\n        }\n";
        for split in [
            "            old = map.insert(pk, token.clone());\n            \
             CancellationToken::new().cancel();\n        }\n        \
             if let Some(old) = old {\n            old.cancel();\n        }\n",
            "            cancel = map\n                .insert(pk, token.clone())\n                \
             .and_then(|old| Some(move || old.cancel()));\n        }\n",
            "            if let Some(old) = map.insert(pk, token.clone()) {\n                \
             token.cancel();\n            }\n        }\n",
        ] {
            reported(
                fixture(cancel, split),
                "spawn_enable_task: the displaced token is not cancelled under the guard",
            );
        }
    }
}
