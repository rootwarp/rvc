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
        let cancel_token = CancellationToken::new();
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

        // SF-3 / KM-2 (a): register the cancellation token. If a token was
        // already present for this pubkey (e.g. a stale task from a prior import
        // that a racing delete had not yet cancelled), cancel the DISPLACED token
        // so it can never enable a key that is now inside a fresh window. No
        // token is ever dropped from the map without being cancelled.
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
        // Sleep until the stored deadline, and no longer than the window.
        // Capture the `Instant` before spawn so a paused test clock still
        // sees a fixed deadline.
        let residual = if kind == ImportKind::Local {
            match self.validator_manager.armed_hold_unix(&pubkey) {
                Some(stored) => self.clamped_hold_wait(stored),
                None => self.window,
            }
        } else {
            self.window
        };
        let deadline = tokio::time::Instant::now() + residual;
        tokio::spawn(async move {
            this.run_enable_task(pubkey, kind, token, deadline, pubkey_hex).await;
        });
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
        if let Some(token) =
            self.cancel_tokens.lock().expect("cancel_tokens poisoned").remove(pubkey)
        {
            token.cancel();
        }

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
                                    let residual =
                                        match self.validator_manager.armed_hold_unix(&pubkey) {
                                            Some(stored) => self.clamped_hold_wait(stored),
                                            None => self.window,
                                        };
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

    /// Caller holds `state_lock`. The spawned task is built in this sync fn.
    fn spawn_enable_task(self: &Arc<Self>, pubkey: Pubkey, kind: ImportKind, residual: Duration) {
        let cancel_token = CancellationToken::new();
        {
            let mut tokens = self.cancel_tokens.lock().expect("cancel_tokens poisoned");
            if let Some(displaced) = tokens.insert(pubkey, cancel_token.clone()) {
                displaced.cancel();
            }
        }
        let this = Arc::clone(self);
        let token = cancel_token;
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let deadline = tokio::time::Instant::now() + residual;
        tokio::spawn(async move {
            this.run_enable_task(pubkey, kind, token, deadline, pubkey_hex).await;
        });
    }

    /// Re-arm a hold that was already persisted. Does not write the validators file.
    pub fn rearm_persisted_hold(
        self: &Arc<Self>,
        pubkey: Pubkey,
        residual: Duration,
    ) -> Result<(), String> {
        let cancel_token = CancellationToken::new();
        let _guard = self.lock_state();
        self.monitor.start_monitoring(pubkey);
        {
            let mut tokens = self.cancel_tokens.lock().expect("cancel_tokens poisoned");
            if let Some(displaced) = tokens.insert(pubkey, cancel_token.clone()) {
                displaced.cancel();
            }
        }
        let this = Arc::clone(self);
        let token = cancel_token;
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let deadline = tokio::time::Instant::now() + residual;
        tokio::spawn(async move {
            this.run_enable_task(pubkey, ImportKind::Local, token, deadline, pubkey_hex).await;
        });
        Ok(())
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

        life.rearm_persisted_hold(pk, Duration::from_secs(30)).expect("re-arm");
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
}
