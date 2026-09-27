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
//!   `set_validator_enabled(false)` and cancel-token remove/cancel. No `.await`.
//! - **delete** ([`Self::on_delete`]): holds the lock across the caller's remove
//!   operation + unconditional cancel-token remove/cancel, and on success across
//!   `remove_validator` (Local) + `cancel_monitoring` (PRD §KM-2 (b)+(Finding 3)).
//! - **spawned enable task** (timer branch): acquires the lock after
//!   `sleep_until` resolves, re-checks `is_cancelled()` under the lock before
//!   enabling, then holds it across `set_validator_enabled` (Local) +
//!   `stop_monitoring` + cancel-token self-prune (PRD §KM-2 (c)+(Finding 1+2)).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use observability::logging::TruncatedPubkey;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::traits::{DoppelgangerMonitor, Pubkey, QuiesceError, SigningQuiesce, ValidatorManager};

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
    pub fn disable_for_delete(&self, pubkey: &Pubkey) {
        let _guard = self.state_lock.lock().expect("doppelganger state_lock poisoned");
        self.validator_manager.set_validator_enabled(pubkey, false);
        if let Some(token) =
            self.cancel_tokens.lock().expect("cancel_tokens poisoned").remove(pubkey)
        {
            token.cancel();
        }
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
    pub fn on_import(self: &Arc<Self>, pubkey: Pubkey, kind: ImportKind) {
        let cancel_token = CancellationToken::new();
        let _guard = self.state_lock.lock().expect("doppelganger state_lock poisoned");

        if kind == ImportKind::Local {
            self.validator_manager.add_validator(pubkey, false);
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
        let window = self.window;
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        // Capture the deadline NOW (before spawn) so that `sleep_until(deadline)`
        // resolves correctly even when the tokio mock clock is paused in tests:
        // the deadline is a fixed instant, not a relative duration computed at
        // first-poll time.
        let deadline = tokio::time::Instant::now() + window;
        tokio::spawn(async move {
            this.run_enable_task(pubkey, kind, token, deadline, pubkey_hex).await;
        });
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
    /// - both kinds: [`DoppelgangerMonitor::cancel_monitoring`]
    pub fn on_delete<T>(
        &self,
        pubkey: &Pubkey,
        kind: ImportKind,
        remove_op: impl FnOnce() -> (bool, T),
    ) -> T {
        let _guard = self.state_lock.lock().expect("doppelganger state_lock poisoned");
        let (removed, value) = remove_op();

        // KM-2 Finding 3: cancel any live token unconditionally.
        if let Some(token) =
            self.cancel_tokens.lock().expect("cancel_tokens poisoned").remove(pubkey)
        {
            token.cancel();
        }

        if removed {
            if kind == ImportKind::Local {
                self.validator_manager.remove_validator(pubkey);
            }
            // DELETE: hard-cancel forward-window / gate state so a re-import
            // starts a fresh monitoring window (KM-2).
            self.monitor.cancel_monitoring(pubkey);
        }

        value
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
                // KM-2 (Finding 1+2): the sleep branch and a concurrent cancel()
                // can both be ready in the same scheduler tick; `select!` does
                // not prioritize cancelled().  Re-check cancellation under
                // `state_lock` so the enable is serialised against a concurrent
                // displacement.  The `sleep_until` future has already resolved,
                // so no std-Mutex is held across any `.await`.
                let _g = self.state_lock.lock().expect("doppelganger state_lock poisoned");
                // Displaced: a delete or re-import cancelled our token under the
                // same lock — never enable.
                if token.is_cancelled() {
                    return;
                }
                if kind == ImportKind::Local {
                    self.validator_manager.set_validator_enabled(&pubkey, true);
                }
                // SF-4 / SEC-2b: prune wall-clock pending only.
                // Must NOT cancel ForwardWindowMachine state —
                // M-12 elapsed ≠ forward-window satisfied.
                self.monitor.stop_monitoring(&pubkey);
                // KM-2 (c): prune our OWN cancel-token entry now that the window
                // has elapsed.  We hold `state_lock` here, consistent with the
                // lock-ordering invariant (outer lock, then cancel_tokens).
                self.cancel_tokens
                    .lock()
                    .expect("cancel_tokens poisoned")
                    .remove(&pubkey);
                info!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    "Doppelganger window elapsed; enabling validator for attestation"
                );
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

    /// Snapshot the cancel-token currently registered for `pubkey` (tests).
    pub fn current_cancel_token(&self, pubkey: &Pubkey) -> Option<CancellationToken> {
        self.cancel_tokens.lock().expect("cancel_tokens poisoned").get(pubkey).cloned()
    }
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
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
            self.state.lock().unwrap().insert(pubkey, enabled);
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> bool {
            self.state.lock().unwrap().remove(pubkey).is_some()
        }

        fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
            if let Some(v) = self.state.lock().unwrap().get_mut(pubkey) {
                *v = enabled;
            }
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

        life.on_import(pk, ImportKind::Remote);

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

        life.on_import(pk, ImportKind::Local);
        let t1 = life.current_cancel_token(&pk).expect("T1 after first import");
        assert!(!t1.is_cancelled());

        life.on_import(pk, ImportKind::Local);
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

        life.on_import(pk, ImportKind::Local);
        let t1 = life.current_cancel_token(&pk).expect("token after import");
        assert!(vm.is_tracked(&pk));
        assert!(!gate.is_doppelganger_safe(&pk));

        let removed = life.on_delete(&pk, ImportKind::Local, || (true, true));
        assert!(removed);
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

        life.on_import(pk, ImportKind::Local);
        // Advance past the original deadline so the enable task's sleep is ready,
        // then displace before the task is polled (Finding 1+2).
        tokio::time::advance(window + Duration::from_secs(1)).await;

        life.on_delete(&pk, ImportKind::Local, || (true, ()));
        life.on_import(pk, ImportKind::Local);

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

        life.on_import(pk, ImportKind::Local);
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

        life.on_import(pk, ImportKind::Local);
        assert!(!vm.is_enabled(&pk));
        assert!(life.current_cancel_token(&pk).is_some());

        tokio::time::advance(window + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(vm.is_enabled(&pk));
        assert!(life.current_cancel_token(&pk).is_none());
    }
}
