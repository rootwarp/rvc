//! Single key-admission choke point (ADR-007 / ARCH-2b).
//!
//! Both secret-provider refresh and keymanager import will call
//! [`KeyAdmissionService::admit`] so every admitted key reaches
//! `CompositeSigner`, `PubkeyMap`, `ValidatorStore`, doppelganger registration,
//! and the orchestrator generation counter.
//!
//! `withdraw` is intentionally absent here (Phase 7 / A-1.4 / C5).

use std::path::PathBuf;
use std::sync::Arc;

use crypto::{CompositeSigner, SecretKey};
use doppelganger::{ForwardWindowMachine, MonotonicEpochClock};
use observability::logging::TruncatedPubkey;
use thiserror::Error;
use tokio::sync::watch;
use tracing::info;
use validator_store::{ValidatorConfig, ValidatorStore};

use crate::deletion_denylist::DeletionDenylist;
use crate::keymanager_adapters::KeyChangeNotifier;
use crate::orchestrator::PubkeyMap;

/// Where an admitted key came from.
///
/// [`AdmissionSource::RawSecret`] is a first-class mode (C4): no keystore file
/// on disk and no denylist row to persist. Filesystem persistence (if any) is
/// the caller's responsibility (keymanager adapter), never this service.
#[derive(Debug, Clone)]
pub enum AdmissionSource {
    /// Keymanager import: a keystore exists and is persisted by the adapter.
    ///
    /// `doppelganger_hold_until` is set for a windowed import. Admit then
    /// writes `enabled = false` and that deadline in one update before the
    /// signer is published. `None` keeps the enabled row (window zero, or a
    /// caller that does not hold the key).
    Keystore { keystore_path: PathBuf, doppelganger_hold_until: Option<u64> },
    /// Secret-provider refresh: raw `SecretKey` from a cloud secret manager.
    RawSecret,
}

/// Result of a successful [`KeyAdmissionService::admit`] call.
///
/// Denylist skips and idempotent re-admits are outcomes, not errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// Key was fully admitted; `key_gen` is the post-bump generation counter.
    ///
    /// `inserted_row` is true only when this call created the validators-file
    /// row. A pre-existing row is left in place.
    Admitted { pubkey: [u8; 48], key_gen: u64, inserted_row: bool },
    /// Denylist re-check fired (DELETE-races-refresh guard). Not an error.
    SkippedDenylisted { pubkey: [u8; 48] },
    /// Already present in `PubkeyMap`; idempotent no-op (no generation bump).
    AlreadyPresent { pubkey: [u8; 48] },
}

/// Fallible admission failures.
///
/// The happy path and denylist skip return [`AdmissionOutcome`]. Variants exist
/// for future fallible store updates; callers must still handle `Err`.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// Invariant violated during multi-store admission (should be rare).
    #[error("key admission invariant violated: {0}")]
    Invariant(&'static str),
    /// The validators file could not be updated. Memory was rolled back.
    #[error("validator config persist failed: {0}")]
    Persist(String),
}

/// Single multi-store key admission path (ADR-007).
///
/// [`KeyChangeNotifier`] is retained as an internal collaborator for
/// `PubkeyMap` + generation-counter access; it is not widened.
pub struct KeyAdmissionService {
    notifier: KeyChangeNotifier,
    /// Clone of the notifier's sender so `Admitted.key_gen` can be read after
    /// the last-step bump without widening [`KeyChangeNotifier`].
    key_gen_tx: watch::Sender<u64>,
    composite_signer: Arc<CompositeSigner>,
    validator_store: Arc<ValidatorStore>,
    denylist: Arc<DeletionDenylist>,
    machine: Option<Arc<ForwardWindowMachine>>,
    epoch_clock: Arc<MonotonicEpochClock>,
    /// Test pause after the pubkey-map insert and before the generation bump.
    #[cfg(test)]
    after_map_insert: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl KeyAdmissionService {
    /// Bind the admission service to process-wide stores.
    pub fn new(
        pubkey_map: PubkeyMap,
        key_gen_tx: watch::Sender<u64>,
        composite_signer: Arc<CompositeSigner>,
        validator_store: Arc<ValidatorStore>,
        denylist: Arc<DeletionDenylist>,
        machine: Option<Arc<ForwardWindowMachine>>,
        epoch_clock: Arc<MonotonicEpochClock>,
    ) -> Self {
        Self {
            notifier: KeyChangeNotifier::new(pubkey_map, key_gen_tx.clone()),
            key_gen_tx,
            composite_signer,
            validator_store,
            denylist,
            machine,
            epoch_clock,
            #[cfg(test)]
            after_map_insert: std::sync::Mutex::new(None),
        }
    }

    /// Run `hook` once, after the next admit inserts the pubkey map entry.
    ///
    /// The hook fires before the generation bump, so a test can hold a refresh
    /// between those two steps.
    #[cfg(test)]
    pub(crate) fn pause_once_after_map_insert(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.after_map_insert.lock().unwrap_or_else(|poison| poison.into_inner()) =
            Some(Arc::new(hook));
    }

    /// Drop forward-window state for a key just removed from the signer.
    ///
    /// Takes only the machine mutex, not the doppelganger lifecycle lock.
    /// Callers already holding `tracked_keys` keep that order: this mutex is
    /// the same one [`ForwardWindowMachine::register_for_import`] takes.
    /// Whether `pubkey` is already in the duty map.
    pub(crate) fn pubkey_is_present(&self, pubkey: &[u8; 48]) -> bool {
        self.notifier.pubkey_map().read().contains_key(pubkey)
    }

    /// Persist a windowed keystore row while its key file is still `.partial`.
    ///
    /// Returns whether this call inserted the row. An existing enabled row
    /// gains the hold. A plain disable is left alone and returns `Ok(false)`.
    pub(crate) fn persist_keystore_hold(
        &self,
        pubkey: &[u8; 48],
        until: u64,
    ) -> Result<bool, AdmissionError> {
        let mut config = ValidatorConfig::new(*pubkey);
        config.enabled = false;
        config.doppelganger_hold_until = Some(until);
        match self.validator_store.add_validator_durable(config) {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.validator_store
                    .begin_doppelganger_hold(pubkey, until)
                    .map_err(|e| AdmissionError::Persist(e.to_string()))?;
                Ok(false)
            }
            Err(e) => Err(AdmissionError::Persist(e.to_string())),
        }
    }

    pub fn cancel_forward_window(&self, pubkey: &[u8; 48]) {
        let Some(machine) = &self.machine else {
            return;
        };
        let Ok(pk) = crypto::PublicKey::from_bytes(pubkey) else {
            return;
        };
        machine.cancel(&pk);
    }

    /// Admit `secret` into every store that must observe a live key.
    ///
    /// Order (generation bump **last** so no orchestrator wake sees a
    /// half-populated set):
    /// 1. denylist re-check (`RawSecret` only — DELETE-races-refresh)
    /// 2. for a windowed keystore import, the disabled hold row
    /// 3. composite signer (`add_local_key`)
    /// 4. `PubkeyMap`
    /// 5. `ValidatorStore` when step 2 did not already write the row
    /// 6. denylist re-check again (TOCTOU: DELETE may have raced the mutations)
    /// 7. doppelganger `register_for_import` (when enabled)
    /// 8. `key_gen_tx` bump
    ///
    /// # Synchronous by necessity
    ///
    /// This method is **synchronous** (not `async`) so it is usable from
    /// `RefreshService::run<F>(…, on_new_key: F) where F: FnMut(SecretKey) -> bool` —
    /// a non-`async` bound (`crates/secret-provider`). Every store touched is
    /// `parking_lot` / `watch`-guarded and synchronously updatable. The
    /// rejected alternative is changing `RefreshService`'s bound to an async
    /// callback (a `secret-provider` API break).
    ///
    /// # C4 — keystore-less admission
    ///
    /// [`AdmissionSource::RawSecret`] performs **no** filesystem write and
    /// requires no denylist row. Writing a synthetic keystore, or failing when
    /// no keystore path is present, is explicitly rejected.
    ///
    /// # Denylist and [`AdmissionSource::Keystore`]
    ///
    /// Intentional keymanager re-import is the authorized recovery path and
    /// clears the denylist *after* successful persistence (SEC-1b). The
    /// denylist guard therefore applies only to [`AdmissionSource::RawSecret`]
    /// (provider refresh / boot resurrection races), not to keystore import.
    pub fn admit(
        &self,
        secret: SecretKey,
        source: AdmissionSource,
    ) -> Result<AdmissionOutcome, AdmissionError> {
        let public_key = secret.public_key();
        let pubkey = public_key.to_bytes();
        let source_label = match &source {
            AdmissionSource::RawSecret => "raw_secret",
            AdmissionSource::Keystore { .. } => "keystore",
        };
        let enforce_denylist = matches!(source, AdmissionSource::RawSecret);

        // 1. Early denylist re-check (DELETE-races-refresh). Skip is not Err.
        if enforce_denylist && self.denylist.contains(&pubkey) {
            return Ok(Self::skipped_denylisted(pubkey, source_label));
        }

        // Idempotent no-op: already in the duty-matching map.
        if self.notifier.pubkey_map().read().contains_key(&pubkey) {
            return Ok(AdmissionOutcome::AlreadyPresent { pubkey });
        }

        // Re-check immediately before the first mutation (narrow TOCTOU window).
        if enforce_denylist && self.denylist.contains(&pubkey) {
            return Ok(Self::skipped_denylisted(pubkey, source_label));
        }

        let hold_until = match &source {
            AdmissionSource::Keystore { doppelganger_hold_until, .. } => *doppelganger_hold_until,
            AdmissionSource::RawSecret => None,
        };

        // A windowed keystore import persists `enabled = false` and the hold
        // before the signer exists. A failed write leaves the signer absent
        // and does not publish an enabled row.
        let mut inserted_row = false;
        if let Some(until) = hold_until {
            let mut config = ValidatorConfig::new(pubkey);
            config.enabled = false;
            config.doppelganger_hold_until = Some(until);
            match self.validator_store.add_validator_durable(config) {
                Ok(true) => inserted_row = true,
                Ok(false) => {
                    // The row already exists. An enabled row must gain the
                    // hold before the signer is live. A plain disable is left
                    // alone (`Ok(false)` from begin).
                    self.validator_store
                        .begin_doppelganger_hold(&pubkey, until)
                        .map_err(|e| AdmissionError::Persist(e.to_string()))?;
                }
                Err(e) => return Err(AdmissionError::Persist(e.to_string())),
            }
        }

        // 3. Composite signer
        self.composite_signer.add_local_key(secret);

        // 4. PubkeyMap (no generation bump yet)
        self.notifier.pubkey_map().write().insert(pubkey, public_key.clone());

        #[cfg(test)]
        if let Some(hook) =
            self.after_map_insert.lock().unwrap_or_else(|poison| poison.into_inner()).take()
        {
            hook();
        }

        // 5. ValidatorStore, when this import is not already a hold.
        // Insert only when the pubkey is absent, inside `save_lock`, so a
        // slashed `enabled = false` is not replaced. A failed write publishes
        // nothing; roll the signer and map back too.
        if hold_until.is_none() {
            inserted_row =
                match self.validator_store.add_validator_durable(ValidatorConfig::new(pubkey)) {
                    Ok(inserted) => inserted,
                    Err(e) => {
                        let _ = self.composite_signer.remove_local_key(&pubkey);
                        self.notifier.pubkey_map().write().remove(&pubkey);
                        return Err(AdmissionError::Persist(e.to_string()));
                    }
                };
        }

        // 6. Final denylist re-check before irreversible notify / doppelganger.
        // If DELETE won the race after mutations, roll back only what this
        // admission inserted.
        if enforce_denylist && self.denylist.contains(&pubkey) {
            self.revoke_failed_import(&pubkey, inserted_row);
            return Ok(Self::skipped_denylisted(pubkey, source_label));
        }

        // 7. Doppelganger import registration (optional machine)
        if let Some(ref machine) = self.machine {
            machine.register_for_import(&public_key, self.epoch_clock.current_epoch());
        }

        // 8. Generation bump last
        self.notifier.notify();
        let key_gen = *self.key_gen_tx.borrow();

        info!(
            pubkey = %TruncatedPubkey::new(&format!("0x{}", hex::encode(pubkey))),
            source = source_label,
            key_gen,
            "Admitted key"
        );

        Ok(AdmissionOutcome::Admitted { pubkey, key_gen, inserted_row })
    }

    /// Drop signer and map state. Does not change the validators row.
    ///
    /// The key generation is bumped so duty caches drop the unpublished key.
    pub fn unpublish_failed_import(&self, pubkey: &[u8; 48]) {
        let _ = self.composite_signer.remove_local_key(pubkey);
        self.notifier.pubkey_map().write().remove(pubkey);
        self.cancel_forward_window(pubkey);
        self.notifier.notify();
    }

    /// Drop signer and map state for an import that must not stay live.
    ///
    /// The validators row is removed only when `inserted_row` is set: a
    /// pre-existing operator or slashing disable is left in place. The key
    /// generation is always bumped so duty caches drop the unpublished key.
    /// Keystore rollback does not use this for the row: it unpublishes, unlinks
    /// the keystore, and only then removes an inserted row.
    pub fn revoke_failed_import(&self, pubkey: &[u8; 48], inserted_row: bool) {
        self.unpublish_failed_import(pubkey);
        if inserted_row {
            self.remove_inserted_row(pubkey);
        }
    }

    /// After the keystore files are gone, drop a row this import inserted.
    ///
    /// When the unlink did not stick, leave `enabled = false` with no hold so
    /// boot cannot treat the still-present keystore as a new enabled key.
    /// Returns whether the disable listener still has to run.
    ///
    /// The listener takes the doppelganger `state_lock`. Callers holding
    /// `tracked_keys` must drop that lock before [`Self::run_disable_listener`].
    pub(crate) fn finish_keystore_rollback(
        &self,
        pubkey: &[u8; 48],
        inserted_row: bool,
        files_gone: bool,
    ) -> bool {
        if files_gone {
            if inserted_row {
                self.remove_inserted_row(pubkey);
            }
            return false;
        }
        let held = self
            .validator_store
            .get_config(pubkey)
            .and_then(|cfg| cfg.doppelganger_hold_until)
            .is_some();
        if inserted_row || held || !self.validator_store.has_validator(pubkey) {
            return self.keep_disabled_tombstone(pubkey);
        }
        false
    }

    /// Run a disable listener owed by [`Self::finish_keystore_rollback`].
    ///
    /// The caller must already have released `tracked_keys`.
    pub(crate) fn run_disable_listener(&self, pubkey: &[u8; 48]) {
        self.validator_store.run_disable_listener(pubkey);
    }

    fn remove_inserted_row(&self, pubkey: &[u8; 48]) {
        if let Err(e) = self.validator_store.remove_validator_durable(pubkey) {
            tracing::warn!(
                error = %e,
                pubkey = %TruncatedPubkey::new(&format!("0x{}", hex::encode(pubkey))),
                "failed to persist validator removal after a failed keystore import"
            );
        }
    }

    /// A renamed keystore could not be removed after `AlreadyPresent`.
    ///
    /// Inserts `enabled = false` with no hold when this import has no row.
    /// A row this import inserted becomes that tombstone. A row another
    /// admission owns is left in place. Returns whether the disable listener
    /// still has to run.
    pub(crate) fn tombstone_late_duplicate(&self, pubkey: &[u8; 48], inserted_row: bool) -> bool {
        if self.validator_store.has_validator(pubkey) && !inserted_row {
            return false;
        }
        self.keep_disabled_tombstone(pubkey)
    }

    /// Persist the tombstone. The bool means the disable listener still has to run.
    fn keep_disabled_tombstone(&self, pubkey: &[u8; 48]) -> bool {
        if !self.validator_store.has_validator(pubkey) {
            let mut config = ValidatorConfig::new(*pubkey);
            config.enabled = false;
            if let Err(e) = self.validator_store.add_validator_durable(config) {
                tracing::warn!(
                    error = %e,
                    pubkey = %TruncatedPubkey::new(&format!("0x{}", hex::encode(pubkey))),
                    "failed to persist a disabled tombstone after a keystore unlink failure"
                );
            }
            return false;
        }
        let (result, fire) = self.validator_store.persist_signing_disable(pubkey);
        if let Err(e) = result {
            tracing::warn!(
                error = %e,
                pubkey = %TruncatedPubkey::new(&format!("0x{}", hex::encode(pubkey))),
                "failed to persist a disabled tombstone after a keystore unlink failure"
            );
        }
        fire
    }

    fn skipped_denylisted(pubkey: [u8; 48], source_label: &str) -> AdmissionOutcome {
        info!(
            pubkey = %TruncatedPubkey::new(&format!("0x{}", hex::encode(pubkey))),
            source = source_label,
            "Skipping denylisted key at admission (DELETE raced refresh)"
        );
        AdmissionOutcome::SkippedDenylisted { pubkey }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use crypto::{KeyManager, LocalSigner};
    use doppelganger::ForwardWindowStatus;
    use slashing::SlashingDb;
    use tempfile::TempDir;

    /// Serialize CWD mutations across tests in this module.
    fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    struct Harness {
        service: KeyAdmissionService,
        pubkey_map: PubkeyMap,
        validator_store: Arc<ValidatorStore>,
        composite_signer: Arc<CompositeSigner>,
        denylist: Arc<DeletionDenylist>,
        key_gen_rx: watch::Receiver<u64>,
        machine: Option<Arc<ForwardWindowMachine>>,
        _denylist_dir: TempDir,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_machine(false)
        }

        fn with_machine(enable_machine: bool) -> Self {
            let denylist_dir = TempDir::new().expect("denylist tempdir");
            let denylist =
                Arc::new(DeletionDenylist::empty_at(denylist_dir.path().join(".rvc.deleted_keys")));
            let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
            let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
            let composite_signer =
                Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
            let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
            let epoch_clock = Arc::new(MonotonicEpochClock::new(0));
            let machine = if enable_machine {
                let db: Arc<dyn slashing::SlashingDbReader> =
                    Arc::new(SlashingDb::open_in_memory().expect("in-memory slashing db"));
                Some(Arc::new(ForwardWindowMachine::new(db, 2, [0xabu8; 32])))
            } else {
                None
            };
            let service = KeyAdmissionService::new(
                Arc::clone(&pubkey_map),
                key_gen_tx,
                Arc::clone(&composite_signer),
                Arc::clone(&validator_store),
                Arc::clone(&denylist),
                machine.clone(),
                epoch_clock,
            );
            Self {
                service,
                pubkey_map,
                validator_store,
                composite_signer,
                denylist,
                key_gen_rx,
                machine,
                _denylist_dir: denylist_dir,
            }
        }
    }

    #[test]
    fn admit_raw_secret_reaches_pubkey_map_validator_store_and_bumps_key_gen() {
        let h = Harness::new();
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let before = *h.key_gen_rx.borrow();

        let outcome = h.service.admit(sk, AdmissionSource::RawSecret).expect("admit");

        match outcome {
            AdmissionOutcome::Admitted { pubkey, key_gen, .. } => {
                assert_eq!(pubkey, pk);
                assert_eq!(key_gen, before + 1);
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
        assert!(h.pubkey_map.read().contains_key(&pk), "must reach PubkeyMap");
        assert!(h.validator_store.has_validator(&pk), "must reach ValidatorStore");
        assert!(h.composite_signer.has_local_key(&pk), "must reach CompositeSigner");
        assert_eq!(*h.key_gen_rx.borrow(), before + 1, "key_gen_rx must observe a bump");
    }

    #[test]
    fn admit_denylisted_key_returns_skipped_and_touches_no_store() {
        let h = Harness::new();
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        h.denylist.insert(&pk).expect("denylist insert");
        let before = *h.key_gen_rx.borrow();

        let outcome = h.service.admit(sk, AdmissionSource::RawSecret).expect("admit");

        assert_eq!(outcome, AdmissionOutcome::SkippedDenylisted { pubkey: pk });
        assert!(!h.pubkey_map.read().contains_key(&pk));
        assert!(!h.validator_store.has_validator(&pk));
        assert!(!h.composite_signer.has_local_key(&pk));
        assert_eq!(*h.key_gen_rx.borrow(), before, "denylist skip must not bump key_gen");
    }

    #[test]
    fn admit_is_idempotent_and_returns_already_present() {
        let h = Harness::new();
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        // Test-only: recreate the same key for a second admit. Never log these bytes.
        #[allow(clippy::disallowed_methods)]
        let sk_bytes = sk.to_bytes();

        let first = h.service.admit(sk, AdmissionSource::RawSecret).expect("first admit");
        assert!(matches!(first, AdmissionOutcome::Admitted { .. }));
        let gen_after_first = *h.key_gen_rx.borrow();

        let sk2 = SecretKey::from_bytes(&sk_bytes).expect("recreate secret");
        let second = h.service.admit(sk2, AdmissionSource::RawSecret).expect("second admit");
        assert_eq!(second, AdmissionOutcome::AlreadyPresent { pubkey: pk });
        assert_eq!(
            *h.key_gen_rx.borrow(),
            gen_after_first,
            "second admit must not double-bump key_gen_tx"
        );
    }

    #[test]
    fn admit_raw_secret_writes_nothing_to_the_filesystem() {
        let _guard = cwd_lock();
        let cwd = TempDir::new().expect("cwd tempdir");
        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(cwd.path()).expect("set_current_dir");

        let h = Harness::new();
        let sk = SecretKey::generate();
        h.service.admit(sk, AdmissionSource::RawSecret).expect("admit");

        let entries: Vec<_> =
            std::fs::read_dir(cwd.path()).expect("read cwd").filter_map(|e| e.ok()).collect();
        std::env::set_current_dir(prev).expect("restore cwd");
        assert!(
            entries.is_empty(),
            "RawSecret admission must write nothing under CWD (C4); found {entries:?}"
        );
    }

    #[test]
    fn admit_with_disabled_doppelganger_succeeds() {
        let h = Harness::with_machine(false);
        assert!(h.machine.is_none());
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();

        let outcome = h.service.admit(sk, AdmissionSource::RawSecret).expect("admit");
        assert!(matches!(outcome, AdmissionOutcome::Admitted { pubkey, .. } if pubkey == pk));
        assert!(h.pubkey_map.read().contains_key(&pk));
        assert!(h.validator_store.has_validator(&pk));
    }

    #[tokio::test]
    async fn key_gen_is_bumped_last() {
        let h = Harness::new();
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let mut rx = h.key_gen_rx.clone();
        rx.borrow_and_update();
        let map = Arc::clone(&h.pubkey_map);

        let watcher = tokio::spawn(async move {
            rx.changed().await.expect("key_gen change");
            map.read().contains_key(&pk)
        });
        tokio::task::yield_now().await;

        h.service.admit(sk, AdmissionSource::RawSecret).expect("admit");
        assert!(
            watcher.await.expect("watcher join"),
            "on key_gen bump the pubkey must already be present in PubkeyMap"
        );
    }

    #[test]
    fn admit_is_callable_from_fn_secret_key_closure() {
        let h = Harness::new();
        let service = Arc::new(h.service);
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();

        // Compile-level proof: admit is usable behind `Fn(SecretKey)` (A-1.3).
        let on_new_key: &dyn Fn(SecretKey) = &|secret| {
            let _ = service.admit(secret, AdmissionSource::RawSecret);
        };
        on_new_key(sk);

        assert!(h.pubkey_map.read().contains_key(&pk));
        assert!(h.validator_store.has_validator(&pk));
    }

    #[test]
    fn admit_registers_with_doppelganger_when_machine_present() {
        let h = Harness::with_machine(true);
        let machine = h.machine.as_ref().expect("machine");
        let sk = SecretKey::generate();
        let pk = sk.public_key();

        h.service.admit(sk, AdmissionSource::RawSecret).expect("admit");
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Pending,
            "import path must enter Pending"
        );
    }

    #[test]
    fn admit_persists_the_validator_when_a_config_path_is_set() {
        let dir = TempDir::new().expect("validators dir");
        let path = dir.path().join("validators.toml");
        std::fs::write(
            &path,
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
        )
        .expect("seed validators file");
        let validator_store = Arc::new(ValidatorStore::load_from_config(&path).expect("load"));
        let denylist_dir = TempDir::new().expect("denylist");
        let denylist =
            Arc::new(DeletionDenylist::empty_at(denylist_dir.path().join(".rvc.deleted_keys")));
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let (key_gen_tx, _key_gen_rx) = watch::channel(0u64);
        let composite_signer = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let epoch_clock = Arc::new(MonotonicEpochClock::new(0));
        let service = KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx,
            Arc::clone(&composite_signer),
            Arc::clone(&validator_store),
            denylist,
            None,
            epoch_clock,
        );
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        service
            .admit(
                sk,
                AdmissionSource::Keystore {
                    keystore_path: dir.path().join("k.json"),
                    doppelganger_hold_until: None,
                },
            )
            .expect("admit");
        assert!(validator_store.has_validator(&pk));
        let disk = ValidatorStore::load_from_config(&path).expect("reload");
        assert!(disk.has_validator(&pk), "import must persist the validator under save_lock");
    }

    /// A windowed keystore import writes the disabled hold before the signer is live.
    #[test]
    fn admit_windowed_keystore_persists_disabled_hold_before_the_signer() {
        let dir = TempDir::new().expect("validators dir");
        let path = dir.path().join("validators.toml");
        std::fs::write(
            &path,
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
        )
        .expect("seed validators file");
        let validator_store = Arc::new(ValidatorStore::load_from_config(&path).expect("load"));
        let denylist_dir = TempDir::new().expect("denylist");
        let denylist =
            Arc::new(DeletionDenylist::empty_at(denylist_dir.path().join(".rvc.deleted_keys")));
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let (key_gen_tx, _key_gen_rx) = watch::channel(0u64);
        let composite_signer = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let epoch_clock = Arc::new(MonotonicEpochClock::new(0));
        let service = KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx,
            Arc::clone(&composite_signer),
            Arc::clone(&validator_store),
            denylist,
            None,
            epoch_clock,
        );
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let deadline = 1_700_000_100u64;
        service
            .admit(
                sk,
                AdmissionSource::Keystore {
                    keystore_path: dir.path().join("k.json"),
                    doppelganger_hold_until: Some(deadline),
                },
            )
            .expect("admit");
        assert!(
            composite_signer.has_local_key(&pk),
            "the signer is published after the hold write"
        );
        assert!(!validator_store.is_signing_enabled(&pk));
        assert_eq!(
            validator_store.get_config(&pk).unwrap().doppelganger_hold_until,
            Some(deadline)
        );
        let disk = ValidatorStore::load_from_config(&path).expect("reload");
        assert!(!disk.is_signing_enabled(&pk), "disk must not show the key enabled");
        assert_eq!(disk.get_config(&pk).unwrap().doppelganger_hold_until, Some(deadline));
    }

    /// Importing over an existing enabled row persists the hold before the signer.
    #[test]
    fn admit_over_enabled_row_persists_disabled_hold_before_the_signer() {
        let dir = TempDir::new().expect("validators dir");
        let path = dir.path().join("validators.toml");
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let pk_hex = hex::encode(pk);
        let fee = "0x0000000000000000000000000000000000000002";
        std::fs::write(
            &path,
            format!(
                "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"0x{pk_hex}\"\nfee_recipient = \"{fee}\"\nenabled = true\n"
            ),
        )
        .expect("seed validators file");
        let validator_store = Arc::new(ValidatorStore::load_from_config(&path).expect("load"));
        assert!(validator_store.is_signing_enabled(&pk));
        let denylist_dir = TempDir::new().expect("denylist");
        let denylist =
            Arc::new(DeletionDenylist::empty_at(denylist_dir.path().join(".rvc.deleted_keys")));
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let (key_gen_tx, _key_gen_rx) = watch::channel(0u64);
        let composite_signer = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let epoch_clock = Arc::new(MonotonicEpochClock::new(0));
        let service = KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx,
            Arc::clone(&composite_signer),
            Arc::clone(&validator_store),
            denylist,
            None,
            epoch_clock,
        );
        let deadline = 1_700_000_100u64;
        service
            .admit(
                sk,
                AdmissionSource::Keystore {
                    keystore_path: dir.path().join("k.json"),
                    doppelganger_hold_until: Some(deadline),
                },
            )
            .expect("admit");
        assert!(
            composite_signer.has_local_key(&pk),
            "the signer is published after the hold write"
        );
        let disk = ValidatorStore::load_from_config(&path).expect("reload");
        assert!(
            !disk.is_signing_enabled(&pk),
            "an import over an enabled row must persist the hold before the key is live"
        );
        assert_eq!(disk.get_config(&pk).unwrap().doppelganger_hold_until, Some(deadline));
        assert_eq!(
            disk.get_config(&pk).unwrap().fee_recipient,
            Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        );
    }

    /// A secret-provider admit must not turn a slashed `enabled = false` back on.
    #[test]
    fn admit_does_not_overwrite_a_disabled_validator() {
        let dir = TempDir::new().expect("validators dir");
        let path = dir.path().join("validators.toml");
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let pk_hex = hex::encode(pk);
        std::fs::write(
            &path,
            format!(
                "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"0x{pk_hex}\"\nenabled = false\n"
            ),
        )
        .expect("seed validators file");
        let validator_store = Arc::new(ValidatorStore::load_from_config(&path).expect("load"));
        assert!(!validator_store.is_signing_enabled(&pk));
        let denylist_dir = TempDir::new().expect("denylist");
        let denylist =
            Arc::new(DeletionDenylist::empty_at(denylist_dir.path().join(".rvc.deleted_keys")));
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let (key_gen_tx, _key_gen_rx) = watch::channel(0u64);
        let composite_signer = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let epoch_clock = Arc::new(MonotonicEpochClock::new(0));
        let service = KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx,
            Arc::clone(&composite_signer),
            Arc::clone(&validator_store),
            denylist,
            None,
            epoch_clock,
        );
        service.admit(sk, AdmissionSource::RawSecret).expect("admit");
        assert!(
            !validator_store.is_signing_enabled(&pk),
            "admit must not overwrite a slashed enabled=false"
        );
        let disk = ValidatorStore::load_from_config(&path).expect("reload");
        assert!(!disk.is_signing_enabled(&pk), "the file must stay disabled");
    }

    #[test]
    fn admit_keystore_source_also_admits_without_using_path() {
        let h = Harness::new();
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let outcome = h
            .service
            .admit(
                sk,
                AdmissionSource::Keystore {
                    keystore_path: PathBuf::from("/nonexistent/keystore.json"),
                    doppelganger_hold_until: None,
                },
            )
            .expect("admit");
        assert!(matches!(outcome, AdmissionOutcome::Admitted { pubkey, .. } if pubkey == pk));
        assert!(h.pubkey_map.read().contains_key(&pk));
    }

    /// Revoke drops only a row this admission inserted, and bumps key_gen.
    #[test]
    fn revoke_failed_import_keeps_a_preexisting_row_and_bumps_key_gen() {
        let dir = TempDir::new().expect("validators dir");
        let path = dir.path().join("validators.toml");
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let pk_hex = hex::encode(pk);
        std::fs::write(
            &path,
            format!(
                "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"0x{pk_hex}\"\nfee_recipient = \"0x0000000000000000000000000000000000000007\"\nenabled = false\n"
            ),
        )
        .expect("seed");
        let validator_store = Arc::new(ValidatorStore::load_from_config(&path).expect("load"));
        let denylist_dir = TempDir::new().expect("denylist");
        let denylist =
            Arc::new(DeletionDenylist::empty_at(denylist_dir.path().join(".rvc.deleted_keys")));
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let (key_gen_tx, key_gen_rx) = watch::channel(0u64);
        let composite_signer = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let service = KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx,
            Arc::clone(&composite_signer),
            Arc::clone(&validator_store),
            denylist,
            None,
            Arc::new(MonotonicEpochClock::new(0)),
        );
        let outcome = service.admit(sk, AdmissionSource::RawSecret).expect("admit");
        let (key_gen, inserted_row) = match outcome {
            AdmissionOutcome::Admitted { key_gen, inserted_row, .. } => (key_gen, inserted_row),
            other => panic!("expected Admitted, got {other:?}"),
        };
        assert!(!inserted_row, "a pre-existing row must not be recorded as inserted");
        service.revoke_failed_import(&pk, inserted_row);
        assert!(
            validator_store.has_validator(&pk),
            "revoke must not delete a row this admission did not insert"
        );
        assert!(!validator_store.is_signing_enabled(&pk));
        assert_eq!(
            validator_store.get_config(&pk).unwrap().fee_recipient,
            Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7])
        );
        assert_eq!(
            *key_gen_rx.borrow(),
            key_gen + 1,
            "revoke must bump the key generation so duty caches drop the key"
        );
        let disk = ValidatorStore::load_from_config(&path).expect("reload");
        assert!(disk.has_validator(&pk));
        assert!(!disk.is_signing_enabled(&pk));
    }
}
