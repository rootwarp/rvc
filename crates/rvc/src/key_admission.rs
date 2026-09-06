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
    Keystore { keystore_path: PathBuf },
    /// Secret-provider refresh: raw `SecretKey` from a cloud secret manager.
    RawSecret,
}

/// Result of a successful [`KeyAdmissionService::admit`] call.
///
/// Denylist skips and idempotent re-admits are outcomes, not errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// Key was fully admitted; `key_gen` is the post-bump generation counter.
    Admitted { pubkey: [u8; 48], key_gen: u64 },
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
        }
    }

    /// Admit `secret` into every store that must observe a live key.
    ///
    /// Order (generation bump **last** so no orchestrator wake sees a
    /// half-populated set):
    /// 1. denylist re-check (`RawSecret` only — DELETE-races-refresh)
    /// 2. composite signer (`add_local_key`)
    /// 3. `PubkeyMap`
    /// 4. `ValidatorStore` (`add_validator`)
    /// 5. denylist re-check again (TOCTOU: DELETE may have raced the mutations)
    /// 6. doppelganger `register_for_import` (when enabled)
    /// 7. `key_gen_tx` bump
    ///
    /// # Synchronous by necessity
    ///
    /// This method is **synchronous** (not `async`) so it is usable from
    /// `RefreshService::run<F>(…, on_new_key: F) where F: Fn(SecretKey)` —
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

        // 2. Composite signer
        self.composite_signer.add_local_key(secret);

        // 3. PubkeyMap (no generation bump yet)
        self.notifier.pubkey_map().write().insert(pubkey, public_key.clone());

        // 4. ValidatorStore
        self.validator_store
            .add_validator(ValidatorConfig::new(pubkey))
            .expect("ValidatorConfig::new has no builder URLs");

        // 5. Final denylist re-check before irreversible notify / doppelganger.
        // If DELETE won the race after mutations, roll stores back and skip.
        if enforce_denylist && self.denylist.contains(&pubkey) {
            let _ = self.composite_signer.remove_local_key(&pubkey);
            self.notifier.pubkey_map().write().remove(&pubkey);
            let _ = self.validator_store.remove_validator(&pubkey);
            return Ok(Self::skipped_denylisted(pubkey, source_label));
        }

        // 6. Doppelganger import registration (optional machine)
        if let Some(ref machine) = self.machine {
            machine.register_for_import(&public_key, self.epoch_clock.current_epoch());
        }

        // 7. Generation bump last
        self.notifier.notify();
        let key_gen = *self.key_gen_tx.borrow();

        info!(
            pubkey = %TruncatedPubkey::new(&format!("0x{}", hex::encode(pubkey))),
            source = source_label,
            key_gen,
            "Admitted key"
        );

        Ok(AdmissionOutcome::Admitted { pubkey, key_gen })
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
            AdmissionOutcome::Admitted { pubkey, key_gen } => {
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
                },
            )
            .expect("admit");
        assert!(matches!(outcome, AdmissionOutcome::Admitted { pubkey, .. } if pubkey == pk));
        assert!(h.pubkey_map.read().contains_key(&pk));
    }
}
