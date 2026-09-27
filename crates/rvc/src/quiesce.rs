//! Per-pubkey signing quiesce.
//!
//! Closes the doppelganger enablement gate the signer re-checks under the
//! slashable per-pubkey lock, then acquires and drops that lock. `Ok` does not
//! mean non-slashable duties are idle. DELETE calls [`SigningQuiesceAdapter`]
//! before it exports.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use crypto::{CompositeSigner, PublicKey};
use doppelganger::SigningEnablement;
use keymanager_api::traits::{Pubkey, QuiesceError, SigningQuiesce};
use parking_lot::{Mutex, MutexGuard, RwLock};
use signer::SignerService;

#[cfg(test)]
use std::sync::atomic::AtomicU64;

/// Import/delete lock shared with the keystore adapter.
///
/// DELETE's presence check and quiesce insert take it and drop it before the
/// drain. [`QuiesceRegistry::readmit`] runs under the same mutex inside import.
pub(crate) struct TrackedKeys {
    keys: Mutex<Vec<Pubkey>>,
    #[cfg(test)]
    contended: AtomicU64,
    #[cfg(test)]
    stall_ms: AtomicU64,
}

impl TrackedKeys {
    pub(crate) fn new() -> Self {
        Self {
            keys: Mutex::new(Vec::new()),
            #[cfg(test)]
            contended: AtomicU64::new(0),
            #[cfg(test)]
            stall_ms: AtomicU64::new(0),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Vec<Pubkey>> {
        let guard = self.lock_inner();
        #[cfg(test)]
        {
            let ms = self.stall_ms.load(Ordering::Relaxed);
            if ms > 0 {
                std::thread::sleep(Duration::from_millis(ms));
            }
        }
        guard
    }

    fn lock_inner(&self) -> MutexGuard<'_, Vec<Pubkey>> {
        #[cfg(test)]
        {
            if let Some(guard) = self.keys.try_lock() {
                guard
            } else {
                self.contended.fetch_add(1, Ordering::SeqCst);
                self.keys.lock()
            }
        }
        #[cfg(not(test))]
        {
            self.keys.lock()
        }
    }

    #[cfg(test)]
    pub(crate) fn contended(&self) -> u64 {
        self.contended.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn set_stall_ms(&self, ms: u64) {
        self.stall_ms.store(ms, Ordering::Relaxed);
    }
}

/// Pubkeys whose signing gate is closed until a successful re-admission.
///
/// [`Self::insert`] and [`Self::contains`] record and query that set.
/// [`Self::readmit`] is the only removal. The set is process-local; a restart
/// does not restore it.
#[derive(Debug, Default)]
pub struct QuiesceRegistry {
    pubkeys: RwLock<HashSet<[u8; 48]>>,
}

impl QuiesceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self { pubkeys: RwLock::new(HashSet::new()) }
    }

    /// Record `pubkey` as quiesced. Idempotent.
    pub fn insert(&self, pubkey: &[u8; 48]) {
        self.pubkeys.write().insert(*pubkey);
    }

    /// Whether [`Self::insert`] has recorded `pubkey`.
    #[must_use]
    pub fn contains(&self, pubkey: &[u8; 48]) -> bool {
        self.pubkeys.read().contains(pubkey)
    }

    /// Drop `pubkey` after a successful keystore admission.
    ///
    /// This is the only public removal. The only legal caller is the keystore
    /// import path, after [`crate::key_admission::AdmissionOutcome::Admitted`]
    /// and a successful SEC-1b denylist clear, while that path still holds
    /// `tracked_keys`.
    ///
    /// Never call it for `AlreadyPresent` / `Duplicate`, `SkippedDenylisted`,
    /// an admission or persistence error, or the raw-secret provider path.
    /// Remote-key import does not use it.
    ///
    /// In-memory only. A process restart starts from an empty registry; this
    /// method does not change that.
    pub fn readmit(&self, pubkey: &[u8; 48]) {
        self.pubkeys.write().remove(pubkey);
    }
}

/// Decorator over the doppelganger [`SigningEnablement`] the signer re-checks.
///
/// `SignerService` calls [`SigningEnablement::is_signing_enabled`] before
/// signing and again under the per-pubkey lock. This wrapper returns `false`
/// for every pubkey in the [`QuiesceRegistry`], then delegates. That is the
/// gate a quiesced key must close.
///
/// [`validator_store::ValidatorStore`]'s `enabled` flag
/// (`ValidatorStore::is_signing_enabled`) is a different gate. The signer does
/// not read it on the sign path, so closing only that flag leaves a live
/// signing window.
pub struct QuiescingEnablement {
    inner: Arc<dyn SigningEnablement>,
    registry: Arc<QuiesceRegistry>,
}

impl QuiescingEnablement {
    #[must_use]
    pub fn new(inner: Arc<dyn SigningEnablement>, registry: Arc<QuiesceRegistry>) -> Self {
        Self { inner, registry }
    }
}

impl SigningEnablement for QuiescingEnablement {
    fn is_signing_enabled(&self, pubkey: &PublicKey) -> bool {
        let bytes = pubkey.to_bytes();
        if self.registry.contains(&bytes) {
            return false;
        }
        self.inner.is_signing_enabled(pubkey)
    }
}

/// [`SigningQuiesce`] for the VC: insert into the registry the signer's
/// [`QuiescingEnablement`] reads, then [`SignerService::drain_pubkey`].
///
/// The insert happens before the drain, including when the drain times out, so
/// the key stays closed. `false` from the drain is [`QuiesceError::DrainTimedOut`],
/// never `Ok`.
pub struct SigningQuiesceAdapter {
    registry: Arc<QuiesceRegistry>,
    signer: Arc<SignerService>,
    tracked_keys: Arc<TrackedKeys>,
    /// `Some` — insert only while this composite still has the local key.
    /// `None` — insert unconditionally (no shared keystore membership).
    membership: Option<Arc<CompositeSigner>>,
    #[cfg(test)]
    inserts: AtomicU64,
    #[cfg(test)]
    after_insert: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl SigningQuiesceAdapter {
    #[must_use]
    pub fn new(registry: Arc<QuiesceRegistry>, signer: Arc<SignerService>) -> Self {
        Self {
            registry,
            signer,
            tracked_keys: Arc::new(TrackedKeys::new()),
            membership: None,
            #[cfg(test)]
            inserts: AtomicU64::new(0),
            #[cfg(test)]
            after_insert: Mutex::new(None),
        }
    }

    /// Presence-check and insert under the keystore adapter's `tracked_keys`.
    ///
    /// The lock is not held across [`SignerService::drain_pubkey`].
    #[must_use]
    pub(crate) fn with_keystore_membership(
        mut self,
        tracked_keys: Arc<TrackedKeys>,
        composite: Arc<CompositeSigner>,
    ) -> Self {
        self.tracked_keys = tracked_keys;
        self.membership = Some(composite);
        self
    }

    #[cfg(test)]
    pub(crate) fn quiesce_inserts(&self) -> u64 {
        self.inserts.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn set_after_insert_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.after_insert.lock() = Some(hook);
    }
}

#[async_trait]
impl SigningQuiesce for SigningQuiesceAdapter {
    async fn quiesce(&self, pubkey: &Pubkey, timeout: Duration) -> Result<(), QuiesceError> {
        // Same mutex as import's readmit, dropped before the drain so an import
        // is not blocked for the wait. readmit can only clear an entry inserted
        // before its own critical section.
        let inserted = {
            let _guard = self.tracked_keys.lock();
            let present = match &self.membership {
                Some(composite) => composite.has_local_key(pubkey),
                None => true,
            };
            if present {
                self.registry.insert(pubkey);
                true
            } else {
                false
            }
        };
        #[cfg(test)]
        if inserted {
            self.inserts.fetch_add(1, Ordering::SeqCst);
            let hook = self.after_insert.lock().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        #[cfg(not(test))]
        let _ = inserted;
        let started = Instant::now();
        let drained = self.signer.drain_pubkey(pubkey, timeout).await;
        let waited = started.elapsed();
        // The sample is the wait itself. Timeout is reported by the `Err`, not
        // by omitting the observation.
        crate::metrics::RVC_KEYMANAGER_QUIESCE_WAIT_MS.observe(waited.as_secs_f64() * 1000.0);
        if drained {
            Ok(())
        } else {
            Err(QuiesceError::DrainTimedOut { waited })
        }
    }
}

#[cfg(test)]
use signer::ValidatorSigner;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use validator_store::{ValidatorConfig, ValidatorStore};

#[cfg(test)]
const GVR: eth_types::Root = [0x11; 32];

#[cfg(test)]
struct AllowOne([u8; 48]);

#[cfg(test)]
impl SigningEnablement for AllowOne {
    fn is_signing_enabled(&self, pubkey: &PublicKey) -> bool {
        pubkey.to_bytes() == self.0
    }
}

#[cfg(test)]
fn open_db() -> Arc<slashing::SlashingDb> {
    let db = Arc::new(slashing::SlashingDb::open_in_memory().expect("slashing db"));
    db.set_genesis_validators_root(&GVR).expect("pin gvr");
    db
}

#[cfg(test)]
fn signer_for(enablement: Arc<dyn SigningEnablement>) -> SignerService {
    let composite =
        Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(crypto::KeyManager::new())));
    SignerService::new(composite, open_db()).with_enablement(enablement)
}

#[cfg(test)]
async fn sign_block(
    signer: &SignerService,
    pubkey: &PublicKey,
) -> Result<crypto::Signature, signer::SignerError> {
    let fork = eth_types::ForkSchedule::unscheduled_gloas();
    let root = [0xabu8; 32];
    signer.sign_block(&root, 1, pubkey, &fork, &GVR).await
}

/// The outer enablement check passes, then the pubkey is inserted, and the
/// under-lock re-check returns [`signer::SignerError::BlockedByDoppelganger`]
/// with no signature. `ValidatorStore::enabled` stays open.
#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn quiesced_pubkey_is_refused_by_the_gate_the_signer_rechecks() {
    let secret = crypto::SecretKey::generate();
    let pubkey = secret.public_key();
    let bytes = pubkey.to_bytes();

    let store = ValidatorStore::new([1u8; 20], 30_000_000);
    store.add_validator(ValidatorConfig::new(bytes)).expect("track validator");
    assert!(
        store.is_signing_enabled(&bytes),
        "ValidatorStore::enabled stays open; it is not the gate under test"
    );

    let mut keys = crypto::KeyManager::new();
    keys.insert(secret);
    let composite = Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(keys)));
    let db = open_db();
    let inner: Arc<dyn SigningEnablement> = Arc::new(doppelganger::DoppelgangerDisabledByOperator);
    let (signer, registry) = crate::config::ServiceBuilder::new(crate::config::Config::default())
        .build_signer(composite, Arc::clone(&db), inner);
    assert!(!registry.contains(&bytes), "the outer check must see an open quiesce gate");

    // Hold the slashable lock so `sign_block` parks after the outer check and
    // before the under-lock re-check.
    let (holding_tx, holding_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let signer_holder = Arc::clone(&signer);
    let inflight = tokio::spawn(async move {
        let guard = signer_holder.acquire_signing_lock_for_test(&bytes).await;
        holding_tx.send(()).expect("holding");
        release_rx.await.expect("release");
        drop(guard);
    });
    holding_rx.await.expect("slashable lock held");

    let mut sign = std::pin::pin!(sign_block(&signer, &pubkey));
    tokio::select! {
        biased;
        result = &mut sign => {
            panic!(
                "sign_block finished while the slashable lock was held ({result:?}); \
                 the outer check must pass and the call must wait for the under-lock re-check"
            )
        }
        _ = tokio::task::yield_now() => {}
    }

    registry.insert(&bytes);
    release_tx.send(()).expect("release");
    let result = sign.await;
    assert!(
        matches!(result, Err(signer::SignerError::BlockedByDoppelganger)),
        "under-lock re-check must refuse without a signature, got {result:?}"
    );
    let rows = db.get_blocks(&hex::encode(bytes)).expect("query blocks");
    assert!(rows.is_empty(), "under-lock refusal must not record a block, found {rows:?}");
    inflight.await.expect("lock holder was not cancelled");
}

/// Hold the per-pubkey lock on a second task, then release it. Ordering is
/// the lock handshake, not a wall-clock sleep.
#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn drain_pubkey_returns_after_an_in_flight_signature_completes() {
    let signer = Arc::new(signer_for(Arc::new(doppelganger::DoppelgangerDisabledByOperator)));
    let pk = [0xabu8; 48];
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));

    let (holding_tx, holding_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let log_holder = Arc::clone(&log);
    let signer_holder = Arc::clone(&signer);
    let inflight = tokio::spawn(async move {
        let guard = signer_holder.acquire_signing_lock_for_test(&pk).await;
        log_holder.lock().expect("log").push("held");
        holding_tx.send(()).expect("holding");
        release_rx.await.expect("in-flight signature released");
        log_holder.lock().expect("log").push("released");
        drop(guard);
    });

    holding_rx.await.expect("in-flight signature holds the lock");

    let mut drain = std::pin::pin!(signer.drain_pubkey(&pk, Duration::from_secs(5)));
    tokio::select! {
        biased;
        result = &mut drain => {
            panic!("drain_pubkey returned {result} while the in-flight signature held the lock")
        }
        _ = tokio::task::yield_now() => {}
    }

    release_tx.send(()).expect("release");
    assert!(drain.await, "drain_pubkey must return after the in-flight signature drops the lock");
    log.lock().expect("log").push("drained");
    inflight.await.expect("in-flight signature task was not cancelled");
    assert_eq!(
        log.lock().expect("log").as_slice(),
        ["held", "released", "drained"],
        "drain must be ordered after the in-flight signature releases the lock"
    );
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn drain_timeout_is_an_error_and_leaves_the_key_quiesced() {
    let signer = Arc::new(signer_for(Arc::new(doppelganger::DoppelgangerDisabledByOperator)));
    let registry = Arc::new(QuiesceRegistry::new());
    let adapter = SigningQuiesceAdapter::new(Arc::clone(&registry), Arc::clone(&signer));
    let pk = [0xcdu8; 48];

    let (holding_tx, holding_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let completed = Arc::new(AtomicBool::new(false));
    let completed_task = Arc::clone(&completed);
    let signer_holder = Arc::clone(&signer);
    let inflight = tokio::spawn(async move {
        let _guard = signer_holder.acquire_signing_lock_for_test(&pk).await;
        holding_tx.send(()).expect("holding");
        release_rx.await.expect("in-flight signature must not be cancelled");
        completed_task.store(true, Ordering::Release);
    });

    holding_rx.await.expect("in-flight signature holds the lock");

    let before = crate::metrics::RVC_KEYMANAGER_QUIESCE_WAIT_MS.get_sample_count();
    let timeout = Duration::from_millis(25);
    let mut quiesce = std::pin::pin!(adapter.quiesce(&pk, timeout));
    tokio::select! {
        biased;
        _ = &mut quiesce => panic!("quiesce finished while the in-flight signature held the lock"),
        _ = tokio::task::yield_now() => {}
    }
    tokio::time::advance(timeout).await;

    let err = quiesce.await.expect_err("timed-out drain is an error");
    assert!(matches!(err, QuiesceError::DrainTimedOut { .. }), "got {err:?}");
    assert!(registry.contains(&pk), "timeout leaves the key quiesced");
    assert!(
        !completed.load(Ordering::Acquire),
        "in-flight signature must still be running after the drain times out"
    );
    assert!(!inflight.is_finished(), "drain timeout must not cancel the in-flight signature");
    assert!(
        crate::metrics::RVC_KEYMANAGER_QUIESCE_WAIT_MS.get_sample_count() > before,
        "rvc_keymanager_quiesce_wait_ms must record the drain wait"
    );

    release_tx.send(()).expect("release");
    inflight.await.expect("in-flight signature completes after release");
    assert!(completed.load(Ordering::Acquire));

    let mid = crate::metrics::RVC_KEYMANAGER_QUIESCE_WAIT_MS.get_sample_count();
    adapter
        .quiesce(&pk, Duration::from_secs(5))
        .await
        .expect("drain succeeds once the in-flight signature has finished");
    assert!(registry.contains(&pk), "a finished drain does not remove the key");
    assert!(
        crate::metrics::RVC_KEYMANAGER_QUIESCE_WAIT_MS.get_sample_count() > mid,
        "a finished drain must also record rvc_keymanager_quiesce_wait_ms"
    );
}

#[cfg(test)]
#[tokio::test]
async fn non_quiesced_pubkeys_are_unaffected() {
    let allowed = crypto::SecretKey::generate().public_key();
    let denied = crypto::SecretKey::generate().public_key();
    let allow = Arc::new(AllowOne(allowed.to_bytes()));
    let registry = Arc::new(QuiesceRegistry::new());
    let gate = QuiescingEnablement::new(
        Arc::clone(&allow) as Arc<dyn SigningEnablement>,
        Arc::clone(&registry),
    );

    assert!(gate.is_signing_enabled(&allowed));
    assert!(!gate.is_signing_enabled(&denied));
    assert_eq!(gate.is_signing_enabled(&allowed), allow.is_signing_enabled(&allowed));
    assert_eq!(gate.is_signing_enabled(&denied), allow.is_signing_enabled(&denied));

    let other = [0xeeu8; 48];
    registry.insert(&other);
    assert!(
        gate.is_signing_enabled(&allowed),
        "quiescing a different pubkey must leave this one open"
    );
    assert!(
        !gate.is_signing_enabled(&denied),
        "the decorator must not open a pubkey the inner gate denies"
    );
    assert!(!registry.contains(&allowed.to_bytes()));
    assert!(!registry.contains(&denied.to_bytes()));

    let signer = signer_for(Arc::new(gate));
    let result = sign_block(&signer, &allowed).await;
    assert!(
        !matches!(result, Err(signer::SignerError::BlockedByDoppelganger)),
        "non-quiesced pubkey must pass ensure_signing_enabled, got {result:?}"
    );
}
