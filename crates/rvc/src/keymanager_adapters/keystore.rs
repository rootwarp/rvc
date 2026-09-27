//! Local keystore manager adapter for the Keymanager API.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use doppelganger::MonotonicEpochClock;
use parking_lot::Mutex;
use validator_store::ValidatorStore;

use crypto::{CompositeSigner, Keystore};
use keymanager_api::traits::{DeleteKeystoreError, ImportKeystoreError, KeystoreManager, Pubkey};
use observability::logging::TruncatedPubkey;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::deletion_denylist::DeletionDenylist;
use crate::key_admission::{AdmissionOutcome, AdmissionSource, KeyAdmissionService};
use crate::orchestrator::PubkeyMap;
use crate::quiesce::{QuiesceRegistry, TrackedKeys};

use super::notifier::{pubkey_hex, KeyChangeNotifier};

/// Adapts `CompositeSigner` local keys to the Keymanager `KeystoreManager` trait.
///
/// # Canonical registry
///
/// The source of truth for "which local keys can this VC sign with" is
/// [`CompositeSigner::local_public_keys`] / [`CompositeSigner::has_local_key`] —
/// the union of boot-loaded keys (keystore-dir / secret-provider in
/// `LocalSigner`) and keys admitted via [`KeyAdmissionService`] (API import,
/// secret-provider refresh). `list_keys` / `has_key` / `delete_keystore` all
/// consult that set.
///
/// `tracked_keys` serializes import, `delete_keystore`, and DELETE's quiesce
/// insert. It is shared with [`crate::quiesce::SigningQuiesceAdapter`] and is
/// **not** the registry for list/has/delete.
///
/// # Deletion denylist (SEC-1b)
///
/// On successful `delete_keystore`, the pubkey is recorded in
/// [`DeletionDenylist`] so keystore-dir / secret-provider loaders skip it on
/// the next boot. Intentional re-import via `import_keystore` clears the entry.
pub struct KeystoreManagerAdapter {
    keystore_dir: PathBuf,
    composite_signer: Arc<CompositeSigner>,
    /// API-imported keys; also serializes import, delete, and quiesce insert.
    pub(crate) tracked_keys: Arc<TrackedKeys>,
    /// Cleared by [`QuiesceRegistry::readmit`] after a successful import.
    quiesce: Option<Arc<QuiesceRegistry>>,
    #[cfg(test)]
    after_admit: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    after_readmit: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    after_delete_unlock: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// In-flight DELETE counts. Touched only while `tracked_keys` is held.
    ///
    /// `requests` is how many `begin_delete_export` calls have not yet ended.
    /// `per_key` counts snapshotted pubkeys. One request's end decrements only
    /// the pubkeys that request began with.
    delete_inflight: Mutex<DeleteInflight>,
    /// Shared pubkey map + generation notifier for the orchestrator (RF1-06 / RF1-07).
    /// Used for DELETE (`remove_and_notify`); import goes through [`KeyAdmissionService`].
    notifier: KeyChangeNotifier,
    /// Durable deletion denylist; `None` disables persistence (tests).
    denylist: Option<Arc<DeletionDenylist>>,
    /// Single multi-store admission path (ADR-007 / ARCH-2c).
    admissions: Arc<KeyAdmissionService>,
}

impl KeystoreManagerAdapter {
    /// Construct an adapter with a private admission service over the same
    /// `pubkey_map` / `key_gen_tx` / signer (unit tests and simple call sites).
    ///
    /// Production should call [`Self::with_admission_service`] with the process-wide
    /// [`KeyAdmissionService`] so import and provider refresh share one choke point.
    pub fn new(
        keystore_dir: PathBuf,
        composite_signer: Arc<CompositeSigner>,
        pubkey_map: PubkeyMap,
        key_gen_tx: watch::Sender<u64>,
    ) -> Self {
        // Private default admissions for unit tests / call sites that do not
        // inject a process-wide service. Production always calls
        // `with_admission_service` with the shared choke point.
        //
        // `load` treats a missing file as empty. On IO failure (rare in tests),
        // fall back to a process-temp empty denylist so construction never panics.
        let default_denylist =
            Arc::new(DeletionDenylist::load(keystore_dir.as_path()).unwrap_or_else(|_| {
                DeletionDenylist::load(
                    &std::env::temp_dir()
                        .join(format!(".rvc.admission_denylist.{}", std::process::id())),
                )
                .expect("temp admission denylist")
            }));
        let admissions = Arc::new(KeyAdmissionService::new(
            Arc::clone(&pubkey_map),
            key_gen_tx.clone(),
            Arc::clone(&composite_signer),
            Arc::new(ValidatorStore::new([0u8; 20], 30_000_000)),
            default_denylist,
            None,
            Arc::new(MonotonicEpochClock::new(0)),
        ));
        Self {
            keystore_dir,
            composite_signer,
            tracked_keys: Arc::new(TrackedKeys::new()),
            delete_inflight: Mutex::new(DeleteInflight::default()),
            notifier: KeyChangeNotifier::new(pubkey_map, key_gen_tx),
            denylist: None,
            admissions,
            quiesce: None,
            #[cfg(test)]
            after_admit: Mutex::new(None),
            #[cfg(test)]
            after_readmit: Mutex::new(None),
            #[cfg(test)]
            after_delete_unlock: Mutex::new(None),
        }
    }

    /// Attach the process-wide deletion denylist (SEC-1b).
    pub fn with_denylist(mut self, denylist: Arc<DeletionDenylist>) -> Self {
        self.denylist = Some(denylist);
        self
    }

    /// Use the process-wide [`KeyAdmissionService`] (ARCH-2c).
    ///
    /// Required in production so keymanager import and secret-provider refresh
    /// share `ValidatorStore`, doppelganger machine, and denylist.
    pub fn with_admission_service(mut self, admissions: Arc<KeyAdmissionService>) -> Self {
        self.admissions = admissions;
        self
    }

    /// Registry a successful import clears after the denylist update.
    pub fn with_quiesce_registry(mut self, registry: Arc<QuiesceRegistry>) -> Self {
        self.quiesce = Some(registry);
        self
    }

    #[cfg(test)]
    pub(crate) fn set_after_admit_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.after_admit.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_after_readmit_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.after_readmit.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_after_delete_unlock_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.after_delete_unlock.lock() = Some(hook);
    }
}

/// Per-pubkey DELETE snapshots that have not yet finished.
#[derive(Debug, Default)]
struct DeleteInflight {
    requests: u32,
    per_key: HashMap<Pubkey, u32>,
}

#[cfg(test)]
fn run_hook(slot: &Mutex<Option<Arc<dyn Fn() + Send + Sync>>>) {
    let hook = slot.lock().clone();
    if let Some(hook) = hook {
        hook();
    }
}

/// Returns the path for the M-12 import-time metadata sidecar for `pubkey`.
///
/// Format: `<keystore_dir>/0x<hex_pubkey>.import_meta.json`
pub(crate) fn import_meta_path(keystore_dir: &Path, pubkey: &Pubkey) -> PathBuf {
    keystore_dir.join(format!("{}.import_meta.json", pubkey_hex(pubkey)))
}

/// Unlink every keystore JSON under `keystore_dir` whose EIP-2335 `pubkey`
/// field matches `pubkey` (plus the canonical API-import name
/// `0x{hex}.json`).
///
/// Boot load accepts any `*.json` name (`KeyManager::load_from_directory`);
/// DELETE must therefore not rely solely on the API-import filename
/// convention. Secret-provider keys with no on-disk file are fine — this
/// returns `Ok` when nothing matches.
///
/// Path-traversal: each candidate is canonicalized and required to stay
/// under `keystore_dir` before unlink (same rule as key load).
fn remove_matching_keystore_files(
    keystore_dir: &Path,
    pubkey: &Pubkey,
) -> Result<(), DeleteKeystoreError> {
    let target_hex = hex::encode(pubkey);
    let canonical_name = format!("0x{target_hex}.json");
    let canonical_path = keystore_dir.join(&canonical_name);

    match std::fs::remove_file(&canonical_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
    }

    let entries = match std::fs::read_dir(keystore_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
    };

    let canonical_dir = match keystore_dir.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Only keystore JSON; never the import-meta sidecar (handled separately).
        if !name.ends_with(".json") || name.ends_with(".import_meta.json") {
            continue;
        }
        // Already attempted above; skip re-stat of the canonical name.
        if name == canonical_name {
            continue;
        }

        let canonical_file = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !canonical_file.starts_with(&canonical_dir) {
            warn!(
                path = %path.display(),
                "Skipping keystore candidate outside keystore directory during delete"
            );
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        let Some(pk_str) = value.get("pubkey").and_then(|v| v.as_str()) else {
            continue;
        };
        let pk_norm =
            pk_str.strip_prefix("0x").or_else(|| pk_str.strip_prefix("0X")).unwrap_or(pk_str);
        if !pk_norm.eq_ignore_ascii_case(&target_hex) {
            continue;
        }

        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    pubkey = %TruncatedPubkey::new(&target_hex),
                    "Removed non-canonical keystore file on delete"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
        }
    }

    Ok(())
}
impl KeystoreManager for KeystoreManagerAdapter {
    /// Local keys the VC can sign with (`CompositeSigner::local_public_keys`).
    fn list_keys(&self) -> Vec<Pubkey> {
        self.composite_signer.local_public_keys()
    }

    /// Whether `pubkey` is a local signing key (boot-loaded or API-imported).
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.composite_signer.has_local_key(pubkey)
    }

    fn membership_for_delete(&self, candidates: &[Pubkey]) -> Vec<Pubkey> {
        // Same lock import holds across check-and-admit, so this set cannot
        // tear an in-flight import.
        let _keys = self.tracked_keys.lock();
        let mut members = Vec::new();
        for pubkey in candidates {
            if self.composite_signer.has_local_key(pubkey) && !members.contains(pubkey) {
                members.push(*pubkey);
            }
        }
        members
    }

    fn begin_delete_export(&self, members: &[Pubkey]) {
        let _keys = self.tracked_keys.lock();
        let mut inflight = self.delete_inflight.lock();
        inflight.requests = inflight.requests.saturating_add(1);
        for pubkey in members {
            let count = inflight.per_key.entry(*pubkey).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    fn end_delete_export(&self, members: &[Pubkey]) {
        let _keys = self.tracked_keys.lock();
        let mut inflight = self.delete_inflight.lock();
        inflight.requests = inflight.requests.saturating_sub(1);
        for pubkey in members {
            let next = inflight.per_key.get(pubkey).copied().unwrap_or(0).saturating_sub(1);
            if next == 0 {
                inflight.per_key.remove(pubkey);
            } else {
                inflight.per_key.insert(*pubkey, next);
            }
        }
    }

    fn import_keystore(
        &self,
        keystore_json: &str,
        password: &str,
    ) -> Result<Pubkey, ImportKeystoreError> {
        let keystore: Keystore = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;

        let secret_key = keystore
            .decrypt(password.as_bytes())
            .map_err(|e| ImportKeystoreError::DecryptionFailed(e.to_string()))?;

        let pubkey_bytes = secret_key.public_key().to_bytes();

        // Hold lock for the entire check-and-insert to prevent TOCTOU race.
        // Duplicate check uses the real local registry (not only API-tracked keys).
        let mut keys = self.tracked_keys.lock();
        if self.composite_signer.has_local_key(&pubkey_bytes) {
            return Err(ImportKeystoreError::Duplicate);
        }
        // Absent, but a DELETE that snapshotted this key has not finished.
        // Admitting here would `readmit` during that request's export.
        if self.delete_inflight.lock().per_key.get(&pubkey_bytes).copied().unwrap_or(0) > 0 {
            return Err(ImportKeystoreError::DeleteInProgress);
        }

        // Save keystore file to disk with restricted permissions (0o600)
        let filename = format!("{}.json", pubkey_hex(pubkey_bytes));
        let file_path = self.keystore_dir.join(&filename);

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&file_path)
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
            file.write_all(keystore_json.as_bytes())
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&file_path, keystore_json)
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        }

        // M-12 (Critical #2): persist the import timestamp so that after a
        // restart the doppelganger gate can detect keys whose window is still
        // active and re-arm monitoring rather than treating them as safe.
        let meta_path = import_meta_path(&self.keystore_dir, &pubkey_bytes);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let meta_json = format!("{{\"imported_unix_seconds\":{}}}", now_unix);

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            if let Ok(mut f) = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&meta_path)
            {
                let _ = f.write_all(meta_json.as_bytes());
            }
        }

        #[cfg(not(unix))]
        {
            let _ = std::fs::write(&meta_path, meta_json.as_bytes());
        }

        // Multi-store admission (ARCH-2c): composite signer, PubkeyMap,
        // ValidatorStore, doppelganger, key_gen bump — single choke point.
        let outcome = self
            .admissions
            .admit(secret_key, AdmissionSource::Keystore { keystore_path: file_path.clone() })
            .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;

        match outcome {
            AdmissionOutcome::Admitted { .. } => {}
            AdmissionOutcome::AlreadyPresent { .. } => {
                return Err(ImportKeystoreError::Duplicate);
            }
            AdmissionOutcome::SkippedDenylisted { .. } => {
                // Keystore source does not enforce denylist inside admit;
                // this branch is defensive.
                return Err(ImportKeystoreError::Io(
                    "admission skipped denylisted key unexpectedly".into(),
                ));
            }
        }

        #[cfg(test)]
        run_hook(&self.after_admit);

        // Track the key (lock still held)
        keys.push(pubkey_bytes);

        // SEC-1b: clear denylist only *after* successful persistence + registry
        // add so a mid-import IO failure cannot un-delete a previously deleted
        // key (restart would otherwise re-load it from secret-provider).
        if let Some(ref denylist) = self.denylist {
            if let Err(e) = denylist.remove(&pubkey_bytes) {
                // Key is already loaded and signable; surface IO so operators
                // can repair the denylist file. Do not roll back the import.
                // Do not readmit: a failed clear leaves the key quiesced.
                return Err(ImportKeystoreError::Io(e.to_string()));
            }
        }

        let delete_still_in_flight =
            self.delete_inflight.lock().per_key.get(&pubkey_bytes).copied().unwrap_or(0) > 0;
        if let Some(registry) = &self.quiesce {
            if !delete_still_in_flight {
                // admit's register_for_import leaves a deleted key Pending.
                // Unmonitored (post-cancel, before that register) is closed too.
                registry.readmit(&pubkey_bytes);
            }
        }

        #[cfg(test)]
        run_hook(&self.after_readmit);
        // Hold `tracked_keys` through readmit. Releasing earlier would let a
        // DELETE insert a quiescence that this readmit then erases.
        drop(keys);

        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey_bytes)),
            "Imported keystore"
        );
        Ok(pubkey_bytes)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        // Serialize with import via the same lock so concurrent import/delete
        // cannot race. Registry membership is the real local signing set.
        let mut keys = self.tracked_keys.lock();
        {
            let inflight = self.delete_inflight.lock();
            let snapshotted = inflight.per_key.get(pubkey).copied().unwrap_or(0) > 0;
            if inflight.requests > 0 && self.composite_signer.has_local_key(pubkey) && !snapshotted
            {
                return Err(DeleteKeystoreError::Io(
                    "refusing to delete a key absent from the slashing-protection export".into(),
                ));
            }
        }
        if !self.composite_signer.has_local_key(pubkey) {
            // Retry / break-glass: a prior DELETE may have removed the key from
            // the registry before denylist durability failed. Allow authenticated
            // DELETE of a non-local pubkey to force-insert the denylist entry so
            // secret-provider keys cannot resurrect on the next boot.
            if let Some(ref denylist) = self.denylist {
                denylist.insert(pubkey).map_err(|e| DeleteKeystoreError::Io(e.to_string()))?;
            }
            return Ok(false);
        }

        // Order (SEC-1b fail-closed for durability):
        //   1. Unlink keystore files (IO failure leaves memory intact)
        //   2. Durable denylist.insert (IO failure leaves key still local → retryable)
        //   3. Remove from signing registry
        //
        // Writing the denylist *before* remove_local_key ensures a failed
        // insert does not leave a non-signable key that cannot be re-deleted.

        // Matches any `*.json` whose EIP-2335 pubkey field equals this key
        // (API-import `0x{hex}.json` and boot-loaded names like `validator1.json`).
        // No matching file is OK (secret-provider / already removed).
        remove_matching_keystore_files(&self.keystore_dir, pubkey)?;

        // M-12 (Critical #2): remove the import-time sidecar so a
        // subsequent re-import starts with a clean timestamp.
        let meta_path = import_meta_path(&self.keystore_dir, pubkey);
        let _ = std::fs::remove_file(&meta_path);

        // SEC-1b: persist deletion *before* registry removal so durability
        // failure leaves the key still present for DELETE retry.
        if let Some(ref denylist) = self.denylist {
            denylist.insert(pubkey).map_err(|e| DeleteKeystoreError::Io(e.to_string()))?;
        }

        // Drop bookkeeping after denylist succeeds (lock still held for
        // remove_local_key + map update so concurrent deletes/imports serialize).
        if let Some(pos) = keys.iter().position(|k| k == pubkey) {
            keys.remove(pos);
        }

        // Remove from the real signing registry (dynamic + boot-loaded).
        let removed = self.composite_signer.remove_local_key(pubkey);

        // Map remove + notify under the same `tracked_keys` lock as registry
        // mutation (S1). If we released the lock first, a concurrent re-import
        // could re-insert the map entry and then be erased by our late remove.
        self.notifier.remove_and_notify(pubkey);
        // Machine mutex only, while `tracked_keys` is still held: the same
        // order as `register_for_import` inside `admit`. `on_delete` still
        // calls `cancel_monitoring` after this returns.
        self.admissions.cancel_forward_window(pubkey);
        drop(keys);
        #[cfg(test)]
        run_hook(&self.after_delete_unlock);

        // After a positive membership check under this lock, `!removed` is an
        // inconsistency (or an external concurrent remover). Disk side effects
        // already happened — do not map this to dishonest `not_found`.
        if !removed {
            debug_assert!(removed, "remove_local_key returned false after has_local_key was true");
            error!(
                pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                "remove_local_key returned false after positive membership; \
                 treating delete as success (key is not signable)"
            );
        }

        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            "Deleted keystore"
        );
        Ok(true)
    }
}
