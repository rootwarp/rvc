//! Local keystore manager adapter for the Keymanager API.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use doppelganger::MonotonicEpochClock;
use parking_lot::Mutex;
use validator_store::ValidatorStore;

use async_trait::async_trait;
use crypto::{CompositeSigner, Keystore};
use keymanager_api::traits::{DeleteKeystoreError, ImportKeystoreError, KeystoreManager, Pubkey};
use observability::logging::TruncatedPubkey;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::deletion_denylist::DeletionDenylist;
use crate::key_admission::{AdmissionOutcome, AdmissionSource, KeyAdmissionService};
use crate::orchestrator::PubkeyMap;
use crate::quiesce::{QuiesceRegistry, TrackedKeys};

use super::kdf_budget::{KdfBudget, KdfBudgetConfig};
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
/// `delete_keystore` records the pubkey in [`DeletionDenylist`] even when
/// import-secret removal fails, so the next boot skips the key. The signing
/// registry is updated only after secret removal and the denylist write both
/// succeed. Intentional re-import via `import_keystore` clears the entry.
pub struct KeystoreManagerAdapter {
    keystore_dir: PathBuf,
    composite_signer: Arc<CompositeSigner>,
    /// API-imported keys; also serializes import, delete, and quiesce insert.
    pub(crate) tracked_keys: Arc<TrackedKeys>,
    /// Cleared by [`QuiesceRegistry::readmit`] after a successful import.
    quiesce: Option<Arc<QuiesceRegistry>>,
    #[cfg(test)]
    before_admit: TestHookSlot,
    #[cfg(test)]
    before_discard: TestHookSlot,
    #[cfg(test)]
    fail_after_admit: Arc<std::sync::atomic::AtomicBool>,
    /// After the keystore `*.json` rename, before the metadata rename.
    #[cfg(test)]
    fail_after_keystore_rename: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    after_admit: TestHookSlot,
    #[cfg(test)]
    after_readmit: TestHookSlot,
    #[cfg(test)]
    after_delete_unlock: TestHookSlot,
    /// Runs after `membership_for_delete` drops `tracked_keys`, before it returns.
    /// The delete task is paused here, so the key is still present and the lock is free.
    #[cfg(test)]
    after_membership_scan: TestHookSlot,
    /// Runs inside the import `spawn_blocking` body, after the permit is moved
    /// in and before `decrypt`.
    #[cfg(test)]
    during_blocking: TestHookSlot,
    /// After the import secret is durable and before the keystore is staged.
    #[cfg(test)]
    after_secret_before_keystore: TestHookSlot,
    /// Import KDF admission (RR2-09/10). Decrypt runs only after [`KdfBudget::admit`].
    kdf_budget: Arc<KdfBudget>,
    /// In-flight DELETE counts. Touched only while `tracked_keys` is held.
    ///
    /// `requests` is how many [`KeystoreManager::membership_for_delete`]
    /// snapshots have not yet been ended. `per_key` counts the pubkeys in
    /// those snapshots. [`KeystoreManager::end_delete_export`] decrements
    /// only the pubkeys that snapshot returned.
    delete_inflight: Arc<Mutex<DeleteInflight>>,
    /// Shared pubkey map + generation notifier for the orchestrator (RF1-06 / RF1-07).
    /// Used for DELETE (`remove_and_notify`); import goes through [`KeyAdmissionService`].
    notifier: KeyChangeNotifier,
    /// Durable deletion denylist; `None` disables persistence (tests).
    denylist: Option<Arc<DeletionDenylist>>,
    /// Single multi-store admission path (ADR-007 / ARCH-2c).
    admissions: Arc<KeyAdmissionService>,
    /// Seconds of the doppelganger window. Zero admits the key enabled.
    doppelganger_window_secs: AtomicU64,
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
            Arc::new(MonotonicEpochClock::new(0, 12_000)),
        ));
        Self {
            keystore_dir,
            composite_signer,
            tracked_keys: Arc::new(TrackedKeys::new()),
            kdf_budget: Arc::new(KdfBudget::new(KdfBudgetConfig::default())),
            delete_inflight: Arc::new(Mutex::new(DeleteInflight::default())),
            notifier: KeyChangeNotifier::new(pubkey_map, key_gen_tx),
            denylist: None,
            admissions,
            doppelganger_window_secs: AtomicU64::new(0),
            quiesce: None,
            #[cfg(test)]
            before_admit: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            before_discard: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            fail_after_admit: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            fail_after_keystore_rename: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            after_admit: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_readmit: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_delete_unlock: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_membership_scan: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            during_blocking: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_secret_before_keystore: Arc::new(Mutex::new(None)),
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

    /// Share the process-wide import/delete/sidecar-cleanup lock.
    ///
    /// Production passes the same [`TrackedKeys`] the liveness loop holds
    /// across Safe re-check and unlink.
    pub fn with_tracked_keys(mut self, tracked_keys: Arc<TrackedKeys>) -> Self {
        self.tracked_keys = tracked_keys;
        self
    }

    /// Replace the default import KDF budget. Production passes the RR2-10 knobs.
    #[must_use]
    pub fn with_kdf_budget(mut self, kdf_budget: Arc<KdfBudget>) -> Self {
        self.kdf_budget = kdf_budget;
        self
    }

    /// Window used to persist a doppelganger hold on the next keystore import.
    ///
    /// Zero leaves the admitted row enabled. Called after the adapter is built,
    /// once the process window is known.
    pub fn set_doppelganger_window(&self, window: Duration) {
        self.doppelganger_window_secs.store(window.as_secs(), Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_before_admit_hook(&self, hook: TestHook) {
        *self.before_admit.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_before_discard_hook(&self, hook: TestHook) {
        *self.before_discard.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn fail_after_admit(&self) {
        self.fail_after_admit.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Fail `publish_keystore` after the boot-visible `*.json` rename lands.
    #[cfg(test)]
    pub(crate) fn fail_after_keystore_rename(&self) {
        self.fail_after_keystore_rename.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn set_after_admit_hook(&self, hook: TestHook) {
        *self.after_admit.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_after_readmit_hook(&self, hook: TestHook) {
        *self.after_readmit.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_after_delete_unlock_hook(&self, hook: TestHook) {
        *self.after_delete_unlock.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_after_membership_scan_hook(&self, hook: TestHook) {
        *self.after_membership_scan.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_during_blocking_hook(&self, hook: TestHook) {
        *self.during_blocking.lock() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_after_secret_before_keystore_hook(&self, hook: TestHook) {
        *self.after_secret_before_keystore.lock() = Some(hook);
    }
}

/// Per-pubkey DELETE snapshots that have not yet finished.
#[derive(Debug, Default)]
struct DeleteInflight {
    requests: u32,
    per_key: HashMap<Pubkey, u32>,
}

#[cfg(test)]
type TestHook = Arc<dyn Fn() + Send + Sync>;

#[cfg(test)]
type TestHookSlot = Arc<Mutex<Option<TestHook>>>;

#[cfg(test)]
fn run_hook(slot: &Mutex<Option<TestHook>>) {
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

/// Not `*.json`, so boot load (`extension == "json"`) ignores the staged file.
fn staged_keystore_path(keystore_dir: &Path, pubkey: &Pubkey) -> PathBuf {
    keystore_dir.join(format!("{}.json.partial", pubkey_hex(pubkey)))
}

fn staged_meta_path(keystore_dir: &Path, pubkey: &Pubkey) -> PathBuf {
    keystore_dir.join(format!("{}.import_meta.json.partial", pubkey_hex(pubkey)))
}

/// Drop leftover `0x<pubkey>.import_meta.json.removing.<n>` files.
///
/// Older cleanups renamed the final sidecar aside before unlink. A crash left
/// those set-asides on disk; boot still treats them as unfinished. DELETE and
/// Safe cleanup remove them under `tracked_keys`.
fn remove_leftover_removing_sidecars(keystore_dir: &Path, pubkey: &Pubkey) {
    let prefix = format!("{}.import_meta.json.removing.", pubkey_hex(pubkey));
    let entries = match std::fs::read_dir(keystore_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let after = &name[prefix.len()..];
        if after.is_empty() || !after.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let _ = std::fs::remove_file(entry.path());
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ImportKeystoreError> {
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
            .open(path)
            .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        file.write_all(bytes).map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    pub(super) static IMPORT_SECRET_DIR_SYNC_FAILS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Fail the Nth `sync_keystore_dir` call on this thread. `0` is off.
    /// [`IMPORT_SECRET_DIR_SYNC_CALLS`] is 1-based and must be reset by the test.
    pub(super) static IMPORT_SECRET_DIR_SYNC_FAIL_ON_CALL: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
    pub(super) static IMPORT_SECRET_DIR_SYNC_CALLS: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
    /// The next import-secret unlink fails with `PermissionDenied`.
    pub(super) static IMPORT_SECRET_REMOVE_FAILS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn sync_keystore_dir(dir: &Path) -> Result<(), ImportKeystoreError> {
    #[cfg(test)]
    {
        let call = IMPORT_SECRET_DIR_SYNC_CALLS.with(|slot| {
            let next = slot.get().saturating_add(1);
            slot.set(next);
            next
        });
        let one_shot = IMPORT_SECRET_DIR_SYNC_FAILS.with(|flag| flag.replace(false));
        let nth = IMPORT_SECRET_DIR_SYNC_FAIL_ON_CALL.with(|slot| slot.get());
        if one_shot || (nth != 0 && call == nth) {
            if nth != 0 && call == nth {
                IMPORT_SECRET_DIR_SYNC_FAIL_ON_CALL.with(|slot| slot.set(0));
            }
            return Err(ImportKeystoreError::Io(format!(
                "sync import secret directory {} failed",
                dir.display()
            )));
        }
    }
    let file = std::fs::File::open(dir).map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| ImportKeystoreError::Io(e.to_string()))
}

fn unlink_import_path(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if IMPORT_SECRET_REMOVE_FAILS.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"));
    }
    std::fs::remove_file(path)
}

fn attach_import_sync(
    first_err: Option<ImportKeystoreError>,
    sync_err: ImportKeystoreError,
) -> ImportKeystoreError {
    match first_err {
        Some(err) => ImportKeystoreError::Io(format!("{err}; {sync_err}")),
        None => sync_err,
    }
}

fn io_import(action: &str, path: &Path, err: std::io::Error) -> ImportKeystoreError {
    ImportKeystoreError::Io(format!("{action} {}: {err}", path.display()))
}

fn import_secrets_dir(keystore_dir: &Path) -> PathBuf {
    keystore_dir.join(crate::config::Config::IMPORT_SECRETS_DIR)
}

fn import_secret_path(keystore_dir: &Path, pubkey: &Pubkey) -> PathBuf {
    import_secrets_dir(keystore_dir).join(pubkey_hex(pubkey))
}

/// The keystore `pubkey` field must be the lowercase bare hex boot stores.
fn reject_unbootable_pubkey(
    field: Option<&str>,
    derived: &[u8],
) -> Result<(), ImportKeystoreError> {
    let Some(field) = field else {
        return Err(ImportKeystoreError::PubkeyField("missing pubkey field"));
    };
    let lowercase_bare = field.len() == derived.len() * 2
        && field.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if !lowercase_bare {
        return Err(ImportKeystoreError::PubkeyField("pubkey field must be lowercase bare hex"));
    }
    let Ok(bytes) = hex::decode(field) else {
        return Err(ImportKeystoreError::PubkeyField("pubkey field must be lowercase bare hex"));
    };
    if bytes.as_slice() != derived {
        return Err(ImportKeystoreError::PubkeyField(
            "pubkey field does not match the decrypted key",
        ));
    }
    Ok(())
}

fn ensure_import_secrets_dir(keystore_dir: &Path) -> Result<PathBuf, ImportKeystoreError> {
    let secrets_dir = import_secrets_dir(keystore_dir);
    match std::fs::symlink_metadata(&secrets_dir) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err(ImportKeystoreError::Io(format!(
                "import secret directory {} escapes the keystore directory",
                secrets_dir.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&secrets_dir)
                    .map_err(|e| io_import("create import secret directory", &secrets_dir, e))?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir(&secrets_dir)
                    .map_err(|e| io_import("create import secret directory", &secrets_dir, e))?;
            }
        }
        Err(e) => return Err(io_import("stat import secret directory", &secrets_dir, e)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(&secrets_dir)
            .map_err(|e| io_import("stat import secret directory", &secrets_dir, e))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(ImportKeystoreError::Io(format!(
                "import secret directory {} escapes the keystore directory",
                secrets_dir.display()
            )));
        }
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&secrets_dir, perms)
            .map_err(|e| io_import("set import secret directory mode", &secrets_dir, e))?;
    }
    let base = keystore_dir
        .canonicalize()
        .map_err(|e| io_import("canonicalize keystore directory", keystore_dir, e))?;
    let canonical = secrets_dir
        .canonicalize()
        .map_err(|e| io_import("canonicalize import secret directory", &secrets_dir, e))?;
    if !canonical.starts_with(&base) {
        return Err(ImportKeystoreError::Io(format!(
            "import secret directory {} escapes the keystore directory",
            secrets_dir.display()
        )));
    }
    Ok(secrets_dir)
}

fn abandon_staged(path: &Path, err: ImportKeystoreError) -> ImportKeystoreError {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return ImportKeystoreError::Io(format!(
                "{err}; staged import secret could not be removed: {e}"
            ));
        }
    }
    if let Some(dir) = path.parent() {
        if let Err(sync_err) = sync_keystore_dir(dir) {
            return ImportKeystoreError::Io(format!("{err}; {sync_err}"));
        }
    }
    err
}

fn write_new_secret_file(path: &Path, bytes: &[u8]) -> Result<(), ImportKeystoreError> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| io_import("create import secret", path, e))?;
    if let Err(e) = file.write_all(bytes) {
        return Err(abandon_staged(path, io_import("write import secret", path, e)));
    }
    if let Err(e) = file.sync_all() {
        return Err(abandon_staged(path, io_import("sync import secret", path, e)));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = match file.metadata() {
            Ok(meta) => meta,
            Err(e) => return Err(abandon_staged(path, io_import("stat import secret", path, e))),
        };
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        if let Err(e) = file.set_permissions(perms) {
            return Err(abandon_staged(path, io_import("set import secret mode", path, e)));
        }
        if let Err(e) = file.sync_all() {
            return Err(abandon_staged(path, io_import("sync import secret", path, e)));
        }
    }
    Ok(())
}

fn staged_secret_path(secrets_dir: &Path, pubkey: &Pubkey) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    secrets_dir.join(format!(
        ".{}.{}.{nanos}.keymanager-secret.partial",
        pubkey_hex(pubkey),
        std::process::id()
    ))
}

fn remove_staged_secret_partials(
    secrets_dir: &Path,
    pubkey: &Pubkey,
) -> Result<(), ImportKeystoreError> {
    let prefix = format!(".{}.", pubkey_hex(pubkey));
    let entries = match std::fs::read_dir(secrets_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_import("read import secret directory", secrets_dir, e)),
    };
    let mut removed = false;
    let mut first_err = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(io_import("read import secret directory", secrets_dir, e));
                }
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) || !crate::config::is_staged_import_secret_name(name) {
            continue;
        }
        let path = entry.path();
        match unlink_import_path(&path) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(io_import("remove staged import secret", &path, e));
                }
            }
        }
    }
    if removed {
        if let Err(sync_err) = sync_keystore_dir(secrets_dir) {
            first_err = Some(attach_import_sync(first_err, sync_err));
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// `create_new` a mode `0600` file, fsync it, then rename into the secrets dir.
///
/// `write_private_file` keeps an existing file's mode, so the secret uses its
/// own create-new path. The secret is durable before the caller stages the
/// keystore. A failure leaves neither the staged file nor the final secret.
fn persist_import_secret(
    keystore_dir: &Path,
    pubkey: &Pubkey,
    password: &str,
) -> Result<(), ImportKeystoreError> {
    let secrets_dir = ensure_import_secrets_dir(keystore_dir)?;
    remove_staged_secret_partials(&secrets_dir, pubkey)?;
    let final_path = secrets_dir.join(pubkey_hex(pubkey));
    let staged = staged_secret_path(&secrets_dir, pubkey);
    debug_assert!(
        staged.starts_with(&secrets_dir),
        "import secret partials are staged inside the secrets directory"
    );
    write_new_secret_file(&staged, password.as_bytes())?;
    if let Err(e) = std::fs::rename(&staged, &final_path) {
        return Err(abandon_staged(&staged, io_import("rename import secret", &final_path, e)));
    }
    if let Err(e) = sync_keystore_dir(&secrets_dir) {
        return Err(abandon_staged(&final_path, e));
    }
    if let Err(e) = sync_keystore_dir(keystore_dir) {
        return Err(abandon_staged(&final_path, e));
    }
    Ok(())
}

/// Remove the persisted import password.
///
/// `NotFound` for the file or the secrets directory is success. A directory
/// open or fsync error is returned so the caller can retry while the key is
/// still registered.
fn remove_import_secret(keystore_dir: &Path, pubkey: &Pubkey) -> Result<(), ImportKeystoreError> {
    let path = import_secret_path(keystore_dir, pubkey);
    let secrets_dir = import_secrets_dir(keystore_dir);
    let mut removed = false;
    let mut first_err = None;
    match unlink_import_path(&path) {
        Ok(()) => removed = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "failed to remove an import password secret"
            );
            first_err = Some(io_import("remove import password secret", &path, e));
        }
    }
    // Partials are attempted even when the final secret could not be removed.
    // A later partial or fsync error is attached to that first error. A failed
    // partial unlink does not skip the directory fsync after the final secret
    // was removed.
    if let Err(e) = remove_staged_secret_partials(&secrets_dir, pubkey) {
        first_err = Some(match first_err {
            Some(first) => attach_import_sync(Some(first), e),
            None => e,
        });
    }
    if removed {
        if let Err(sync_err) = sync_keystore_dir(&secrets_dir) {
            first_err = Some(attach_import_sync(first_err, sync_err));
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Write the denylist after the secret-removal attempt.
///
/// A failed secret removal still denylists the key. Registry updates stay
/// with the caller and run only when this returns `Ok`.
fn insert_denylist_after_secret(
    denylist: Option<&Arc<DeletionDenylist>>,
    pubkey: &Pubkey,
    secret_removed: Result<(), ImportKeystoreError>,
) -> Result<(), DeleteKeystoreError> {
    if let Some(denylist) = denylist {
        if let Err(e) = denylist.insert(pubkey) {
            let deny = e.to_string();
            return Err(match secret_removed {
                Ok(()) => DeleteKeystoreError::Io(deny),
                Err(secret) => DeleteKeystoreError::Io(format!("{secret}; {deny}")),
            });
        }
    }
    secret_removed.map_err(|e| DeleteKeystoreError::Io(e.to_string()))
}

/// Unlink staged and final names, then fsync the directory.
///
/// Returns whether every name is gone and the directory sync landed. A failed
/// unlink denylists the key so boot will not load a file this process could
/// not remove.
fn discard_staged_keystore(
    keystore_dir: &Path,
    pubkey: &Pubkey,
    denylist: Option<&Arc<DeletionDenylist>>,
    #[cfg(test)] before_discard: &TestHookSlot,
) -> bool {
    #[cfg(test)]
    run_hook(before_discard);
    let mut unlink_failed = false;
    for path in [
        staged_keystore_path(keystore_dir, pubkey),
        staged_meta_path(keystore_dir, pubkey),
        keystore_dir.join(format!("{}.json", pubkey_hex(*pubkey))),
        import_meta_path(keystore_dir, pubkey),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                unlink_failed = true;
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove a keystore file after a failed import"
                );
            }
        }
    }
    if let Err(e) = remove_import_secret(keystore_dir, pubkey) {
        warn!(error = %e, "failed to remove an import password secret after a failed import");
        unlink_failed = true;
    }
    let synced = match sync_keystore_dir(keystore_dir) {
        Ok(()) => true,
        Err(e) => {
            warn!(error = %e, "failed to fsync the keystore directory after discarding an import");
            false
        }
    };
    if unlink_failed {
        if let Some(denylist) = denylist {
            if let Err(e) = denylist.insert(pubkey) {
                warn!(
                    error = %e,
                    "failed to denylist a key whose keystore file could not be unlinked"
                );
            }
        }
    }
    !unlink_failed && synced
}

/// Remove this import's staged `.json.partial` and sidecar.
///
/// AlreadyPresent means another admission owns the signer, map, window, and
/// row. These two names were never renamed onto the boot path, so dropping
/// them does not touch that admission.
fn discard_unrenamed_partials(keystore_dir: &Path, pubkey: &Pubkey) {
    for path in [staged_keystore_path(keystore_dir, pubkey), staged_meta_path(keystore_dir, pubkey)]
    {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove a staged keystore partial"
                );
            }
        }
    }
    if let Err(e) = remove_import_secret(keystore_dir, pubkey) {
        warn!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            error = %e,
            "failed to remove an import password secret after dropping staged partials"
        );
    }
    if let Err(e) = sync_keystore_dir(keystore_dir) {
        warn!(
            error = %e,
            "failed to fsync the keystore directory after dropping staged partials"
        );
    }
}

/// Remove this import's renamed `0x<pk>.json` and metadata, then fsync the directory.
///
/// A late `AlreadyPresent` means the rename already landed. These names are
/// still this import's. The other admission's signer, map, window, and row
/// are not touched. Returns whether every name is gone and the directory sync
/// landed.
fn discard_renamed_keystore(keystore_dir: &Path, pubkey: &Pubkey) -> bool {
    let mut unlink_failed = false;
    for path in [
        keystore_dir.join(format!("{}.json", pubkey_hex(*pubkey))),
        import_meta_path(keystore_dir, pubkey),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                unlink_failed = true;
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove a renamed keystore file after AlreadyPresent"
                );
            }
        }
    }
    discard_renamed_removed_secret(keystore_dir, pubkey, &mut unlink_failed);
    let synced = match sync_keystore_dir(keystore_dir) {
        Ok(()) => true,
        Err(e) => {
            warn!(
                error = %e,
                "failed to fsync the keystore directory after removing a renamed keystore"
            );
            false
        }
    };
    !unlink_failed && synced
}

/// Unpublish the key, unlink its keystore, then drop an inserted validators row.
///
/// The row stays until the boot-visible `*.json` is gone. A failed unlink
/// leaves `enabled = false` with no hold, so boot does not enable the key.
///
/// Returns whether the disable listener still has to run. That listener takes
/// `state_lock`, so the caller must drop `tracked_keys` before running it.
fn rollback_failed_keystore(
    admissions: &crate::key_admission::KeyAdmissionService,
    keystore_dir: &Path,
    pubkey: &Pubkey,
    denylist: Option<&Arc<DeletionDenylist>>,
    inserted_row: bool,
    #[cfg(test)] before_discard: &TestHookSlot,
) -> bool {
    admissions.unpublish_failed_import(pubkey);
    let files_gone = discard_staged_keystore(
        keystore_dir,
        pubkey,
        denylist,
        #[cfg(test)]
        before_discard,
    );
    admissions.finish_keystore_rollback(pubkey, inserted_row, files_gone)
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

fn discard_renamed_removed_secret(keystore_dir: &Path, pubkey: &Pubkey, unlink_failed: &mut bool) {
    if let Err(e) = remove_import_secret(keystore_dir, pubkey) {
        warn!(error = %e, "failed to remove an import password secret after AlreadyPresent");
        *unlink_failed = true;
    }
}
/// Owned inputs for one import. The closure is `'static`, so every field is
/// owned or an `Arc` clone. The KDF permit is *not* stored here: the
/// `spawn_blocking` closure binds it so it cannot be dropped early.
struct ImportJob {
    keystore: Keystore,
    keystore_json: String,
    password: zeroize::Zeroizing<String>,
    keystore_dir: PathBuf,
    composite_signer: Arc<CompositeSigner>,
    tracked_keys: Arc<TrackedKeys>,
    delete_inflight: Arc<Mutex<DeleteInflight>>,
    denylist: Option<Arc<DeletionDenylist>>,
    admissions: Arc<KeyAdmissionService>,
    quiesce: Option<Arc<QuiesceRegistry>>,
    #[cfg(test)]
    before_admit: TestHookSlot,
    #[cfg(test)]
    before_discard: TestHookSlot,
    #[cfg(test)]
    fail_after_admit: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    fail_after_keystore_rename: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    after_admit: TestHookSlot,
    #[cfg(test)]
    after_readmit: TestHookSlot,
    #[cfg(test)]
    during_blocking: TestHookSlot,
    #[cfg(test)]
    after_secret_before_keystore: TestHookSlot,
    doppelganger_window_secs: u64,
}

/// Decrypt, then the same check-and-admit the async method used to run inline.
///
/// `tracked_keys` / `delete_inflight` ordering is unchanged. Callers hold the
/// KDF admission for the whole call.
fn import_keystore_blocking(job: ImportJob) -> Result<Pubkey, ImportKeystoreError> {
    let ImportJob {
        keystore,
        keystore_json,
        password,
        keystore_dir,
        composite_signer,
        tracked_keys,
        delete_inflight,
        denylist,
        admissions,
        quiesce,
        #[cfg(test)]
        before_admit,
        #[cfg(test)]
        before_discard,
        #[cfg(test)]
        fail_after_admit,
        #[cfg(test)]
        fail_after_keystore_rename,
        #[cfg(test)]
        after_admit,
        #[cfg(test)]
        after_readmit,
        #[cfg(test)]
        during_blocking,
        #[cfg(test)]
        after_secret_before_keystore,
        doppelganger_window_secs,
    } = job;

    #[cfg(test)]
    run_hook(&during_blocking);

    let secret_key = keystore
        .decrypt(password.as_bytes())
        .map_err(|e| ImportKeystoreError::DecryptionFailed(e.to_string()))?;

    let pubkey_bytes = secret_key.public_key().to_bytes();
    reject_unbootable_pubkey(keystore.pubkey.as_deref(), &pubkey_bytes)?;

    // Hold lock for the entire check-and-insert to prevent TOCTOU race.
    // Duplicate check uses the real local registry (not only API-tracked keys).
    let mut keys = tracked_keys.lock();
    if composite_signer.has_local_key(&pubkey_bytes) {
        return Err(ImportKeystoreError::Duplicate);
    }
    // Absent, but a DELETE that snapshotted this key has not finished.
    // Admitting here would `readmit` during that request's export.
    if delete_inflight.lock().per_key.get(&pubkey_bytes).copied().unwrap_or(0) > 0 {
        return Err(ImportKeystoreError::DeleteInProgress);
    }

    // The secret is durable before the keystore is staged. A later failure
    // removes it via `discard_staged_keystore` / `rollback_failed_keystore`.
    persist_import_secret(&keystore_dir, &pubkey_bytes, password.as_str())?;
    #[cfg(test)]
    run_hook(&after_secret_before_keystore);

    // Stage under a non-`.json` name. Boot load only accepts `*.json`, so a
    // crash before rename cannot resurrect a key the API reported as failed.
    let staged_keystore = staged_keystore_path(&keystore_dir, &pubkey_bytes);
    let staged_meta = staged_meta_path(&keystore_dir, &pubkey_bytes);
    let final_keystore = keystore_dir.join(format!("{}.json", pubkey_hex(pubkey_bytes)));
    let final_meta = import_meta_path(&keystore_dir, &pubkey_bytes);
    if let Err(e) = write_private_file(&staged_keystore, keystore_json.as_bytes()) {
        discard_staged_keystore(
            &keystore_dir,
            &pubkey_bytes,
            denylist.as_ref(),
            #[cfg(test)]
            &before_discard,
        );
        return Err(e);
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let meta_json = format!("{{\"imported_unix_seconds\":{}}}", now_unix);
    if let Err(e) = write_private_file(&staged_meta, meta_json.as_bytes()) {
        discard_staged_keystore(
            &keystore_dir,
            &pubkey_bytes,
            denylist.as_ref(),
            #[cfg(test)]
            &before_discard,
        );
        return Err(e);
    }

    // A windowed import persists the disabled hold while the key file is
    // still `.json.partial`, then renames it onto the boot path. A crash
    // before that rename cannot load the key over the old enabled row.
    let hold_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let doppelganger_hold_until = (doppelganger_window_secs > 0)
        .then_some(hold_unix.saturating_add(doppelganger_window_secs));
    let mut preinserted = false;
    // The tombstone persist must not run the disable listener while `keys` is
    // held. DELETE takes `state_lock` and then this same `tracked_keys` lock.
    let notify_disable = std::cell::Cell::new(false);
    let publish_keystore = |preinserted: bool| {
        let rollback = |preinserted: bool, err: ImportKeystoreError| {
            if preinserted {
                notify_disable.set(rollback_failed_keystore(
                    &admissions,
                    &keystore_dir,
                    &pubkey_bytes,
                    denylist.as_ref(),
                    true,
                    #[cfg(test)]
                    &before_discard,
                ));
            } else {
                discard_staged_keystore(
                    &keystore_dir,
                    &pubkey_bytes,
                    denylist.as_ref(),
                    #[cfg(test)]
                    &before_discard,
                );
            }
            Err(err)
        };
        if let Err(e) = std::fs::rename(&staged_keystore, &final_keystore)
            .map_err(|e| ImportKeystoreError::Io(e.to_string()))
        {
            return rollback(preinserted, e);
        }
        // The `*.json` name is boot-visible. A failure from here keeps the
        // disabled row until that file is unlinked.
        #[cfg(test)]
        if fail_after_keystore_rename.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return rollback(
                preinserted,
                ImportKeystoreError::Io("injected publish failure after keystore rename".into()),
            );
        }
        if let Err(e) = std::fs::rename(&staged_meta, &final_meta)
            .map_err(|e| ImportKeystoreError::Io(e.to_string()))
            .and_then(|_| sync_keystore_dir(&keystore_dir))
        {
            return rollback(preinserted, e);
        }
        Ok(())
    };
    macro_rules! fail_import {
        ($err:expr) => {{
            let notify = notify_disable.get();
            drop(keys);
            if notify {
                admissions.run_disable_listener(&pubkey_bytes);
            }
            return Err($err);
        }};
    }
    if let Some(until) = doppelganger_hold_until {
        if admissions.pubkey_is_present(&pubkey_bytes) {
            discard_unrenamed_partials(&keystore_dir, &pubkey_bytes);
            return Err(ImportKeystoreError::Duplicate);
        }
        match admissions.persist_keystore_hold(&pubkey_bytes, until) {
            Ok(inserted) => preinserted = inserted,
            Err(e) => {
                discard_staged_keystore(
                    &keystore_dir,
                    &pubkey_bytes,
                    denylist.as_ref(),
                    #[cfg(test)]
                    &before_discard,
                );
                return Err(ImportKeystoreError::Io(e.to_string()));
            }
        }
        #[cfg(test)]
        run_hook(&before_admit);
        // A refresh can insert the map inside the hook, before `notify`.
        // Decide AlreadyPresent before rename so this import still owns only
        // its staged partials.
        if admissions.pubkey_is_present(&pubkey_bytes) {
            discard_unrenamed_partials(&keystore_dir, &pubkey_bytes);
            return Err(ImportKeystoreError::Duplicate);
        }
        if let Err(e) = publish_keystore(preinserted) {
            fail_import!(e);
        }
    } else if admissions.pubkey_is_present(&pubkey_bytes) {
        discard_unrenamed_partials(&keystore_dir, &pubkey_bytes);
        return Err(ImportKeystoreError::Duplicate);
    } else if let Err(e) = publish_keystore(false) {
        fail_import!(e);
    } else {
        #[cfg(test)]
        run_hook(&before_admit);
    }
    let outcome = match admissions.admit(
        secret_key,
        AdmissionSource::Keystore {
            keystore_path: final_keystore.clone(),
            doppelganger_hold_until,
        },
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            // Admit rolls its own signer back without a generation bump.
            // Unpublish, unlink the keystore, then drop an inserted row.
            // The disable listener runs only after `tracked_keys` is released.
            notify_disable.set(rollback_failed_keystore(
                &admissions,
                &keystore_dir,
                &pubkey_bytes,
                denylist.as_ref(),
                preinserted,
                #[cfg(test)]
                &before_discard,
            ));
            fail_import!(ImportKeystoreError::Io(e.to_string()));
        }
    };

    #[cfg_attr(not(test), allow(unused_variables))]
    let inserted_row = match outcome {
        AdmissionOutcome::Admitted { inserted_row, .. } => preinserted || inserted_row,
        AdmissionOutcome::AlreadyPresent { .. } => {
            // The rename already happened, so these final names are this
            // import's. Remove them and fsync. Another admission owns the
            // signer, map, window, and its own row; leave those alone. If the
            // unlink or fsync does not stick, keep a disabled row with no hold
            // so boot cannot enable the leftover keystore.
            let files_gone = discard_renamed_keystore(&keystore_dir, &pubkey_bytes);
            if !files_gone {
                notify_disable.set(admissions.tombstone_late_duplicate(&pubkey_bytes, preinserted));
            }
            fail_import!(ImportKeystoreError::Duplicate);
        }
        AdmissionOutcome::SkippedDenylisted { .. } => {
            notify_disable.set(rollback_failed_keystore(
                &admissions,
                &keystore_dir,
                &pubkey_bytes,
                denylist.as_ref(),
                preinserted,
                #[cfg(test)]
                &before_discard,
            ));
            fail_import!(ImportKeystoreError::Io(
                "admission skipped denylisted key unexpectedly".into(),
            ));
        }
    };

    #[cfg(test)]
    if fail_after_admit.swap(false, std::sync::atomic::Ordering::SeqCst) {
        notify_disable.set(rollback_failed_keystore(
            &admissions,
            &keystore_dir,
            &pubkey_bytes,
            denylist.as_ref(),
            inserted_row,
            #[cfg(test)]
            &before_discard,
        ));
        fail_import!(ImportKeystoreError::Io("injected post-admit failure".into()));
    }

    #[cfg(test)]
    run_hook(&after_admit);

    // Track the key (lock still held)
    keys.push(pubkey_bytes);

    // SEC-1b: clear denylist only *after* successful persistence + registry
    // add so a mid-import IO failure cannot un-delete a previously deleted
    // key (restart would otherwise re-load it from secret-provider).
    if let Some(ref denylist) = denylist {
        if let Err(e) = denylist.remove(&pubkey_bytes) {
            // Key is already loaded and signable; surface IO so operators
            // can repair the denylist file. Do not roll back the import.
            // Do not readmit: a failed clear leaves the key quiesced.
            return Err(ImportKeystoreError::Io(e.to_string()));
        }
    }

    let delete_still_in_flight =
        delete_inflight.lock().per_key.get(&pubkey_bytes).copied().unwrap_or(0) > 0;
    if let Some(registry) = &quiesce {
        if !delete_still_in_flight {
            // admit's register_for_import leaves a deleted key Pending.
            // Unmonitored (post-cancel, before that register) is closed too.
            registry.readmit(&pubkey_bytes);
        }
    }

    #[cfg(test)]
    run_hook(&after_readmit);
    // Hold `tracked_keys` through readmit. Releasing earlier would let a
    // DELETE insert a quiescence that this readmit then erases.
    drop(keys);

    info!(
        pubkey = %TruncatedPubkey::new(&hex::encode(pubkey_bytes)),
        "Imported keystore"
    );
    Ok(pubkey_bytes)
}

#[async_trait]
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
        // Same lock import holds across check-and-admit. The in-flight count
        // is taken before this guard drops, so a re-import cannot `readmit`
        // between the scan and `begin_delete_export`.
        let _keys = self.tracked_keys.lock();
        let mut members = Vec::new();
        for pubkey in candidates {
            if self.composite_signer.has_local_key(pubkey) && !members.contains(pubkey) {
                members.push(*pubkey);
            }
        }
        let mut inflight = self.delete_inflight.lock();
        inflight.requests = inflight.requests.saturating_add(1);
        for pubkey in &members {
            let count = inflight.per_key.entry(*pubkey).or_insert(0);
            *count = count.saturating_add(1);
        }
        drop(inflight);
        drop(_keys);
        #[cfg(test)]
        run_hook(&self.after_membership_scan);
        members
    }

    fn begin_delete_export(&self, _members: &[Pubkey]) {
        // The count was taken in `membership_for_delete` under the scan's
        // `tracked_keys` guard. Incrementing again would leak a count of 1
        // after one `end_delete_export` and block re-import.
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

    async fn import_keystore(
        &self,
        keystore_json: &str,
        password: &str,
    ) -> Result<Pubkey, ImportKeystoreError> {
        if password.len()
            > usize::try_from(crate::config::IMPORT_SECRET_MAX_BYTES).unwrap_or(usize::MAX)
        {
            return Err(ImportKeystoreError::PasswordTooLarge);
        }
        // Parse on the async side (~1 KB) so admission can read r/N without
        // occupying a blocking thread.
        let keystore: Keystore = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        keystore.validate().map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;

        // Async wait. A queued import holds no blocking thread.
        let admit = self
            .kdf_budget
            .admit(crypto::kdf_working_set_bytes(&keystore))
            .await
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;

        let job = ImportJob {
            keystore,
            keystore_json: keystore_json.to_owned(),
            password: zeroize::Zeroizing::new(password.to_owned()),
            keystore_dir: self.keystore_dir.clone(),
            composite_signer: Arc::clone(&self.composite_signer),
            tracked_keys: Arc::clone(&self.tracked_keys),
            delete_inflight: Arc::clone(&self.delete_inflight),
            denylist: self.denylist.clone(),
            admissions: Arc::clone(&self.admissions),
            quiesce: self.quiesce.clone(),
            #[cfg(test)]
            before_admit: Arc::clone(&self.before_admit),
            #[cfg(test)]
            before_discard: Arc::clone(&self.before_discard),
            #[cfg(test)]
            fail_after_admit: Arc::clone(&self.fail_after_admit),
            #[cfg(test)]
            fail_after_keystore_rename: Arc::clone(&self.fail_after_keystore_rename),
            #[cfg(test)]
            after_admit: Arc::clone(&self.after_admit),
            #[cfg(test)]
            after_readmit: Arc::clone(&self.after_readmit),
            #[cfg(test)]
            during_blocking: Arc::clone(&self.during_blocking),
            #[cfg(test)]
            after_secret_before_keystore: Arc::clone(&self.after_secret_before_keystore),
            doppelganger_window_secs: self.doppelganger_window_secs.load(Ordering::Relaxed),
        };

        // The permit moves into the closure. A permit held on this future would
        // drop when axum drops the handler on client disconnect, while decrypt
        // kept running. `spawn_blocking` is outside the G-4 ban.
        let span = tracing::Span::current();
        let joined = tokio::task::spawn_blocking(move || {
            let _entered = span.enter();
            let _admit = admit;
            import_keystore_blocking(job)
        })
        .await
        .map_err(|e| ImportKeystoreError::Io(format!("keystore import task failed: {e}")))?;
        joined
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
            // Already absent from the signer. Still remove a leftover secret
            // and write the denylist. A failed secret removal does not skip
            // the denylist and does not register the key.
            insert_denylist_after_secret(
                self.denylist.as_ref(),
                pubkey,
                remove_import_secret(&self.keystore_dir, pubkey),
            )?;
            return Ok(false);
        }

        // Order:
        //   1. Unlink keystore files. Failure leaves memory and the denylist
        //      unchanged. The keystore directory is not fsynced.
        //   2. Remove the import secret, including the secrets-dir fsync.
        //   3. Durable denylist.insert, including when step 2 fails.
        //   4. Remove from the signing registry only when 2 and 3 both succeed.
        //
        // A failed secret removal still denylists the key so a restart does
        // not load it. The registry stays so DELETE can be retried.

        // Matches any `*.json` whose EIP-2335 pubkey field equals this key
        // (API-import `0x{hex}.json` and boot-loaded names like `validator1.json`).
        // No matching file is OK (secret-provider / already removed).
        remove_matching_keystore_files(&self.keystore_dir, pubkey)?;
        let secret_removed = remove_import_secret(&self.keystore_dir, pubkey);
        if secret_removed.is_ok() {
            // M-12: remove the import-time sidecar so a re-import starts clean.
            // A leftover staged partial or `.removing.*` set-aside is the same
            // unfinished marker (older cleanups used rename-aside; boot still
            // fails closed). Skipped when the secret is still on disk.
            let meta_path = import_meta_path(&self.keystore_dir, pubkey);
            let _ = std::fs::remove_file(&meta_path);
            let _ = std::fs::remove_file(staged_meta_path(&self.keystore_dir, pubkey));
            remove_leftover_removing_sidecars(&self.keystore_dir, pubkey);
        }
        insert_denylist_after_secret(self.denylist.as_ref(), pubkey, secret_removed)?;

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
